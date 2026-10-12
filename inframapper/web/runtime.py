"""In-process runtime for the live pivot graph.

Builds the Investigator and data sources exactly like ``infra-mapper.py`` does with default
options (keys from .env), and keeps one ``PivotServer`` per opened case. The PivotServer's HTTP
server is not started: the web app calls its ``submit`` / ``submit_regex`` / ``verdict`` / ``jobs``
directly, so the graph page (which calls ``api/...`` relative to its own URL) works unchanged under
``/cases/<case>/graph/``.
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

from ..clients import Cache, URLScan, VirusTotal
from ..intel import PriorReporting, Warninglists
from ..feeds import Feeds
from ..investigator import Config, Investigator
from ..knowledge import Knowledge
from ..pdns import PassiveDNS

KEYS = [
    ("VT_API_KEY", "VirusTotal API key", "File / domain / IP relationships, detections, comments"),
    ("VT_API_KEY_BACKUP", "VirusTotal backup key(s)", "Comma separated; takes over when the main key's quota runs out"),
    ("VT_RPM", "VirusTotal requests / minute", "4 on a free key"),
    ("URLSCAN_API_KEY", "urlscan.io API key", "Search pivots, scan parsing (works keyless but heavily rate limited)"),
    ("OTX_API_KEY", "AlienVault OTX key", "Prior reporting: OTX pulses"),
    ("ABUSECH_API_KEY", "abuse.ch key", "MalwareBazaar sample lookups (also ThreatFox / URLhaus)"),
]
SECRET = {k for k, *_ in KEYS if k != "VT_RPM"}
VALUE_RE = re.compile(r"""^[\x21-\x7e]*$""")   # printable ASCII…
BAD_CHARS = set("\"'`\\")                       # …minus what would break .env quoting


class Runtime:
    def __init__(self, root: Path, out: Path):
        self.root, self.out = root, out
        self.kb = Knowledge(out / "knowledge.db")
        self.servers: dict[str, object] = {}
        self.lock = threading.Lock()
        self.case_locks: dict[str, threading.Lock] = {}
        self._shared: dict = {}
        self.shared_lock = threading.Lock()

    SHARED_TTL = 24 * 3600   # warninglists refresh weekly on disk; re-read them daily

    def shared(self, with_vt: bool = False) -> dict:
        """Read-only reference data every case uses (MISP warninglists: ~350k IP ranges, a few seconds
        to parse; actor names; TLD list): loaded once per web server, not on every case open."""
        with self.shared_lock:
            if not self._shared or time.time() - self._shared["at"] > self.SHARED_TTL:
                self._shared = {"at": time.time(), "warn": Warninglists(self.root / ".cache")}
            if with_vt and "actors" not in self._shared:
                from ..extract import load_tlds
                from ..vtcomments import ActorNames
                self._shared.update(actors=ActorNames(self.root / ".cache"), tlds=load_tlds(self.root / ".cache"))
            return self._shared

    def preload(self) -> None:
        """Warm shared() at start-up (background thread) so the first case opens fast too."""
        try:
            self.shared(with_vt=bool(os.getenv("VT_API_KEY") or os.getenv("VT_API_KEY_BACKUP")))
        except Exception:   # noqa: BLE001 — loaded again on first use
            pass

    def build_investigator(self):
        """Same wiring as infra-mapper.py's main() with default options."""
        cache = Cache(self.root / ".cache", 24)
        vt_key, us_key = os.getenv("VT_API_KEY"), os.getenv("URLSCAN_API_KEY")
        vt_backup = [k.strip() for k in os.getenv("VT_API_KEY_BACKUP", "").split(",") if k.strip()]
        vt_key = vt_key or (vt_backup.pop(0) if vt_backup else None)
        vt = VirusTotal(vt_key, cache, float(os.getenv("VT_RPM", 4) or 4), vt_backup) if vt_key else None
        us = URLScan(us_key, cache)
        pdns = PassiveDNS(cache, os.getenv("MNEMONIC_API_KEY"), os.getenv("CIRCL_PDNS_USER"),
                          os.getenv("CIRCL_PDNS_PASS"), live=True)
        feeds = Feeds(self.root / ".cache", cache, os.getenv("ABUSECH_API_KEY"), os.getenv("GREYNOISE_API_KEY"),
                      os.getenv("ABUSEIPDB_API_KEY"), live=True)
        sh = self.shared(with_vt=vt is not None)
        warn = sh["warn"]
        otx, abuse = os.getenv("OTX_API_KEY"), os.getenv("ABUSECH_API_KEY")
        intel = PriorReporting(cache, otx, abuse) if (otx or abuse) else None
        cfg = Config(use_vt=vt is not None, use_urlscan=True, use_pdns=True)
        inv = Investigator(vt, us, cfg, pdns, intel, warn, feeds)
        inv.cache_dir, inv.cache, inv.tlp, inv.kb = self.root / ".cache", cache, "amber", self.kb
        if vt:
            inv.actors, inv.tlds = sh["actors"], sh["tlds"]
        from ..ct import CertTransparency
        inv.ct = CertTransparency(cache, os.getenv("CERTSPOTTER_API_KEY"))
        return inv, vt, us, pdns

    def server(self, case_dir: Path):
        """The live PivotServer for a case (created on first use; loading re-saves the case)."""
        from ..server import PivotServer
        name = case_dir.name
        with self.lock:
            if name in self.servers:
                return self.servers[name]
            lk = self.case_locks.setdefault(name, threading.Lock())
        with lk:
            if name not in self.servers:
                inv, vt, us, pdns = self.build_investigator()
                self.servers[name] = PivotServer(inv, case_dir, vt, us, pdns)
        return self.servers[name]

    def drop_all(self) -> None:
        """Forget live servers (after API keys change, so new sessions use the new keys)."""
        with self.lock:
            self.servers.clear()

    def sources(self) -> dict:
        return {"VirusTotal": bool(os.getenv("VT_API_KEY") or os.getenv("VT_API_KEY_BACKUP")),
                "urlscan.io": bool(os.getenv("URLSCAN_API_KEY")), "Passive DNS": True,
                "Prior reporting": bool(os.getenv("OTX_API_KEY") or os.getenv("ABUSECH_API_KEY")),
                "Public feeds": True, "Cert Transparency": True}


# ── .env editing ──────────────────────────────────────────────────────────────

def env_status(root: Path) -> list[dict]:
    """Per setting: set or not, and a masked hint (never more than the last 4 characters of a secret)."""
    from ..keycheck import mask
    out = []
    for key, label, help_ in KEYS:
        v = os.getenv(key, "")
        out.append({"key": key, "label": label, "help": help_, "set": bool(v), "secret": key in SECRET,
                    "hint": mask(key, v)})
    return out


def env_set(root: Path, key: str, value: str) -> None:
    if key not in {k for k, *_ in KEYS}:
        raise ValueError("unknown setting")
    value = (value or "").strip().replace("\n", "").replace("\r", "")
    if len(value) > 1000 or not VALUE_RE.match(value.replace(" ", "")) or BAD_CHARS & set(value):
        raise ValueError("the value has characters a key never contains (quotes, control characters…) or is too long")
    if key == "VT_RPM" and value:
        try:
            if not 0 < float(value) <= 1000:
                raise ValueError
        except ValueError:
            raise ValueError("VT requests / minute must be a number between 1 and 1000") from None
    if key == "VT_API_KEY_BACKUP":
        value = ",".join(v.strip() for v in value.split(",") if v.strip())
    path = root / ".env"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    done, out = False, []
    for ln in lines:
        if ln.split("=", 1)[0].strip() == key and not ln.lstrip().startswith("#"):
            if not done:
                out.append(f"{key}={value}")
                done = True
            continue
        out.append(ln)
    if not done:
        out.append(f"{key}={value}")
    tmp = path.with_suffix(".env.tmp")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(tmp, 0o600)   # secrets: owner only
    os.replace(tmp, path)
    if value:
        os.environ[key] = value
    else:
        os.environ.pop(key, None)
