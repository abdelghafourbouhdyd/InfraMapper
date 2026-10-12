"""Prior reporting: has an IOC already been published / attributed to a campaign?

Sources: AlienVault OTX pulses (where most vendor reports — DFIR Report, Unit42, … — get mirrored),
ThreatFox and MalwareBazaar (abuse.ch). IOCs on a MISP warninglist (cloud / CDN ranges, public
resolvers, top sites, known-good hashes…) are never attributed: they turn up in every report.

A report is only context for the analyst: it doesn't add to the cluster score. IP (and re-registered
domain) matches are checked against *when* the IOC was used here, since infrastructure changes hands.
"""

from __future__ import annotations

import io
import ipaddress
import json
import re
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests

from .clients import Cache
from .log import log
from .patterns import apex_of

WARNINGLISTS_URL = "https://codeload.github.com/MISP/misp-warninglists/tar.gz/refs/heads/main"
# report older than the IOC's use here by more than this = probably someone else's infrastructure
TIMING_SLACK = 180 * 86400


def _ts(v) -> int | None:
    """Epoch seconds from OTX / abuse.ch date strings ('2024-05-01T10:00:00.123', '… UTC')."""
    if isinstance(v, (int, float)):
        return int(v)
    if not v:
        return None
    s = str(v).replace(" UTC", "").replace("T", " ")[:19]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return int(datetime.strptime(s[:len(fmt) + 2], fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    return None


# Warninglists that would hide real attacker infrastructure are not "benign":
#  - rented hosting / cloud / VPN / Tor / dynamic DNS: where C2s live -> still looked up, but flagged
#  - huge top-site lists (a compromised or free-hosting site can be in the top 1M), and lists that
#    say nothing about maliciousness (universities, banks, TLDs) -> ignored
HOSTING_RE = re.compile(r"hetzner|leaseweb|ovh|amazon|aws|azure|oracle|google cloud|gcp|digitalocean|linode|"
                        r"vultr|alibaba|aliyun|tencent|huawei|ibm cloud|scaleway|rackspace|coreweave|godaddy|"
                        r"vpn|tor exit|icloud|dynamic dns|dyndns", re.I)
IGNORE_RE = re.compile(r"universit|bank|tlds|covid|1million|crux", re.I)
TOP_MAX = 10_000


def _classify(name: str) -> str | None:
    """'benign' / 'hosting' / None (ignored) for a MISP warninglist."""
    if IGNORE_RE.search(name):
        return None
    if HOSTING_RE.search(name):
        return "hosting"
    m = re.search(r"top\s*([\d][\d,\s]*)(k?)\b", name, re.I)
    if m:
        n = int(re.sub(r"[,\s]", "", m.group(1)) or 0) * (1000 if m.group(2) else 1)
        if n > TOP_MAX:
            return None
    return "benign"


class Warninglists:
    """MISP warninglists, cached locally and refreshed weekly.

    Hostname lists are matched on the exact name only: a top-sites list containing pages.dev must
    not whitelist every phishing subdomain of it."""

    def __init__(self, directory: Path, max_age_days: float = 7):
        self.path = directory / "warninglists-v2.json"
        self.nets: list[tuple[ipaddress._BaseNetwork, str, str]] = []
        self.exact: dict[str, tuple[str, str]] = {}
        try:
            if not self.path.exists() or time.time() - self.path.stat().st_mtime > max_age_days * 86400:
                self._download()
            self._load()
        except Exception as exc:
            log.warning(f"MISP warninglists unavailable ({exc}) — known-benign IOCs won't be filtered")

    def _download(self) -> None:
        log.info("downloading MISP warninglists…")
        r = requests.get(WARNINGLISTS_URL, timeout=120)
        r.raise_for_status()
        lists = []
        with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
            for m in tar:
                if m.isfile() and m.name.endswith("/list.json") and "/lists/" in m.name:
                    d = json.load(tar.extractfile(m))
                    kind = _classify(d.get("name") or "")
                    if kind and d.get("type") in ("cidr", "hostname", "string") and d.get("list"):
                        lists.append({"name": d.get("name"), "kind": kind, "type": d["type"], "list": d["list"]})
        self.path.write_text(json.dumps(lists))
        log.info(f"  {len(lists)} warninglists kept")

    def _load(self) -> None:
        for wl in json.loads(self.path.read_text()):
            kind = _classify(wl["name"])   # re-classified on load: the cache may predate a rule change
            if not kind:
                continue
            tag = (wl["name"], kind)
            for entry in wl["list"]:
                entry = str(entry).strip().lower().rstrip(".")
                if wl["type"] == "cidr":
                    try:
                        net = ipaddress.ip_network(entry, strict=False)
                    except ValueError:
                        continue
                    if net.num_addresses == 1:   # single hosts: dict lookup instead of a scan
                        self.exact.setdefault(str(net.network_address), tag)
                    else:
                        self.nets.append((net, *tag))
                else:
                    self.exact.setdefault(entry, tag)

    def match(self, ntype: str, value: str) -> tuple[str, str] | None:
        """(list name, 'benign' | 'hosting') or None."""
        v = value.strip().lower().rstrip(".")
        if ntype == "IP":
            try:
                ip = ipaddress.ip_address(v)
            except ValueError:
                return None
            hit = self.exact.get(str(ip))
            if hit:
                return hit
            found = [(name, kind) for net, name, kind in self.nets if ip.version == net.version and ip in net]
            # a benign list (CDN, resolver) wins over a generic cloud range
            return next((f for f in found if f[1] == "benign"), found[0] if found else None)
        return self.exact.get(v)


class PriorReporting:
    """Look an IOC up in OTX / ThreatFox / MalwareBazaar. Every hit = one report dict."""

    def __init__(self, cache: Cache, otx_key: str | None, abusech_key: str | None,
                 max_pulses: int = 10):
        self.cache, self.max_pulses = cache, max_pulses
        self.otx = requests.Session() if otx_key else None
        if self.otx:
            self.otx.headers.update({"X-OTX-API-KEY": otx_key, "User-Agent": "inframapper/1.0"})
        self.abuse = requests.Session() if abusech_key else None
        if self.abuse:
            self.abuse.headers.update({"Auth-Key": abusech_key, "User-Agent": "inframapper/1.0"})
        self.calls = 0
        self.failed: set[str] = set()   # sources that errored: stop hammering them this run

    @property
    def sources(self) -> list[str]:
        return [n for n, s in (("OTX", self.otx), ("ThreatFox", self.abuse), ("MalwareBazaar", self.abuse)) if s]

    def _req(self, source: str, key: str, fn):
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        if source in self.failed:
            return None
        for attempt in range(2):   # parallel lookups can trip a burst limit: one retry after a pause
            self.calls += 1
            try:
                r = fn()
            except requests.RequestException as exc:
                log.warning(f"{source} request failed: {exc}")
                self.failed.add(source)
                return None
            if r.status_code != 429 or attempt:
                break
            time.sleep(2)
            if source in self.failed:   # another lookup thread already gave up on it
                return None
        if r.status_code == 404:
            self.cache.set(key, {})
            return {}
        if r.status_code in (401, 403):
            log.warning(f"{source}: HTTP {r.status_code} — check the API key")
            self.failed.add(source)
            return None
        if r.status_code != 200:
            log.warning(f"{source}: HTTP {r.status_code}")
            return None
        data = r.json()
        self.cache.set(key, data)
        return data

    # ------------------------------------------------------------------ sources
    def _otx(self, ntype: str, value: str) -> tuple[int, list[dict]]:
        if ntype == "IP":
            section = "IPv6" if ":" in value else "IPv4"
        elif ntype == "Domain":
            section = "domain" if apex_of(value) == value else "hostname"
        else:
            section = {"File": "file", "URL": "url"}[ntype]
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(value, safe='')}/general"
        data = self._req("OTX", f"otx:{section}:{value}", lambda: self.otx.get(url, timeout=30))
        info = (data or {}).get("pulse_info") or {}
        pulses = sorted(info.get("pulses") or [], key=lambda p: p.get("created") or "", reverse=True)
        out = []
        for p in pulses[: self.max_pulses]:
            refs = [x for x in p.get("references") or [] if isinstance(x, str) and x.startswith("http")]
            author = p.get("author") if isinstance(p.get("author"), dict) else {}
            out.append({"source": "OTX", "key": f"otx:{p.get('id')}", "name": p.get("name") or "OTX pulse",
                        "date": _ts(p.get("created")), "url": refs[0] if refs else
                        f"https://otx.alienvault.com/pulse/{p.get('id')}",
                        "references": refs[:5], "actor": p.get("adversary") or None,
                        "malware": sorted({m.get("display_name") for m in p.get("malware_families") or []
                                           if isinstance(m, dict) and m.get("display_name")}),
                        "tags": (p.get("tags") or [])[:10],
                        "attack": sorted({a.get("id") for a in p.get("attack_ids") or [] if isinstance(a, dict)
                                          and a.get("id")})[:10],
                        "author": author.get("username") or p.get("author_name")})
        return info.get("count") or len(pulses), out

    def _threatfox(self, ntype: str, value: str) -> list[dict]:
        # ThreatFox stores most C2 IPs as ip:port, which an exact match on the bare IP misses:
        # search loosely, then keep only that IP (with or without a port)
        body = ({"query": "search_hash", "hash": value} if ntype == "File"
                else {"query": "search_ioc", "search_term": value, "exact_match": ntype != "IP"})
        data = self._req("ThreatFox", f"threatfox:{json.dumps(body, sort_keys=True)}",
                         lambda: self.abuse.post("https://threatfox-api.abuse.ch/api/v1/", json=body, timeout=30))
        rows = (data or {}).get("data")
        if (data or {}).get("query_status") != "ok" or not isinstance(rows, list):
            return []
        if ntype == "IP":
            rows = [r for r in rows if str(r.get("ioc") or "") in (value, f"[{value}]")
                    or str(r.get("ioc") or "").startswith((f"{value}:", f"[{value}]:"))]
        fams: dict[str, dict] = {}   # one report per malware family
        for row in rows:
            fam = row.get("malware_printable") or row.get("malware") or "unknown"
            cur = fams.setdefault(fam, {
                "source": "ThreatFox", "key": f"threatfox:{row.get('malware') or fam}", "name": f"ThreatFox: {fam}",
                "date": _ts(row.get("first_seen")), "url": row.get("reference") or
                f"https://threatfox.abuse.ch/ioc/{row.get('id')}/", "references": [], "actor": None,
                "malware": [fam], "tags": [], "threat_type": row.get("threat_type_desc") or row.get("threat_type"),
                "confidence": row.get("confidence_level"), "author": row.get("reporter")})
            d = _ts(row.get("first_seen"))
            if d and (not cur["date"] or d < cur["date"]):
                cur["date"] = d
            if row.get("reference") and row["reference"] not in cur["references"]:
                cur["references"].append(row["reference"])
            cur["tags"] = sorted(set(cur["tags"]) | set(row.get("tags") or []))[:10]
        return list(fams.values())

    def _bazaar(self, value: str) -> list[dict]:
        data = self._req("MalwareBazaar", f"bazaar:{value}", lambda: self.abuse.post(
            "https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": value}, timeout=30))
        if (data or {}).get("query_status") != "ok" or not (data.get("data") or []):
            return []
        d = data["data"][0]
        sig = d.get("signature")
        return [{"source": "MalwareBazaar", "key": f"bazaar:{sig or d.get('sha256_hash')}",
                 "name": f"MalwareBazaar: {sig or 'unsigned sample'}", "date": _ts(d.get("first_seen")),
                 "url": f"https://bazaar.abuse.ch/sample/{d.get('sha256_hash')}/", "references": [],
                 "actor": None, "malware": [sig] if sig else [], "tags": (d.get("tags") or [])[:10],
                 "author": d.get("reporter"), "file_name": d.get("file_name")}]

    def lookup(self, ntype: str, value: str) -> tuple[int, list[dict]]:
        """(OTX pulse count, reports) for one IOC."""
        total, reports = 0, []
        if self.otx:
            total, reports = self._otx(ntype, value)
        if self.abuse:
            reports += self._threatfox(ntype, value)
            if ntype == "File" and len(value) in (32, 40, 64):
                reports += self._bazaar(value)
        return total, reports


def timing(report_date: int | None, used: tuple[int, int] | None, last_seen: int | None = None) -> str | None:
    """Does the report date (or the feed's first..last seen window) fit when the IOC was used here?"""
    first = report_date or last_seen
    if not first or not used or not used[0]:
        return None
    if (last_seen or first) < used[0] - TIMING_SLACK:
        return "earlier"     # reported well before this use: likely a previous tenant / owner
    if first > used[1] + TIMING_SLACK:
        return "later"       # reported well after: the address may have been reassigned since
    return "fits"
