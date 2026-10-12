"""API key validation: test each provider's credentials and read its quota where the API exposes one.

Every check makes one cheap authenticated call (an account / quota endpoint when the provider has
one) and returns::

    {"provider", "status": valid | invalid | keyless | not_configured | rate_limited | error,
     "message", "quota": [{"label", "used", "limit", "remaining"}], "plan", "checked_at", "latency_ms"}

Secrets never leave this module: messages are built from status codes and known response fields,
and anything else (exception text, which can include request URLs) goes through ``redact`` with
every configured secret. Results are cached in ``.cache/key_status.json`` keyed by a short hash of
the key, so a replaced key shows as untested instead of inheriting the old status.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import re

import requests


def redact(text: str, *secrets: str | None) -> str:
    """Remove secrets (and anything that looks like a key=… query value) from a message."""
    out = str(text)
    for s in secrets:
        if s and len(s) >= 4:
            out = out.replace(s, "***")
    return re.sub(r"(?i)((?:api[_-]?)?key=)[^&\s'\"]+", r"\1***", out)

UA = {"User-Agent": "inframapper/1.0"}
TIMEOUT = 15

# provider -> what it needs; ``keys`` are .env names (first = main credential), ``keyless`` = works
# without a key at a lower quota. Order = display order.
PROVIDERS = [
    {"id": "virustotal", "name": "VirusTotal", "keys": ["VT_API_KEY", "VT_API_KEY_BACKUP", "VT_RPM"], "keyless": False,
     "used_for": "File / domain / IP / URL relationships, detections, community comments, certificates, JARM",
     "docs": "https://www.virustotal.com/gui/my-apikey"},
    {"id": "urlscan", "name": "urlscan.io", "keys": ["URLSCAN_API_KEY"], "keyless": True,
     "used_for": "Search pivots (title, favicon, HTML, scripts, patterns), scan parsing, regex hunts",
     "docs": "https://urlscan.io/user/profile/"},
    {"id": "otx", "name": "AlienVault OTX", "keys": ["OTX_API_KEY"], "keyless": False,
     "used_for": "Prior reporting: OTX pulses", "docs": "https://otx.alienvault.com/settings"},
    {"id": "abusech", "name": "abuse.ch · MalwareBazaar", "keys": ["ABUSECH_API_KEY"], "keyless": False,
     "used_for": "MalwareBazaar sample lookups (the same abuse.ch key also serves ThreatFox / URLhaus)",
     "docs": "https://auth.abuse.ch/"},
]
BY_ID = {p["id"]: p for p in PROVIDERS}
NON_SECRET = {"VT_RPM"}
MIN_INTERVAL = 3.0   # seconds between two tests of the same provider


def secrets_in_env() -> list[str]:
    return [os.getenv(k, "") for p in PROVIDERS for k in p["keys"] if k not in NON_SECRET and os.getenv(k)]


def fingerprint(*values: str) -> str:
    return hashlib.sha256("\x00".join(v or "" for v in values).encode()).hexdigest()[:12]


def mask(key: str, value: str) -> str:
    """What the UI may show of a stored value: never more than the last 4 characters of a secret."""
    if not value:
        return ""
    if key in NON_SECRET:
        return value
    if key == "VT_API_KEY_BACKUP":
        n = len([v for v in value.split(",") if v.strip()])
        return f"{n} key{'s' if n != 1 else ''} · " + ", ".join("••••" + v.strip()[-4:] for v in value.split(",") if v.strip())
    return "••••••••" + value[-4:] if len(value) >= 12 else "••••••••"


def _http(method: str, url: str, **kw) -> requests.Response:
    """Single choke point for provider calls (tests patch this)."""
    kw.setdefault("timeout", TIMEOUT)
    kw["headers"] = {**UA, **(kw.get("headers") or {})}
    return requests.request(method, url, **kw)


def _q(label: str, used=None, limit=None, remaining=None) -> dict:
    def num(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    used, limit, remaining = num(used), num(limit), num(remaining)
    if remaining is None and used is not None and limit is not None:
        remaining = max(0, limit - used)
    if used is None and remaining is not None and limit is not None:
        used = max(0, limit - remaining)
    return {"label": label, "used": used, "limit": limit, "remaining": remaining}


def _status_from_http(r: requests.Response, ok_msg: str) -> tuple[str, str]:
    if r.status_code == 200:
        return "valid", ok_msg
    if r.status_code in (401, 403):
        return "invalid", f"authentication failed (HTTP {r.status_code}): the key was rejected. Check it was copied completely."
    if r.status_code == 429:
        return "rate_limited", "the key works but its quota is exhausted right now (HTTP 429). Retry later."
    if r.status_code >= 500:
        return "error", f"the provider is having problems (HTTP {r.status_code}). Retry in a few minutes."
    return "error", f"unexpected answer (HTTP {r.status_code})."


# ── provider checks: (status, message, quota, plan) ────────────────────────────

def _virustotal(vals: dict) -> tuple:
    key = vals["VT_API_KEY"] or (vals.get("VT_API_KEY_BACKUP") or "").split(",")[0].strip()
    r = _http("GET", f"https://www.virustotal.com/api/v3/users/{key}/overall_quotas", headers={"x-apikey": key})
    st, msg = _status_from_http(r, "authenticated")
    quota = []
    if st == "valid":
        d = (r.json() or {}).get("data") or {}
        for k, label in (("api_requests_hourly", "requests / hour"), ("api_requests_daily", "requests / day"),
                         ("api_requests_monthly", "requests / month")):
            u = (d.get(k) or {}).get("user") or {}
            if u:
                quota.append(_q(label, u.get("used"), u.get("allowed")))
        daily = next((q for q in quota if q["label"] == "requests / day"), None)
        plan = "premium" if daily and (daily["limit"] or 0) > 500 else "public (free)"
        if daily and daily["remaining"] == 0:
            st, msg = "rate_limited", "authenticated, but today's quota is used up"
    backups = [b.strip() for b in (vals.get("VT_API_KEY_BACKUP") or "").split(",") if b.strip()]
    if st in ("valid", "rate_limited") and backups:
        bad = 0
        for b in backups[:5]:
            rb = _http("GET", f"https://www.virustotal.com/api/v3/users/{b}/overall_quotas", headers={"x-apikey": b})
            bad += rb.status_code in (401, 403)
        msg += f"; backup keys: {len(backups) - bad}/{len(backups)} accepted" + (" (fix the rejected ones)" if bad else "")
    return st, msg, quota, (plan if st in ("valid", "rate_limited") else None)


def _urlscan(vals: dict) -> tuple:
    r = _http("GET", "https://urlscan.io/user/quotas/", headers={"API-Key": vals["URLSCAN_API_KEY"]})
    st, msg = _status_from_http(r, "authenticated")
    if st != "valid":
        return st, msg, [], None
    limits = (r.json() or {}).get("limits") or {}
    quota = []
    for action in ("search", "public", "unlisted", "private", "retrieve"):
        day = (limits.get(action) or {}).get("day") or {}
        if day:
            quota.append(_q(f"{action} / day", day.get("used"), day.get("limit"), day.get("remaining")))
    return st, msg, quota, None


def _otx(vals: dict) -> tuple:
    r = _http("GET", "https://otx.alienvault.com/api/v1/users/me", headers={"X-OTX-API-KEY": vals["OTX_API_KEY"]})
    st, msg = _status_from_http(r, "authenticated")
    if st == "valid":
        user = (r.json() or {}).get("username")
        msg = f"authenticated as {user}" if user else msg
    return st, msg, [], None


def _abusech(vals: dict) -> tuple:
    """MalwareBazaar lookup of a hash that isn't there: authenticated -> 'hash_not_found'."""
    r = _http("POST", "https://mb-api.abuse.ch/api/v1/", headers={"Auth-Key": vals["ABUSECH_API_KEY"]},
              data={"query": "get_info", "hash": "0" * 64})
    st, msg = _status_from_http(r, "authenticated (MalwareBazaar)")
    if st == "valid":
        qs = str((r.json() or {}).get("query_status") or "")
        if "auth" in qs or "unknown" in qs and "key" in qs:
            st, msg = "invalid", f"authentication failed: MalwareBazaar answered '{qs[:40]}'"
    return st, msg, [], None


CHECKS = {"virustotal": _virustotal, "urlscan": _urlscan, "otx": _otx, "abusech": _abusech}


class KeyChecker:
    def __init__(self, cache_dir: Path):
        self.path = cache_dir / "key_status.json"
        self.lock = threading.Lock()
        self.last: dict[str, float] = {}

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _store(self, pid: str, rec: dict) -> None:
        with self.lock:
            data = self._load()
            data[pid] = rec
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)

    @staticmethod
    def values(pid: str, override: dict | None = None) -> dict:
        p = BY_ID[pid]
        vals = {k: os.getenv(k, "") for k in p["keys"]}
        for k, v in (override or {}).items():
            if k in vals and v:
                vals[k] = str(v).strip()
        return vals

    def status(self) -> dict[str, dict]:
        """Last result per provider, marked stale when the key changed since."""
        saved = self._load()
        out = {}
        for p in PROVIDERS:
            vals = self.values(p["id"])
            main = vals[p["keys"][0]] or (vals.get("VT_API_KEY_BACKUP") if p["id"] == "virustotal" else "")
            rec = saved.get(p["id"])
            if not main:
                out[p["id"]] = {"status": "keyless" if p["keyless"] else "not_configured",
                                "message": "works without a key at a lower quota" if p["keyless"] else "no key set",
                                "checked_at": None, "quota": []}
            elif rec and rec.get("fp") == fingerprint(*[vals[k] for k in p["keys"]]):
                out[p["id"]] = {k: v for k, v in rec.items() if k != "fp"}
            else:
                out[p["id"]] = {"status": "untested", "message": "key set, not tested yet", "checked_at": None, "quota": []}
        return out

    def test(self, pid: str, override: dict | None = None) -> dict:
        """Run one provider's check. ``override``: unsaved values to try (not stored, not cached)."""
        if pid not in BY_ID:
            raise ValueError("unknown provider")
        now = time.time()
        if now - self.last.get(pid, 0) < MIN_INTERVAL:
            raise ValueError("tested a moment ago: wait a few seconds")
        self.last[pid] = now
        p = BY_ID[pid]
        vals = self.values(pid, override)
        main = vals[p["keys"][0]] or (vals.get("VT_API_KEY_BACKUP") if pid == "virustotal" else "")
        secrets = secrets_in_env() + [v for k, v in vals.items() if v and k not in NON_SECRET]
        rec = {"provider": pid, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "quota": [], "plan": None, "latency_ms": None}
        if not main:
            rec.update(status="keyless" if p["keyless"] else "not_configured",
                       message="no key to test" + (": the keyless API is used" if p["keyless"] else ""))
            return rec
        t0 = time.time()
        try:
            st, msg, quota, plan = CHECKS[pid](vals)
            rec.update(status=st, message=redact(msg, *secrets), quota=quota, plan=plan)
        except requests.Timeout:
            rec.update(status="error", message=f"no answer within {TIMEOUT} s: check network access / proxy")
        except requests.ConnectionError:
            rec.update(status="error", message="could not connect: check network access, DNS or proxy settings")
        except (requests.RequestException, ValueError) as exc:   # ValueError: non-JSON answer
            rec.update(status="error", message=redact(f"request failed: {type(exc).__name__}: {exc}", *secrets)[:300])
        rec["latency_ms"] = round((time.time() - t0) * 1000)
        if not override:
            self._store(pid, {**rec, "fp": fingerprint(*[vals[k] for k in p["keys"]])})
        return rec
