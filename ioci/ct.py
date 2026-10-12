"""Certificate Transparency lookups for certificate pivots.

Cert Spotter (SSLMate) answers reliably but only lists unexpired certificates (and allows ~10
unauthenticated queries an hour; set CERTSPOTTER_API_KEY for more). crt.sh also has expired
ones but is often down (502). Both are asked; results are merged by serial / SHA-256.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import requests

from .clients import Cache
from .log import log

UA = {"User-Agent": "inframapper (+https://github.com/abdelghafourbouhdyd/InfraMapper)"}


def _ts(s) -> int | None:
    """Epoch seconds from an ISO date, a VT "YYYY-MM-DD HH:MM:SS" or an epoch number."""
    if s in (None, ""):
        return None
    if isinstance(s, (int, float)):
        return int(s)
    try:
        return int(datetime.fromisoformat(str(s).replace("Z", "")[:19].replace(" ", "T"))
                   .replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


class CertTransparency:
    def __init__(self, cache: Cache, certspotter_key: str | None = None):
        self.cache, self.key = cache, certspotter_key
        self.calls = 0
        self.down: set[str] = set()   # services that failed this session: don't hammer them

    # ------------------------------------------------------------ sources
    def _certspotter(self, domain: str) -> list[dict]:
        key = f"certspotter:{domain}"
        data = self.cache.get(key)
        if data is None and "certspotter" not in self.down:
            data, after = [], None
            headers = dict(UA, **({"Authorization": f"Bearer {self.key}"} if self.key else {}))
            for _ in range(5):   # pages of 100
                params = [("domain", domain), ("include_subdomains", "true"),
                          ("expand", "dns_names"), ("expand", "issuer")] + ([("after", after)] if after else [])
                self.calls += 1
                try:
                    r = requests.get("https://api.certspotter.com/v1/issuances", params=params,
                                     headers=headers, timeout=60)
                    if r.status_code == 429:
                        log.warning("Cert Spotter rate limit hit (set CERTSPOTTER_API_KEY for more)")
                        self.down.add("certspotter")
                        break
                    r.raise_for_status()
                    page = r.json()
                except (requests.RequestException, ValueError) as exc:
                    log.warning(f"Cert Spotter unavailable ({exc})")
                    self.down.add("certspotter")
                    break
                data += page
                if len(page) < 100:
                    break
                after = page[-1]["id"]
            if "certspotter" not in self.down:
                self.cache.set(key, data)
        return [{"sha256": c.get("cert_sha256"), "names": c.get("dns_names") or [],
                 "not_before": _ts(c.get("not_before")), "not_after": _ts(c.get("not_after")),
                 "issuer": (c.get("issuer") or {}).get("friendly_name") or (c.get("issuer") or {}).get("name"),
                 "pubkey_sha256": c.get("pubkey_sha256"), "source": "Cert Spotter"}
                for c in data or []]

    def _crtsh(self, domain: str) -> list[dict]:
        key = f"crtsh-ident:{domain}"
        data = self.cache.get(key)
        if data is None and "crt.sh" not in self.down:
            for attempt in range(2):   # crt.sh often answers 502 under load
                self.calls += 1
                try:
                    r = requests.get("https://crt.sh/", params={"q": domain, "output": "json"},
                                     headers=UA, timeout=45)
                    r.raise_for_status()
                    data = r.json()
                    self.cache.set(key, data)
                    break
                except (requests.RequestException, ValueError) as exc:
                    if attempt:
                        log.warning(f"crt.sh unavailable ({exc}) — expired certificates not listed")
                        self.down.add("crt.sh")
                    else:
                        time.sleep(3)
        out: dict[str, dict] = {}
        for c in data or []:   # one row per log entry: precert + cert share a serial
            serial = (c.get("serial_number") or "").lower()
            rec = out.setdefault(serial or str(c.get("id")), {
                "serial": serial, "names": set(), "not_before": _ts(c.get("not_before")),
                "not_after": _ts(c.get("not_after")), "crtsh_id": c.get("id"),
                "issuer": _issuer_o(c.get("issuer_name", "")), "source": "crt.sh"})
            rec["names"] |= {n.strip().lower() for n in str(c.get("name_value", "")).split("\n") if n.strip()}
        return [dict(r, names=sorted(r["names"])) for r in out.values()]

    # ------------------------------------------------------------ public
    def issuances(self, domain: str) -> list[dict]:
        """Certificates for ``domain`` and its subdomains, newest first."""
        certs = self._certspotter(domain)
        seen = {(c["not_before"], tuple(sorted(c["names"]))) for c in certs}
        for c in self._crtsh(domain):
            if (c["not_before"], tuple(c["names"])) not in seen:
                certs.append(c)
        return sorted(certs, key=lambda c: c["not_before"] or 0, reverse=True)

    @staticmethod
    def match(certs: list[dict], sha256: str | None = None, serial: str | None = None,
              cn: str | None = None, not_before=None) -> dict | None:
        """The issuance that is this certificate (by hash, serial, or CN + issue time)."""
        nb = _ts(not_before)
        for c in certs:
            if sha256 and c.get("sha256") == sha256.lower():
                return c
            if serial and c.get("serial") and c["serial"].lstrip("0") == serial.lower().lstrip("0"):
                return c
        if cn and nb:
            for c in certs:
                if c["not_before"] and abs(c["not_before"] - nb) <= 120 and cn.lower() in c["names"]:
                    return c
        return None


def _issuer_o(dn: str) -> str | None:
    parts = dict(p.strip().split("=", 1) for p in dn.split(",") if "=" in p)
    return parts.get("O") or parts.get("CN")
