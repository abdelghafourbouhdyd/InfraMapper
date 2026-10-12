"""Passive DNS (Mnemonic, CIRCL) and live DNS-over-HTTPS lookups, normalised to one record shape.

Every lookup returns a list of records:
    {"rrname", "rrtype", "rdata", "first", "last", "count", "source"}
with ``first``/``last`` as epoch seconds and ``rrtype`` lower-case ("a", "ns", "mx"…).
A query matches either side of a record, so looking up an IP or a nameserver returns the
domains that pointed at it — that's what makes pDNS useful for finding sibling infrastructure.
"""

from __future__ import annotations

import json
import ipaddress
import time

import requests

from .clients import Cache, _QuotaPause
from .log import log

# Nameserver / mail providers shared by millions of unrelated domains: sharing them proves nothing
COMMODITY_NS = (
    "cloudflare.com", "domaincontrol.com", "registrar-servers.com", "awsdns-", "azure-dns.",
    "googledomains.com", "google.com", "nsone.net", "dnsmadeeasy.com", "ultradns.", "akam.net",
    "digitalocean.com", "linode.com", "vultr.com", "hetzner.com", "hetzner.de", "ovh.net",
    "ovh.com", "name.com", "namecheaphosting.com", "hostinger.com", "dns-parking.com",
    "parkingcrew.net", "sedoparking.com", "bodis.com", "above.com", "afternic.com",
    "dan.com", "hugedomains.com", "porkbun.com", "gandi.net", "dynadot.com", "namebrightdns.com",
    "cloudns.net", "he.net", "afraid.org", "dnsowl.com", "wixdns.net", "squarespacedns.com",
    "vercel-dns.com", "netlify.com", "dnspod.net", "dnsv", "hichina.com", "alidns.com",
    "yandex.net", "yandex.ru", "reg.ru", "nic.ru", "sitehost.pro", "bluehost.com",
    "hostgator.com", "dreamhost.com", "ionos.", "ui-dns.", "one.com", "networksolutions.com",
    "worldnic.com", "epik.com", "123-reg.co.uk", "siteground.net", "a2hosting.com",
    "wordpress.com", "shopify.com", "github.io", "desec.", "njal.la", "1984.is",
    "freenom.com", "dns.jp",
    "eurodns.", "dnsimple.com", "easydns.", "rackspace.com", "register.it", "aruba.it",
    "strato.de", "wedos.", "key-systems.net", "rrpproxy.net", "openprovider.", "gname-dns.com",
    "dynect.net", "constellix.", "akamaiedge.net", "incapdns.net", "fastly.net", "nsone.net",
    "timeweb.ru", "beget.com", "sprinthost.ru", "hosting.reg.ru", "nameself.com", "share-dns.", "webhostbox.net", "zoneedit.com",
    "outlook.com", "protection.outlook.com", "googlemail.com", "zoho.", "mailgun.org",
    "secureserver.net", "mimecast.com", "pphosted.com", "messagelabs.com", "icloud.com",
    "yahoodns.net", "mx.cloudflare.net", "improvmx.com", "forwardemail.net", "privateemail.com",
    "mailhostbox.com", "titan.email",
)
GENERIC_SOA_RNAME = ("dns.cloudflare.com", "hostmaster", "awsdns-hostmaster", "dns-admin.google",
                     "support.domaincontrol.com", "admin.registrar-servers.com")


def is_commodity(host: str) -> bool:
    h = host.lower().rstrip(".")
    # entries ending in "." or "-" are name fragments (awsdns-12.org, ionos.de); others are suffixes
    return any(c in h if c.endswith((".", "-")) else h == c or h.endswith("." + c)
               for c in COMMODITY_NS)


class _Provider:
    name = ""

    def __init__(self, cache: Cache):
        self.cache = cache
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "inframapper/1.0"
        self.calls = 0
        self.auth_failed = False   # bad key / plan: stop asking for this run
        self.paused = _QuotaPause(self.name)

    @property
    def dead(self) -> bool:
        return self.auth_failed or self.paused.active

    def _fetch(self, key: str, url: str, **kw):
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        if self.dead:
            return None
        for attempt in range(3):
            self.calls += 1
            try:
                r = self.s.get(url, timeout=30, **kw)
            except requests.RequestException as exc:
                log.warning(f"{self.name} request failed: {exc}")
                time.sleep(3)
                continue
            if r.status_code == 200:
                return r
            if r.status_code == 404:
                self.cache.set(key, [])
                return None
            if r.status_code == 429:
                self.paused.start()
                return None
            if r.status_code in (401, 402, 403):
                log.warning(f"{self.name} HTTP {r.status_code} (quota/auth) — disabled for this run")
                self.auth_failed = True
                return None
            if r.status_code >= 500:
                time.sleep(3 * (attempt + 1))
                continue
            log.warning(f"{self.name} HTTP {r.status_code}: {r.text[:150]}")
            return None
        return None


class Mnemonic(_Provider):
    """api.mnemonic.no — free, works without a key (MNEMONIC_API_KEY raises the quota)."""
    name = "Mnemonic pDNS"
    BASE = "https://api.mnemonic.no/pdns/v3/"

    def __init__(self, cache: Cache, api_key: str | None = None):
        super().__init__(cache)
        if api_key:
            self.s.headers["Argus-API-Key"] = api_key

    def lookup(self, q: str, limit: int) -> list[dict]:
        key = f"pdns:mnemonic:{q}:{limit}"
        r = self._fetch(key, self.BASE + q, params={"limit": limit})
        if r is None or isinstance(r, list):
            return r or []
        out = []
        for x in r.json().get("data") or []:
            out.append({"rrname": (x.get("query") or "").lower().rstrip("."),
                        "rrtype": (x.get("rrtype") or "").lower(),
                        "rdata": (x.get("answer") or "").lower().rstrip("."),
                        "first": (x.get("firstSeenTimestamp") or 0) // 1000,
                        "last": (x.get("lastSeenTimestamp") or 0) // 1000,
                        "count": x.get("times"), "source": self.name})
        self.cache.set(key, out)
        return out


class Circl(_Provider):
    """CIRCL Passive DNS (COF / NDJSON) — needs CIRCL_PDNS_USER / CIRCL_PDNS_PASS."""
    name = "CIRCL pDNS"
    BASE = "https://www.circl.lu/pdns/query/"

    def __init__(self, cache: Cache, user: str, password: str):
        super().__init__(cache)
        self.s.auth = (user, password)

    def lookup(self, q: str, limit: int) -> list[dict]:
        key = f"pdns:circl:{q}"
        r = self._fetch(key, self.BASE + q)
        if r is None or isinstance(r, list):
            return (r or [])[:limit]
        out = []
        for line in r.text.splitlines():
            try:
                x = json.loads(line)
            except ValueError:
                continue
            out.append({"rrname": str(x.get("rrname", "")).lower().rstrip("."),
                        "rrtype": str(x.get("rrtype", "")).lower(),
                        "rdata": str(x.get("rdata", "")).lower().rstrip("."),
                        "first": int(x.get("time_first") or 0), "last": int(x.get("time_last") or 0),
                        "count": x.get("count"), "source": self.name})
        self.cache.set(key, out)
        return out[:limit]


class LiveDNS(_Provider):
    """Current NS / MX / SOA / A via Cloudflare DNS-over-HTTPS (no key, no extra dependency)."""
    name = "live DNS"
    URL = "https://cloudflare-dns.com/dns-query"
    TYPES = {1: "a", 2: "ns", 5: "cname", 6: "soa", 15: "mx", 28: "aaaa"}

    def lookup(self, name: str, rrtypes=("A", "NS", "MX", "SOA")) -> list[dict]:
        out, now = [], int(time.time())
        for t in rrtypes:
            key = f"doh:{name}:{t}"
            r = self._fetch(key, self.URL, params={"name": name, "type": t},
                            headers={"accept": "application/dns-json"})
            if r is None or isinstance(r, list):
                out += r or []
                continue
            recs = []
            for a in r.json().get("Answer") or []:
                rt = self.TYPES.get(a.get("type"))
                if not rt:
                    continue
                data = str(a.get("data", "")).lower().rstrip(".")
                if rt == "mx":
                    data = data.split()[-1].rstrip(".")
                recs.append({"rrname": str(a.get("name", "")).lower().rstrip("."), "rrtype": rt,
                             "rdata": data, "first": now, "last": now, "count": None,
                             "source": self.name})
            self.cache.set(key, recs)
            out += recs
        return out


class PassiveDNS:
    """Fans a query out to every configured pDNS provider and merges the answers."""

    def __init__(self, cache: Cache, mnemonic_key: str | None = None,
                 circl_user: str | None = None, circl_pass: str | None = None,
                 live: bool = True):
        self.providers: list[_Provider] = [Mnemonic(cache, mnemonic_key)]
        if circl_user and circl_pass:
            self.providers.append(Circl(cache, circl_user, circl_pass))
        self.live = LiveDNS(cache) if live else None

    @property
    def calls(self) -> int:
        return sum(p.calls for p in self.providers) + (self.live.calls if self.live else 0)

    @property
    def available(self) -> bool:
        """False once every provider is out of quota / failed auth: an empty answer means 'unknown'."""
        return any(not p.dead for p in self.providers)

    def lookup(self, q: str, limit: int = 500) -> list[dict]:
        merged: dict[tuple, dict] = {}
        for p in self.providers:
            for r in p.lookup(q, limit):
                if r["rrtype"] in ("a", "aaaa"):   # 2a02:4780:0027:… and 2a02:4780:27:… are one address
                    r = {**r, "rdata": norm_ip(r["rdata"])}
                k = (r["rrname"], r["rrtype"], r["rdata"])
                cur = merged.get(k)
                if not cur:
                    merged[k] = dict(r)
                    continue
                # same record seen by several sensors: widen the window, keep every source
                cur["first"] = min((x for x in (cur["first"], r["first"]) if x), default=0)
                cur["last"] = max(cur["last"], r["last"])
                if r["source"] not in cur["source"]:
                    cur["source"] += f", {r['source']}"
        return list(merged.values())

    def current(self, name: str) -> list[dict]:
        return self.live.lookup(name) if self.live else []


def norm_ip(v: str) -> str:
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return v


def soa_parts(rdata: str) -> tuple[str, str]:
    """'ns1.x.com. hostmaster.x.com. 2024 …' -> (mname, rname as an email address)."""
    parts = rdata.split()
    if len(parts) < 2:
        return "", ""
    mname, rname = parts[0].rstrip("."), parts[1].rstrip(".")
    user, _, dom = rname.partition(".")
    return mname, f"{user}@{dom}" if dom else rname


def overlaps(a: tuple[int, int], b: tuple[int, int], slack: int = 7 * 86400) -> bool:
    """Two first/last-seen windows overlap (with a week of slack for sensor gaps)."""
    return bool(a[0] and b[0]) and a[0] <= b[1] + slack and b[0] <= a[1] + slack


def window(edge: dict) -> tuple[int, int] | None:
    """(first, last) seen of a RESOLVES_TO edge: pDNS window, or a VT resolution's single date."""
    f, l = edge.get("first_seen"), edge.get("last_seen")
    if isinstance(f, int) and f:
        return f, l or f
    d = edge.get("date")
    return (d, d) if isinstance(d, int) and d else None
