"""Public threat feeds: is an IOC on a C2 / phishing / abuse list *right now*, and is it just noise?

Bulk lists (downloaded to .cache/feeds, refreshed per feed, stale copy used if a refresh fails):
  Feodo Tracker (botnet C2), C2IntelFeeds (Cobalt Strike C2 IPs / domains, rolling 90 days),
  OpenPhish (live phishing URLs), IPsum (IP on N public blocklists), Tor exit nodes,
  Spamhaus DROP / ASN-DROP (hijacked or criminal netblocks), CISA KEV (exploited CVEs).
Per-IOC lookups (cached like every other API call):
  URLhaus (ABUSECH_API_KEY), Shodan InternetDB (no key), GreyNoise community (key optional),
  AbuseIPDB (ABUSEIPDB_API_KEY).

A hit that names a campaign / family (Feodo, C2IntelFeeds, OpenPhish, URLhaus) is returned as a
report dict, like OTX / ThreatFox: it becomes a Report node, so every IOC of the case on the same
feed links to the same node. Everything else (noise, reputation, exposure) is a node property that
triage() turns into an action: what to block now, what to retro-hunt, what never to block.
Like prior reporting, none of this changes the cluster score.
"""

from __future__ import annotations

import ipaddress
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests

from .clients import Cache
from .intel import _ts
from .log import log

UA = {"User-Agent": "inframapper/1.0"}
C2INTEL = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds"
# name -> (url, refresh after N hours)
BULK = {
    "feodo": ("https://feodotracker.abuse.ch/downloads/ipblocklist.json", 6),
    "c2intel_ip": (f"{C2INTEL}/IPPortC2s-90day.csv", 12),
    "c2intel_domain": (f"{C2INTEL}/domainC2s-90day.csv", 12),
    "openphish": ("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", 6),
    "ipsum": ("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", 12),
    "tor": ("https://check.torproject.org/torbulkexitlist", 6),
    "drop4": ("https://www.spamhaus.org/drop/drop_v4.json", 24),
    "drop6": ("https://www.spamhaus.org/drop/drop_v6.json", 24),
    "asndrop": ("https://www.spamhaus.org/drop/asndrop.json", 24),
    "kev": ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 24),
}
IPSUM_MIN = 2   # on a single list is too weak to mention

# Default team-server / operator ports: a hint for the analyst, never a verdict on its own
C2_PORTS = {50050: "Cobalt Strike team server", 31337: "Sliver multiplayer", 40056: "Havoc team server",
            7443: "Mythic UI"}

# feeds whose listing means "malicious right now" (vs historical reporting)
LIVE_SOURCES = {"Feodo Tracker", "C2IntelFeeds", "OpenPhish", "URLhaus"}


def _asn(v) -> int | None:
    try:
        return int(str(v).upper().removeprefix("AS").split()[0])
    except (ValueError, IndexError):
        return None


class BulkFeeds:
    def __init__(self, directory: Path):
        self.dir = directory / "feeds"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.fetched: dict[str, int] = {}
        self.ip: dict[str, list[dict]] = {}       # ip -> report dicts
        self.domain: dict[str, list[dict]] = {}
        self.url: dict[str, dict] = {}
        self.fronting: dict[str, str] = {}        # legit domain abused for CS domain fronting
        self.ipsum: dict[str, int] = {}
        self.tor: set[str] = set()
        self.drop: list[tuple[ipaddress._BaseNetwork, str]] = []
        self.asndrop: dict[int, str] = {}
        self.kev: dict[str, dict] = {}
        for name in BULK:
            try:
                text = self._text(name)
                if text:
                    getattr(self, f"_parse_{name.rstrip('46')}")(name, text)
            except Exception as exc:
                log.warning(f"feed {name} unusable: {exc}")
        log.info(f"public feeds: {len(self.ip)} C2 IPs, {len(self.domain)} C2 / phishing domains, "
                 f"{len(self.url)} phishing URLs, {len(self.tor)} Tor exits, {len(self.drop)} DROP nets, "
                 f"{len(self.ipsum)} IPsum IPs")

    @property
    def sources(self) -> list[str]:
        return ["Feodo Tracker", "C2IntelFeeds", "OpenPhish", "IPsum", "Tor", "Spamhaus DROP", "CISA KEV"]

    def _text(self, name: str) -> str | None:
        url, hours = BULK[name]
        path = self.dir / (name + Path(urlsplit(url).path).suffix)
        if not path.exists() or time.time() - path.stat().st_mtime > hours * 3600:
            try:
                r = requests.get(url, headers=UA, timeout=60)
                r.raise_for_status()
                path.write_text(r.text)
            except requests.RequestException as exc:
                log.warning(f"feed {name} refresh failed ({exc})" + (" — using the stale copy" if path.exists() else ""))
        if not path.exists():
            return None
        self.fetched[name] = int(path.stat().st_mtime)
        return path.read_text()

    # ------------------------------------------------------------------ parsers
    def _parse_feodo(self, name: str, text: str) -> None:
        for row in json.loads(text):
            fam = row.get("malware") or "botnet"
            online = row.get("status") == "online"
            self.ip.setdefault(row["ip_address"], []).append({
                "source": "Feodo Tracker", "key": f"feodo:{fam.lower()}", "name": f"Feodo Tracker: {fam} C2",
                "date": _ts(row.get("first_seen")), "url": f"https://feodotracker.abuse.ch/browse/host/{row['ip_address']}/",
                "references": [], "actor": None, "malware": [fam], "tags": ["c2", "botnet"],
                "edge": {"status": row.get("status"), "current": online, "port": row.get("port"),
                         "last_seen": _ts(row.get("last_online"))}})

    def _c2intel(self, label: str) -> tuple[str, str]:
        fam = "Cobalt Strike" if "cobalt" in label.lower() else label
        return fam, f"c2intel:{fam.lower().replace(' ', '')}"

    def _parse_c2intel_ip(self, name: str, text: str) -> None:
        now = self.fetched[name]
        for line in text.splitlines():
            parts = line.strip().split(",", 2)
            if len(parts) < 3 or line.startswith("#"):
                continue
            ip, port, label = parts
            hits = self.ip.setdefault(ip, [])
            prev = next((h for h in hits if h["source"] == "C2IntelFeeds"), None)
            if prev:   # one IP, several ports
                prev["edge"]["port"] = f"{prev['edge']['port']},{port}"
                continue
            fam, key = self._c2intel(label)
            hits.append({"source": "C2IntelFeeds", "key": key, "name": f"C2IntelFeeds: {fam} C2",
                         "date": None, "url": "https://github.com/drb-ra/C2IntelFeeds", "references": [],
                         "actor": None, "malware": [fam], "tags": ["c2"],
                         "edge": {"current": True, "port": port, "last_seen": now,
                                  "detail": "C2 seen in the last 90 days"}})

    def _parse_c2intel_domain(self, name: str, text: str) -> None:
        now = self.fetched[name]
        for line in text.splitlines():
            parts = line.strip().split(",", 1)
            if len(parts) < 2 or line.startswith("#"):
                continue
            dom, label = parts[0].lower(), parts[1]
            if "front" in label.lower():
                self.fronting[dom] = label   # a CDN / legit site used to front C2: not the actor's
                continue
            fam, key = self._c2intel(label)
            self.domain.setdefault(dom, []).append({
                "source": "C2IntelFeeds", "key": key, "name": f"C2IntelFeeds: {fam} C2", "date": None,
                "url": "https://github.com/drb-ra/C2IntelFeeds", "references": [], "actor": None,
                "malware": [fam], "tags": ["c2"],
                "edge": {"current": True, "last_seen": now, "detail": "C2 seen in the last 90 days"}})

    def _parse_openphish(self, name: str, text: str) -> None:
        now = self.fetched[name]
        for line in text.splitlines():
            u = line.strip()
            host = (urlsplit(u).hostname or "").lower()
            if not host:
                continue
            hit = {"source": "OpenPhish", "key": "openphish", "name": "OpenPhish: live phishing", "date": None,
                   "url": "https://openphish.com/", "references": [], "actor": None, "malware": [],
                   "tags": ["phishing"], "edge": {"current": True, "last_seen": now, "detail": u[:200]}}
            self.url[u] = hit
            self.url.setdefault(u.rstrip("/"), hit)
            if host not in self.domain or all(h["source"] != "OpenPhish" for h in self.domain[host]):
                self.domain.setdefault(host, []).append(hit)

    def _parse_ipsum(self, name: str, text: str) -> None:
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 2 and int(parts[1]) >= IPSUM_MIN:
                self.ipsum[parts[0]] = int(parts[1])

    def _parse_tor(self, name: str, text: str) -> None:
        self.tor = {x.strip() for x in text.splitlines() if x.strip() and not x.startswith("#")}

    def _parse_drop(self, name: str, text: str) -> None:
        for line in text.splitlines():
            try:
                d = json.loads(line)
                self.drop.append((ipaddress.ip_network(d["cidr"], strict=False), d.get("sblid") or ""))
            except (ValueError, KeyError):
                continue   # trailing metadata line

    def _parse_asndrop(self, name: str, text: str) -> None:
        for line in text.splitlines():
            try:
                d = json.loads(line)
                self.asndrop[int(d["asn"])] = d.get("asname") or ""
            except (ValueError, KeyError):
                continue

    def _parse_kev(self, name: str, text: str) -> None:
        for v in json.loads(text).get("vulnerabilities") or []:
            self.kev[v["cveID"].upper()] = {"name": v.get("vulnerabilityName"), "added": v.get("dateAdded"),
                                            "ransomware": v.get("knownRansomwareCampaignUse") == "Known"}

    # ------------------------------------------------------------------ lookup
    def match(self, ntype: str, value: str, props: dict) -> tuple[dict, list[dict]]:
        """(node props, report dicts) for one IOC."""
        v = value.strip().lower().rstrip(".")
        ctx, reps = {}, []
        if ntype == "IP":
            reps += [dict(h, edge=dict(h["edge"])) for h in self.ip.get(v, [])]
            if v in self.tor:
                ctx["tor_exit"] = True
            if v in self.ipsum:
                ctx["ipsum_lists"] = self.ipsum[v]
            try:
                ip = ipaddress.ip_address(v)
                for net, sbl in self.drop:
                    if ip.version == net.version and ip in net:
                        ctx.update(spamhaus_drop=f"{sbl} {net}", drop_cidr=str(net))
                        break
            except ValueError:
                pass
            asn = _asn(props.get("asn"))
            if asn in self.asndrop:
                ctx["asn_drop"] = f"AS{asn} {self.asndrop[asn]}".strip()
        elif ntype == "Domain":
            reps += [dict(h, edge=dict(h["edge"])) for h in self.domain.get(v, [])]
            if v in self.fronting:
                ctx["c2_fronting"] = self.fronting[v]
        elif ntype == "URL":
            hit = self.url.get(value.strip()) or self.url.get(value.strip().rstrip("/"))
            if hit:
                reps.append(dict(hit, edge=dict(hit["edge"])))
        return ctx, reps


class LiveFeeds:
    """Per-IOC APIs. A source that errors (quota, bad key) is dropped for the rest of the run."""

    def __init__(self, cache: Cache, kev: dict[str, dict], abusech_key: str | None = None,
                 greynoise_key: str | None = None, abuseipdb_key: str | None = None, greynoise: bool = True):
        self.cache, self.kev = cache, kev
        self.keys = {"URLhaus": abusech_key, "GreyNoise": greynoise_key, "AbuseIPDB": abuseipdb_key}
        self.enabled = {"InternetDB": True, "GreyNoise": greynoise, "URLhaus": bool(abusech_key),
                        "AbuseIPDB": bool(abuseipdb_key)}
        self.s = requests.Session()
        self.s.headers.update(UA)
        self.calls = 0

    @property
    def sources(self) -> list[str]:
        return [k for k, on in self.enabled.items() if on]

    def _req(self, source: str, key: str, method: str, url: str, ok=(200,), **kw):
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        if not self.enabled.get(source):
            return None
        for attempt in range(2):   # parallel lookups can trip a burst limit: one retry after a pause
            self.calls += 1
            try:
                r = self.s.request(method, url, timeout=30, **kw)
            except requests.RequestException as exc:
                log.warning(f"{source} request failed: {exc}")
                self.enabled[source] = False
                return None
            if r.status_code != 429 or attempt:
                break
            time.sleep(2)
            if not self.enabled.get(source):   # another lookup thread already gave up on it
                return None
        if r.status_code in ok:
            data = r.json() if r.content else {}
            self.cache.set(key, data)
            return data
        if r.status_code == 404:
            self.cache.set(key, {})
            return {}
        log.warning(f"{source}: HTTP {r.status_code}" + (" — quota or key problem, skipped for this run"
                                                         if r.status_code in (401, 403, 429) else ""))
        if r.status_code in (401, 403, 429):
            self.enabled[source] = False
        return None

    def internetdb(self, ip: str) -> dict:
        d = self._req("InternetDB", f"internetdb:{ip}", "GET", f"https://internetdb.shodan.io/{ip}") or {}
        if not d.get("ports") and not d.get("vulns"):
            return {}
        vulns = sorted({x.upper() for x in d.get("vulns") or []})
        ctx = {"open_ports": d.get("ports") or [], "shodan_tags": d.get("tags") or [],
               "cpes": (d.get("cpes") or [])[:10], "shodan_hostnames": (d.get("hostnames") or [])[:10],
               "vulns": vulns[:30], "kev": [c for c in vulns if c in self.kev]}
        hints = [f"{p}: {C2_PORTS[p]}" for p in ctx["open_ports"] if p in C2_PORTS]
        if hints:
            ctx["c2_port_hint"] = hints
        return ctx

    def greynoise(self, ip: str) -> dict:
        key = self.keys["GreyNoise"]
        d = self._req("GreyNoise", f"greynoise:{ip}", "GET", f"https://api.greynoise.io/v3/community/{ip}",
                      headers={"key": key} if key else {}) or {}
        if d.get("riot"):
            return {"gn_riot": d.get("name") or "benign service"}
        if d.get("noise"):
            return {"gn_noise": True, "gn_class": d.get("classification"), "gn_name": d.get("name"),
                    "gn_last_seen": d.get("last_seen")}
        return {}

    def abuseipdb(self, ip: str) -> dict:
        d = self._req("AbuseIPDB", f"abuseipdb:{ip}", "GET", "https://api.abuseipdb.com/api/v2/check",
                      params={"ipAddress": ip, "maxAgeInDays": 90},
                      headers={"Key": self.keys["AbuseIPDB"] or "", "Accept": "application/json"})
        d = (d or {}).get("data") or {}
        if not d.get("totalReports"):
            return {"usage_type": d.get("usageType")} if d.get("usageType") else {}
        return {"abuseipdb_score": d.get("abuseConfidenceScore"), "abuseipdb_reports": d.get("totalReports"),
                "abuseipdb_last": d.get("lastReportedAt"), "usage_type": d.get("usageType")}

    def urlhaus(self, ntype: str, value: str) -> tuple[dict, list[dict]]:
        base = "https://urlhaus-api.abuse.ch/v1"
        hdr = {"Auth-Key": self.keys["URLhaus"] or ""}
        if ntype == "File":
            field = {32: "md5_hash", 64: "sha256_hash"}.get(len(value))
            if not field:
                return {}, []
            d = self._req("URLhaus", f"urlhaus:payload:{value}", "POST", f"{base}/payload/",
                          data={field: value}, headers=hdr) or {}
            if d.get("query_status") != "ok":
                return {}, []
            sig = d.get("signature")
            urls = d.get("urls") or []
            online = sum(1 for u in urls if u.get("url_status") == "online")
            return {"urlhaus_urls": len(urls), "urlhaus_online": online or None}, [{
                "source": "URLhaus", "key": f"urlhaus:{(sig or 'payload').lower()}",
                "name": f"URLhaus: {sig or 'malware payload'}", "date": _ts(d.get("firstseen")),
                "url": f"https://urlhaus.abuse.ch/browse.php?search={value}", "references": [],
                "actor": None, "malware": [sig] if sig else [], "tags": [],
                "edge": {"current": online > 0, "last_seen": _ts(d.get("lastseen")),
                         "detail": f"served by {len(urls)} URL(s), {online} online"}}]
        if ntype == "URL":
            d = self._req("URLhaus", f"urlhaus:url:{value}", "POST", f"{base}/url/", data={"url": value},
                          headers=hdr) or {}
            urls = [d] if d.get("query_status") == "ok" else []
        else:
            d = self._req("URLhaus", f"urlhaus:host:{value}", "POST", f"{base}/host/", data={"host": value},
                          headers=hdr) or {}
            urls = (d.get("urls") or []) if d.get("query_status") == "ok" else []
        if not urls:
            return {}, []
        # one report per threat + family tag, so the same malware links IOCs together
        groups: dict[str, dict] = {}
        for u in urls:
            tags = [t for t in u.get("tags") or [] if t]
            fam = tags[0] if tags else (u.get("threat") or "malware")
            g = groups.setdefault(fam.lower(), {
                "source": "URLhaus", "key": f"urlhaus:{fam.lower()}", "name": f"URLhaus: {fam}",
                "date": _ts(u.get("date_added")), "url": u.get("urlhaus_reference") or
                f"https://urlhaus.abuse.ch/host/{quote(value, safe='')}/", "references": [], "actor": None,
                "malware": [fam] if tags else [], "tags": [], "threat_type": u.get("threat"),
                "edge": {"current": False, "last_seen": None, "online": 0, "count": 0}})
            d_added = _ts(u.get("date_added"))
            if d_added and (not g["date"] or d_added < g["date"]):
                g["date"] = d_added
            e = g["edge"]
            e["count"] += 1
            e["last_seen"] = max(filter(None, [e["last_seen"], d_added]), default=None)
            if u.get("url_status") == "online":
                e["online"] += 1
                e["current"] = True
                e["last_seen"] = int(time.time())
            g["tags"] = sorted(set(g["tags"]) | set(tags))[:10]
        reps = list(groups.values())
        for r in reps:
            e = r["edge"]
            e["detail"] = f"{e.pop('count')} URL(s), {e.pop('online')} online"
        online = sum(1 for u in urls if u.get("url_status") == "online")
        return {"urlhaus_urls": len(urls), "urlhaus_online": online or None}, reps


class Feeds:
    def __init__(self, cache_dir: Path, cache: Cache, abusech_key: str | None = None,
                 greynoise_key: str | None = None, abuseipdb_key: str | None = None, live: bool = True):
        self.bulk = BulkFeeds(cache_dir)
        self.live = LiveFeeds(cache, self.bulk.kev, abusech_key, greynoise_key, abuseipdb_key) if live else None

    @property
    def sources(self) -> list[str]:
        return self.bulk.sources + (self.live.sources if self.live else [])

    @property
    def calls(self) -> int:
        return self.live.calls if self.live else 0

    def lookup(self, ntype: str, value: str, props: dict) -> tuple[dict, list[dict]]:
        ctx, reps = self.bulk.match(ntype, value, props)
        lv = self.live
        if lv:
            if ntype == "IP":
                ctx.update(lv.greynoise(value))
                if not ctx.get("gn_riot"):
                    ctx.update(lv.internetdb(value))
                    ctx.update(lv.abuseipdb(value))
            c, r = lv.urlhaus(ntype, value)
            ctx.update(c)
            reps += r
        return ctx, reps


# ---------------------------------------------------------------------- triage
PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "noise": 3}
BLOCK_WHERE = {"IP": "firewall / proxy", "Domain": "DNS / proxy", "URL": "proxy", "File": "EDR hash"}


def triage(gr, nid: str) -> tuple[str, str, list[str]] | None:
    """(priority, action, reasons) for a host node in the case view; None if it's out of view."""
    r = _triage(gr, nid)
    p = gr.nodes[nid]["props"]
    if r and p.get("dns_dead") and r[0] != "noise":
        # dead today: the block protects little, the 90-day retro-hunt is where the value is
        r = (r[0], r[1], r[2] + ["no longer resolves: retro-hunt matters more than the block"])
    return r


def _triage(gr, nid: str) -> tuple[str, str, list[str]] | None:
    n = gr.nodes[nid]
    p, t = n["props"], n["type"]
    if p.get("cluster") is False and not p.get("pinned"):
        return None
    reps = [(gr.nodes[d]["props"], ep) for (s, d, rel), ep in gr.edges.items()
            if rel == "REPORTED_IN" and s == nid and d in gr.nodes]
    where = BLOCK_WHERE.get(t, "")

    if p.get("analyst_verdict") == "fp":
        return "noise", "don't block: an analyst marked it a false positive", \
            [f"analyst: {p['analyst_note']}" if p.get("analyst_note") else "analyst: false positive"]
    if p.get("warninglist"):
        return "noise", "don't block: known-benign / shared service", [p["warninglist"]]
    if p.get("c2_fronting"):
        return "noise", "don't block the domain: legit site used for domain fronting; hunt the Host header", \
            [p["c2_fronting"]]
    if p.get("tor_exit"):
        return "noise", "Tor exit: block by policy only, never attribute", ["Tor exit node"]
    if t == "IP" and p.get("shared_hosting"):
        return "noise", "shared hosting: block the cluster's domains, not the IP", ["many domains on this IP"]

    fits = [(r, ep) for r, ep in reps if ep.get("timing") not in ("earlier", "later")]
    live = [(r, ep) for r, ep in fits if r.get("source") in LIVE_SOURCES and ep.get("current")]
    p1 = [f"{r['source']}: {', '.join(r.get('malware') or r.get('tags') or []) or 'listed'}"
          + (f" ({ep['detail']})" if ep.get("detail") else "") for r, ep in live]
    if p.get("spamhaus_drop"):
        p1.append(f"Spamhaus DROP {p['spamhaus_drop']}")
    if p.get("asn_drop"):
        p1.append(f"Spamhaus ASN-DROP {p['asn_drop']}")
    if "c2" in (p.get("shodan_tags") or []):
        p1.append("Shodan tags it as C2")
    if p1 and p.get("hosting"):
        p1.append(f"caveat: rented / VPN range ({p['hosting'][:60]})")
    if p1:
        action = f"block now ({where})" if where else "block now"
        if p.get("drop_cidr"):
            action += f" + netblock {p['drop_cidr']}"
        return "P1", action + ", retro-hunt 90 days", p1

    if p.get("gn_noise"):
        return "noise", "mass scanner: edge block optional, not campaign infrastructure", \
            [f"GreyNoise: {p.get('gn_class') or 'noise'}" + (f" ({p['gn_name']})" if p.get("gn_name") else "")]

    # VT-derived names (comments, YARA, sandboxes, AV consensus) describe the IOC, they aren't vetted
    # reporting: they back up a P2, never make one (VT detections count on their own below)
    p2 = [f"{r['source']}: {r.get('name', '')[:60]}" + (f" ({ep['detail']})" if ep.get("detail") else "")
          for r, ep in fits if not str(r.get("source", "")).startswith("VT ")]
    if (p.get("vt_malicious") or 0) >= 3:
        p2.append(f"VT {p['vt_malicious']}/{p.get('vt_total')}")
    if (p.get("abuseipdb_score") or 0) >= 75:
        p2.append(f"AbuseIPDB {p['abuseipdb_score']}% ({p.get('abuseipdb_reports')} reports)")
    if (p.get("ipsum_lists") or 0) >= 3:
        p2.append(f"on {p['ipsum_lists']} blocklists (IPsum)")
    if p.get("c2_port_hint"):
        p2.append("default C2 port open: " + "; ".join(p["c2_port_hint"]))
    if p2:
        p2 += [r["name"] for r, _ in fits if str(r.get("source", "")).startswith("VT ")][:3]
    if p2 and p.get("hosting"):
        p2.append(f"caveat: rented / VPN range ({p['hosting'][:60]}), check it's still theirs")
    if p2:
        return "P2", f"block ({where}) + retro-hunt" if where else "block + retro-hunt", p2

    stale = sorted({r.get("source", "") for r, ep in reps if ep.get("timing") in ("earlier", "later")})
    fresh = ("only in the input report: no public feed or other reporting matched" if p.get("input_ioc")
             else "in the confirmed cluster, not in any public feed or report yet")
    why = ([f"listed on {', '.join(stale)} but outside the time it was used here: previous / next owner?"]
           if stale else [fresh])
    if p.get("reported_unlinked"):
        why.append(p["reported_unlinked"])
    if p.get("input_ioc"):
        return "P3", "retro-hunt / watchlist: not corroborated outside this report", why
    return "P3", "retro-hunt / watchlist: unreported, candidate for new detection", why


def triage_all(gr) -> list[tuple[dict, str, str, list[str]]]:
    """Tag every in-view host with its triage; returns [(node, priority, action, reasons)] sorted."""
    out = []
    for nid, n in gr.nodes.items():
        if n["type"] not in BLOCK_WHERE:
            continue
        r = triage(gr, nid)
        if not r:
            n["props"].pop("priority", None)
            continue
        gr.set_prop(nid, priority=r[0], action=r[1], action_reasons=r[2])
        out.append((n, *r))
    out.sort(key=lambda x: (PRIORITY_ORDER[x[1]], x[0]["type"], x[0]["value"]))
    return out


def last_active(gr, nid: str) -> int | None:
    """Most recent date a feed / report saw this IOC active."""
    ts = [ep.get("last_seen") or gr.nodes[d]["props"].get("date") for (s, d, rel), ep in gr.edges.items()
          if rel == "REPORTED_IN" and s == nid and d in gr.nodes]
    ts = [t for t in ts if isinstance(t, int)]
    return max(ts) if ts else None


def day(ts) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d") if isinstance(ts, int) and ts else ""
