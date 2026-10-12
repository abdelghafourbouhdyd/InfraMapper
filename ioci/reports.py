"""Published threat reports -> a local STIX 2.1 dataset (``--ingest``).

Pulls the RSS / Atom feeds of the vendors that publish technical threat research (The DFIR Report,
Unit 42, Google Threat Intelligence / Mandiant, Microsoft, Talos, ESET, Securelist, Check Point,
Proofpoint, SentinelLabs, Sekoia, Elastic, Zscaler, Sophos, …), reads every article of the last
``--days`` days and keeps what an investigation can use:

* **IOCs**: the report extractor (``extract.py``: every defang style, hyperlinked hosts are citations,
  file names aren't domains…) + MISP warninglists (benign infrastructure a report mentions never
  enters the dataset). IOC files a report links on GitHub (``…/iocs.txt``) are read too
* **fingerprints**: imphash (-> a STIX pattern), JA3 / ssdeep / TLSH (kept on the report)
* **TTPs**: ATT&CK technique ids the report states (``T1059.001``), named from MITRE's list. Technique
  names in prose aren't matched: "phishing" in a sentence isn't a TTP mapping
* **actors / malware families**: MISP galaxy + Malpedia names mentioned at least twice or in the title
* **CVEs** and **YARA rules** found in the text

Each report becomes a STIX 2.1 bundle (``dataset/stix/<source>/<date>_<slug>.json``): an identity for
the vendor, the ``report``, ``indicator`` s, ``malware``, ``intrusion-set``, ``attack-pattern``,
``vulnerability``, TLP:CLEAR. Relationships are only drawn when the report is unambiguous: indicators
``indicates`` a family only when the report names exactly one; an intrusion set ``uses`` the TTPs /
families only when it names exactly one actor. ``dataset/bundle.json`` merges every report (ids are
deterministic, so re-importing into OpenCTI / MISP updates objects). Everything is indexed in the
knowledge base so investigations match IOCs against it offline.
"""

from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

import requests

from . import graph as g
from .clients import Cache
from .extract import extract, html_to_text, link_hosts, url_host
from .log import log
from .patterns import apex_of
from .share import TLP, _pattern, _sid
from .vtcomments import ActorNames

# slug, display name, feed
SOURCES = [
    ("dfir-report", "The DFIR Report", "https://thedfirreport.com/feed/"),
    ("unit42", "Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("google-ti", "Google Threat Intelligence (Mandiant)", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    ("microsoft", "Microsoft Threat Intelligence", "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/"),
    ("talos", "Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("eset", "ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/"),
    ("securelist", "Kaspersky Securelist", "https://securelist.com/feed/"),
    ("checkpoint", "Check Point Research", "https://research.checkpoint.com/feed/"),
    ("proofpoint", "Proofpoint", "https://www.proofpoint.com/us/threat-insight-blog.xml"),
    ("sentinellabs", "SentinelLabs", "https://www.sentinelone.com/labs/feed/"),
    ("sekoia", "Sekoia TDR", "https://blog.sekoia.io/feed/"),
    ("elastic", "Elastic Security Labs", "https://www.elastic.co/security-labs/rss/feed.xml"),
    ("zscaler", "Zscaler ThreatLabz", "https://www.zscaler.com/blogs/feeds/security-research"),
    ("huntress", "Huntress", "https://www.huntress.com/blog/rss.xml"),
    ("redcanary", "Red Canary", "https://redcanary.com/blog/feed/"),
    ("volexity", "Volexity", "https://www.volexity.com/feed/"),
    ("fortinet", "FortiGuard Labs", "https://feeds.fortinet.com/fortinet/blog/threat-research"),
    ("anyrun", "ANY.RUN", "https://any.run/cybersecurity-blog/feed/"),
    ("recordedfuture", "Recorded Future Insikt", "https://www.recordedfuture.com/feed"),
    ("eclecticiq", "EclecticIQ", "https://blog.eclecticiq.com/rss.xml"),
    ("trendmicro", "Trend Micro Research", "https://feeds.feedburner.com/TrendMicroResearch"),
    ("darktrace", "Darktrace", "https://www.darktrace.com/blog/rss.xml"),
    ("malwarebytes", "Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml"),
    ("bitdefender", "Bitdefender Labs", "https://www.bitdefender.com/nuxt/api/en-us/rss/labs/"),
    ("gdata", "G DATA", "https://www.gdatasoftware.com/blog/rss.xml"),
    ("cyble", "Cyble", "https://cyble.com/feed/"),
    ("seqrite", "Seqrite Labs", "https://www.seqrite.com/blog/feed/"),
    ("qualys", "Qualys TRU", "https://blog.qualys.com/vulnerabilities-threat-research/feed"),
    ("censys", "Censys", "https://censys.com/feed/"),
    ("silentpush", "Silent Push", "https://www.silentpush.com/feed/"),
    ("infoblox", "Infoblox Threat Intel", "https://www.infoblox.com/blog/category/threat-intelligence/feed/"),
    ("sucuri", "Sucuri", "https://blog.sucuri.net/feed/"),
    ("ncsc-uk", "NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"),
]
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"}
# some feed hosts (FeedBurner-style) serve an HTML page to browsers and XML to feed readers
FEED_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; InfraMapper feed reader)",
                "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5"}
TTP_RE = re.compile(r"\b(T1\d{3}(?:\.\d{3})?)\b")
YARA_RE = re.compile(r"(?ms)^[ \t]*(?:(?:private|global)\s+)*rule\s+\w+\s*(?::[^{\n]*)?\{.*?\bcondition\s*:.*?^[ \t]*\}")
# IOC files published next to the post (DFIR-Report-Indicators/…md, unit42 …/iocs.txt), linked or in plain text
GITHUB_FILE_RE = re.compile(r"""(?i)https://(?:github\.com/[^\s"'<>#?]+?/blob/|raw\.githubusercontent\.com/)"""
                            r"""[^\s"'<>#?]+\.(?:txt|csv|md|json|ya?ml)""")
IOC_PATH_RE = re.compile(r"(?i)ioc|indicator")
BOILERPLATE_MIN = 3       # a line in this many of a source's articles (and 30 %+) is page furniture
TLP_CLEAR = TLP["clear"][0]
MIN_MENTIONS = 2
# legitimate services attackers abuse: listed in many reports, attribute nothing (their subdomains still count)
SHARED_SERVICES = {"webhook.site", "pastebin.com", "paste.ee", "transfer.sh", "file.io", "gofile.io", "mega.nz",
                   "dropbox.com", "drive.google.com", "docs.google.com", "discord.com", "cdn.discordapp.com",
                   "api.telegram.org", "t.me", "raw.githubusercontent.com", "github.com", "gist.github.com",
                   "trycloudflare.com", "workers.dev", "pages.dev", "ngrok.io", "ngrok-free.app", "duckdns.org",
                   "onedrive.live.com", "1drv.ms", "bit.ly", "tinyurl.com", "pipedream.net", "requestbin.net",
                   "interact.sh", "oast.fun", "ipinfo.io", "ip-api.com", "api.ipify.org", "ifconfig.me", "icanhazip.com"}
# platforms where anyone gets a subdomain: a benign parent says nothing about <user>.<platform>.
# The Public Suffix List's private section (github.io, pages.dev, duckdns.org, us.com…) + what it misses.
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
USER_CONTENT_EXTRA = {"beehiiv.com", "substack.com", "wordpress.com", "backblazeb2.com", "jimdofree.com", "jimdosite.com", "site123.me", "canva.site",
                      "screenconnect.com", "quickconnect.to", "cloudapp.azure.com", "cloudflarestorage.com",
                      "core.windows.net", "azurewebsites.net", "activehosted.com", "secureserver.net", "ovh.net",
                      "sharepoint.com", "godaddysites.com", "wixsite.com", "weebly.com", "notion.site", "webflow.io",
                      "mypixieset.com", "fc2.com", "amazonaws.com", "cloudfront.net", "googleusercontent.com",
                      "sites.google.com", "hf.space", "lovable.app", "bolt.new", "replit.app", "tilda.ws"}
_user_content: set[str] | None = None


def user_content(cache_dir: Path | None = None) -> set[str]:
    global _user_content
    if _user_content is None:
        _user_content = set(USER_CONTENT_EXTRA)
        path = cache_dir / "public_suffix_list.dat" if cache_dir else None
        try:
            if path and (not path.exists() or time.time() - path.stat().st_mtime > 7 * 86400):
                r = requests.get(PSL_URL, timeout=60)
                r.raise_for_status()
                path.write_text(r.text)
            if path and path.exists():
                priv = path.read_text().split("===BEGIN PRIVATE DOMAINS===", 1)[-1]
                _user_content |= {x.strip().lstrip("*.!").lower() for x in priv.splitlines()
                                  if x.strip() and not x.startswith("//")}
        except Exception as exc:
            log.warning(f"Public Suffix List unavailable ({exc}): built-in user-content platforms only")
    return _user_content


IOC_LINE = re.compile(r"\b[0-9a-fA-F]{32,64}\b|\b\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}|\[\.\]|hxxp|https?://", re.I)
# security products / services named in vendor posts that are also Malpedia family names
PRODUCTS = {"wildfire", "cortex", "defender", "sentinel", "falcon", "prisma", "guardduty", "sophos", "vision one",
            "apex one", "deep instinct", "carbon black", "intercept x", "threatlabz", "any.run", "virustotal"}


# ---------------------------------------------------------------------- feeds
def _ts(s: str | None) -> int | None:
    if not s:
        return None
    s = s.strip()
    try:
        return int(parsedate_to_datetime(s).timestamp())
    except (TypeError, ValueError):
        pass
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_feed(xml: bytes) -> list[dict]:
    """[{title, url, published, content (html)}] from RSS 2.0 or Atom."""
    root = ET.fromstring(xml)
    out = []
    for it in root.iter():
        if _local(it.tag) not in ("item", "entry"):
            continue
        f = {"title": "", "url": "", "published": None, "content": ""}
        for c in it:
            t = _local(c.tag)
            if t == "title":
                f["title"] = (c.text or "").strip()
            elif t == "link":
                href = c.get("href")
                if href and c.get("rel", "alternate") == "alternate":
                    f["url"] = href.strip()
                elif not href and c.text:
                    f["url"] = c.text.strip()
            elif t in ("pubdate", "published") or (t in ("updated", "date") and not f["published"]):
                f["published"] = _ts(c.text) or f["published"]
            elif t in ("encoded", "content") or (t in ("description", "summary") and not f["content"]):
                f["content"] = c.text or f["content"]
        if f["url"] and f["title"]:
            out.append(f)
    return out


# ---------------------------------------------------------------------- ATT&CK
class Attack:
    """ATT&CK technique id -> (name, tactics), from the MISP galaxy (cached weekly)."""
    URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json"

    def __init__(self, directory: Path):
        self.t: dict[str, tuple[str, list[str]]] = {}
        path = directory / "mitre-attack-techniques.json"
        try:
            if not path.exists() or time.time() - path.stat().st_mtime > 7 * 86400:
                log.info("downloading MITRE ATT&CK techniques (MISP galaxy)…")
                r = requests.get(self.URL, timeout=60)
                r.raise_for_status()
                out = {}
                for v in r.json().get("values", []):
                    meta = v.get("meta") or {}
                    tid, name = meta.get("external_id"), re.sub(r"\s*-\s*T\d{4}(\.\d{3})?$", "", v.get("value") or "")
                    # 'attack-Windows:execution', 'attack-Linux:execution' -> execution; retired pre-attack dropped
                    tactics = sorted({k.split(":", 1)[-1] for k in meta.get("kill_chain", [])
                                      if ":" in k and not k.startswith("pre-attack")})
                    if tid and re.fullmatch(r"T\d{4}(\.\d{3})?", tid) and tactics:   # pre-attack (retired) dropped
                        out[tid] = [name, tactics]
                path.write_text(json.dumps(out))
            self.t = {k: (v[0], v[1]) for k, v in json.loads(path.read_text()).items()}
        except Exception as exc:
            log.warning(f"ATT&CK techniques unavailable ({exc}): TTPs won't be extracted")

    def find(self, text: str) -> list[str]:
        """Technique ids stated in the text that exist in ATT&CK (a sub-technique implies nothing more)."""
        return sorted({t for t in TTP_RE.findall(text) if t in self.t})


# ---------------------------------------------------------------------- one article
TYPE = {"file": g.FILE, "ip": g.IP, "domain": g.DOMAIN, "url": g.URL}


def benign_parent(host: str, warn) -> bool:
    """get.adobe.com: a subdomain of a known-benign site that isn't a user-content platform."""
    h, apex = host.lower(), apex_of(host)
    labels = h.split(".")
    if apex == h or any(".".join(labels[i:]) in user_content() for i in range(1, len(labels))):
        return False
    wl = warn.match(g.DOMAIN, apex)
    return bool(wl and wl[1] == "benign")


def analyse(item: dict, text: str, links: set[str], names: ActorNames, attack: Attack, warn, tlds,
            exclude: set[str], template_iocs: set[str] = frozenset()) -> dict:
    """Everything worth keeping from one article. ``template_iocs``: IOCs the source repeats on many
    pages (a weekly 'most prevalent files' footer), not this report's."""
    ex = extract(text, item["url"], tlds, exclude, None, links)
    iocs = []
    for kind, v in ex.iocs:
        t = TYPE[kind]
        if v.lower() in template_iocs or (t == g.DOMAIN and v.lower() in SHARED_SERVICES):
            continue
        if t == g.DOMAIN and warn and benign_parent(v, warn):
            continue
        wl = warn.match(t, v) if warn else None
        if wl and wl[1] == "benign":
            continue
        if t in (g.DOMAIN, g.URL) and apex_of(url_host(v) if t == g.URL else v) in exclude:
            continue
        iocs.append((t, v))
    actors, fams = names.mentions(text)
    ta, tf = names.mentions(item["title"])
    keep = lambda c, tc: sorted(n for n in set(c) | set(tc) if (c[n] >= MIN_MENTIONS or tc[n])
                                and n.lower() not in PRODUCTS)
    return {"iocs": iocs, "ttps": attack.find(text), "actors": keep(actors, ta), "families": keep(fams, tf),
            "cves": ex.cves, "fingerprints": ex.fingerprints, "aliases": ex.aliases,
            "yara": [y.strip() for y in YARA_RE.findall(text)][:20]}


# ---------------------------------------------------------------------- STIX


def _ref(name: str, url: str | None = None, ext: str | None = None) -> dict:
    return {k: v for k, v in {"source_name": name, "url": url, "external_id": ext}.items() if v}


def to_stix(src_name: str, item: dict, a: dict, attack: Attack) -> dict:
    """STIX 2.1 bundle for one report."""
    when = datetime.fromtimestamp(item["published"] or time.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ident = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", src_name), "created": when,
             "modified": when, "name": src_name, "identity_class": "organization"}
    base = {"spec_version": "2.1", "created": when, "modified": when, "created_by_ref": ident["id"],
            "object_marking_refs": [TLP_CLEAR]}
    objs: list[dict] = []
    fams = [{"type": "malware", **base, "id": _sid("malware", f.lower()), "name": f, "is_family": True} for f in a["families"]]
    sets = [{"type": "intrusion-set", **base, "id": _sid("intrusion-set", x.lower()), "name": x} for x in a["actors"]]
    aps = [{"type": "attack-pattern", **base, "id": _sid("attack-pattern", t), "name": attack.t[t][0],
            "external_references": [_ref("mitre-attack", f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/", t)],
            **({"kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": k} for k in attack.t[t][1]]}
               if attack.t[t][1] else {})} for t in a["ttps"]]
    vulns = [{"type": "vulnerability", **base, "id": _sid("vulnerability", c), "name": c,
              "external_references": [_ref("cve", f"https://nvd.nist.gov/vuln/detail/{c}", c)]} for c in a["cves"]]
    inds = []
    for t, v in a["iocs"]:
        pat = _pattern(t, v)
        alias = a["aliases"].get(v) or {}
        if t == g.FILE and alias:   # one sample, all its hashes in one pattern
            parts = [f"file:hashes.'{k}' = '{h}'" for k, h in (("MD5", alias.get("md5")), ("SHA-1", alias.get("sha1")),
                                                                ("SHA-256", v if len(v) == 64 else None)) if h]
            pat = "[" + " OR ".join(parts) + "]" if parts else pat
        if pat:
            inds.append({"type": "indicator", **base, "id": _sid("indicator", f"{t}:{v.lower()}"), "name": v,
                         "pattern": pat, "pattern_type": "stix", "valid_from": when,
                         "indicator_types": ["malicious-activity"]})
    for kind, v in a["fingerprints"]:
        if kind == "imphash":
            inds.append({"type": "indicator", **base, "id": _sid("indicator", f"imphash:{v}"), "name": f"imphash {v}",
                         "pattern": f"[file:extensions.'windows-pebinary-ext'.imphash = '{v}']", "pattern_type": "stix",
                         "valid_from": when, "indicator_types": ["malicious-activity"]})
    for y in a["yara"]:
        rname = re.search(r"rule\s+(\w+)", y).group(1)
        inds.append({"type": "indicator", **base, "id": _sid("indicator", f"yara:{rname}:{item['url']}"),
                     "name": f"YARA {rname}", "pattern": y, "pattern_type": "yara", "valid_from": when})
    rels = []

    def rel(kind: str, s: str, d: str) -> None:
        rels.append({"type": "relationship", **base, "id": _sid("relationship", f"{kind}:{s}:{d}"),
                     "relationship_type": kind, "source_ref": s, "target_ref": d})

    if len(fams) == 1:   # unambiguous: the report's IOCs are this family's
        for i in inds:
            rel("indicates", i["id"], fams[0]["id"])
    if len(sets) == 1:
        for x in fams + aps:
            rel("uses", sets[0]["id"], x["id"])
        for vln in vulns:
            rel("targets", sets[0]["id"], vln["id"])
    elif len(fams) == 1:
        for x in aps:
            rel("uses", fams[0]["id"], x["id"])
    objs = [ident] + fams + sets + aps + vulns + inds + rels
    report = {"type": "report", **base, "id": _sid("report", item["url"]), "name": item["title"],
              "published": when, "report_types": ["threat-report"],
              "object_refs": [o["id"] for o in objs if o["type"] != "identity"] or [ident["id"]],
              "external_references": [_ref(src_name, item["url"])],
              "labels": sorted({*a["actors"], *a["families"]}),
              **({"x_ioci_fingerprints": [f"{k}:{v}" for k, v in a["fingerprints"]]} if a["fingerprints"] else {})}
    return {"type": "bundle", "id": _sid("bundle", item["url"]), "objects": [report] + objs}


# ---------------------------------------------------------------------- ingest
class Ingestor:
    def __init__(self, cache_dir: Path, kb, warn, tlds, out_dir: Path, days: int = 60):
        self.kb, self.warn, self.tlds, self.days = kb, warn, tlds, days
        self.out = out_dir
        self.pages = Cache(cache_dir / "articles", 24 * 3650)   # an article doesn't change: cache for good
        self.names = ActorNames(cache_dir)
        self.attack = Attack(cache_dir)
        self.s = requests.Session()
        self.s.headers.update(UA)
        self.exclude = {apex_of(urlsplit(u).hostname or "") for _, _, u in SOURCES}
        user_content(cache_dir)

    def _get(self, url: str, timeout: int = 30, headers: dict | None = None) -> str | None:
        try:
            r = self.s.get(url, timeout=timeout, headers=headers)
            if r.status_code == 200:
                return r.text
            log.debug(f"HTTP {r.status_code} {url}")
        except requests.RequestException as exc:
            log.debug(f"{url}: {exc}")
        return None

    def _article(self, item: dict) -> tuple[str, set[str]] | None:
        """(visible text, hyperlinked hosts) of the article; the feed's full content when it has it."""
        hit = self.pages.get(f"article:{item['url']}")
        if hit:
            return hit["text"], set(hit["links"])
        page = self._get(item["url"])
        time.sleep(0.3)   # polite: one site, one article at a time (sites run in parallel)
        html = page if page and len(html_to_text(page)) > len(html_to_text(item["content"] or "")) else item["content"]
        if not html or len(html_to_text(html)) < 400:
            return None
        text, links = html_to_text(html), link_hosts(html)
        for u in [u for u in dict.fromkeys(GITHUB_FILE_RE.findall(html)) if IOC_PATH_RE.search(u)][:3]:
            raw = u.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/", 1)
            body = self._get(raw)
            if body:
                text += "\n\n" + body[:500_000]
        self.pages.set(f"article:{item['url']}", {"text": text, "links": sorted(links)})
        return text, links

    def source(self, slug: str, name: str, feed: str, known: set[str]) -> list[dict]:
        # some hosts only serve XML to feed readers (FortiGuard), others only to browsers (Sekoia);
        # anything else (a challenge page, a timeout) gets one slower retry
        is_xml = lambda t: bool(t) and t.lstrip()[:200].lstrip("\ufeff").startswith(("<?xml", "<rss", "<feed"))
        xml = next((t for h in (FEED_HEADERS, UA) if is_xml(t := self._get(feed, headers=h))), None)
        if not xml:
            time.sleep(5)
            xml = next((t for h in (FEED_HEADERS, UA) if is_xml(t := self._get(feed, timeout=60, headers=h))), None)
        if not xml:
            log.warning(f"{name}: feed unavailable")
            return []
        try:
            items = parse_feed(xml.encode())
        except ET.ParseError as exc:
            log.warning(f"{name}: bad feed ({exc})")
            return []
        cutoff = time.time() - self.days * 86400
        todo = [i for i in items if (i["published"] or 0) >= cutoff and i["url"] not in known]
        if not todo:
            log.info(f"{name}: nothing new")
            return []
        # sidebars / related posts / product plugs repeat on every page and would name the same malware
        # everywhere: lines shared by several of this source's recent articles are removed first
        sample = sorted(items, key=lambda i: -(i["published"] or 0))[:30]
        texts = {i["url"]: art for i in sample + todo if (art := self._article(i))}
        freq: dict[str, int] = {}
        for text, _ in texts.values():
            for line in {x.strip() for x in text.splitlines() if len(x.strip()) >= 12}:
                freq[line] = freq.get(line, 0) + 1
        # prose repeated verbatim on two pages is furniture (related-post teasers vary per page, so a
        # ratio misses them); a repeated IOC line may be a series' shared indicators, so it needs more
        furniture = {ln for ln, c in freq.items()
                     if c >= 2 and not IOC_LINE.search(ln) or c >= max(BOILERPLATE_MIN, 0.3 * len(texts))}
        clean = {u: "\n".join(x for x in t.splitlines() if x.strip() not in furniture) for u, (t, _) in texts.items()}
        seen: dict[str, int] = {}
        for u, body in clean.items():
            for _, v in extract(body, u, self.tlds, self.exclude, None, texts[u][1]).iocs:
                seen[v.lower()] = seen.get(v.lower(), 0) + 1
        template_iocs = {v for v, c in seen.items() if c >= BOILERPLATE_MIN and c >= 0.25 * len(texts)}
        done = []
        for it in todo:
            art = texts.get(it["url"])
            if not art:
                continue
            try:
                a = analyse(it, clean[it["url"]], art[1], self.names, self.attack, self.warn, self.tlds,
                            self.exclude, template_iocs)
                if not (a["iocs"] or a["ttps"] or a["yara"]):
                    continue   # news / marketing: nothing an investigation can match on
                bundle = to_stix(name, it, a, self.attack)
            except Exception as exc:   # one odd article never stops the ingest
                log.warning(f"{name}: skipped {it['url']} ({type(exc).__name__}: {exc})")
                continue
            day = datetime.fromtimestamp(it["published"] or time.time(), timezone.utc).strftime("%Y-%m-%d")
            slug_t = re.sub(r"[^a-z0-9]+", "-", it["title"].lower()).strip("-")[:70]
            path = self.out / "stix" / slug / f"{day}_{slug_t}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(bundle, indent=1))
            meta = {"report_id": bundle["objects"][0]["id"], "source": name, "title": it["title"], "url": it["url"],
                    "published": it["published"], "actors": a["actors"], "families": a["families"],
                    "ttps": a["ttps"], "cves": a["cves"], "stix_path": str(path)}
            self.kb.add_report(meta, a["iocs"])
            done.append({**meta, "n_iocs": len(a["iocs"]), "n_yara": len(a["yara"])})
        # articles skipped as news / marketing are re-checked every run (cached): only report real additions
        (log.info if done else log.debug)(f"{name}: {len(done)} reports kept of {len(todo)} new articles")
        return done

    def run(self, only: list[str] | None = None) -> list[dict]:
        known = self.kb.known_report_urls()
        todo = [s for s in SOURCES if not only or s[0] in only]
        def one(src):
            try:
                return self.source(*src, known)
            except Exception as exc:
                log.warning(f"{src[1]}: failed ({type(exc).__name__}: {exc})")
                return []

        with ThreadPoolExecutor(max_workers=8) as pool:   # sites in parallel, each site sequential
            done = [r for rs in pool.map(one, todo) for r in rs]
        self.write_bundle()
        return done

    def write_bundle(self) -> int:
        """dataset/bundle.json: every report merged (same id = same object across reports)."""
        objs: dict[str, dict] = {}
        for p in sorted((self.out / "stix").glob("*/*.json")):
            for o in json.loads(p.read_text()).get("objects", []):
                objs.setdefault(o["id"], o)
        bundle = {"type": "bundle", "id": _sid("bundle", "inframapper-dataset"), "objects": list(objs.values())}
        (self.out / "bundle.json").write_text(json.dumps(bundle))
        return len(objs)
