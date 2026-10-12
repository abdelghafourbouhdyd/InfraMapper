"""Pivot engine: breadth-first expansion of an IOC through VirusTotal, urlscan.io and passive DNS."""

from __future__ import annotations

import base64
import codecs
import re
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from . import cluster
from . import graph as g
from .clients import URLScan, VirusTotal
from .feeds import Feeds
from . import nrd
from . import regex_hunt as rh
from .intel import PriorReporting, Warninglists, _ts, timing
from .pdns import PassiveDNS, is_commodity, soa_parts, window
from .log import log
from rich.markup import escape
from .patterns import (UrlWindow, apex_of, split_domain, domain_patterns, es_escape, host_of, is_ip,
                       title_is_generic, url_path_pattern)

try:
    import mmh3
except ImportError:   # optional: only used for Shodan/FOFA favicon hashes
    mmh3 = None

def _age(day: str) -> int:
    return (datetime.now(timezone.utc).date() - datetime.fromisoformat(day[:10]).date()).days


def ARTEFACT_W(kind: str) -> int:
    """How much a shared artefact of this pivot kind says about a new domain (0 = not an artefact)."""
    if kind.startswith("domain pattern"):
        return 1
    return nrd.ARTEFACT_KINDS.get(kind, 0)


# host -> pivot artefact edges (the host a pivot was run from)
ORIGIN_RELS = {"MATCHES_PATTERN", "ANALYST_PIVOT", "HAS_TITLE", "HAS_FAVICON", "SERVES_HTML", "SERVES_SCRIPT"}
# report fingerprints (--from) -> where to hunt them
FINGERPRINT_QUERY = {"imphash": ("VT Intelligence", "imphash:{v}"), "vhash": ("VT Intelligence", 'vhash:"{v}"'),
                     "ssdeep": ("VT Intelligence", 'ssdeep:"{v}"'), "tlsh": ("VT Intelligence", "tlsh:{v}"),
                     "ja3": ("Zeek / Suricata", "ssl.log ja3 == {v} / ja3.hash; content:\"{v}\""),
                     "jarm": ("Shodan", "ssl.jarm:{v}"), "authentihash": ("VT Intelligence", "authentihash:{v}")}
US_CAP = 10000       # urlscan search totals stop at this
LOOKUP_WORKERS = 6  # parallel feed / OTX / abuse.ch lookups (VT keeps its own rate limit)
NOISY_PULSES = 50    # IOC in more OTX pulses than this = sandbox noise (Google, Windows Update…)
DATASET_CO_IOCS = 25  # other IOCs of a matching dataset report kept on its report node

VT_FILE_RELS = ["contacted_domains", "contacted_ips", "contacted_urls", "dropped_files",
                "execution_parents", "itw_urls", "embedded_domains", "embedded_ips"]
VT_DOMAIN_RELS = ["resolutions", "communicating_files", "downloaded_files",
                  "referrer_files", "subdomains", "urls"]
VT_IP_RELS = ["resolutions", "communicating_files", "downloaded_files",
              "referrer_files", "urls"]

# VT relationship -> (edge label, reverse?)  reverse means neighbour -> source
REL_MAP = {
    "contacted_domains": ("CONTACTS", False), "contacted_ips": ("CONTACTS", False),
    "contacted_urls": ("CONTACTS", False), "dropped_files": ("DROPS", False),
    "execution_parents": ("DROPS", True), "itw_urls": ("DOWNLOADED_FROM", False),
    "embedded_domains": ("EMBEDS", False), "embedded_ips": ("EMBEDS", False),
    "communicating_files": ("CONTACTS", True), "downloaded_files": ("DOWNLOADED_FROM", True),
    "referrer_files": ("EMBEDS", True), "subdomains": ("HAS_SUBDOMAIN", False),
    "urls": ("HAS_URL", False),
}


@dataclass
class Config:
    depth: int = 1               # expand nodes whose depth < this
    limit: int = 10              # max objects per VT relationship / urlscan pivot
    scans: int = 3               # urlscan full results to parse per domain/IP
    broad: int = 250             # pivot with more urlscan hits than this is not expanded
    broad_pattern: int = 5000    # domain/url patterns: above this, don't even add sample hits
    refine: int = 6              # searches spent tightening one too-broad urlscan pivot (0 = off)
    refine_budget: int = 60      # refinement searches per run, all pivots together
    new_hunt: bool = True        # hunt newly created domains after the cluster is built
    nrd_days: int = 7            # WhoisDS newly-registered-domain lists to scan (days back)
    young_days: int = 30         # "new" = apex younger than this (urlscan kit reuse, CT certs)
    young_queries: int = 12      # urlscan searches for kit reuse on young domains
    ct: bool = True              # Certificate Transparency (crt.sh) for the actor's names
    max_expand: int = 40         # hard cap on number of expanded nodes
    history: int = 100           # urlscan scans per host used for the change timeline
    vt_history_depth: int = 0    # VT whois/cert history for hosts at depth <= this (costs VT quota)
    min_score: int = 2           # evidence needed for a discovered host to join the cluster
    vt_intel: bool = False       # VT Intelligence searches (premium)
    pdns_broad: int = 25         # IP with more pDNS domains than this = shared hosting
    ns_broad: int = 200          # nameserver / MX used by more domains than this isn't expanded
    use_vt: bool = True
    use_urlscan: bool = True
    use_pdns: bool = True
    intel_max: int = 200         # max hosts checked for prior reporting per run / pivot
    batch_vt: int = 50           # report triage (--from): VT verdict lookups, at most
    vt_comments: int = 10        # IOCs whose VT community comments are read per run / pivot (0 = off)
    hop: bool = True             # hosting pivot: IP -> domains -> their other IPs -> shared domains
    hop_ips: int = 5             # anchor IPs per run
    hop_domains: int = 15        # domains per anchor whose hosting history is fetched
    hop_siblings: int = 8        # candidate sibling IPs per anchor that get a reverse pDNS lookup
    extra_queries: list[str] = field(default_factory=list)
    extra_regexes: list[str] = field(default_factory=list)   # analyst regexes, searched on urlscan page.domain
    regex_hunt: bool = True      # progressive regex ladder on the cluster's domain names
    regex_steps: int = 6         # urlscan searches per ladder


def clean_regex(pattern: str) -> str:
    """Analyst regex as urlscan (Elasticsearch) takes it: always a whole-name match, so ^ / $ are
    dropped; a ``/.../`` wrapper and unescaped / are handled."""
    p = pattern.strip()
    if len(p) > 1 and p.startswith("/") and p.endswith("/"):
        p = p[1:-1]
    p = p.removeprefix("^")
    if p.endswith("$") and not p.endswith("\\$"):
        p = p[:-1]
    return re.sub(r"(?<!\\)/", r"\/", p)


def regex_query(pattern: str) -> str:
    p = clean_regex(pattern)
    return f"page.domain:/{p}/" if p else ""


class Investigator:
    def __init__(self, vt: VirusTotal | None, us: URLScan | None, cfg: Config,
                 pdns: PassiveDNS | None = None, intel: PriorReporting | None = None,
                 warn: Warninglists | None = None, feeds: Feeds | None = None):
        self.intel, self.warn, self.feeds = intel, warn, feeds
        self.vt = vt if cfg.use_vt else None
        self.us = us if cfg.use_urlscan else None
        self.pdns = pdns if cfg.use_pdns else None
        self.cfg = cfg
        self.g = g.Graph()
        self.queue: deque[tuple[str, str, int]] = deque()
        self.seen: set[str] = set()
        self.expanded = 0
        self.pivots: list[dict] = []          # every pivot query run, for the report
        self.hunt_queries: list[dict] = []    # queries for other platforms (Shodan/FOFA/VT)
        self.timelines: dict[str, list[dict]] = {}  # host node id -> observations over time
        self.seed_id = ""
        self.cluster: set[str] = set()        # node ids in the confirmed-cluster view
        self.skipped = 0                      # unconfirmed hosts not expanded
        self.dns_history: dict[str, list[dict]] = {}  # host node id -> its own pDNS / live records
        self.manual_pivots: list[dict] = []   # pivots run from the graph page (--serve)
        self.refine_calls = 0
        self.new_domains: list[dict] = []     # new-domain hunt leads
        self.cache_dir = self.cache = None    # set by the CLI: NRD lists folder, API cache (RDAP / crt.sh)
        self.ct = None                        # CertTransparency, set by the CLI (certificate pivots)
        self.batch: dict | None = None        # report triage (--from): source, counts, dropped, CVEs
        self.actors = self.tlds = None        # MISP actor aliases + TLD list for VT comments, set by the CLI
        self.hosting: list[dict] = []         # hosting pivot results per anchor IP, for the report
        self.kb = None                        # Knowledge (cases/knowledge.db): memory + analyst verdicts, set by the CLI
        self.vt_pending: dict[str, list[dict]] = {}   # node id -> VT YARA / sandbox / AV attribution, not linked yet
        self.regex_ladders: list[dict] = []   # progressive regex pivots: every step, its hits and why

    # ------------------------------------------------------------------ engine
    def run(self, ioc_type: str, value: str) -> g.Graph:
        ntype = {"file": g.FILE, "domain": g.DOMAIN, "ip": g.IP, "url": g.URL}[ioc_type]
        self.seed_id = self.g.add_node(ntype, value, seed=True, depth=0)
        self._enqueue(ntype, value, 0)
        for q in self.cfg.extra_queries:
            pid = self.g.add_node(g.PATTERN, q, kind="custom")
            self.g.add_edge(self.seed_id, pid, "ANALYST_PIVOT")
            self._urlscan_pivot(pid, q, "custom", 1)
        if self.us:
            self.regex_pivot(self.cfg.extra_regexes)

        while self.queue and self.expanded < self.cfg.max_expand:
            ntype, value, depth = self.queue.popleft()
            if depth > 0:
                # only spend API calls on hosts the evidence says belong to the cluster
                self._apply_verdicts([g.node_id(ntype, value)])   # an analyst FP is never crawled
                r = cluster.score(self.g, self.seed_id, self.cfg.min_score).get(g.node_id(ntype, value))
                if r and not r["confirmed"]:
                    self.skipped += 1
                    log.debug(f"skip unconfirmed {ntype} {escape(value)} (score {r['score']})")
                    continue
            self.expanded += 1
            try:
                self._expand(ntype, value, depth)
            except Exception as exc:   # one bad node shouldn't kill the whole run
                log.exception(f"error expanding {ntype} {value}: {exc}")
        if self.queue:
            log.warning(f"max-expand reached; {len(self.queue)} nodes left unexpanded")
        self.recluster()
        if self.hosting_pivot():   # linked sibling IPs / their domains are scored like everything else
            self.recluster()
        if self.check_reporting():
            self.recluster()
        if self.us and self.cfg.regex_hunt and self.regex_hunt():
            self.recluster()
        if self.cfg.new_hunt and self.hunt_new_domains():
            self.recluster()
            if self.check_reporting():   # feeds / reports for what the hunt confirmed
                self.recluster()
        hosts = [n for n in self.g.nodes.values() if n["type"] in cluster.HOSTS]
        conf = sum(1 for n in hosts if n["props"].get("cluster"))
        log.info(f"cluster: {conf} confirmed hosts, {len(hosts) - conf} unconfirmed candidates "
                 f"({self.skipped} not expanded)")
        return self.g

    def run_batch(self, label: str, iocs: list[tuple[str, str]], extracted=None) -> g.Graph:
        """Triage every IOC of a threat report without crawling: is it noise, live on a feed,
        reported elsewhere, still resolving? The report is the seed and each IOC is a co-seed, so
        pivots run later from the graph page (--serve) are scored against the whole report."""
        types = {"file": g.FILE, "domain": g.DOMAIN, "ip": g.IP, "url": g.URL}
        self.batch = {"source": label, "iocs": len(iocs),
                      "counts": extracted.counts() if extracted else {},
                      "dropped": extracted.dropped if extracted else {},
                      "cves": extracted.cves if extracted else [],
                      "fingerprints": extracted.fingerprints if extracted else []}
        for kind, v in self.batch["fingerprints"]:   # imphash / JA3…: pivots, not IOCs
            q = FINGERPRINT_QUERY.get(kind.split()[0].rstrip("s") if kind.startswith("ja3") else kind)
            if q:
                self.hunt_queries.append({"platform": q[0], "query": q[1].format(v=v), "note": f"{kind} from the report"})
        self.seed_id = self.g.add_node(g.REPORT, label, name=label, source="Input report", seed=True, depth=0,
                                       url=label if label.startswith("http") else None)
        nids = []
        aliases = extracted.aliases if extracted else {}
        for kind, value in iocs:
            nid = self.g.add_node(types[kind], value, input_ioc=True, pinned=True, depth=1,
                                  **aliases.get(value, {}))
            self.g.add_edge(self.seed_id, nid, "MENTIONS")
            self.seen.add(nid)
            nids.append(nid)
        benign = {nid for nid in nids if self.warn and (wl := self.warn.match(
            self.g.nodes[nid]["type"], self.g.nodes[nid]["value"])) and wl[1] == "benign"}

        if self.vt:   # one object lookup per IOC, files first: VT is the main verdict source for hashes
            todo = sorted((n for n in nids if n not in benign),
                          key=lambda n: ["File", "URL", "Domain", "IP"].index(self.g.nodes[n]["type"]))
            todo = todo[: self.cfg.batch_vt]
            if len(todo) > 8 and self.vt.rpm < 30:
                log.info(f"VT: {len(todo)} lookups at {self.vt.rpm:g}/min, up to {len(todo) / self.vt.rpm:.0f} min "
                         f"(cached next time; --batch-vt N caps it, --no-vt skips)")
            for nid in todo:
                try:
                    self._vt_enrich(nid)
                except Exception as exc:
                    log.warning(f"VT lookup failed for {escape(self.g.nodes[nid]['value'])}: {exc}")
        if self.pdns and self.pdns.live:   # dead IOCs: retro-hunt still matters, blocking barely does
            for nid in nids:
                n = self.g.nodes[nid]
                if n["type"] == g.DOMAIN and nid not in benign:
                    a = [r["rdata"] for r in self.pdns.live.lookup(n["value"], ("A",)) if r["rrtype"] == "a"]
                    self.g.set_prop(nid, resolves_now=a[:5] or None, dns_dead=not a or None)
        self.check_reporting()
        self.recluster()
        log.info(f"report triage: {len(nids)} IOCs ({', '.join(f'{v} {k}' for k, v in self.batch['counts'].items())})")
        return self.g

    def _vt_enrich(self, nid: str) -> None:
        """Verdict + basic context for one IOC (1 VT call), no relationships."""
        n = self.g.nodes[nid]
        t, v = n["type"], n["value"]
        obj = self.vt.obj(*_vt_id(t, v))
        if not obj:
            self.g.set_prop(nid, vt_unknown=True)
            return
        a = obj.get("attributes", {})
        extra = {}
        if t == g.FILE:
            extra = dict(sha256=a.get("sha256"), md5=a.get("md5"), sha1=a.get("sha1"), name=a.get("meaningful_name"),
                         file_type=a.get("type_description"), label=_threat_label(a),
                         first_seen=a.get("first_submission_date"), tags=a.get("tags"))
        elif t == g.DOMAIN:
            extra = dict(registrar=a.get("registrar"), created=a.get("creation_date"),
                         categories=sorted(set((a.get("categories") or {}).values())))
        elif t == g.IP:
            extra = dict(asn=a.get("asn"), as_owner=a.get("as_owner"), country=a.get("country"))
        self.g.add_node(t, v, **extra, **self._stats(a))
        self._vt_attrib(t, v, a)

    def _expand(self, ntype: str, value: str, depth: int) -> None:
        log.info(f"[bold cyan]expand[/] {ntype} {escape(value)} (depth {depth})")
        self.g.set_prop(g.node_id(ntype, value), expanded=True)
        if ntype == g.FILE:
            self._vt_file(value, depth)
            self._us_file(value, depth)
        elif ntype == g.DOMAIN:
            self._vt_domain(value, depth)
            self._us_host(value, depth, is_ip_=False)
            self._pdns_domain(value, depth)
        elif ntype == g.IP:
            self._vt_ip(value, depth)
            self._us_host(value, depth, is_ip_=True)
            self._pdns_ip(value, depth)
        elif ntype == g.URL:
            self._vt_url(value, depth)
        elif ntype == g.CERT:   # only from the graph page: certs aren't queued by the crawl
            self._cert(value, depth)

    def known_domains(self) -> list[str]:
        """Domains the case says are the actor's: the seed's host and every confirmed domain."""
        out = [n["value"] for n in self.g.nodes.values()
               if n["type"] == g.DOMAIN and (n["id"] == self.seed_id or n["props"].get("cluster") is True)
               and not n["props"].get("warninglist") and n["props"].get("analyst_verdict") != "fp"]
        seed = self.g.nodes.get(self.seed_id, {})
        first = host_of(seed["value"]) if seed.get("type") == g.URL else seed.get("value", "")
        out = sorted({d.lower() for d in out if d and not is_ip(d)})
        return sorted(out, key=lambda d: d != first.lower())   # the seed first: it breaks keyword ties

    def regex_hunt(self, domains: list[str] | None = None) -> list[str]:
        """Automatic ladder from the actor's naming (the cluster's domains, or the ones given)."""
        known = domains or self.known_domains()
        step = rh.start(known)
        if not step:
            return []
        known = [d for d in known if step.kw in rh.parts(d)[1]]   # refinements must keep these, not every host
        log.info(escape(f"regex hunt on '{step.kw}' ({len(known)} known domain{'s' if len(known) > 1 else ''})"))
        return self._ladder(step, known, "domain pattern (regex)")

    def regex_pivot(self, patterns: list[str], depth: int = 1) -> list[str]:
        """Each analyst regex starts its own ladder: searched as given, then tightened from its hits.
        Returns the pivot node ids (a regex already searched in this case is not run again)."""
        known, pids = self.known_domains(), []
        for pat in patterns:
            p = clean_regex(pat)
            if not p:
                continue
            fits = [d for d in known if re.fullmatch(p, d)]   # the analyst's regex may target other names
            pids += self._ladder(rh.start(fits, p), fits, "custom regex", depth)
        return pids

    def _ladder(self, step, known: list[str], kind: str, depth: int = 1) -> list[str]:
        """broad -> analyse the hits -> refine -> ... -> best pivot. Each rung is searched once; a
        refinement is kept only if it cuts the hits by a fifth, and the ladder stops at the first
        pivot small enough to expand (or when the step budget / the useful refinements run out)."""
        q = step.query()
        if any(p["query"] == q for p in self.pivots) or any(L["steps"][0]["query"] == q for L in self.regex_ladders):
            log.info(escape(f"  regex {q} already searched in this case"))
            return []
        sample = lambda res: list(dict.fromkeys((r.get("page") or {}).get("domain") for r in res
                                                if (r.get("page") or {}).get("domain")))[:8]
        total, res = self.us.search(q, 100)
        rungs = [{"label": "broad", "why": "simplest pattern: " + (f"'{step.kw}' anywhere in the name" if step.kw
                  else "your regex as given"), "query": q, "regexes": step.regexes(), "exclude": list(step.exclude), "recent": step.recent, "total": total,
                  "sample": sample(res), "decision": "start"}]
        log.info(escape(f"  regex [broad] {q} -> {total}"))
        best, tried, searches = 0, {q}, 1
        while 0 < total and total > self.cfg.broad and searches < self.cfg.regex_steps:
            moved = False
            for label, why, nxt in rh.refinements(step, known, res, capped=total >= US_CAP):
                nq = nxt.query()
                if nq in tried or searches >= self.cfg.regex_steps:
                    continue
                tried.add(nq)
                searches += 1
                t, r2 = self.us.search(nq, 100)
                # urlscan stops counting at 10,000: two capped totals say nothing, the sample said why to refine
                capped = t >= US_CAP and total >= US_CAP
                keep = t and (t <= total * 0.8 or capped)
                decision = ("0 hits: too specific, dropped" if t == 0 else "best pivot" if t <= self.cfg.broad
                            else "still 10,000+: kept" if capped else "narrower: kept" if keep
                            else "barely narrower: dropped")
                rungs.append({"label": label, "why": why, "query": nq, "regexes": nxt.regexes(), "exclude": list(nxt.exclude), "recent": nxt.recent, "total": t,
                              "sample": sample(r2), "decision": decision})
                log.info(escape(f"  regex [{label}] -> {t}: {decision}"))
                if keep:
                    step, total, res, best, moved = nxt, t, r2, len(rungs) - 1, True
                    break
            if not moved:
                break
        final = rungs[best]
        if total > self.cfg.broad:
            final["decision"] = "best reached: " + ("sample attached" if total <= self.cfg.broad_pattern else "still too broad")
        elif best == 0 and total:
            final["decision"] = "best pivot"
        self.regex_ladders.append({"kind": kind, "keyword": step.kw, "known": known[:6], "steps": rungs, "best": best,
                                   "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        if not total:
            return []
        pid = self.g.add_node(g.PATTERN, final["query"], kind=kind, regex=" AND ".join(final["regexes"]))
        self.g.add_edge(self.seed_id, pid, "ANALYST_PIVOT")
        self._urlscan_pivot(pid, final["query"], kind, depth)
        return [pid]

    def expand_node(self, nid: str) -> None:
        """Interactive pivot: expand one existing node now, without following what it finds."""
        node = self.g.nodes[nid]
        self._expand(node["type"], node["value"], node["props"].get("depth", 1))
        self.queue.clear()
        if node["type"] == g.IP:
            self.hosting_pivot([nid])
        self.recluster()
        if self.check_reporting():
            self.recluster()

    # ------------------------------------------------------- knowledge base
    def recluster(self) -> None:
        """Analyst verdicts first (an FP never joins, a confirmed node is a co-seed), then scoring."""
        self._apply_verdicts()
        self.cluster = cluster.apply(self.g, self.seed_id, self.cfg.min_score)

    ANALYST_KEYS = ("analyst_verdict", "analyst_actor", "analyst_family", "analyst_note", "analyst_case", "analyst_date")

    def _apply_verdicts(self, nids: list[str] | None = None) -> None:
        """Copy the knowledge base's verdicts onto the nodes; an actor / malware-family label becomes an
        "Analyst" report linked REPORTED_IN, so attribution / STIX pick it up like any other source."""
        if not self.kb:
            return
        from .knowledge import MARKABLE
        from .vtcomments import _norm
        targets = [i for i in (nids if nids is not None else list(self.g.nodes))
                   if i in self.g.nodes and self.g.nodes[i]["type"] in MARKABLE]
        found = self.kb.verdicts(targets)
        for nid in targets:
            p, v = self.g.nodes[nid]["props"], found.get(nid)
            if not v and not any(k in p for k in self.ANALYST_KEYS):
                continue
            for k in self.ANALYST_KEYS:
                p.pop(k, None)
            if v:
                self.g.set_prop(nid, **{f"analyst_{k}": v[k] for k in ("verdict", "actor", "family", "note", "case", "date")
                                        if v.get(k)})
            # the labels become "Analyst" reports: dropped and re-linked so an edited label doesn't linger
            for key in [k for k in self.g.edges if k[0] == nid and k[2] == "REPORTED_IN"
                        and self.g.nodes.get(k[1], {}).get("props", {}).get("source") == "Analyst"]:
                del self.g.edges[key]
            v = v or {}
            for key, props in ((f"analyst:{_norm(v['actor'])}", {"name": f"Analyst: {v['actor']}", "actor": v["actor"]})
                               if v.get("actor") else (None, None),
                               (f"analyst-family:{_norm(v['family'])}", {"name": f"Analyst: {v['family']}",
                                                                         "malware": [v["family"]]})
                               if v.get("family") else (None, None)):
                if key:
                    rid = self.g.add_node(g.REPORT, key, source="Analyst", date=v.get("date"), **props)
                    self.g.add_edge(nid, rid, "REPORTED_IN", source="Analyst", date=v.get("date"))
        linked = {d for (_, d, rel) in self.g.edges if rel == "REPORTED_IN"}
        for rid in [i for i, n in self.g.nodes.items() if n["type"] == g.REPORT
                    and n["props"].get("source") == "Analyst" and i not in linked]:
            del self.g.nodes[rid]   # label removed everywhere

    def cross_case(self, case: str) -> int:
        """Tag every IOC / fingerprint of the graph seen in another case. Returns nodes tagged."""
        if not self.kb:
            return 0
        from .knowledge import MARKABLE
        nids = [i for i, n in self.g.nodes.items() if n["type"] in MARKABLE]
        seen = self.kb.seen_elsewhere(nids, case)
        for nid in nids:
            p = self.g.nodes[nid]["props"]
            p.pop("seen_in", None)
            p.pop("seen_cases", None)
            if seen.get(nid):
                self.g.set_prop(nid, seen_cases=len({x["case"] for x in seen[nid]}), seen_in=seen[nid][:5])
        hits = [i for i in nids if seen.get(i) and _in_view(self.g.nodes[i])]
        if hits:
            log.info(f"[bold]seen before[/]: {len(hits)} IOCs / fingerprints of this case are in "
                     f"{len({x['case'] for i in hits for x in seen[i]})} earlier case(s)")
        return len(hits)

    # ------------------------------------------------------- prior reporting
    def check_reporting(self) -> int:
        """Has an IOC in view already been published / tied to a campaign, is it on a live C2 /
        phishing feed, or is it noise? Returns hosts checked."""
        if self._articles_to_reports():
            self.recluster()
        # VT comments are bound by the VT rate limit, feeds / OTX / abuse.ch by latency: run both at once
        pool = ThreadPoolExecutor(max_workers=LOOKUP_WORKERS)
        comments = pool.submit(self._vt_comments_fetch, self._vt_comments_todo())   # picked here: graph reads stay on this thread
        self._apply_vt_pending()
        if not self.intel and not self.warn and not self.feeds:
            n_comments = self._vt_comments_apply(comments.result())
            pool.shutdown()
            return n_comments
        todo = [n for n in self.g.nodes.values() if n["type"] in cluster.HOSTS
                and (n["props"].get("cluster") is not False or n["props"].get("pinned"))
                and not (n["props"].get("intel_checked") and (n["props"].get("feeds_checked") or not self.feeds))]
        todo.sort(key=lambda n: (n["id"] != self.seed_id, n["props"].get("cluster") is False))
        todo = todo[: self.cfg.intel_max]
        # network lookups in parallel (they don't touch the graph), results applied in order below
        found = pool.map(self._lookup, todo)
        checked = hits = 0
        for n, (wl, ctx, reports, total, prior) in zip(todo, found):
            nid, ntype, value = n["id"], n["type"], n["value"]
            if wl and wl[1] == "benign":
                # CDN / resolver / top site / known-good hash: in every report, attributes nothing
                self.g.set_prop(nid, warninglist=wl[0], intel_checked=True, feeds_checked=True)
                continue
            if wl:   # rented cloud / VPS / VPN range: reports only count if the timing fits
                self.g.set_prop(nid, hosting=wl[0])
            if self.feeds:
                self.g.set_prop(nid, feeds_checked=True, **{k: v for k, v in ctx.items() if v not in (None, [], "")})
                if ctx.get("gn_riot"):   # Microsoft / Google / Zoom… traffic: never attributed
                    self.g.set_prop(nid, warninglist=f"GreyNoise RIOT: {ctx['gn_riot']}", intel_checked=True)
                    continue
                if ctx.get("tor_exit") and not wl:
                    wl = ("Tor exit node", "hosting")
                    self.g.set_prop(nid, hosting=wl[0])
            if self.feeds or self.intel:
                checked += 1
            if not self.intel and not reports:
                continue
            reports = prior + reports
            used = self._used_window(nid) if ntype in (g.IP, g.DOMAIN) else None
            for r in reports:
                edge = r.get("edge") or {}
                r["timing"] = timing(r["date"], used, edge.get("last_seen"))
                if not r["timing"] and not used and edge.get("current"):
                    r["timing"] = "current"   # listed right now; this case has no dates to compare

            why = None
            if total > NOISY_PULSES:
                why = f"in {total} OTX pulses: too common to attribute"
                reports = [r for r in reports if r["source"] != "OTX"]
            if ntype == g.IP and (wl or n["props"].get("shared_hosting")):
                # a cloud / VPS address changes hands: only a report from when it was used here counts
                kept = [r for r in reports if r["timing"] in ("fits", "current")]
                if len(kept) < len(reports):
                    why = (f"{len(reports) - len(kept)} report(s) on this shared-hosting IP from outside "
                           f"the time it was used here" + ("" if used else " (usage dates unknown)"))
                reports = kept
            self.g.set_prop(nid, intel_checked=True, otx_pulses=total or None,
                            reported=len(reports) or None, reported_unlinked=why)
            for r in reports:
                self._observe(nid, r["date"], r["source"], reported=r["name"][:90])   # timeline: when it was reported
                rid = self.g.add_node(g.REPORT, r["key"], **{k: v for k, v in r.items()
                                                             if k not in ("key", "timing", "edge")})
                self.g.add_edge(nid, rid, "REPORTED_IN", source=r["source"], date=r["date"],
                                timing=r["timing"], **(r.get("edge") or {}))
            if reports:
                hits += 1
                log.info(escape(f"  reported: {ntype} {value} — " + "; ".join(
                    r["name"][:60] for r in reports[:3]) + (" …" if len(reports) > 3 else "")))
        if checked:
            srcs = (self.intel.sources if self.intel else []) + (self.feeds.sources if self.feeds else [])
            log.info(f"prior reporting / feeds: {hits}/{checked} IOCs already reported or listed "
                     f"({', '.join(srcs)})")
        n_comments = self._vt_comments_apply(comments.result())
        pool.shutdown()
        return checked + n_comments

    def _lookup(self, n: dict) -> tuple:
        """(warninglist hit, feed context, feed reports, OTX pulse count, prior reports) for one IOC.
        Network only, no graph writes: safe to run in a thread."""
        ntype, value = n["type"], n["value"]
        wl = self.warn.match(ntype, value) if self.warn else None
        if wl and wl[1] == "benign":
            return wl, {}, [], 0, []
        ctx, reports = self.feeds.lookup(ntype, value, n["props"]) if self.feeds else ({}, [])
        if ctx.get("gn_riot"):
            return wl, ctx, reports, 0, []
        reports = self._dataset_reports(n) + reports
        if not self.intel:
            return wl, ctx, reports, 0, []
        total, prior = self.intel.lookup(ntype, value)
        return wl, ctx, reports, total, prior

    def _dataset_reports(self, n: dict) -> list[dict]:
        """Published reports in the local dataset (--ingest) that list this IOC, in the prior-reporting
        format: each vendor is its own source, so they count as independent groups."""
        if not self.kb:
            return []
        own = (self.batch or {}).get("source")   # --from <that same report>: it isn't prior reporting
        out = []
        for r in self.kb.report_hits(n["id"]):
            if r["url"] == own:
                continue
            # what else the same article lists: related infrastructure / samples of that campaign
            others = [f"{i['type']}:{i['value']}" for i in self.kb.report_iocs(r["report_id"], DATASET_CO_IOCS + 1)
                      if i["nid"] != n["id"]][:DATASET_CO_IOCS]
            out.append({"source": r["source"], "key": f"dataset:{r['report_id']}", "name": r["title"],
                        "date": r["published"], "url": r["url"], "references": [r["url"]],
                        "actor": r["actors"][0] if len(r["actors"]) == 1 else None, "malware": r["families"][:5],
                        "tags": r["ttps"][:10], "attack": r["ttps"][:20], "summary": r.get("summary"),
                        "feed": r.get("feed"), "n_iocs": r["n_iocs"], "other_iocs": others,
                        # the IOC's role in that report (AI): "c2 in <report>" is what an analyst needs
                        "edge": {"detail": r["role"]} if r.get("role") else {}})
        return out

    def _vt_comments_todo(self) -> list[dict]:
        """Seed / report IOCs / confirmed cluster, files first, up to --vt-comments."""
        if not self.vt or not self.cfg.vt_comments or self.actors is None:
            return []
        todo = [n for n in self.g.nodes.values() if n["type"] in cluster.HOSTS
                and (n["props"].get("cluster") is not False or n["props"].get("pinned"))
                and not n["props"].get("vt_comments_checked") and not n["props"].get("vt_unknown")
                and not n["props"].get("warninglist")]
        todo.sort(key=lambda n: (n["id"] != self.seed_id, not n["props"].get("input_ioc"),
                                 n["props"].get("cluster") is not True, n["type"] != g.FILE,
                                 -(n["props"].get("vt_malicious") or 0)))
        todo = [n for n in todo if not (self.warn and (wl := self.warn.match(n["type"], n["value"]))
                                        and wl[1] == "benign")][: self.cfg.vt_comments]
        return todo

    def _vt_comments_fetch(self, todo: list[dict]) -> list[tuple[dict, list, list]]:
        """[(node, reports, co-mentions)]. Only VT calls, no graph access, so it runs in the
        background next to the feed lookups."""
        if not todo:
            return []
        from .vtcomments import comment_reports
        if len(todo) > self.vt.rpm:
            log.info(f"VT comments: {len(todo)} IOCs at {self.vt.rpm:g}/min, in the background "
                     f"(--vt-comments N caps it)")
        out = []
        for n in todo:
            try:
                out.append((n, *comment_reports(self.vt, *_vt_id(n["type"], n["value"]), self.actors,
                                                tlds=self.tlds, self_value=n["value"])))
            except Exception as exc:
                log.warning(f"VT comments failed for {escape(n['value'])}: {exc}")
        return out

    def _vt_comments_apply(self, fetched: list[tuple[dict, list, list]]) -> int:
        """Actor and family names become reports ("VT comments: APT28", shared by every IOC carrying
        the tag), IOCs listed in the same comment become CO_MENTIONED candidates (+1 in the cluster
        score: they need corroboration)."""
        types = {"file": g.FILE, "domain": g.DOMAIN, "ip": g.IP, "url": g.URL}
        hits = links = 0
        for n, reports, comentions in fetched:
            nid, ntype, value = n["id"], n["type"], n["value"]
            self.g.set_prop(nid, vt_comments_checked=True)
            for r in reports:   # an article we have in the dataset: its real title, date, actors, families
                known = self.kb.report_by_url(r["url"]) if self.kb and r.get("linked_article") else None
                if known:
                    r.update(name=known["title"], date=known["published"] or r["date"],
                             source=f"VT comment → {known['source']}", malware=known["families"][:5],
                             actor=known["actors"][0] if len(known["actors"]) == 1 else None,
                             summary=known.get("summary"))
            if self._link_vt_reports(n, reports):
                hits += 1
                log.info(escape(f"  VT comments: {ntype} {value} — " + ", ".join(
                    r["name"].removeprefix("VT comments: ") for r in reports[:5])))
            for c in comentions[:20]:
                ct = types[c["kind"]]
                if self.warn and (wl := self.warn.match(ct, c["value"])) and wl[1] == "benign":
                    continue
                cid = self.g.add_node(ct, c["value"], depth=(n["props"].get("depth") or 0) + 1, co_mentioned=True)
                self.g.add_edge(nid, cid, "CO_MENTIONED", source="VT comment", comment=c["comment"],
                                date=c["date"], iocs_in_comment=c["n"])
                links += 1
        if fetched:
            log.info(f"VT comments: {hits}/{len(fetched)} IOCs tagged with an actor / family, "
                     f"{links} co-mentioned IOCs")
        return len(fetched)

    def _link_vt_reports(self, n: dict, reports: list[dict]) -> int:
        """REPORTED_IN edges for VT-derived reports (comments, YARA, sandboxes…), with the same
        guard as OTX: on a rented / shared IP only a report from when it was used here counts."""
        nid, ntype = n["id"], n["type"]
        used = self._used_window(nid) if ntype in (g.IP, g.DOMAIN) else None
        rented = ntype == g.IP and (n["props"].get("hosting") or n["props"].get("shared_hosting"))
        kept = 0
        for r in reports:
            t = timing(r["date"], used)
            if rented and t != "fits":
                continue
            rid = self.g.add_node(g.REPORT, r["key"], **{k: v for k, v in r.items() if k != "key"})
            self.g.add_edge(nid, rid, "REPORTED_IN", source=r["source"], date=r["date"], timing=t,
                            comments=r.get("comments"))
            self._observe(nid, r["date"], r["source"], reported=r["name"][:90])
            kept += 1
        if kept:
            self.g.set_prop(nid, reported=(n["props"].get("reported") or 0) + kept)
        return kept

    def _vt_attrib(self, ntype: str, value: str, attrs: dict) -> None:
        """Keep the attribution VT returned with an object (YARA, sandboxes, AV consensus, partner
        context) until the IOC is in view: no extra VT call."""
        if self.actors is None or not attrs:
            return
        from .vtcomments import object_reports
        reports = object_reports(attrs, self.actors, *_vt_id(ntype, value))
        if reports:
            self.vt_pending[g.node_id(ntype, value)] = reports

    def _apply_vt_pending(self) -> None:
        """Link pending VT attribution for IOCs that are now in view (seed, report, cluster, pinned)."""
        done = 0
        for nid in list(self.vt_pending):
            n = self.g.nodes.get(nid)
            if n and (n["props"].get("cluster") is not False or n["props"].get("pinned")):
                done += bool(self._link_vt_reports(n, self.vt_pending.pop(nid)))
        if done:
            log.info(f"VT YARA / sandbox / AV attribution linked for {done} IOCs")

    # ------------------------------------------------------- hosting pivot
    def hosting_pivot(self, anchors: list[str] | None = None) -> int:
        """IP -> its domains -> every other IP those domains lived on -> reverse pDNS on those IPs:
        which ones share several of the anchor's domains, concurrently or by a quick move? (pDNS only,
        no VT / urlscan quota.) Returns sibling IPs found linked."""
        if not self.pdns or not self.cfg.hop:
            return 0
        from . import hosting
        if anchors is None:   # the seed IP / the seed domain's IPs first, then confirmed cluster IPs
            seed_ips = {d for (s, d, rel) in self.g.edges if s == self.seed_id and rel == "RESOLVES_TO"}
            anchors = sorted((n["id"] for n in self.g.nodes.values() if n["type"] == g.IP
                              and (n["id"] == self.seed_id or n["props"].get("cluster"))),
                             key=lambda i: (i != self.seed_id, i not in seed_ips))
        anchors = [a for a in anchors if a in self.g.nodes and not self.g.nodes[a]["props"].get("hop_done")
                   and not self._noise_ip(self.g.nodes[a])][: self.cfg.hop_ips]
        linked = 0
        pool = ThreadPoolExecutor(max_workers=4)   # pDNS lookups are independent; graph writes stay here
        for aid in anchors:
            a = self.g.nodes[aid]
            ip, depth = a["value"], a["props"].get("depth") or 0
            self.g.set_prop(aid, hop_done=True)
            self._pdns_ip(ip, depth)   # no-op if already run
            if a["props"].get("shared_hosting"):
                continue
            doms = {}
            for (s, d, rel), ep in self.g.edges.items():
                if d == aid and rel == "RESOLVES_TO" and self.g.nodes[s]["type"] == g.DOMAIN \
                        and not self._benign(self.g.nodes[s]):
                    w = window(ep)
                    doms[self.g.nodes[s]["value"]] = w or (0, 0)
            doms = dict(sorted(doms.items(), key=lambda kv: -kv[1][1])[: self.cfg.hop_domains])
            if not doms:
                continue
            log.info(escape(f"hosting pivot {ip}: where its {len(doms)} domains were hosted"))
            recs = dict(zip(doms, pool.map(self.pdns.lookup, doms)))
            domain_ips = {}
            for d, rr in recs.items():
                ips = {i: w for i, w in hosting.ips_of(rr, d).items()
                       if not self._benign({"type": g.IP, "value": i, "props": {}})}
                domain_ips[d] = ips
                if len(ips) > hosting.FASTFLUX:
                    self.g.set_prop(g.node_id(g.DOMAIN, d), fast_flux=len(ips))
                    continue
                for i, (f, l) in ips.items():
                    if i != ip:
                        self._discover(g.IP, i, depth + 2, g.node_id(g.DOMAIN, d), "RESOLVES_TO",
                                       edge_props={"source": "pDNS (hosting pivot)", "first_seen": f, "last_seen": l})
            sibs = hosting.siblings(ip, doms, domain_ips)
            ranked = sorted(sibs.items(), key=lambda kv: (-len(kv[1]), -sum(hosting.is_tight(r) for r in kv[1].values())))
            top = [s for s, _ in ranked[: self.cfg.hop_siblings]]
            reverse = dict(zip(top, pool.map(self.pdns.lookup, top)))
            rows = []
            for sip, shared in ranked[: self.cfg.hop_siblings]:
                on_sib = hosting.domains_of(reverse[sip], sip)
                # reverse pDNS may see more of the anchor's domains than the forward lookups did
                for d in set(on_sib) & set(doms) - set(shared):
                    shared[d] = hosting.relation(doms[d], on_sib[d])
                v = hosting.verdict(shared, len(on_sib) or None, self.cfg.pdns_broad)
                sid = g.node_id(g.IP, sip)
                new = sorted(set(on_sib) - set(doms), key=lambda d: -on_sib[d][1])
                self.g.set_prop(sid, pdns_domains=len(on_sib) or None, hop_verdict=v, hop_anchor=ip,
                                shared_hosting=True if v == "shared hosting" else None)
                if v in ("linked", "possible"):
                    self.g.add_edge(aid, sid, "SHARES_DOMAINS", shared=len(shared), verdict=v,
                                    domains=sorted(shared)[:10],
                                    tight=sum(hosting.is_tight(r) for r in shared.values()))
                    for d in new[: self.cfg.limit * 2]:   # the payoff: domains on the linked IP we didn't know
                        f, l = on_sib[d]
                        self._discover(g.DOMAIN, d, depth + 3, sid, "RESOLVES_TO", reverse=True,
                                       edge_props={"source": "pDNS (hosting pivot)", "first_seen": f, "last_seen": l})
                    linked += v == "linked"
                rows.append({"ip": sip, "verdict": v, "shared": shared, "total": len(on_sib) or None, "new": new[:10]})
            self.hosting.append({"anchor": ip, "domains": len(doms), "siblings": rows,
                                 "candidates": len(sibs), "pdns_out": not self.pdns.available})
            log.info(escape(f"  {len(sibs)} other IPs, " + ", ".join(
                f"{sum(r['verdict'] == k for r in rows)} {k}" for k in ("linked", "possible", "shared hosting", "unverified"))))
        pool.shutdown()
        self.queue.clear()   # found after the crawl: scored, not crawled (pivot on them from the graph page)
        return linked

    def _articles_to_reports(self) -> int:
        """Cases made before article links were recognised: a published report's URL that came in as a
        co-mentioned 'IOC' becomes a report relation of the IOCs that listed it."""
        from .extract import url_host
        from .vtcomments import article_name, is_article
        fixed = 0
        for nid in [i for i, n in self.g.nodes.items() if n["type"] == g.URL and n["props"].get("co_mentioned")
                    and is_article(n["value"])]:
            url = self.g.nodes[nid]["value"]
            known = self.kb.report_by_url(url) if self.kb else None
            for (s, d, rel), ep in list(self.g.edges.items()):
                if rel != "CO_MENTIONED" or nid not in (s, d):
                    continue
                other = d if s == nid else s
                name = known["title"] if known else article_name(url)
                date = (known or {}).get("published") or ep.get("date")
                rid = self.g.add_node(g.REPORT, f"vtref:{url}", url=url, name=name, date=date,
                                      source=f"VT comment → {known['source']}" if known else "VT comment → linked report",
                                      malware=(known or {}).get("families", [])[:5])
                self.g.add_edge(other, rid, "REPORTED_IN", source="VT comment", date=date, timing=None)
                self._observe(other, date, "VT comment", reported=name[:90])
            for key in [k for k in self.g.edges if nid in (k[0], k[1])]:
                del self.g.edges[key]
            del self.g.nodes[nid]
            fixed += 1
            # the article's site came in too (www.jamf.com): drop it when a comment co-mention is all it had
            hid = g.node_id(g.DOMAIN, url_host(url))
            host_edges = [k for k in self.g.edges if hid in (k[0], k[1])]
            if hid in self.g.nodes and self.g.nodes[hid]["props"].get("co_mentioned") \
                    and all(k[2] == "CO_MENTIONED" for k in host_edges):
                for key in host_edges:
                    del self.g.edges[key]
                del self.g.nodes[hid]
        return fixed

    def _benign(self, n: dict) -> bool:
        wl = self.warn.match(n["type"], n["value"]) if self.warn else None
        return bool(n["props"].get("warninglist") or (wl and wl[1] == "benign"))

    def _noise_ip(self, n: dict) -> bool:
        return self._benign(n) or bool(n["props"].get("shared_hosting") or n["props"].get("tor_exit"))

    # ------------------------------------------------------- new-domain hunt
    def hunt_new_domains(self) -> int:
        """Look for domains the actor created since: kit reuse on young domains (urlscan), look-alikes
        in newly registered domain lists (WhoisDS) and fresh certificates (crt.sh). Returns leads."""
        log.info("new-domain hunt")
        conf = [n for n in self.g.nodes.values() if n["props"].get("cluster") and n["type"] in (g.DOMAIN, g.IP)]
        known = {apex_of(n["value"]) for n in conf if n["type"] == g.DOMAIN}
        leads: dict[str, dict] = {}

        def lead(domain: str, via: str, reason: str, weight: int, origin: str, **extra) -> None:
            domain = domain.lower().strip(".")
            if not domain or is_ip(domain) or apex_of(domain) in known:   # already in the confirmed cluster
                return
            cur = leads.setdefault(domain, {"domain": domain, "via": [], "reasons": [], "score": 0, "origin": []})
            if reason not in cur["reasons"]:
                cur["reasons"].append(reason)
                cur["via"] = sorted(set(cur["via"]) | {via})
                cur["score"] = max(cur["score"], weight)
                cur["origin"].append(origin)
            for k, v in extra.items():
                if v is not None and cur.get(k) is None:
                    cur[k] = v

        # 1. kit reuse on young domains
        if self.us:
            seen_q, ran = set(), 0
            for p in list(self.pivots):
                kind = p["kind"]
                w = ARTEFACT_W(kind)
                if p["source"] != "urlscan" or not w or not p["total"] or p["query"] in seen_q or "refine step" in kind:
                    continue
                if ran >= self.cfg.young_queries:
                    break
                seen_q.add(p["query"])
                q = f"({p['query']}) AND page.apexDomainAgeDays:<{self.cfg.young_days}"
                ran += 1
                total, results = self.us.search(q, 100)
                too_broad = total > self.cfg.broad
                self.pivots.append({"source": "urlscan", "kind": f"{kind} (new domains)", "query": q, "total": total,
                                    "broad": too_broad, "decision": "new-domain hunt"
                                    + (": too broad even among new domains" if too_broad else "")})
                log.info(escape(f"  kit reuse [{kind}] on domains < {self.cfg.young_days}d -> {total}"
                                + (" (too broad)" if too_broad else "")))
                if too_broad or not total:
                    continue
                pid = next((n["id"] for n in self.g.nodes.values() if n["props"].get("urlscan_query") == p["query"]), None)
                for r in results:
                    page, t = r.get("page") or {}, (r.get("task") or {}).get("time", "")
                    d = page.get("domain")
                    if not d:
                        continue
                    # apexDomainAgeDays is the age at scan time: registration ≈ scan date - age
                    reg = None
                    if t and page.get("apexDomainAgeDays") is not None:
                        reg = (datetime.fromisoformat(t[:19]).replace(tzinfo=timezone.utc)
                               - timedelta(days=int(page["apexDomainAgeDays"]))).strftime("%Y-%m-%d")
                    lead(d, "urlscan", f"reuses the {kind} artefact", w + 1, pid or "",
                         registered=reg, seen=t[:10], query=q, ip=page.get("ip"))

        # 2 + 3. look-alike names: rules from domains the actor probably registered
        srcs = [self.g.nodes[self.seed_id]["value"]] if self.g.nodes[self.seed_id]["type"] == g.DOMAIN else []
        others = sorted((n for n in conf if n["type"] == g.DOMAIN and n["id"] != self.seed_id
                         and not n["props"].get("warninglist")),
                        key=lambda n: -(n["props"].get("cluster_score") or 0))
        for n in others[:10]:
            created = n["props"].get("created") if isinstance(n["props"].get("created"), int) else \
                (nrd.rdap_created(self.cache, apex_of(n["value"])) if self.cache else None)
            if created and time.time() - created < nrd.RULE_MAX_AGE:
                srcs.append(n["value"])
        # young domains that reuse the kit are the actor's own registrations: their names seed rules too
        srcs += [x["domain"] for x in sorted(leads.values(), key=lambda x: x.get("registered") or "", reverse=True)
                 if "urlscan" in x["via"]][:15]
        rules = nrd.build_rules(list(dict.fromkeys(apex_of(d) for d in srcs)))
        if rules and self.cfg.nrd_days and self.cache_dir:
            match, hits, n = nrd.Matcher(rules), {}, 0
            for d, day in nrd.NRDFeed(self.cache_dir).stream(self.cfg.nrd_days):
                n += 1
                _, label, _ = split_domain(d)
                for i in match(label):
                    if apex_of(d) != rules[i].source:
                        hits.setdefault(i, []).append((d, day))
            log.info(f"  NRD: {n} domains registered in the last {self.cfg.nrd_days} days, "
                     f"{len(rules)} look-alike rules from {len({r.source for r in rules})} actor domain(s)")
            for i, r in enumerate(rules):
                found = hits.get(i, [])
                r.hits = len(found)
                if len(found) > nrd.RULE_MAX_HITS:
                    log.info(escape(f"  rule [{r.kind}] {r.desc}: {len(found)} matches, too generic, dropped"))
                    continue
                if found:
                    log.info(escape(f"  rule [{r.kind}] {r.desc}: {len(found)} new domain(s)"))
                for d, day in found:
                    lead(d, "NRD", f"{r.kind} of {r.source} ({r.desc})", 2 if r.kind == "same name, other TLD" else 1,
                         r.source, registered=day)
        if rules and self.cfg.ct and self.cache:
            ct = nrd.CrtSh(self.cache)
            since = int(time.time()) - self.cfg.young_days * 86400
            for name in list(dict.fromkeys(r.name for r in rules if len(r.name) >= 6))[:3]:
                for host, nb in ct.hosts(name, since):
                    if apex_of(host) in known:
                        continue    # the actor's own domain / its subdomains are already in the case
                    lead(host, "CT", f"fresh certificate for a host containing '{name}'", 1, "",
                         cert_date=datetime.fromtimestamp(nb, timezone.utc).strftime("%Y-%m-%d"))

        # enrich + tie into the graph
        cluster_ips = {n["value"] for n in conf if n["type"] == g.IP and not n["props"].get("shared_hosting")
                       and not n["props"].get("warninglist")}
        cluster_ns = {self.g.nodes[d]["value"] for (s, d, rel) in self.g.edges if rel == "USES_NS"
                      and self.g.nodes.get(s, {}).get("props", {}).get("cluster")
                      and not self.g.nodes[d]["props"].get("commodity")}
        for L in sorted(leads.values(), key=lambda x: -x["score"])[:60]:
            dns = self.pdns.current(L["domain"]) if self.pdns else []
            L["a"] = sorted({r["rdata"] for r in dns if r["rrtype"] == "a"} | ({L["ip"]} if L.get("ip") else set()))
            L["ns"] = sorted({r["rdata"] for r in dns if r["rrtype"] == "ns"})
            L["overlap"] = [f"IP {ip}" for ip in L["a"] if ip in cluster_ips] + \
                           [f"NS {ns}" for ns in L["ns"] if ns in cluster_ns]
            if L["overlap"]:
                L["score"] += 2
            reg = L.get("registered") or ""
            L["age_days"] = _age(reg) if re.match(r"\d{4}-\d{2}-\d{2}", reg) else None
            L["new"] = (L["age_days"] is not None and L["age_days"] <= self.cfg.young_days) or "NRD" in L["via"] \
                or "CT" in L["via"]
            if L["new"] and ((L["age_days"] is not None and L["age_days"] <= 7) or reg.startswith("1-7")):
                L["score"] += 1
            L["strength"], L["action"] = nrd.strength(L["score"])
            if not L["new"]:   # same kit, but registered long ago: not a fresh registration
                L["action"] = "older kit domain: block + retro-hunt"
            did = self.g.add_node(g.DOMAIN, L["domain"], new_domain=L["strength"], age_days=L.get("age_days"),
                                  registered=L.get("registered"))
            for o in L["origin"]:
                if o in self.g.nodes:   # artefact pivot node: kit reuse
                    self.g.add_edge(o, did, "SEEN_ON", source="urlscan", query=L.get("query"))
                elif g.node_id(g.DOMAIN, o) in self.g.nodes:   # look-alike of this actor domain
                    pid = self.g.add_node(g.PATTERN, f"look-alike of {o}", kind="new-domain look-alike")
                    self.g.add_edge(g.node_id(g.DOMAIN, o), pid, "MATCHES_PATTERN")
                    self.g.add_edge(pid, did, "SEEN_ON", source="NRD")
            for ip in L["a"]:
                if ip in cluster_ips:
                    self.g.add_edge(did, g.node_id(g.IP, ip), "RESOLVES_TO", source="live DNS")
            for ns in L["ns"]:
                if ns in cluster_ns:
                    self.g.add_edge(did, g.node_id(g.NS, ns), "USES_NS", source="live DNS")
            L.pop("origin", None)
            self.new_domains.append(L)
        self.new_domains.sort(key=lambda x: (not x["new"], -x["score"], x.get("registered") or "~", x["domain"]))
        self.hunt_queries += [{"platform": "regex (DNS logs / certstream)", "query": r.regex,
                               "note": f"{r.kind} of {r.source}"} for r in rules
                              if r.hits <= nrd.RULE_MAX_HITS and r.kind != "look-alike"]
        fresh = [x for x in self.new_domains if x["new"]]
        log.info(f"  new-domain hunt: {len(fresh)} new domain(s) ({sum(x['strength'] == 'strong' for x in fresh)} strong), "
                 f"{len(self.new_domains) - len(fresh)} older domain(s) reusing the kit")
        return len(self.new_domains)

    def _used_window(self, nid: str) -> tuple[int, int] | None:
        """When this case saw the IP / domain in use: resolution windows, registration date."""
        firsts, lasts = [], []
        for (s, d, rel), ep in self.g.edges.items():
            if rel == "RESOLVES_TO" and nid in (s, d):
                w = window(ep) or ((_ts(ep["date"]),) * 2 if isinstance(ep.get("date"), str) and _ts(ep["date"]) else None)
                if w:
                    firsts.append(w[0])
                    lasts.append(w[1])
        created = self.g.nodes[nid]["props"].get("created")
        if isinstance(created, int) and created:
            # a report older than the current registration is about a previous owner
            return created, max(lasts) if lasts else int(time.time())
        return (min(firsts), max(lasts)) if firsts else None

    def _enqueue(self, ntype: str, value: str, depth: int) -> None:
        nid = g.node_id(ntype, value)
        if nid in self.seen:
            return
        if depth == 0 or depth < self.cfg.depth:
            self.seen.add(nid)
            self.queue.append((ntype, value, depth))

    def _discover(self, ntype: str, value: str, depth: int, src: str, rel: str,
                  reverse: bool = False, edge_props: dict | None = None, **props) -> str:
        """Add a neighbour node + edge and queue it for expansion if within depth."""
        nid = self.g.add_node(ntype, value, **props)
        node = self.g.nodes[nid]
        node["props"].setdefault("depth", depth)
        a, b = (nid, src) if reverse else (src, nid)
        self.g.add_edge(a, b, rel, **(edge_props or {}))
        if ntype in (g.FILE, g.DOMAIN, g.IP, g.URL):
            self._enqueue(ntype, value, depth)
        return nid

    def _observe(self, nid: str, when, source: str, **fields) -> None:
        """Record what a host looked like at a point in time (for the change timeline)."""
        if not when:
            return
        if isinstance(when, (int, float)):
            when = datetime.fromtimestamp(when, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif isinstance(when, str):   # normalise "…:SS.mmmZ" / "+00:00" so events sort as strings
            when = when.replace(" ", "T")[:19] + "Z"
        fields = {k: v for k, v in fields.items() if v not in (None, "", [])}
        if when and set(fields) - {"scan", "url", "cert_sha256"}:
            self.timelines.setdefault(nid, []).append({"t": when, "src": source, **fields})

    # ------------------------------------------------------------ VT helpers
    @staticmethod
    def _stats(attrs: dict) -> dict:
        st = attrs.get("last_analysis_stats") or {}
        total = sum(st.values()) if st else None
        return {"vt_malicious": st.get("malicious"), "vt_suspicious": st.get("suspicious"),
                "vt_total": total}

    def _vt_object_node(self, obj: dict, depth: int, src: str, rel: str,
                        reverse: bool = False, edge_props: dict | None = None) -> None:
        otype, oid, attrs = obj.get("type"), obj.get("id"), obj.get("attributes", {})
        vt_type = {"file": g.FILE, "domain": g.DOMAIN, "ip_address": g.IP}.get(otype)
        if vt_type:   # related objects come with full attributes: their YARA / AV attribution is free
            self._vt_attrib(vt_type, attrs.get("sha256", oid) if otype == "file" else oid, attrs)
        if otype == "file":
            self._discover(g.FILE, attrs.get("sha256", oid), depth, src, rel, reverse, edge_props,
                           name=attrs.get("meaningful_name"),
                           file_type=attrs.get("type_description"),
                           label=_threat_label(attrs), **self._stats(attrs))
        elif otype == "domain":
            self._discover(g.DOMAIN, oid, depth, src, rel, reverse, edge_props,
                           **self._stats(attrs))
        elif otype == "ip_address":
            self._discover(g.IP, oid, depth, src, rel, reverse, edge_props,
                           asn=attrs.get("asn"), country=attrs.get("country"),
                           **self._stats(attrs))
        elif otype == "url":
            url = attrs.get("url") or attrs.get("last_final_url")
            if url:
                self._discover(g.URL, url, depth, src, rel, reverse, edge_props,
                               **self._stats(attrs))
        elif otype == "resolution":
            ip, host = attrs.get("ip_address"), attrs.get("host_name")
            ep = {"date": attrs.get("date"), "source": "vt"}
            if ip and host:
                if src.startswith(g.DOMAIN + ":") and attrs.get("date"):
                    self._observe(src, attrs["date"], "VT resolution", ip=ip)
                elif src.startswith(g.IP + ":") and attrs.get("date"):
                    self._observe(src, attrs["date"], "VT resolution", domain=host)
                if g.node_id(g.IP, ip) == src:
                    self._discover(g.DOMAIN, host, depth, src, "RESOLVES_TO", True, ep)
                else:
                    self._discover(g.IP, ip, depth, src, "RESOLVES_TO", False, ep)

    def _vt_rels(self, collection: str, oid: str, src: str, rels: list[str], depth: int):
        for rel in rels:
            if rel in self.vt.denied:
                continue
            objs = self.vt.related(collection, oid, rel, self.cfg.limit)
            log.info(escape(f"  VT {rel}: {len(objs)}"))
            name, reverse = REL_MAP.get(rel, (rel.upper(), False))
            for obj in objs:
                self._vt_object_node(obj, depth + 1, src, name, reverse)

    def _vt_infra(self, src: str, attrs: dict) -> None:
        """Certificate / JARM / ASN nodes shared between hosts reveal clusters."""
        cert = attrs.get("last_https_certificate") or {}
        thumb = cert.get("thumbprint_sha256") or cert.get("thumbprint")
        if thumb:
            cid = self.g.add_node(g.CERT, thumb,
                                  subject_cn=(cert.get("subject") or {}).get("CN"),
                                  issuer=(cert.get("issuer") or {}).get("O") or
                                  (cert.get("issuer") or {}).get("CN"),
                                  not_before=(cert.get("validity") or {}).get("not_before"),
                                  san=(cert.get("extensions") or {}).get("subject_alternative_name"))
            self.g.add_edge(src, cid, "USES_CERT", seen_by=["VirusTotal"])
        jarm = attrs.get("jarm")
        if jarm and set(jarm) != {"0"}:
            jid = self.g.add_node(g.JARM, jarm)
            self.g.add_edge(src, jid, "HAS_JARM", seen_by=["VirusTotal"])
            if self.cfg.vt_intel:
                self._vt_intel_pivot(jid, f"entity:domain jarm:{jarm}", "jarm")
            self.hunt_queries.append({"platform": "Shodan", "query": f"ssl.jarm:{jarm}"})

    def _vt_intel_pivot(self, pivot_id: str, query: str, kind: str) -> None:
        objs = self.vt.intel_search(query, self.cfg.limit)
        self.pivots.append({"source": "VT Intelligence", "kind": kind, "query": query,
                            "total": len(objs), "broad": False})
        self.g.set_prop(pivot_id, vt_query=query, vt_intel_hits=len(objs))
        for obj in objs:
            self._vt_object_node(obj, self.cfg.depth, pivot_id, "MATCHES", reverse=True,
                                 edge_props={"source": "VT Intelligence", "query": query})

    # --------------------------------------------------------------- VT types
    def _vt_file(self, h: str, depth: int) -> None:
        if not self.vt:
            return
        obj = self.vt.obj("files", h)
        if not obj:
            log.info("  VT: file not found")
            return
        a = obj.get("attributes", {})
        sha = a.get("sha256", h)
        src = g.node_id(g.FILE, h)
        if sha != h:  # seeded by md5/sha1: normalise onto the sha256 node
            self.g.set_prop(src, sha256=sha)
            src = self.g.add_node(g.FILE, sha)
            self.g.add_edge(g.node_id(g.FILE, h), src, "SAME_AS")
        pe = a.get("pe_info") or {}
        self.g.add_node(g.FILE, sha, md5=a.get("md5"), sha1=a.get("sha1"),
                        name=a.get("meaningful_name"), names=(a.get("names") or [])[:10],
                        file_type=a.get("type_description"), size=a.get("size"),
                        imphash=pe.get("imphash"), vhash=a.get("vhash"), ssdeep=a.get("ssdeep"),
                        tlsh=a.get("tlsh"), tags=a.get("tags"), label=_threat_label(a),
                        first_seen=a.get("first_submission_date"), **self._stats(a))
        self._vt_attrib(g.FILE, sha, a)
        label = _threat_label(a)
        if label:
            lid = self.g.add_node(g.LABEL, label)
            self.g.add_edge(src, lid, "LABELLED")
        if self.cfg.vt_intel:
            if pe.get("imphash"):
                pid = self.g.add_node(g.INTEL, f"imphash:{pe['imphash']}", kind="imphash")
                self.g.add_edge(src, pid, "HAS_IMPHASH")
                self._vt_intel_pivot(pid, f"imphash:{pe['imphash']}", "imphash")
            if a.get("vhash"):
                pid = self.g.add_node(g.INTEL, f"vhash:{a['vhash']}", kind="vhash")
                self.g.add_edge(src, pid, "HAS_VHASH")
                self._vt_intel_pivot(pid, f'vhash:"{a["vhash"]}"', "vhash")
        for k, q in (("imphash", f"imphash:{pe.get('imphash')}"),
                     ("vhash", f'vhash:"{a.get("vhash")}"')):
            if (pe if k == "imphash" else a).get(k):
                self.hunt_queries.append({"platform": "VT Intelligence", "query": q})
        self._vt_rels("files", sha, src, VT_FILE_RELS, depth)

    def _vt_domain(self, d: str, depth: int) -> None:
        if not self.vt:
            return
        src = g.node_id(g.DOMAIN, d)
        obj = self.vt.obj("domains", d)
        if obj:
            a = obj.get("attributes", {})
            self.g.add_node(g.DOMAIN, d, registrar=a.get("registrar"),
                            created=a.get("creation_date"), tld=a.get("tld"),
                            categories=sorted(set((a.get("categories") or {}).values())),
                            tags=a.get("tags"), **self._stats(a))
            self._vt_infra(src, a)
            self._vt_attrib(g.DOMAIN, d, a)
        if depth <= self.cfg.vt_history_depth:
            self._vt_history("domains", d, src)
        apex = apex_of(d)
        if apex != d and not is_ip(d):
            self._discover(g.DOMAIN, apex, depth + 1, src, "HAS_SUBDOMAIN", reverse=True)
        self._vt_rels("domains", d, src, VT_DOMAIN_RELS, depth)

    def _vt_ip(self, ip: str, depth: int) -> None:
        if not self.vt:
            return
        src = g.node_id(g.IP, ip)
        obj = self.vt.obj("ip_addresses", ip)
        if obj:
            a = obj.get("attributes", {})
            self.g.add_node(g.IP, ip, asn=a.get("asn"), as_owner=a.get("as_owner"),
                            country=a.get("country"), network=a.get("network"),
                            tags=a.get("tags"), **self._stats(a))
            if a.get("asn"):
                aid = self.g.add_node(g.ASN, f"AS{a['asn']}", owner=a.get("as_owner"))
                self.g.add_edge(src, aid, "IN_ASN")
            self._vt_infra(src, a)
            self._vt_attrib(g.IP, ip, a)
        if depth <= self.cfg.vt_history_depth:
            self._vt_history("ip_addresses", ip, src)
        self._vt_rels("ip_addresses", ip, src, VT_IP_RELS, depth)

    def _vt_history(self, collection: str, oid: str, src: str) -> None:
        """Historical certificates and WHOIS records -> change timeline."""
        for c in self.vt.related(collection, oid, "historical_ssl_certificates", 20):
            a = c.get("attributes", {})
            v = a.get("validity") or {}
            when = v.get("not_before")
            # issuer CN matches urlscan's tlsIssuer, so the same cert gets the same label
            self._observe(src, when, "VT certificate",
                          cert=_cert_label((a.get("issuer") or {}).get("CN") or
                                           (a.get("issuer") or {}).get("O"), v.get("not_before")),
                          cert_sha256=a.get("thumbprint_sha256"))
        if collection != "domains":
            return
        for w in self.vt.related(collection, oid, "historical_whois", 20):
            a = w.get("attributes", {})
            wm = a.get("whois_map") or {}
            ns = wm.get("Name Server") or wm.get("Name server") or wm.get("nserver")
            if isinstance(ns, str):
                ns = [x for x in ns.replace("|", " ").split() if "." in x]
            self._observe(src, a.get("first_seen_date") or a.get("last_updated"), "VT whois",
                          registrar=a.get("registrar_name") or wm.get("Registrar"),
                          nameservers=" ".join(sorted(x.lower().rstrip(".") for x in ns)) if ns else None)

    def _vt_url(self, url: str, depth: int) -> None:
        src = g.node_id(g.URL, url)
        host = host_of(url)
        if host:
            self._discover(g.IP if is_ip(host) else g.DOMAIN, host, depth, src, "HOSTED_ON")
        if not self.vt:
            return
        uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        obj = self.vt.obj("urls", uid)
        if obj:
            a = obj.get("attributes", {})
            self.g.add_node(g.URL, url, title=a.get("title"),
                            final_url=a.get("last_final_url"), **self._stats(a))
        for rel in ("downloaded_files", "last_serving_ip_address", "redirecting_urls"):
            for o in self.vt.related("urls", uid, rel, self.cfg.limit):
                self._vt_object_node(o, depth + 1, src,
                                     {"downloaded_files": "SERVES",
                                      "last_serving_ip_address": "SERVED_FROM",
                                      "redirecting_urls": "REDIRECTS_TO"}[rel])

    # ------------------------------------------------------------- urlscan
    def _us_file(self, h: str, depth: int) -> None:
        if not self.us or len(h) != 64:
            sha = self.g.nodes.get(g.node_id(g.FILE, h), {}).get("props", {}).get("sha256")
            if not self.us or not sha:
                return
            h = sha
        src = g.node_id(g.FILE, h)
        total, results = self.us.search(f"hash:{h}", self.cfg.limit)
        self.pivots.append({"source": "urlscan", "kind": "file hash", "query": f"hash:{h}",
                            "total": total, "broad": total > self.cfg.broad})
        log.info(escape(f"  urlscan hash:{h[:12]}… -> {total}"))
        for r in results:
            page = r.get("page", {})
            if page.get("domain"):
                self._discover(g.DOMAIN, page["domain"], depth + 1, src, "SERVED_BY",
                               edge_props={"source": "urlscan", "query": f"hash:{h}"})

    def _us_host(self, host: str, depth: int, is_ip_: bool) -> None:
        if not self.us:
            return
        ntype = g.IP if is_ip_ else g.DOMAIN
        src = g.node_id(ntype, host)
        q = f'page.ip:"{host}"' if is_ip_ else f"page.domain:{es_escape(host)}"
        total, history = self.us.search(q, max(self.cfg.limit, self.cfg.scans, self.cfg.history))
        results = history[: max(self.cfg.limit, self.cfg.scans)]
        log.info(escape(f"  urlscan {q} -> {total}"))
        for r in history:
            page, task = r.get("page", {}), r.get("task", {})
            self._observe(src, task.get("time"), "urlscan", scan=task.get("uuid"), url=page.get("url"),
                          ip=None if is_ip_ else page.get("ip"),
                          domain=page.get("domain") if is_ip_ else None,
                          asn=" ".join(x for x in (page.get("asn"), page.get("asnname")) if x) or None,
                          title=page.get("title"),
                          # a scan with no IP/status means the site didn't answer at that time
                          status=page.get("status") or (None if page.get("ip") else "no response"),
                          server=page.get("server"),
                          cert=_cert_label(page.get("tlsIssuer"), page.get("tlsValidFrom")))
        self.g.set_prop(src, urlscan_scans=total)
        self.pivots.append({"source": "urlscan", "kind": "host scans", "query": q,
                            "total": total, "broad": False})

        if is_ip_:
            # IP pivots to all hostnames urlscan saw on it (guarded against shared hosting)
            if total > self.cfg.broad:
                # CDN / shared hosting: other sites on this IP are almost certainly unrelated
                self.g.set_prop(src, shared_hosting=True)
                log.info("  shared hosting IP — skipping urlscan co-hosted pivots")
                return
            for r in results[: self.cfg.limit]:
                d = r.get("page", {}).get("domain")
                if d and total <= self.cfg.broad:
                    self._discover(g.DOMAIN, d, depth + 1, src, "RESOLVES_TO", reverse=True,
                                   edge_props={"source": "urlscan", "query": q})
        else:
            # Sites that load resources from this domain (e.g. injected JS / C2 panels)
            q2 = f"domain:{es_escape(host)} AND NOT page.domain:{es_escape(host)}"
            t2, emb = self.us.search(q2, self.cfg.limit)
            self.pivots.append({"source": "urlscan", "kind": "embedded by", "query": q2,
                                "total": t2, "broad": t2 > self.cfg.broad})
            if t2 and t2 <= self.cfg.broad:
                for r in emb:
                    d = r.get("page", {}).get("domain")
                    if d:
                        self._discover(g.DOMAIN, d, depth + 1, src, "LOADS_FROM", reverse=True,
                                       edge_props={"source": "urlscan", "query": q2})
            for desc, pq in domain_patterns(host):
                pid = self.g.add_node(g.PATTERN, pq, kind=desc)
                self.g.add_edge(src, pid, "MATCHES_PATTERN")
                self._urlscan_pivot(pid, pq, f"domain pattern ({desc})", depth + 1,
                                    ctx=(results[0].get("page") if results else None))

        for r in results:
            self._us_search_hit(src, r, depth)
        for r in results[: self.cfg.scans]:
            uuid = r.get("task", {}).get("uuid")
            if uuid:
                self._us_full_result(src, uuid, depth)

    def _us_search_hit(self, src: str, r: dict, depth: int) -> None:
        page, task = r.get("page", {}), r.get("task", {})
        if page.get("ip") and src.startswith(g.DOMAIN + ":"):
            self._discover(g.IP, page["ip"], depth + 1, src, "RESOLVES_TO",
                           edge_props={"source": "urlscan", "date": task.get("time")},
                           asn=page.get("asn"), country=page.get("country"))
        if page.get("asn") and page.get("ip"):
            aid = self.g.add_node(g.ASN, page["asn"], owner=page.get("asnname"))
            self.g.add_edge(g.node_id(g.IP, page["ip"]), aid, "IN_ASN")
        if page.get("url"):
            self.g.add_node(g.URL, page["url"], title=page.get("title"),
                            status=page.get("status"))
            self.g.add_edge(src, g.node_id(g.URL, page["url"]), "HAS_URL",
                            source="urlscan")
        # redirect chains: submitted URL on another domain landing here
        tdom = task.get("domain")
        if tdom and page.get("domain") and tdom != page["domain"]:
            a = self.g.add_node(g.DOMAIN, tdom)
            b = self.g.add_node(g.DOMAIN, page["domain"])
            self.g.add_edge(a, b, "REDIRECTS_TO")
        title = page.get("title")
        if title and not title_is_generic(title):
            tid = self.g.add_node(g.TITLE, title)
            self.g.add_edge(src, tid, "HAS_TITLE")
            safe = title.replace("\\", "\\\\").replace('"', '\\"')
            self._urlscan_pivot(tid, f'page.title:"{safe}"', "title", depth + 1, ctx=page)

    def _us_full_result(self, src: str, uuid: str, depth: int) -> None:
        res = self.us.result(uuid)
        if not res:
            return
        page = res.get("page", {})
        page_host = (page.get("domain") or "").lower()

        # --- URL path pattern pivot
        pp = url_path_pattern(page.get("url") or res.get("task", {}).get("url", ""))
        if pp:
            pid = self.g.add_node(g.PATTERN, pp[1], kind="url path", path=pp[0])
            self.g.add_edge(src, pid, "MATCHES_PATTERN")
            self._urlscan_pivot(pid, pp[1], "url path", depth + 1, ctx={**page, "path": pp[0]})

        # --- resources: favicon, main HTML document, first-party scripts
        scripts = 0
        for req in res.get("data", {}).get("requests", []):
            resp = req.get("response") or {}
            sha = resp.get("hash")
            url = ((req.get("request") or {}).get("request") or {}).get("url", "")
            if not sha or not url:
                continue
            mime = ((resp.get("response") or {}).get("mimeType") or "").lower()
            rtype = resp.get("type") or req.get("request", {}).get("type")
            rhost = host_of(url)
            path = urlsplit(url).path.lower()
            if "favicon" in path or "icon" in mime and ("icon" in path or path.endswith(".ico")):
                fid = self.g.add_node(g.FAVICON, sha, url=url, mime=mime)
                self.g.add_edge(src, fid, "HAS_FAVICON")
                self._favicon_hashes(fid, sha)
                self._urlscan_pivot(fid, f"hash:{sha}", "favicon", depth + 1, ctx=page)
            elif rtype == "Document" and rhost == page_host and resp.get("size", 1) > 0:
                hid = self.g.add_node(g.HTML_HASH, sha, url=url, size=resp.get("size"))
                self.g.add_edge(src, hid, "SERVES_HTML")
                self._urlscan_pivot(hid, f"hash:{sha}", "html body", depth + 1, ctx=page)
            elif (rtype == "Script" and scripts < 3 and page_host
                  and apex_of(rhost) == apex_of(page_host)):
                scripts += 1
                jid = self.g.add_node(g.SCRIPT, sha, url=url)
                self.g.add_edge(src, jid, "SERVES_SCRIPT")
                self._urlscan_pivot(jid, f"hash:{sha}", "first-party script", depth + 1, ctx=page)

        for c in (res.get("lists", {}).get("certificates") or [])[:3]:
            if c.get("subjectName") and apex_of(c["subjectName"].lstrip("*.")) == apex_of(page_host):
                cid = self.g.add_node(g.CERT, f"{c['subjectName']}|{c.get('validFrom')}",
                                      subject_cn=c["subjectName"], issuer=c.get("issuer"),
                                      not_before=c.get("validFrom"))
                self.g.add_edge(src, cid, "USES_CERT", seen_by=["urlscan"])

    # ------------------------------------------------------------ certificates
    def _vt_cert(self, hosts: list[str], sha: str) -> dict:
        """The VT record of a certificate, via a host that served it (current or historical)."""
        for h in hosts:
            hn = self.g.nodes[h]
            coll = "ip_addresses" if hn["type"] == g.IP else "domains"
            cur = ((self.vt.obj(coll, hn["value"]) or {}).get("attributes") or {}).get("last_https_certificate") or {}
            certs = [cur] if cur.get("thumbprint_sha256") == sha else [
                c.get("attributes", {}) for c in self.vt.related(coll, hn["value"], "historical_ssl_certificates", 40)]
            for c in certs:
                if c.get("thumbprint_sha256") == sha:
                    return c
        return {}

    def _cert(self, value: str, depth: int) -> None:
        """Certificate pivot: every name on it (SAN), the CT history of its domain, and
        hunt queries for other servers presenting it."""
        cid = g.node_id(g.CERT, value)
        p = self.g.nodes[cid]["props"]
        hosts = [s for (s, d, rel) in self.g.edges
                 if d == cid and rel == "USES_CERT" and self.g.nodes[s]["type"] in (g.DOMAIN, g.IP)]
        cn = (p.get("subject_cn") or value.split("|")[0]).lstrip("*.").lower()
        sha = value.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", value) else p.get("sha256")
        names = {n.lower() for n in p.get("san") or []}
        info: dict = {}
        srcs = []
        if self.vt and sha:
            vc = self._vt_cert(hosts, sha)
            if vc:
                srcs.append("VT")
                v = vc.get("validity") or {}
                names |= {n.lower() for n in (vc.get("extensions") or {}).get("subject_alternative_name") or []}
                info.update(serial=vc.get("serial_number"), sha1=vc.get("thumbprint"),
                            not_after=v.get("not_after"), subject_cn=(vc.get("subject") or {}).get("CN"))
        issued = []
        apex = apex_of(cn) if cn and not is_ip(cn) else None
        if self.ct and apex:
            issued = self.ct.issuances(apex)
            m = self.ct.match(issued, sha, info.get("serial"), cn, p.get("not_before"))
            if m:
                srcs.append(m["source"])
                names |= {n.lower() for n in m["names"]}
                sha = sha or m.get("sha256")
                info.update({k: m.get(k) for k in ("pubkey_sha256", "crtsh_id") if m.get(k)})
                if not info.get("not_after") and m.get("not_after"):
                    info["not_after"] = datetime.fromtimestamp(m["not_after"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        names = sorted({n.lstrip("*.") for n in names if n.lstrip("*.")} or ({cn} if cn else set()))
        apexes = {apex_of(n) for n in names if not is_ip(n)}
        shared = len(apexes) > self.cfg.pdns_broad   # CDN / hosting-provider cert: names are strangers
        self.g.set_prop(cid, **{k: v for k, v in dict(info, san=names, san_count=len(names), sha256=sha).items() if v})
        p.pop("broad", None)
        if shared:
            self.g.set_prop(cid, broad=True, shared_cert=len(apexes))
        self.pivots.append({"source": " + ".join(srcs) or "certificate", "kind": "certificate SAN",
                            "query": sha or value, "total": len(names), "broad": shared,
                            "decision": f"shared certificate ({len(apexes)} domains): names not expanded" if shared else None})
        log.info(escape(f"  certificate {cn}: {len(names)} names on it ({', '.join(srcs) or 'no lookup'})"
                        + (f" — shared by {len(apexes)} domains, not expanded" if shared else "")))

        # same certificate seen twice (VT thumbprint + urlscan subject|date): tie the two nodes
        keys = {k: p.get(k) for k in ("sha256", "serial", "crtsh_id") if p.get(k)}
        for oid, o in self.g.nodes.items():
            if oid != cid and o["type"] == g.CERT and (
                    oid == g.node_id(g.CERT, sha or "-") or any(o["props"].get(k) == v for k, v in keys.items())):
                self.g.add_edge(cid, oid, "SAME_AS")
        known = {self.g.nodes[h]["value"] for h in hosts}
        if not shared:
            for n in names[: self.cfg.limit * 5]:
                if n not in known and not is_ip(n):
                    self._discover(g.DOMAIN, n, depth, cid, "NAMED_IN_CERT", reverse=True,
                                   edge_props={"source": " + ".join(srcs)})

        # CT history of the domain: other names it got certificates for, and when
        subs = []
        for c in issued:
            for n in c["names"]:
                n = n.lower().lstrip("*.")
                if n and apex_of(n) == apex and n not in names and n not in known and n not in subs:
                    subs.append(n)
            iso = datetime.fromtimestamp(c["not_before"], timezone.utc).strftime("%Y-%m-%d") if c["not_before"] else None
            for n in {x.lower().lstrip("*.") for x in c["names"]}:
                hid = g.node_id(g.DOMAIN, n)
                if hid in self.g.nodes:
                    self._observe(hid, c["not_before"], f"CT ({c['source']})",
                                  cert=_cert_label(c.get("issuer"), iso), cert_sha256=c.get("sha256"))
        if issued:
            parent = g.node_id(g.DOMAIN, apex)
            if parent not in self.g.nodes:
                parent = next((h for h in hosts if self.g.nodes[h]["type"] == g.DOMAIN), None)
            if parent:
                for n in subs[: self.cfg.limit * 2]:
                    self._discover(g.DOMAIN, n, depth, parent, "HAS_SUBDOMAIN",
                                   edge_props={"source": "certificate transparency"})
            if not any(x["kind"] == "certificate history" and x["query"] == apex for x in self.pivots):
                self.pivots.append({"source": "CT", "kind": "certificate history", "query": apex,
                                    "total": len(issued), "broad": False})
            log.info(escape(f"  CT {apex}: {len(issued)} certificates, {len(subs)} other names"))

        # other servers presenting it / the same key: internet-scan platforms
        if sha:
            self.hunt_queries.append({"platform": "Censys",
                                      "query": f"services.tls.certificates.leaf_data.fingerprint: {sha}"})
        if info.get("sha1"):
            self.hunt_queries.append({"platform": "Shodan", "query": f"ssl.cert.fingerprint:{info['sha1']}"})
        if info.get("pubkey_sha256"):   # key reuse across certificates = same operator
            self.hunt_queries.append({"platform": "crt.sh (same key)",
                                      "query": f"https://crt.sh/?spkisha256={info['pubkey_sha256']}"})

    def _favicon_hashes(self, fid: str, sha: str) -> None:
        if mmh3 is None:
            return
        body = self.us.response_body(sha)
        if not body:
            return
        h = mmh3.hash(codecs.encode(body, "base64"))
        self.g.set_prop(fid, shodan_mmh3=h)
        self.hunt_queries += [{"platform": "Shodan", "query": f"http.favicon.hash:{h}"},
                              {"platform": "FOFA", "query": f'icon_hash="{h}"'}]

    def _urlscan_pivot(self, pivot_id: str, query: str, kind: str, depth: int, ctx: dict | None = None,
                       refined_from: str | None = None, decision: str | None = None) -> None:
        """Run a urlscan search for a pivot node; attach results unless it's too broad.

        Too broad and ``ctx`` (the scan the pivot came from) given: tighten it step by step and
        pivot on the first version specific enough to expand (see _refine)."""
        if any(p["query"] == query for p in self.pivots):
            return
        total, results = self.us.search(query, 100)
        if total > self.cfg.broad and ctx is not None and self.cfg.refine:
            self.pivots.append({"source": "urlscan", "kind": kind, "query": query, "total": total,
                                "broad": True, "decision": "too broad: refining", "refined_from": refined_from})
            self.g.set_prop(pivot_id, urlscan_query=query, urlscan_hits=total, broad=True)
            log.info(escape(f"  pivot [{kind}] {query[:90]} -> {total} (too broad, refining)"))
            self._sample(pivot_id, results)
            found = self._refine(query, kind, total, results, ctx)
            if found:
                rid = self.g.add_node(g.PATTERN, found["query"], kind=f"{kind} (refined)",
                                      refined_from=query, refine_steps=found["steps"])
                self.g.add_edge(pivot_id, rid, "REFINED_TO")
                for (s, d, rel) in list(self.g.edges):   # the refined pivot hangs off the same hosts
                    if d == pivot_id and rel in ORIGIN_RELS:
                        self.g.add_edge(s, rid, "MATCHES_PATTERN")
                self._urlscan_pivot(rid, found["query"], f"{kind} (refined)", depth, refined_from=query,
                                    decision=found["label"] + (": good pivot" if found["total"] <= self.cfg.broad
                                                               else ": closest, sample only"))
            return
        is_pattern = kind.startswith(("domain pattern", "url path", "custom"))
        # Patterns naturally match many scans of few campaign hosts: attach the sample hits
        # up to a higher threshold, but only *expand* them when under the normal one.
        attach = total <= (self.cfg.broad_pattern if is_pattern else self.cfg.broad)
        expand = total <= self.cfg.broad
        broad = not attach
        self.pivots.append({"source": "urlscan", "kind": kind, "query": query, "total": total, "broad": broad,
                            "refined_from": refined_from, "decision": decision})
        self.g.set_prop(pivot_id, urlscan_query=query, urlscan_hits=total, broad=broad)
        note = " (too broad, skipped)" if broad else ("" if expand else " (sample attached, not expanded)")
        log.info(escape(f"  pivot [{kind}] {query[:90]} -> {total}{note}"))
        domains = self._sample(pivot_id, results)
        if broad:   # keep a sample for the analyst, but don't grow the graph
            return
        for d, r in list(domains.items())[: self.cfg.limit * (2 if is_pattern else 1)]:
            page = r.get("page", {})
            self._discover(g.DOMAIN, d, depth if expand else self.cfg.depth, pivot_id, "SEEN_ON",
                           edge_props={"source": "urlscan", "query": query,
                                       "date": r.get("task", {}).get("time")},
                           urlscan_title=page.get("title"), urlscan_ip=page.get("ip"))

    def _sample(self, pivot_id: str, results: list[dict]) -> dict[str, dict]:
        """First scan per domain in a search result; recorded on the pivot node."""
        domains: dict[str, dict] = {}
        for r in results:
            d = (r.get("page") or {}).get("domain")
            if d and d not in domains:
                domains[d] = r
        self.g.set_prop(pivot_id, distinct_domains_in_sample=len(domains), sample_domains=list(domains)[:10])
        return domains

    def _refine(self, query: str, kind: str, total: int, results: list[dict], ctx: dict) -> dict | None:
        """pivot -> result -> decision -> tune -> pivot again, until the query is specific enough.

        Each round tries candidate tweaks, most natural first: a longer URL path / its query keys,
        dropping the domain that swamps the sample, then conditions taken from the scan the pivot
        came from (recent only, same title / server / ASN / country). A tweak that removes at
        least 20 % of the hits is kept and the next round builds on it; one that gives 0 hits went
        too far and one that barely helps isn't worth the specificity: both are dropped.
        """
        url = UrlWindow(ctx["url"], ctx["path"]) if kind == "url path" and ctx.get("url") and ctx.get("path") else None
        url = url if url and url.ok else None
        conds: list[tuple[str, str]] = [("last 90 days", "date:>now-90d")]
        title = ctx.get("title")
        if title and kind != "title" and not title_is_generic(title):
            conds.append((f"title {title[:30]!r}", 'page.title:"' + title.replace("\\", "\\\\").replace('"', '\\"') + '"'))
        for field, label in (("server", "server"), ("asn", "ASN"), ("country", "country")):
            if ctx.get(field):
                conds.append((f"{label} {ctx[field]}", f'page.{field}:"{ctx[field]}"'))
        own = apex_of(ctx.get("domain") or "")
        base, used, excluded = query, [], []
        steps, tried, first, best = [], {query}, total, None

        def build(b, us, ex):
            q = b if not (us or ex) else f"({b})"
            return " AND ".join([q] + [c for _, c in us] + [f"NOT page.apexDomain:{es_escape(d)}" for d in ex])

        while self.refine_calls < self.cfg.refine_budget and len(steps) < self.cfg.refine:
            cands: list[tuple[str, str, object, list, list]] = []   # (label, query, url, used, excluded)
            for label, w in (url.steps() if url else []):
                cands.append((label, build(w.query(), used, excluded), w, used, excluded))
            apexes = [apex_of((r.get("page") or {}).get("domain") or "") for r in results]
            top = max(set(apexes), key=apexes.count) if apexes else ""
            if top and top != own and len(excluded) < 2 and apexes.count(top) >= 0.3 * len(apexes):
                cands.append((f"exclude {top} ({apexes.count(top)}/{len(apexes)} of sample)",
                              build(base, used, excluded + [top]), url, used, excluded + [top]))
            for c in conds:
                if c not in used:
                    cands.append((f"+ {c[0]}", build(base, used + [c], excluded), url, used + [c], excluded))
            moved = False
            for label, q, w, us, ex in cands:
                if q in tried or self.refine_calls >= self.cfg.refine_budget or len(steps) >= self.cfg.refine:
                    continue
                tried.add(q)
                self.refine_calls += 1
                t, res = self.us.search(q, 100)
                if t == 0:
                    decision = "0 hits: too specific, step dropped"
                elif t <= self.cfg.broad:
                    decision = "good pivot"
                elif t <= total * 0.8:
                    decision = "fewer hits: kept, refining further"
                else:
                    decision = "barely narrower: step dropped"
                steps.append(f"{label}: {total} -> {t} ({decision})")
                log.info(escape(f"    refine {len(steps)} [{label}] -> {t}: {decision}"))
                if decision == "good pivot":   # recorded when the caller runs it
                    return {"query": q, "total": t, "steps": steps, "label": label}
                self.pivots.append({"source": "urlscan", "kind": f"{kind} (refine step)", "query": q, "total": t,
                                    "broad": t > self.cfg.broad or t == 0, "decision": f"{label}: {decision}",
                                    "refined_from": query})
                if decision.startswith("fewer"):
                    best = {"query": q, "total": t, "steps": steps, "label": label}
                    url = w if isinstance(w, UrlWindow) else url
                    base = w.query() if isinstance(w, UrlWindow) else base
                    used, excluded, total, results, moved = us, ex, t, res, True
                    break
            if not moved:
                break
        log.info(escape(f"    no specific-enough pivot after {len(steps)} step(s); best {total} hits"
                        + (" (sample attached)" if best and total <= self.cfg.broad_pattern else "")))
        if best and total <= self.cfg.broad_pattern and total < first:
            # still too broad to expand, but far tighter than where we started: keep it as a sample
            self.pivots = [p for p in self.pivots if p["query"] != best["query"]]
            best["label"] += " (best reached)"
            return best
        return None

    # ----------------------------------------------------------- passive DNS
    def _pdns_domain(self, d: str, depth: int) -> None:
        """Resolution history + NS / MX / SOA of a domain; non-commodity DNS infra is pivoted on."""
        if not self.pdns:
            return
        src = g.node_id(g.DOMAIN, d)
        recs = self.pdns.lookup(d) + self.pdns.current(d)
        own = [r for r in recs if r["rrname"] == d]
        self.dns_history[src] = sorted(own, key=lambda r: (r["rrtype"], -r["last"]))
        log.info(escape(f"  pDNS {d}: {len(own)} records"))
        nss, mxs = {}, {}
        for r in recs:
            rt, win = r["rrtype"], {"source": r["source"], "first_seen": r["first"],
                                    "last_seen": r["last"]}
            if r["rrname"] == d:
                if rt in ("a", "aaaa") and r["rdata"]:
                    self._discover(g.IP, r["rdata"], depth + 1, src, "RESOLVES_TO", edge_props=win)
                    for t in {r["first"], r["last"]}:
                        self._observe(src, t, r["source"], ip=r["rdata"])
                elif rt == "cname":
                    self._discover(g.DOMAIN, r["rdata"], depth + 1, src, "CNAME_TO", edge_props=win)
                elif rt == "ns":
                    nss.setdefault(r["rdata"], win)
                elif rt == "mx":
                    mxs.setdefault(r["rdata"], win)
                elif rt == "soa":
                    mname, email = soa_parts(r["rdata"])
                    if mname and not is_commodity(mname):
                        nss.setdefault(mname, win)
                    if email and not any(x in email for x in ("hostmaster@", "dns@", "admin@dns")) \
                            and not is_commodity(email.split("@")[-1]):
                        sid = self.g.add_node(g.SOA, email)
                        self.g.add_edge(src, sid, "SOA_CONTACT", **win)
            elif r["rdata"] == d and rt == "cname":   # someone else points at this domain
                self._discover(g.DOMAIN, r["rrname"], depth + 1, src, "CNAME_TO", True, win)
            elif rt == "ns" and (r["rdata"] == d or r["rdata"].endswith("." + d)):
                # this domain *is* a nameserver zone: whoever delegates to it shares the operator
                nid = self.g.add_node(g.NS, r["rdata"])
                self.g.add_edge(src, nid, "HOSTS_NS")
                self._discover(g.DOMAIN, r["rrname"], depth + 1, nid, "USES_NS", True, win)
        for host, win in nss.items():
            self._dns_infra_pivot(src, host, g.NS, "ns", "USES_NS", win, depth)
            self._observe(src, win["first_seen"], win["source"], nameservers=host)
        for host, win in mxs.items():
            self._dns_infra_pivot(src, host, g.MX, "mx", "USES_MX", win, depth)
        if depth == 0:
            # co-hosting is the core overlap question, so reverse-resolve the seed's IPs even at
            # --depth 1 (cheap: one pDNS call each, no VT / urlscan quota)
            # (VT / urlscan ran first, so IPs they saw — e.g. of a now-dead domain — are included)
            ips = {r["rdata"] for r in own if r["rrtype"] in ("a", "aaaa")}
            ips |= {self.g.nodes[d]["value"] for (s, d, rel) in self.g.edges
                    if s == src and rel == "RESOLVES_TO" and self.g.nodes[d]["type"] == g.IP}
            for ip in sorted(ips)[:10]:
                self._pdns_ip(ip, depth + 1)

    def _dns_infra_pivot(self, src: str, host: str, ntype: str, rrtype: str, rel: str,
                         win: dict, depth: int) -> None:
        """Reverse pDNS on a nameserver / mail server: which other domains delegate to it."""
        commodity = is_commodity(host)
        nid = self.g.add_node(ntype, host, commodity=commodity or None)
        self.g.add_edge(src, nid, rel, **win)
        if commodity or any(p["query"] == host and p["source"] == "pDNS" for p in self.pivots):
            return
        users: dict[str, dict] = {}
        for r in self.pdns.lookup(host):
            if r["rrtype"] == rrtype and r["rdata"] == host and r["rrname"] != host:
                users.setdefault(r["rrname"], {"source": r["source"], "first_seen": r["first"],
                                               "last_seen": r["last"]})
        broad = len(users) > self.cfg.ns_broad
        kind = "nameserver" if ntype == g.NS else "mail server"
        self.pivots.append({"source": "pDNS", "kind": f"{kind} users", "query": host,
                            "total": len(users), "broad": broad})
        self.g.set_prop(nid, pdns_domains=len(users), broad=broad or None)
        log.info(escape(f"  pDNS {kind} {host} -> {len(users)} domains"
                        + (" (too broad, skipped)" if broad else "")))
        # a self-hosted nameserver's own zone (ns1.evil-dns.net -> evil-dns.net) is actor infra
        zone = apex_of(host)
        if ntype == g.NS and zone != apex_of(self.g.nodes[src]["value"]):
            self._discover(g.DOMAIN, zone, depth + 1, nid, "HOSTS_NS", reverse=True)
        if broad:
            self.g.set_prop(nid, sample_domains=sorted(users)[:10])
            return
        recent = sorted(users.items(), key=lambda kv: -kv[1]["last_seen"])
        for u, uwin in recent[: self.cfg.limit * 2]:
            self._discover(g.DOMAIN, u, depth + 1, nid, rel, reverse=True, edge_props=uwin)

    def _pdns_ip(self, ip: str, depth: int) -> None:
        """Reverse pDNS: every domain that resolved to this IP, with when it did."""
        if not self.pdns or any(p["query"] == ip and p["source"] == "pDNS" for p in self.pivots):
            return
        src = g.node_id(g.IP, ip)
        doms: dict[str, dict] = {}
        for r in self.pdns.lookup(ip):
            if r["rrtype"] in ("a", "aaaa") and r["rdata"] == ip.lower() and r["rrname"]:
                cur = doms.setdefault(r["rrname"], {"source": r["source"], "first_seen": r["first"],
                                                    "last_seen": r["last"]})
                cur["first_seen"] = min(cur["first_seen"] or r["first"], r["first"] or cur["first_seen"])
                cur["last_seen"] = max(cur["last_seen"], r["last"])
        total = len(doms)
        shared = total > self.cfg.pdns_broad
        self.pivots.append({"source": "pDNS", "kind": "IP co-hosting", "query": ip,
                            "total": total, "broad": shared})
        self.g.set_prop(src, pdns_domains=total)
        log.info(escape(f"  pDNS {ip} -> {total} domains" + (" (shared hosting, skipped)" if shared else "")))
        if shared:
            self.g.set_prop(src, shared_hosting=True, sample_domains=sorted(doms)[:10])
            return
        for d, win in sorted(doms.items(), key=lambda kv: -kv[1]["last_seen"])[: self.cfg.limit * 2]:
            self._discover(g.DOMAIN, d, depth + 1, src, "RESOLVES_TO", reverse=True, edge_props=win)
            self._observe(src, win["first_seen"], win["source"], domain=d)


def _in_view(n: dict) -> bool:
    return n["props"].get("cluster") is True or bool(n["props"].get("pinned"))


def _vt_id(ntype: str, value: str) -> tuple[str, str]:
    """(VT collection, object id) of an IOC node."""
    if ntype == g.URL:
        return "urls", base64.urlsafe_b64encode(value.encode()).decode().strip("=")
    return {g.FILE: "files", g.DOMAIN: "domains", g.IP: "ip_addresses"}[ntype], value


def _cert_label(issuer: str | None, valid_from: str | None) -> str | None:
    if not (issuer or valid_from):
        return None
    parts = [issuer, f"valid from {str(valid_from)[:10]}" if valid_from else None]
    return " · ".join(p for p in parts if p)


def _threat_label(attrs: dict) -> str | None:
    ptc = attrs.get("popular_threat_classification") or {}
    return ptc.get("suggested_threat_label")
