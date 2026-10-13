#!/usr/bin/env python3
"""
InfraMapper — pivot a hash / IP / domain / URL through VirusTotal, urlscan.io and passive DNS
and build a relationship graph (interactive HTML, JSON, Markdown report).

  python infra-mapper.py evil-login-01.pages.dev    # investigate, then open the live pivot graph
  python infra-mapper.py evil-login-01.pages.dev --no-serve   # batch: write the case and exit
  python infra-mapper.py 45.9.148.12 --depth 2
  python infra-mapper.py <sha256> --vt-intel
  python infra-mapper.py --serve cases/<case>      # click-to-pivot graph on http://127.0.0.1:8765
  python infra-mapper.py --from report.pdf          # triage every IOC in a threat report
  python infra-mapper.py --from https://vendor.com/blog/new-campaign
  python infra-mapper.py 1.2.3.4 evil[.]com <sha256>   # several IOCs = report triage too
"""

import argparse
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Templates, reports and caches are UTF-8 and read / written without an explicit encoding. Windows
# defaults to its ANSI code page (cp1252), which can't hold → ▸ …: rerun this script in UTF-8 mode.
if os.name == "nt" and not sys.flags.utf8_mode and __name__ == "__main__":
    try:
        sys.exit(subprocess.call([sys.executable, "-X", "utf8", *sys.argv]))
    except KeyboardInterrupt:   # Ctrl+C reaches the child too; it does its own clean-up
        sys.exit(130)

from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")

from inframapper.clients import Cache, URLScan, VirusTotal  # noqa: E402
from inframapper.intel import PriorReporting, Warninglists  # noqa: E402
from inframapper.export import write_html, write_iocs_csv, write_json, write_report  # noqa: E402
from inframapper.feeds import Feeds  # noqa: E402
from inframapper.investigator import Config, Investigator  # noqa: E402
from inframapper.log import console, log  # noqa: E402
from inframapper.patterns import detect_type  # noqa: E402
from inframapper.pdns import PassiveDNS  # noqa: E402


def knowledge_cmd(args, kb, ap) -> int:
    """--mark / --reindex: knowledge base only, no API calls."""
    if not kb:
        ap.error("--mark / --reindex need the knowledge base (drop --no-kb)")
    from inframapper import graph as g
    if args.ingest:
        from inframapper.extract import load_tlds
        from inframapper.reports import SOURCES, Ingestor
        only = [x.strip() for x in args.sources.split(",")] if args.sources else None
        if only and (bad := set(only) - {s[0] for s in SOURCES}):
            ap.error(f"unknown source(s): {', '.join(sorted(bad))}; known: {', '.join(s[0] for s in SOURCES)}")
        ing = Ingestor(HERE / ".cache", kb, Warninglists(HERE / ".cache"), load_tlds(HERE / ".cache"),
                       HERE / "dataset", args.days)
        done = ing.run(only)
        st = kb.report_stats()
        log.info(f"[bold]ingest[/]: {len(done)} new reports ({sum(d['n_iocs'] for d in done)} IOCs, "
                 f"{sum(len(d['ttps']) for d in done)} technique mappings); dataset: {st['reports']} reports, "
                 f"{st['iocs']} IOCs -> {HERE / 'dataset' / 'bundle.json'}")
        return 0
    if args.search_reports or args.recent_reports:
        hits = kb.search_reports(args.search_reports) if args.search_reports else kb.recent_reports(args.recent_reports)
        for r in hits:
            day = datetime.fromtimestamp(r["published"] or 0).strftime("%Y-%m-%d")
            who = ", ".join(r["actors"] + r["families"])
            console.print(f"[bold]{day}[/] {r['source']}: {r['title']}\n    {r['url']}"
                          + (f"\n    {who}" if who else "")
                          + (f"\n    [dim]{r['summary'][:300]}[/]" if r.get("summary") else "") + f"\n    {r['n_iocs']} IOCs, "
                          f"{len(r['ttps'])} TTPs" + (f", {', '.join(r['cves'][:4])}" if r["cves"] else ""))
        console.print(f"{len(hits)} report(s)" + (f" for '{args.search_reports}'" if args.search_reports else
                                                  f" (most recently ingested; dataset: {kb.report_stats()['reports']})"))
        return 0
    if args.mark:
        if len(args.ioc) != 1:
            ap.error("--mark takes exactly one IOC")
        ioc_type, value = detect_type(args.ioc[0])
        ntype = {"file": g.FILE, "domain": g.DOMAIN, "ip": g.IP, "url": g.URL}[ioc_type]
        node = {"id": g.node_id(ntype, value), "type": ntype, "value": value}
        if args.mark == "clear":
            kb.clear_verdict(node["id"])
            log.info(f"verdict cleared: {ntype} {value}")
        else:
            kb.set_verdict(node, args.mark, args.actor, args.note, family=args.family)
            log.info(f"{ntype} {value}: {args.mark}" + (f", actor {args.actor}" if args.actor else "")
                     + (f", family {args.family}" if args.family else "")
                     + " (applied to every case; reopen a case with --serve to refresh it)")
        return 0
    from inframapper.export import case_attribution
    from inframapper.server import load_case
    done = 0
    for gj in sorted(args.out.glob("*/graph.json")):
        inv = Investigator(None, None, Config())
        try:
            load_case(inv, gj.parent)
        except Exception as exc:
            log.warning(f"skipped {gj.parent.name}: {exc}")
            continue
        inv.kb = kb
        if inv._articles_to_reports():   # older cases: report links that were taken for IOCs
            inv.recluster()
        n = kb.index_case(inv, gj.parent, case_attribution(inv))
        log.info(f"indexed {gj.parent.name}: {n} observables")
        done += 1
    log.info(f"knowledge base: {done} cases indexed ({kb.path})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ioc", nargs="*", help="hash (md5/sha1/sha256), IP, domain or URL (defanged OK); "
                                           "several = triage them all like a report")
    ap.add_argument("--from", dest="source", metavar="FILE|URL|-",
                    help="threat report to triage: .txt/.md/.csv/.html/.pdf file, a web page, or - for stdin. "
                         "Every IOC is extracted (defanged or not), noise dropped, then checked against "
                         "feeds / prior reporting / VT / live DNS")
    ap.add_argument("--batch-vt", type=int, default=50,
                    help="report triage: VT verdict lookups at most (default 50; 4/min on a free key)")
    ap.add_argument("--tlp", default="amber", choices=["clear", "white", "green", "amber", "red"],
                    help="TLP marking on the STIX 2.1 export (default amber)")
    ap.add_argument("--serve", type=Path, metavar="CASE_DIR",
                    help="open a case in the browser and pivot on nodes interactively")
    ap.add_argument("--port", type=int, default=8765, help="pivot server port (default 8765, next free if taken)")
    ap.add_argument("--web", action="store_true",
                    help="start the web UI: run investigations and report triage from the browser, browse cases, "
                         "live pivot graphs, verdicts, threat reports (http://127.0.0.1:8770)")
    ap.add_argument("--web-host", default=os.getenv("INFRAMAPPER_WEB_HOST", "127.0.0.1"),
                    help="web UI address (default 127.0.0.1; anything else requires INFRAMAPPER_WEB_PASSWORD)")
    ap.add_argument("--web-port", type=int, default=int(os.getenv("INFRAMAPPER_WEB_PORT", 8770)), help="web UI port (default 8770)")
    ap.add_argument("--no-serve", action="store_true",
                    help="don't start the live pivot server after the investigation (batch / scripted runs)")
    ap.add_argument("--no-browser", action="store_true", help="start the pivot server but don't open a browser")
    ap.add_argument("--depth", type=int, default=1,
                    help="expansion depth: 1 = seed only, 2 = also expand discovered neighbours (default 1)")
    ap.add_argument("--limit", type=int, default=10, help="max objects per relationship / pivot (default 10)")
    ap.add_argument("--scans", type=int, default=3, help="urlscan results parsed in full per host (default 3)")
    ap.add_argument("--broad", type=int, default=250,
                    help="skip expanding urlscan pivots with more hits than this (default 250)")
    ap.add_argument("--broad-pattern", type=int, default=5000,
                    help="domain/URL pattern pivots above this many hits are dropped entirely (default 5000)")
    ap.add_argument("--refine", type=int, default=6,
                    help="searches spent tightening a too-broad urlscan pivot (longer URL path, query keys, "
                         "excluding a dominant domain, date / title / server / ASN filters); 0 = off (default 6)")
    ap.add_argument("--no-new-hunt", action="store_true",
                    help="skip the new-domain hunt (kit reuse on young domains, NRD look-alikes, CT certificates)")
    ap.add_argument("--nrd-days", type=int, default=7, help="newly-registered-domain lists to scan, days back (default 7)")
    ap.add_argument("--young-days", type=int, default=30,
                    help='a domain is "new" below this age in days, for urlscan kit reuse and CT (default 30)')
    ap.add_argument("--no-ct", action="store_true", help="skip Certificate Transparency (crt.sh / Cert Spotter): new-domain hunt and certificate pivots")
    ap.add_argument("--history", type=int, default=100,
                    help="urlscan scans per host used for the change timeline (default 100)")
    ap.add_argument("--vt-history-depth", type=int, default=0,
                    help="fetch VT cert/WHOIS history for hosts up to this depth (default 0 = seed only)")
    ap.add_argument("--min-score", type=int, default=2,
                    help="evidence score a discovered host needs to join the cluster (default 2; "
                         "1 = any single pivot hit, 3 = strong artefacts only)")
    ap.add_argument("--max-expand", type=int, default=40, help="max nodes to expand (default 40)")
    ap.add_argument("--query", "-q", action="append", default=[], metavar="URLSCAN_QUERY",
                    help="extra urlscan query to pivot on, e.g. -q 'page.domain:*-okta-*' (repeatable)")
    ap.add_argument("--regex", "-r", action="append", default=[], metavar="REGEX",
                    help="regex on the domain name, searched on urlscan as page.domain:/REGEX/ and pivoted on, "
                         "e.g. -r '.*-okta-[a-z]+\\.com' -r 'login[0-9]+\\.[a-z]+\\.com' (repeatable; must match the whole name, TLD included)")
    ap.add_argument("--no-regex-hunt", action="store_true",
                    help="skip the automatic regex ladder on the cluster's domain names (broad -> refined -> best pivot)")
    ap.add_argument("--vt-intel", action="store_true", help="use VT Intelligence searches (premium key)")
    ap.add_argument("--no-vt", action="store_true", help="skip VirusTotal")
    ap.add_argument("--no-urlscan", action="store_true", help="skip urlscan.io")
    ap.add_argument("--no-pdns", action="store_true", help="skip passive DNS (Mnemonic / CIRCL)")
    ap.add_argument("--no-live-dns", action="store_true",
                    help="skip current NS/MX/SOA lookups over DNS-over-HTTPS (Cloudflare)")
    ap.add_argument("--pdns-broad", type=int, default=25,
                    help="IP with more pDNS domains than this is treated as shared hosting (default 25)")
    ap.add_argument("--ns-broad", type=int, default=200,
                    help="nameserver / MX used by more domains than this is not expanded (default 200)")
    ap.add_argument("--no-intel", action="store_true",
                    help="skip prior-reporting checks (OTX / ThreatFox / MalwareBazaar, MISP warninglists)")
    ap.add_argument("--no-feeds", action="store_true",
                    help="skip public feeds (Feodo, C2IntelFeeds, OpenPhish, URLhaus, GreyNoise, InternetDB…)")
    ap.add_argument("--no-live-feeds", action="store_true",
                    help="bulk feed lists only: no per-IOC API calls (GreyNoise / InternetDB / URLhaus / AbuseIPDB)")
    ap.add_argument("--intel-max", type=int, default=200,
                    help="max hosts checked for prior reporting per run / pivot (default 200)")
    ap.add_argument("--vt-comments", type=int, default=10,
                    help="IOCs whose VT community comments are read for actors / families / co-mentioned IOCs, "
                         "per run or pivot (1 VT call each; 0 = off; default 10)")
    ap.add_argument("--no-hop", action="store_true",
                    help="skip the hosting pivot (IP -> its domains -> their other IPs -> shared domains)")
    ap.add_argument("--hop-domains", type=int, default=15,
                    help="hosting pivot: domains per anchor IP whose hosting history is checked (default 15)")
    ap.add_argument("--hop-siblings", type=int, default=8,
                    help="hosting pivot: other IPs per anchor checked for shared domains (default 8)")
    ap.add_argument("--vt-rpm", type=float, default=float(os.getenv("VT_RPM", 4)),
                    help="VT requests/minute (free=4, premium: set higher; default from VT_RPM or 4)")
    ap.add_argument("--no-kb", action="store_true",
                    help="don't use the knowledge base (<out>/knowledge.db): no memory across cases, no analyst verdicts")
    ap.add_argument("--mark", choices=["fp", "confirmed", "clear"],
                    help="set an analyst verdict on the IOC given (global, applied to every case), then exit")
    ap.add_argument("--actor", help="with --mark: actor label for the IOC (e.g. APT28)")
    ap.add_argument("--family", help="with --mark: malware family label for the IOC (e.g. Cobalt Strike)")
    ap.add_argument("--note", help="with --mark: why")
    ap.add_argument("--reindex", action="store_true",
                    help="(re)build the knowledge base from every case in --out, then exit (no API calls)")
    ap.add_argument("--ingest", action="store_true",
                    help="pull recent threat reports (DFIR Report, Unit 42, Mandiant, Microsoft, Talos, ESET…) into the "
                         "local STIX dataset (./dataset) and the knowledge base, then exit")
    ap.add_argument("--days", type=int, default=60, help="--ingest: how far back (default 60 days)")
    ap.add_argument("--sources", help="--ingest: comma-separated source slugs (default: all; see inframapper/reports.py)")
    ap.add_argument("--recent-reports", type=int, metavar="N", help="list the N most recently ingested reports")
    ap.add_argument("--search-reports", metavar="TERM",
                    help="search the report dataset by IOC, actor, malware family, ATT&CK id, CVE or title words")
    ap.add_argument("--out", type=Path, default=HERE / "cases", help="output directory (default ./cases)")
    ap.add_argument("--no-cache", action="store_true", help="ignore the on-disk API cache")
    ap.add_argument("--cache-ttl", type=float, default=24, help="cache TTL in hours (default 24)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    if args.verbose:
        log.setLevel("DEBUG")
    from inframapper.rules import RuleStore
    RuleStore(args.out / "hunt_rules.json").apply()   # pivot combinations and tuning from the hunting-rules page
    if args.web:
        from inframapper.web.app import serve as serve_web
        serve_web(HERE, args.out.resolve(), args.web_host, args.web_port, not args.no_browser)
        return 0

    kb_only = args.mark or args.reindex or args.ingest or args.search_reports or args.recent_reports
    if not args.ioc and not args.serve and not args.source and not kb_only:
        ap.error("give an IOC to investigate, --from REPORT, or --serve CASE_DIR")
    kb = None
    if not args.no_kb:
        from inframapper.knowledge import Knowledge
        kb = Knowledge(args.out / "knowledge.db")
    if kb_only:
        return knowledge_cmd(args, kb, ap)
    cache = Cache(HERE / ".cache", args.cache_ttl, enabled=not args.no_cache)

    vt_key, us_key = os.getenv("VT_API_KEY"), os.getenv("URLSCAN_API_KEY")
    vt_backup = [k.strip() for k in os.getenv("VT_API_KEY_BACKUP", "").split(",") if k.strip()]
    vt_key = vt_key or (vt_backup.pop(0) if vt_backup else None)
    vt = VirusTotal(vt_key, cache, args.vt_rpm, vt_backup) if vt_key and not args.no_vt else None
    us = URLScan(us_key, cache) if not args.no_urlscan else None
    if not vt and not args.no_vt:
        log.warning("VT_API_KEY not set — VirusTotal pivots disabled")
    if us and not us_key:
        log.warning("URLSCAN_API_KEY not set — urlscan search will be heavily rate limited")
    pdns = None if args.no_pdns else PassiveDNS(
        cache, os.getenv("MNEMONIC_API_KEY"), os.getenv("CIRCL_PDNS_USER"),
        os.getenv("CIRCL_PDNS_PASS"), live=not args.no_live_dns)
    intel = warn = feeds = None
    if not args.no_feeds:
        feeds = Feeds(HERE / ".cache", cache, os.getenv("ABUSECH_API_KEY"), os.getenv("GREYNOISE_API_KEY"),
                      os.getenv("ABUSEIPDB_API_KEY"), live=not args.no_live_feeds)
    if not args.no_intel:
        warn = Warninglists(HERE / ".cache")
        otx_key, abuse_key = os.getenv("OTX_API_KEY"), os.getenv("ABUSECH_API_KEY")
        if otx_key or abuse_key:
            intel = PriorReporting(cache, otx_key, abuse_key)
        if not otx_key:
            log.warning("OTX_API_KEY not set — OTX pulse lookups (vendor reports) disabled")
        if not abuse_key:
            log.warning("ABUSECH_API_KEY not set — ThreatFox / MalwareBazaar lookups disabled")
    if not vt and not us and not pdns:
        log.error("no data source enabled")
        return 1

    cfg = Config(depth=args.depth, limit=args.limit, scans=args.scans, broad=args.broad, broad_pattern=args.broad_pattern, refine=args.refine,
                 new_hunt=not args.no_new_hunt, nrd_days=args.nrd_days, young_days=args.young_days, ct=not args.no_ct,
                 max_expand=args.max_expand, vt_intel=args.vt_intel, history=args.history,
                 vt_history_depth=args.vt_history_depth, min_score=args.min_score,
                 pdns_broad=args.pdns_broad, ns_broad=args.ns_broad, intel_max=args.intel_max,
                 hop=not args.no_hop, hop_domains=args.hop_domains, hop_siblings=args.hop_siblings,
                 batch_vt=args.batch_vt, vt_comments=args.vt_comments if not args.no_intel else 0,
                 use_vt=vt is not None, use_urlscan=us is not None, use_pdns=pdns is not None,
                 extra_queries=args.query, extra_regexes=args.regex, regex_hunt=not args.no_regex_hunt)
    inv = Investigator(vt, us, cfg, pdns, intel, warn, feeds)
    inv.cache_dir, inv.cache, inv.tlp, inv.kb = HERE / ".cache", cache, args.tlp, kb
    if vt and not args.no_intel:   # actor / family names: VT comments, YARA, sandboxes, AV consensus
        from inframapper.extract import load_tlds
        from inframapper.vtcomments import ActorNames
        inv.actors, inv.tlds = ActorNames(HERE / ".cache"), load_tlds(HERE / ".cache")
    if not args.no_ct:   # certificate pivots from the graph page
        from inframapper.ct import CertTransparency
        inv.ct = CertTransparency(cache, os.getenv("CERTSPOTTER_API_KEY"))
    if args.serve:
        from inframapper.server import PivotServer
        case_dir = args.serve.resolve()
        if not (case_dir / "graph.json").exists():
            log.error(f"{case_dir} has no graph.json")
            return 1
        PivotServer(inv, case_dir, vt, us, pdns).serve("127.0.0.1", args.port, not args.no_browser)
        return 0

    if args.source or len(args.ioc) > 1:
        from inframapper.extract import extract, load_tlds, read_source
        if args.source:
            try:
                text, value, exclude, linked = read_source(args.source)
            except Exception as exc:
                log.error(f"can't read {args.source}: {exc}")
                return 1
        else:
            text, value, exclude, linked = "\n".join(args.ioc), "command line", set(), set()
        text += "\n" + "\n".join(args.ioc if args.source else [])
        ex = extract(text, value, load_tlds(HERE / ".cache"), exclude, feeds.bulk.kev if feeds else None, linked)
        if not ex.iocs:
            log.error("no IOC found in the input")
            return 1
        log.info(f"report triage: [bold]{len(ex.iocs)}[/] IOCs from {value} "
                 f"({', '.join(f'{v} {k}' for k, v in ex.counts().items())}"
                 + (f"; dropped {sum(ex.dropped.values())} as noise" if ex.dropped else "") + ")")
        inv.run_batch(value, ex.iocs, ex)
        slug_src = "report_" + (Path(value).stem if not value.startswith("http") else value.split("//", 1)[-1])
    else:
        ioc_type, value = detect_type(args.ioc[0])
        log.info(f"investigating [bold]{ioc_type}[/] {value}")
        inv.run(ioc_type, value)
        slug_src = value

    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", slug_src)[:60]
    case = f"{datetime.now():%Y%m%d-%H%M%S}_{slug}"
    outdir = args.out / case
    outdir.mkdir(parents=True, exist_ok=True)
    inv.cross_case(case)
    write_json(inv, outdir / "graph.json")
    write_html(inv, outdir / "graph.html", f"InfraMapper — {value}")
    write_report(inv, outdir / "report.md", value)
    write_iocs_csv(inv, outdir / "iocs.csv")
    from inframapper.share import write_all
    write_all(inv, outdir, f"InfraMapper — {value}", args.tlp)
    if kb:
        from inframapper.export import case_attribution
        kb.index_case(inv, outdir, case_attribution(inv))

    console.print(f"\n[bold green]done[/] — {len(inv.g.nodes)} nodes, {len(inv.g.edges)} edges "
                  f"(VT calls: {vt.calls if vt else 0}, urlscan calls: {us.calls if us else 0}, "
                  f"DNS calls: {pdns.calls if pdns else 0}, intel calls: {intel.calls if intel else 0}, "
                  f"feed calls: {feeds.calls if feeds else 0})")
    console.print(f"  graph : {outdir / 'graph.html'}")
    console.print(f"  report: {outdir / 'report.md'}")
    console.print(f"  json  : {outdir / 'graph.json'}")
    console.print(f"  iocs  : {outdir / 'iocs.csv'}")
    console.print(f"  share : {outdir / 'stix2.json'} (STIX 2.1, TLP:{args.tlp.upper()})")
    console.print(f"  hunt  : {outdir / 'hunt'}/ (Defender / Sentinel KQL, Splunk SPL, Suricata, plain lists)")
    if args.no_serve or not sys.stdin.isatty():
        console.print(f"  pivot : {Path(sys.argv[0]).name} --serve {outdir}")
        return 0
    from inframapper.server import PivotServer
    console.print()
    PivotServer(inv, outdir.resolve(), vt, us, pdns).serve("127.0.0.1", args.port, not args.no_browser)
    return 0


if __name__ == "__main__":
    sys.exit(main())
