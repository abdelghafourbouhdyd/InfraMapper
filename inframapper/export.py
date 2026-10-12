"""Exporters: JSON, interactive HTML (vis-network), Markdown report."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import graph as g
from . import scoring
from .feeds import day, last_active, triage_all
from .log import log
from .pdns import overlaps, window

TEMPLATE = Path(__file__).with_name("graph_template.html")


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for it in items:
        key = json.dumps(it, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def _timelines(inv) -> dict[str, list[dict]]:
    return {nid: sorted(_dedupe(ev), key=lambda e: e["t"])
            for nid, ev in getattr(inv, "timelines", {}).items()}


TIMELINE_FIELDS = ("ip", "domain", "asn", "cert", "title", "status", "server",
                   "registrar", "nameservers")


def history_summary(events: list[dict]) -> dict[str, list[tuple[str, str, str, int]]]:
    """field -> [(value, first seen, last seen, observations)] in first-seen order."""
    out: dict[str, dict[str, list]] = {}
    for e in events:
        for f in TIMELINE_FIELDS:
            if f in e:
                v = str(e[f])
                cur = out.setdefault(f, {}).setdefault(v, [e["t"], e["t"], 0])
                cur[1], cur[2] = e["t"], cur[2] + 1
    return {f: [(v, a, b, n) for v, (a, b, n) in vals.items()] for f, vals in out.items()}


def write_json(inv, path: Path) -> None:
    triage_all(inv.g)
    data = inv.g.to_dict()
    data.update(seed=inv.seed_id, pivots=inv.pivots, hunt_queries=_dedupe(inv.hunt_queries),
                timelines=_timelines(inv), dns_history=getattr(inv, "dns_history", {}),
                manual_pivots=getattr(inv, "manual_pivots", []), new_domains=getattr(inv, "new_domains", []),
                batch=getattr(inv, "batch", None), regex_ladders=getattr(inv, "regex_ladders", []))
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# Search artefacts shown as edges, not nodes: origin IOC --pivot kind--> IOC it led to.
# rel on the origin -> artefact edge that marks the IOC the pivot was run from.
PIVOT_ORIGIN_RELS = {"MATCHES_PATTERN", "ANALYST_PIVOT", "HAS_TITLE", "HAS_FAVICON",
                     "SERVES_HTML", "SERVES_SCRIPT", "HAS_JARM", "HAS_IMPHASH", "HAS_VHASH"}
PIVOT_NODE_TYPES = {g.PATTERN, g.INTEL, g.TITLE, g.FAVICON, g.HTML_HASH, g.SCRIPT, g.JARM}


def pivot_view(data: dict, pivots: list[dict]) -> dict:
    """Collapse pivot artefacts into direct 'IOC --pivot type--> new IOC' edges; drop scan ids."""
    kinds = {p["query"]: p["kind"] for p in pivots}
    nodes = {n["id"]: n for n in data["nodes"] if n["type"] != g.SCAN}
    piv = {nid for nid, n in nodes.items() if n["type"] in PIVOT_NODE_TYPES}
    origins: dict[str, list[str]] = {}
    hits: dict[str, list[tuple[str, dict]]] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    for e in data["edges"]:
        s, d, props = e["source"], e["target"], {k: v for k, v in e["props"].items() if k != "scan"}
        if s not in nodes or d not in nodes:
            continue
        if d in piv and s not in piv and e["rel"] in PIVOT_ORIGIN_RELS:
            origins.setdefault(d, []).append(s)
        elif s in piv or d in piv:
            p_id, other = (s, d) if s in piv else (d, s)
            if other not in piv:
                hits.setdefault(p_id, []).append((other, props))
        else:
            edges[(s, d, e["rel"])] = props
    for p_id in piv:
        n = nodes[p_id]
        np_ = n["props"]
        q = np_.get("urlscan_query") or np_.get("vt_query")
        kind = kinds.get(q) or np_.get("kind") or n["type"].lower()
        src = "VT Intelligence" if np_.get("vt_query") and not np_.get("urlscan_query") else "urlscan"
        base = {"query": q, "source": src, "via": n["value"]}
        srcs = list(dict.fromkeys(origins.get(p_id, [])))
        targets = [(o, pr) for o, pr in hits.get(p_id, []) if o not in srcs]
        if srcs:   # hosts sharing the same artefact are linked through the first one
            targets += [(o, {}) for o in srcs[1:]]
        for o in srcs[:1] if targets else []:
            for t, pr in targets:
                if t != o:
                    edges.setdefault((o, t, kind), {**{k: v for k, v in base.items() if v},
                                                    **{k: v for k, v in pr.items() if k not in base}})
    for nid in piv:
        del nodes[nid]
    for n in nodes.values():
        n["props"].pop("scan", None)
    return {"nodes": list(nodes.values()),
            "edges": [{"source": s, "target": d, "rel": r, "props": p} for (s, d, r), p in edges.items()]}


def view_data(inv, title: str, case_dir: Path | None = None) -> dict:
    """What the HTML page renders (also served live by --serve)."""
    triage_all(inv.g)
    data = pivot_view(inv.g.to_dict(), inv.pivots)
    scorer = scoring.Scorer(inv.g.nodes, inv.g.edges, inv.seed_id)
    node_scores = scorer.score()
    for e in data["edges"]:   # relationship confidence on every drawn edge (collapsed pivots: artefact share)
        s, d = e["source"], e["target"]
        e["props"]["score"] = (scorer.pair(s, d) if frozenset((s, d)) in scorer.pairs
                               else scoring.artefact_edge(e["rel"], e["props"]))
    data.update(seed=inv.seed_id, pivots=inv.pivots, hunt_queries=_dedupe(inv.hunt_queries),
                scores={nid: node_scores[nid] for nid in (n["id"] for n in data["nodes"]) if nid in node_scores},
                scoring=scoring.METHOD,
                timelines=_timelines(inv), title=title, manual_pivots=getattr(inv, "manual_pivots", []),
                new_domains=getattr(inv, "new_domains", []), regex_ladders=getattr(inv, "regex_ladders", []),
                campaign=campaign_view(inv), case_dir=str(case_dir) if case_dir else None,
                generated=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    return data


def render_html(inv, title: str, case_dir: Path | None = None) -> str:
    return render_view(view_data(inv, title, case_dir), title)


def render_view(data: dict, title: str) -> str:
    """The graph page for an already-built view_data() payload."""
    payload = json.dumps(data, default=str).replace("</", "<\\/")
    return TEMPLATE.read_text(encoding="utf-8").replace("__TITLE__", title).replace("__DATA__", payload)


def write_html(inv, path: Path, title: str) -> None:
    path.write_text(render_html(inv, title, path.parent), encoding="utf-8")


def write_report(inv, path: Path, seed: str) -> None:
    gr = inv.g
    nodes = gr.nodes.values()
    by_type: dict[str, list[dict]] = {}
    for n in nodes:
        by_type.setdefault(n["type"], []).append(n)
    seed_node = gr.nodes.get(inv.seed_id, {})
    sp = seed_node.get("props", {})

    batch = getattr(inv, "batch", None)
    L = [f"# Report triage — `{batch['source']}`" if batch else f"# InfraMapper — `{seed}`", "",
         f"_Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC_", ""]
    if not batch:
        L += ["## Seed", "", f"- **Type:** {seed_node.get('type')}"]
    if sp.get("vt_total"):
        L.append(f"- **VT detections:** {sp.get('vt_malicious', 0)}/{sp['vt_total']}")
    for k in ("label", "name", "file_type", "registrar", "created", "asn", "as_owner",
              "country", "urlscan_scans"):
        if sp.get(k) and not batch:
            v = sp[k]
            if k == "created" and isinstance(v, int):
                v = datetime.fromtimestamp(v, timezone.utc).date()
            L.append(f"- **{k}:** {v}")
    L += _batch_section(inv)
    L += _actionable_section(inv)
    L += _seen_before_section(inv)
    L += _attribution_section(inv)
    L += _verdicts_section(inv)
    L += ["", "## Share / retro-hunt", "",
          "Actionable IOCs only (P1 / P2 / P3 + strong / medium new-domain leads; `noise` is never exported):", "",
          "- `stix2.json`: STIX 2.1 bundle for OpenCTI / MISP / any TAXII feed (deterministic ids: re-importing "
          "an updated case updates the same objects)",
          "- `hunt/suricata.rules`: DNS / TLS SNI / HTTP Host and IP rules",
          "- `hunt/*.txt`: plain IP / domain / URL / hash lists for firewall and EDR imports"]
    tl = _timelines(inv).get(inv.seed_id)
    if tl:
        L += ["", "## Change history (seed)", "",
              f"{len(tl)} observations, {tl[0]['t'][:10]} → {tl[-1]['t'][:10]}.", "",
              "| Field | Value | First seen | Last seen | Obs. |", "|---|---|---|---|---|"]
        for f, vals in history_summary(tl).items():
            for v, a, b, n in vals:
                v = v.replace("|", "\\|")
                L.append(f"| {f} | `{v[:80]}` | {a[:10]} | {b[:10]} | {n} |")
    hosts = [n for n in nodes if n["type"] in (g.DOMAIN, g.IP, g.URL, g.FILE) and n["id"] != inv.seed_id]
    conf = [n for n in hosts if n["props"].get("cluster")]
    cand = sorted((n for n in hosts if n["props"].get("cluster") is False),
                  key=lambda n: -(n["props"].get("cluster_score") or 0))
    if conf or cand:
        L += ["", "## Cluster", "",
              f"{len(conf)} hosts confirmed (evidence score ≥ {inv.cfg.min_score}), "
              f"{len(cand)} unconfirmed pivot hits left out of the graph.", "",
              "| Type | Value | Score | Evidence |", "|---|---|---|---|"]
        for n in sorted(conf, key=lambda n: (n["type"], n["value"])):
            ev = "; ".join(n["props"].get("cluster_evidence") or []).replace("|", "\\|")
            L.append(f"| {n['type']} | `{n['value'][:80]}` | {n['props'].get('cluster_score')} | {ev} |")
        if cand:
            L += ["", "### Unconfirmed candidates (review manually)", "",
                  "| Type | Value | Score | Evidence |", "|---|---|---|---|"]
            for n in cand[:60]:
                ev = "; ".join(n["props"].get("cluster_evidence") or []).replace("|", "\\|") or "—"
                L.append(f"| {n['type']} | `{n['value'][:80]}` | {n['props'].get('cluster_score')} | {ev} |")
    L += _new_domains_section(inv)
    L += _pdns_section(inv)
    L += _hosting_section(inv)
    L += _reporting_section(inv)
    L += ["", "## Graph summary", "", "| Node type | Count |", "|---|---|"]
    for t, ns in sorted(by_type.items(), key=lambda x: -len(x[1])):
        L.append(f"| {t} | {len(ns)} |")
    L.append(f"\n{len(gr.edges)} relationships.\n")

    mal = sorted((n for n in nodes if (n["props"].get("vt_malicious") or 0) > 0),
                 key=lambda n: -(n["props"].get("vt_malicious") or 0))
    if mal:
        L += ["## Malicious neighbours (VT)", "", "| Type | Value | Detections | Label |",
              "|---|---|---|---|"]
        for n in mal[:40]:
            p = n["props"]
            L.append(f"| {n['type']} | `{n['value']}` | {p.get('vt_malicious')}/{p.get('vt_total')}"
                     f" | {p.get('label') or ''} |")
        L.append("")

    L += _regex_section(inv)
    L += ["## Pivots run", "", "Too-broad urlscan pivots are tightened step by step (`refine step` rows): a step "
          "that cuts the hits is kept, one that gives 0 or barely helps is dropped, until the query is "
          "specific enough to expand.", "", "| Source | Kind | Query | Hits | |", "|---|---|---|---|---|"]
    for p in inv.pivots:
        flag = (p.get("decision") or ("too broad" if p["broad"] else "")).replace("|", "\\|")
        q = p["query"].replace("|", "\\|")
        L.append(f"| {p['source']} | {p['kind']} | `{q}` | {p['total']} | {flag} |")

    # Infrastructure shared by 2+ hosts = cluster evidence
    shared = []
    for n in nodes:
        if n["type"] in (g.FAVICON, g.TITLE, g.HTML_HASH, g.SCRIPT, g.CERT, g.JARM, g.PATTERN):
            linked = {d for (s, d, r) in gr.edges if s == n["id"]} | \
                     {s for (s, d, r) in gr.edges if d == n["id"]}
            hosts = [gr.nodes[x]["value"] for x in linked
                     if gr.nodes[x]["type"] in (g.DOMAIN, g.IP)
                     and gr.nodes[x]["props"].get("cluster") is not False]
            if len(hosts) >= 2 and not n["props"].get("broad"):
                shared.append((n, sorted(hosts)))
    if shared:
        L += ["", "## Shared artefacts (cluster evidence)", ""]
        for n, hosts in sorted(shared, key=lambda x: -len(x[1])):
            L.append(f"- **{n['type']}** `{n['value'][:90]}` — {len(hosts)} hosts: "
                     + ", ".join(f"`{h}`" for h in hosts[:15])
                     + (" …" if len(hosts) > 15 else ""))

    ok = lambda n: n["props"].get("cluster") is not False   # confirmed cluster only
    domains = sorted(n["value"] for n in by_type.get(g.DOMAIN, []) if ok(n))
    ips = sorted(n["value"] for n in by_type.get(g.IP, []) if ok(n))
    files = sorted(n["value"] for n in by_type.get(g.FILE, []) if ok(n))
    L += ["", "## Hunting queries", ""]
    for p in inv.pivots:
        if not p["broad"] and p["total"] and p["source"] == "urlscan" and p["kind"] != "host scans":
            L.append(f"- urlscan: `{p['query']}`")
    for h in _dedupe(inv.hunt_queries):
        L.append(f"- {h['platform']}: `{h['query']}`" + (f" ({h['note']})" if h.get("note") else ""))
    L += ["", "## All observables", "",
          "_Confirmed cluster only — see the candidates table above for the rest._", "",
          f"### Domains ({len(domains)})", "```", *domains, "```",
          f"### IPs ({len(ips)})", "```", *ips, "```",
          f"### Files ({len(files)})", "```", *files, "```"]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def _batch_section(inv) -> list[str]:
    """Report triage (--from): what was extracted, what was dropped, and which earlier public
    reports this report's IOCs overlap with (is this campaign already known?)."""
    b = getattr(inv, "batch", None)
    if not b:
        return []
    gr = inv.g
    L = ["", "## Input report", "",
         f"- **Source:** {b['source']}",
         f"- **IOCs extracted:** {b['iocs']} (" + ", ".join(f"{v} {k}" for k, v in b.get("counts", {}).items()) + ")"]
    if b.get("dropped"):
        L.append("- **Dropped as noise:** " + ", ".join(f"{v} {k}" for k, v in b["dropped"].items()))
    if b.get("cves"):
        L.append("- **CVEs mentioned:** " + ", ".join(b["cves"]))
    if b.get("fingerprints"):
        L.append(f"- **Fingerprints ({len(b['fingerprints'])}):** imphash / JA3 / … kept out of the IOC list, "
                 "turned into pivots under *Hunting queries*")
    inputs = {nid for nid, n in gr.nodes.items() if n["props"].get("input_ioc")}
    dead = sorted(gr.nodes[n]["value"] for n in inputs if gr.nodes[n]["props"].get("dns_dead"))
    if dead:
        L.append(f"- **No longer resolving ({len(dead)}):** " + ", ".join(f"`{d}`" for d in dead[:30])
                 + (" …" if len(dead) > 30 else ""))
    overlap: dict[str, list[str]] = {}
    for (s, d, rel) in gr.edges:
        if rel == "REPORTED_IN" and s in inputs and d in gr.nodes:
            overlap.setdefault(d, []).append(gr.nodes[s]["value"])
    if overlap:
        L += ["", "### Overlap with earlier public reporting", "",
              "Earlier reports / feed entries that list IOCs from this input. Several IOCs pointing at the same "
              "report is the quickest way to tie this activity to a known campaign.", "",
              "| Report | Source | Date | Families / actor | IOCs from this input |", "|---|---|---|---|---|"]
        for rid, vals in sorted(overlap.items(), key=lambda x: -len(x[1]))[:40]:
            r = gr.nodes[rid]["props"]
            name = (r.get("name") or gr.nodes[rid]["value"]).replace("|", "\\|")[:80]
            if r.get("url"):
                name = f"[{name}]({r['url']})"
            fam = ", ".join((r.get("malware") or []) + ([r["actor"]] if r.get("actor") else []))
            L.append(f"| {name} | {r.get('source', '')} | {day(r.get('date'))} | {fam or '—'} | "
                     f"{len(vals)}: " + ", ".join(f"`{v[:50]}`" for v in sorted(vals)[:6]) + (" …" if len(vals) > 6 else "") + " |")
    return L


PRIORITY_NOTE = {
    "P1": "on a live C2 / phishing / malware feed or a criminal netblock: block now",
    "P2": "reported before or flagged by reputation sources: block and retro-hunt",
    "P3": "confirmed by this investigation only: not public yet, hunt and write detections",
    "noise": "shared / benign / Tor / mass-scanner: don't block on this alone, don't attribute",
}


def _actionable_section(inv) -> list[str]:
    """Triage of every IOC in view: what to do with it and why (public feeds + reporting + cluster)."""
    rows = triage_all(inv.g)
    if not rows:
        return []
    count = {k: sum(1 for r in rows if r[1] == k) for k in PRIORITY_NOTE}
    L = ["", "## Actionable intel", "",
         " · ".join(f"**{k}** {v}" for k, v in count.items() if v), "",
         *[f"- **{k}**: {v}" for k, v in PRIORITY_NOTE.items() if count[k]], "",
         "| Priority | Type | IOC | Action | Why | Last active |", "|---|---|---|---|---|---|"]
    for n, pri, action, why in rows:
        w = "; ".join(why).replace("|", "\\|")[:300]
        L.append(f"| {pri} | {n['type']} | `{n['value'][:80]}` | {action} | {w} | {day(last_active(inv.g, n['id']))} |")
    L.append("")
    L.append("Blocklist / watchlist export: `iocs.csv` in the case folder.")
    exp = [n for n, *_ in rows if n["type"] == g.IP and (n["props"].get("open_ports") or n["props"].get("vulns"))]
    if exp:
        L += ["", "### Exposure (Shodan InternetDB)", "",
              "Open ports and CVEs on the cluster's IPs (CVEs are inferred from banners / versions, not "
              "verified). CVEs on CISA KEV are in bold; default C2 "
              "operator ports are flagged as hints (verify: anyone can open 50050).", "",
              "| IP | Ports | CVEs | Hints |", "|---|---|---|---|"]
        for n in exp:
            p = n["props"]
            kev = set(p.get("kev") or [])
            cves = ", ".join(f"**{c}**" if c in kev else c for c in (p.get("vulns") or [])[:12])
            hints = list(p.get("c2_port_hint") or [])
            if p.get("shodan_tags"):
                hints.append("tags: " + ", ".join(p["shodan_tags"]))
            hint = "; ".join(hints)
            L.append(f"| `{n['value']}` | {', '.join(map(str, p.get('open_ports') or []))} | {cves or '—'} | {hint or '—'} |")
    return L


def _regex_section(inv) -> list[str]:
    """Each regex ladder: broad -> refinements (with the reason from the previous hits) -> best pivot."""
    ladders = getattr(inv, "regex_ladders", [])
    if not ladders:
        return []
    L = ["## Regex hunt", ""]
    for lad in ladders:
        L += [f"**{lad['kind']}**" + (f" on `{lad['keyword']}`" if lad.get("keyword") else ""), "",
              "| Step | Query | Hits | Why | Decision |", "|---|---|---|---|---|"]
        for i, s in enumerate(lad["steps"]):
            q, why = s["query"].replace("|", "\\|"), s["why"].replace("|", "\\|")
            dec = f"**{s['decision']}**" if i == lad["best"] else s["decision"]
            L.append(f"| {s['label']} | `{q}` | {s['total']} | {why} | {dec.replace('|', chr(92) + '|')} |")
        L.append("")
    return L


def campaign_view(inv) -> list[dict]:
    """Actors / malware families the case's IOCs are tied to, strongest first (graph page)."""
    rank = {"strong": 0, "medium": 1, "single lead": 2}
    rows = [v for v in attribution_votes(inv).values() if v["fits"]]
    rows.sort(key=lambda v: ("analyst" not in v["groups"], rank.get(v["strength"], 3), -len(v["fits"]), v["name"]))
    return [{"kind": v["kind"], "name": v["name"], "iocs": sorted(v["fits"]), "sources": sorted(v["sources"]),
             "strength": "analyst" if "analyst" in v["groups"] else v["strength"], "first": v["first"]}
            for v in rows[:8]]


def _new_domains_section(inv) -> list[str]:
    leads = getattr(inv, "new_domains", [])
    if not leads:
        return []
    L = ["", "## New-domain hunt", "",
         "Domains created recently that look like this actor's: **kit reuse** (the case's HTML / script / "
         "favicon / URL-path pivots re-run on domains younger than the threshold), **look-alikes** of the "
         "actor's own domains in newly registered domain lists (WhoisDS), and **fresh certificates** (crt.sh). "
         "Look-alike rules are built only from domains the actor probably registered (seed, cluster "
         "domains < 180 days old, and the young kit-reuse finds), and a rule matching too many new domains is dropped as generic. "
         "Score: artefact / name match, +2 infrastructure overlap with the cluster (live DNS), +1 registered "
         "this week. urlscan gives a domain's age *at scan time*, so its registration date is scan date - age; "
         "kit reuse on domains registered long ago is listed separately as older kit domains.", "",
         "| Strength | Domain | Found via | Why | Registered | A / NS | Overlap | Action |",
         "|---|---|---|---|---|---|---|---|"]
    fresh = [x for x in leads if x.get("new")]
    older = [x for x in leads if not x.get("new")]
    if older and fresh:
        leads = fresh + [{"divider": True}] + older
    for x in leads[:100]:
        if x.get("divider"):
            L.append("| | **older domains reusing the kit** | | | | | | |")
            continue
        when = x.get("registered") or x.get("cert_date") or ""
        if x.get("age_days") is not None:
            when += f" ({x['age_days']} d ago)"
        dns = ", ".join((x.get("a") or [])[:2] + (x.get("ns") or [])[:2]) or "no DNS"
        L.append(f"| {x['strength']} | `{x['domain']}` | {', '.join(x['via'])} | "
                 + "; ".join(x["reasons"]).replace("|", "\\|")[:200]
                 + f" | {when} | {dns} | {', '.join(x.get('overlap') or []) or '—'} | {x['action']} |")
    return L


def write_iocs_csv(inv, path: Path) -> None:
    """One row per IOC in view: ready for a SIEM watchlist / EDR / firewall import."""
    gr = inv.g
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["priority", "type", "ioc", "action", "reasons", "families", "feeds", "last_active",
                    "vt_malicious", "cluster_score", "block_cidr"])
        rows = triage_all(gr)
        in_view = {n["value"] for n, *_ in rows}
        for n, pri, action, why in rows:
            reps = [gr.nodes[d]["props"] for (s, d, rel) in gr.edges if rel == "REPORTED_IN" and s == n["id"]
                    and d in gr.nodes]
            fams = sorted({m for r in reps for m in r.get("malware") or []} | {r["actor"] for r in reps if r.get("actor")})
            w.writerow([pri, n["type"], n["value"], action, "; ".join(why), ", ".join(fams),
                        ", ".join(sorted({r.get("source", "") for r in reps})), day(last_active(gr, n["id"])),
                        n["props"].get("vt_malicious") or "", n["props"].get("cluster_score") or "",
                        n["props"].get("drop_cidr") or ""])
        for x in getattr(inv, "new_domains", []):   # hunt leads the cluster evidence didn't confirm
            if x["domain"] not in in_view:
                w.writerow([f"lead-{x['strength']}", "Domain", x["domain"], x["action"], "; ".join(x["reasons"]),
                            "", "new-domain hunt: " + ", ".join(x["via"]), x.get("registered") or "", "", "", ""])


def _day(ts) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d") if isinstance(ts, int) and ts else "?"


def _pdns_section(inv) -> list[str]:
    """Resolution history of the seed + DNS infrastructure (IP / NS / MX / SOA) shared with it."""
    gr = inv.g
    hist = getattr(inv, "dns_history", {})
    L: list[str] = []
    own = hist.get(inv.seed_id)
    if own:
        L += ["", "## DNS history (seed)", "", "| Type | Value | First seen | Last seen | Source |",
              "|---|---|---|---|---|"]
        for r in own[:60]:
            L.append(f"| {r['rrtype'].upper()} | `{r['rdata'][:90]}` | {_day(r['first'])} | "
                     f"{_day(r['last'])} | {r['source']} |")

    seed_win: dict[str, tuple] = {}   # IP id -> the seed's own window on it
    for (s, d, rel), p in gr.edges.items():
        if s == inv.seed_id and rel == "RESOLVES_TO" and window(p):
            seed_win[d] = window(p)

    rows = []
    for n in gr.nodes.values():
        if n["type"] not in (g.IP, g.NS, g.MX, g.SOA):
            continue
        p = n["props"]
        users = []
        for (s, d, rel), ep in gr.edges.items():
            if d != n["id"] or rel not in ("RESOLVES_TO", "USES_NS", "USES_MX", "SOA_CONTACT"):
                continue
            dn = gr.nodes[s]
            if dn["type"] != g.DOMAIN:
                continue
            win = window(ep) or (None, None)
            conc = n["id"] in seed_win and s != inv.seed_id and bool(win[0]) \
                and overlaps(win, seed_win[n["id"]])
            users.append((dn, win, conc))
        if len(users) < 2:
            continue
        rows.append((n, p, users))
    if not rows:
        return L
    def rank(row):
        n, p, users = row
        return (bool(p.get("commodity") or p.get("shared_hosting")),
                -sum(1 for u in users if u[0]["props"].get("cluster")), -len(users))
    L += ["", "## Infrastructure overlap (passive DNS)", "",
          "Domains that share an IP, a nameserver, a mail server or an SOA contact. Dedicated infra "
          "(not a CDN, shared host, or commodity DNS provider) reused across domains is the "
          "strongest sign of one operator / one campaign. **Concurrent** = resolved to the IP "
          "during the same window as the seed.", ""]
    for n, p, users in sorted(rows, key=rank):
        tag = []
        if p.get("commodity"):
            tag.append("commodity provider, not evidence")
        if p.get("shared_hosting"):
            tag.append("shared hosting, not evidence")
        if p.get("pdns_domains") is not None:
            tag.append(f"{p['pdns_domains']} domains in pDNS")
        conf = sum(1 for u in users if u[0]["props"].get("cluster"))
        L += [f"### {n['type']} `{n['value']}`" + (f" _({'; '.join(tag)})_" if tag else ""), "",
              f"{len(users)} domains, {conf} in the confirmed cluster.", "",
              "| Domain | Cluster | First seen | Last seen | |", "|---|---|---|---|---|"]
        for dn, win, conc in sorted(users, key=lambda u: (u[0]["id"] != inv.seed_id,
                                                        not u[0]["props"].get("cluster"), -(u[1][1] or 0))):
            flag = "seed" if dn["id"] == inv.seed_id else ("**concurrent**" if conc else "")
            cl = "yes" if dn["props"].get("cluster") else "no"
            L.append(f"| `{dn['value']}` | {cl} | {_day(win[0])} | {_day(win[1])} | {flag} |")
        L.append("")
    return L


def _hosting_section(inv) -> list[str]:
    """Hosting pivot: which other IPs share the anchor IP's domains, and when."""
    runs = getattr(inv, "hosting", None) or []
    if not runs:
        return []
    gr = inv.g
    L = ["", "## Hosting pivot (IP → domains → other IPs)", "",
         "Where the anchor IP's domains were hosted before / after, then a reverse pDNS lookup on those IPs. "
         "**linked** = 2+ shared domains with at least one concurrent or moved within 30 days (or 3+ shared): "
         "likely the same operator's server. **possible** = one shared domain with tight timing. IPs hosting "
         f"more than {inv.cfg.pdns_broad} domains are shared hosting / parking / sinkholes and never count. "
         "New domains on linked / possible IPs are in the graph and scored like any other candidate.", ""]
    for run in runs:
        rows = [r for r in run["siblings"] if r["verdict"] != "weak"] or run["siblings"][:3]
        L += [f"### `{run['anchor']}`: {run['domains']} domains checked, {run['candidates']} other IPs", ""]
        if run.get("pdns_out"):
            L += ["> Passive DNS quota ran out during this pivot: *unverified* IPs could not be checked for "
                  "shared hosting. Add `MNEMONIC_API_KEY` (free) or CIRCL credentials and re-run.", ""]
        if not rows:
            L += ["No other IP hosted these domains.", ""]
            continue
        L += ["| IP | Verdict | Shared domains (timing) | Domains on IP | New domains there | In cluster |",
              "|---|---|---|---|---|---|"]
        order = {"linked": 0, "possible": 1, "unverified": 2, "weak": 3, "shared hosting": 4}
        for r in sorted(rows, key=lambda r: (order[r["verdict"]], -len(r["shared"]))):
            node = gr.nodes.get(g.node_id(g.IP, r["ip"]), {"props": {}})
            shared = "<br>".join(f"`{d}` ({rel})" for d, rel in sorted(r["shared"].items())[:5]) \
                + (f"<br>+{len(r['shared']) - 5} more" if len(r["shared"]) > 5 else "")
            new = ", ".join(f"`{d}`" for d in r["new"][:4]) + (" …" if len(r["new"]) > 4 else "") \
                if r["verdict"] in ("linked", "possible") else ""
            v = f"**{r['verdict']}**" if r["verdict"] == "linked" else r["verdict"]
            L.append(f"| `{r['ip']}` | {v} | {shared} | {r['total'] if r['total'] is not None else '?'} | {new or '—'} | "
                     f"{'yes' if node['props'].get('cluster') else 'no'} |")
        L.append("")
    return L


TIMING_NOTE = {"fits": "fits", "current": "listed now, usage dates unknown", "earlier": "**reported before this use**: previous owner?",
               "later": "**reported long after this use**: reassigned?"}


def _reporting_section(inv) -> list[str]:
    """IOCs already published / attributed (OTX pulses, ThreatFox, MalwareBazaar)."""
    gr = inv.g
    rows = []
    for (s, d, rel), ep in gr.edges.items():
        if rel != "REPORTED_IN" or s not in gr.nodes or d not in gr.nodes:
            continue
        ioc, rep = gr.nodes[s], gr.nodes[d]
        if ioc["props"].get("cluster") is False and not ioc["props"].get("pinned"):
            continue
        rows.append((ioc, rep, ep))
    benign = sorted((n for n in gr.nodes.values() if n["props"].get("warninglist")
                     and (n["props"].get("cluster") is not False or n["props"].get("pinned"))),
                    key=lambda n: (n["type"], n["value"]))
    if not rows and not benign:
        return []
    L = ["", "## Previously reported", ""]
    if rows:
        by_rep: dict[str, list] = {}
        for ioc, rep, ep in rows:
            by_rep.setdefault(rep["id"], []).append((ioc, ep))
        L += ["IOCs of this case that already appear in public reporting (OTX pulses mirror most vendor "
              "reports: DFIR Report, Unit42, …) or on public feeds (Feodo Tracker, C2IntelFeeds, OpenPhish, "
              "URLhaus). Context only: it doesn't change the cluster score. "
              "For IPs and domains, **Timing** compares the report date with when the IOC was used here.", "",
              "| Report / campaign | Source | Actor / malware | Reported | IOCs (timing) |", "|---|---|---|---|---|"]
        for rid, iocs in sorted(by_rep.items(), key=lambda kv: (-len(kv[1]), -(gr.nodes[kv[0]]["props"].get("date") or 0))):
            p = gr.nodes[rid]["props"]
            name = str(p.get("name", rid)).replace("|", "\\|")[:90]
            link = f"[{name}]({p['url']})" if p.get("url") else name
            who = ", ".join(x for x in [p.get("actor")] + list(p.get("malware") or []) if x).replace("|", "\\|") or "—"
            ioc_s = "<br>".join(f"`{i['value'][:70]}`" + (f" ({TIMING_NOTE[ep['timing']]})" if ep.get("timing") else "")
                                for i, ep in iocs[:8]) + (" …" if len(iocs) > 8 else "")
            when = p.get("date") or max((ep.get("last_seen") or 0 for _, ep in iocs), default=0)
            src = f"{p.get('source')} ({p['feed']})" if p.get("feed") else p.get("source")
            L.append(f"| {link} | {src} | {who} | {_day(when)} | {ioc_s} |")
        L.append("")
        # dataset reports: the other IOCs they list are leads for this case
        co = [(gr.nodes[rid]["props"], {i["value"] for i, _ in iocs}) for rid, iocs in by_rep.items()
              if gr.nodes[rid]["props"].get("other_iocs")]
        if co:
            L += ["**Other IOCs in the matching articles** (same campaign per the publication; not yet in this "
                  "case's graph unless listed above):", ""]
            for p, matched in co:
                rest = [x.split(":", 1) for x in p["other_iocs"]]
                rest = [(t, v) for t, v in rest if v not in matched]
                more = (p.get("n_iocs") or 0) - len(matched) - len(rest)
                L.append(f"- [{str(p.get('name', '')).replace(']', ')')[:90]}]({p.get('url')}): "
                         + ", ".join(f"{t} `{v[:80]}`" for t, v in rest)
                         + (f" … +{more} more" if more > 0 else ""))
            L.append("")
    if benign:
        L += ["Known-benign infrastructure (MISP warninglists, GreyNoise RIOT), never attributed:", ""]
        L += [f"- {n['type']} `{n['value']}`: {n['props']['warninglist']}" for n in benign[:40]]
        L.append("")
    return L


# sources that share data / owners count once: three abuse.ch feeds agreeing is one confirmation
SOURCE_GROUP = {"OTX": "OTX", "ThreatFox": "abuse.ch", "MalwareBazaar": "abuse.ch", "URLhaus": "abuse.ch",
                "Feodo Tracker": "abuse.ch", "C2IntelFeeds": "C2IntelFeeds", "OpenPhish": "OpenPhish",
                "VT comment": "VT community", "VT YARA": "YARA rules", "VT sandbox": "sandboxes",
                "VT AV consensus": "AV engines", "VT crowdsourced context": "VT partners", "Analyst": "analyst"}


def _strength(n: int, k: int) -> str:
    """n distinct IOCs, k independent source groups."""
    if (n >= 3 and k >= 2) or (n >= 2 and k >= 3):
        return "strong"
    return "medium" if n >= 2 or k >= 2 else "single lead"


def _assessment(inv, good: list[dict], in_view: int) -> list[str]:
    """Ready-to-paste assessment in estimative language. Confidence is capped at moderate: source
    agreement found by a tool is a lead for the analyst, not an attribution."""
    L = []
    for v in good:   # the analyst's call comes first and isn't capped: it's theirs
        if "analyst" in v["groups"]:
            what = "" if v["kind"] == "actor" else "malware family "
            L.append(f"- **Analyst:** {len(v['fits'])} IOC{'s' * (len(v['fits']) > 1)} of this case marked as "
                     f"{what}**{v['name']}**" + (f"; automated sources agreeing: {', '.join(sorted(v['groups'] - {'analyst'}))}"
                                                 if len(v["groups"]) > 1 else "") + ".")
    good = [v for v in good if not ("analyst" in v["groups"] and len(v["groups"]) == 1)]
    words = {"strong": ("is **likely** linked to", "moderate confidence"),
             "medium": ("**may** be linked to", "low confidence")}
    for kind, label in (("actor", "Actor"), ("malware", "Tooling")):
        top = [v for v in good if v["kind"] == kind]
        if not top:
            continue
        v = top[0]
        n, grp = len(v["fits"]), sorted(v["groups"])
        ev = (f"{n} of {in_view} IOCs in view, {len(grp)} independent source group{'s' * (len(grp) > 1)} "
              f"({', '.join(grp)}), first named {_day(v['first'])}")
        if v["strength"] in words:
            verb, conf = words[v["strength"]]
            subject = "The activity" if kind == "actor" else "The tooling"
            L.append(f"- **{label}:** {subject} {verb} **{v['name']}** ({conf}): {ev}.")
        else:
            L.append(f"- **{label}:** a single unconfirmed lead points to **{v['name']}**: {ev}.")
    if any(not x.startswith("- **Analyst:**") for x in L):
        L.append("- Confidence never goes above *moderate* here: raise it only after checking TTPs, "
                 "infrastructure overlap (see *Infrastructure overlap*) and the cited reports yourself.")
    return L


def _seen_before_section(inv) -> list[str]:
    """IOCs / fingerprints of this case that earlier cases already had (knowledge base)."""
    gr = inv.g
    rows = [n for n in gr.nodes.values() if n["props"].get("seen_in")
            and (n["props"].get("cluster") is True or n["props"].get("pinned"))]
    if not rows:
        return []
    cases = {x["case"]: x for n in rows for x in n["props"]["seen_in"]}
    L = ["", "## Seen in earlier cases", "",
         f"{len(rows)} IOCs / infrastructure fingerprints of this case were already in **{len(cases)} earlier "
         "case(s)** (only confirmed / analyst-pivoted IOCs and cluster fingerprints are remembered; noise never "
         "is). A shared certificate, HTML body or SOA email ties campaigns together far better than a shared IP.", "",
         "| IOC / fingerprint | Earlier case | Its seed | Date | There as | That case concluded |", "|---|---|---|---|---|---|"]
    order = {g.CERT: 0, g.HTML_HASH: 0, g.SCRIPT: 0, g.SOA: 0, g.FAVICON: 1, g.JARM: 1, g.FILE: 2, g.DOMAIN: 3,
             g.URL: 3, g.NS: 4, g.MX: 4, g.IP: 5}
    for n in sorted(rows, key=lambda n: (order.get(n["type"], 9), n["value"]))[:40]:
        for x in n["props"]["seen_in"][:3]:
            concl = ", ".join(x.get("actors", []) + x.get("families", [])) or "—"
            L.append(f"| {n['type']} `{n['value'][:60]}` | `{x['case']}` | `{str(x.get('seed', ''))[:50]}` | "
                     f"{_day(x.get('date'))} | {x.get('role')} | {concl} |")
    L.append("")
    return L


def _verdicts_section(inv) -> list[str]:
    gr = inv.g
    rows = [n for n in gr.nodes.values() if n["props"].get("analyst_verdict") or n["props"].get("analyst_actor")
            or n["props"].get("analyst_family")]
    if not rows:
        return []
    label = {"fp": "false positive", "confirmed": "confirmed"}
    L = ["", "## Analyst verdicts", "",
         "Set from the graph page or `--mark`, stored in the knowledge base and applied to every case: a false "
         "positive never joins a cluster and is triaged as noise, a confirmed IOC counts as a seed.", "",
         "| IOC | Verdict | Actor | Malware family | Note | Set in |", "|---|---|---|---|---|---|"]
    for n in sorted(rows, key=lambda n: (n["props"].get("analyst_verdict") or "", n["value"])):
        p = n["props"]
        L.append(f"| {n['type']} `{n['value'][:60]}` | {label.get(p.get('analyst_verdict'), '—')} | "
                 f"{p.get('analyst_actor') or '—'} | {p.get('analyst_family') or '—'} | "
                 f"{str(p.get('analyst_note') or '—').replace('|', '/')[:120]} | "
                 f"{p.get('analyst_case') or '—'} |")
    L.append("")
    return L


def attribution_votes(inv) -> dict[tuple[str, str], dict]:
    """{(kind, normalised name): vote} over every REPORTED_IN edge of an in-view IOC; each vote has
    fits / off (IOC ids), sources, independent groups, first date and strength."""
    gr = inv.g
    actors = getattr(inv, "actors", None)
    votes: dict[tuple[str, str], dict] = {}
    for (s, d, rel), ep in gr.edges.items():
        if rel != "REPORTED_IN" or s not in gr.nodes or d not in gr.nodes:
            continue
        ioc, p = gr.nodes[s], gr.nodes[d]["props"]
        if ioc["props"].get("cluster") is False and not ioc["props"].get("pinned") \
                or ioc["props"].get("analyst_verdict") == "fp":
            continue
        names = [("actor", a) for a in [p.get("actor")] if a] + [("malware", m) for m in p.get("malware") or []]
        for kind, name in names:
            if actors:   # aliases -> one name: Fancy Bear = APT28, wannacry = WannaCryptor
                name = (actors.canonical(name) if kind == "actor" else actors.family(name)) or name
            key = (kind, re.sub(r"[^a-z0-9]", "", name.lower()))
            v = votes.setdefault(key, {"kind": kind, "name": name, "fits": set(), "off": set(), "sources": set(),
                                       "groups": set(), "first": None})
            off = ep.get("timing") in ("earlier", "later")
            (v["off"] if off else v["fits"]).add(s)
            v["sources"].add(p.get("source") or "?")
            if not off:
                v["groups"].add(SOURCE_GROUP.get(p.get("source"), p.get("source") or "?"))
            if p.get("date") and (not v["first"] or p["date"] < v["first"]):
                v["first"] = p["date"]
    for v in votes.values():
        v["strength"] = _strength(len(v["fits"]), len(v["groups"]))
    return votes


def case_attribution(inv) -> dict:
    """What a case concluded, for the knowledge base: analyst labels + medium / strong names."""
    out = {"actors": [], "families": []}
    for v in attribution_votes(inv).values():
        if v["fits"] and ("analyst" in v["groups"] or v["strength"] in ("strong", "medium")):
            out["actors" if v["kind"] == "actor" else "families"].append(v["name"])
    return {k: sorted(set(x))[:8] for k, x in out.items()}


def _attribution_section(inv) -> list[str]:
    """Which actors / malware families do several independent IOCs of the case point to?

    Every REPORTED_IN edge (OTX adversary, ThreatFox / MalwareBazaar family, VT comment actor / family,
    feed family) is one vote from one IOC. Actor aliases are merged through the MISP galaxy (Fancy
    Bear = APT28). Votes whose timing doesn't fit (report older / newer than the IOC's use here) are
    shown apart: they're probably about a previous or next owner of the infrastructure."""
    gr = inv.g
    votes = attribution_votes(inv)
    comention = [(s, d, ep) for (s, d, rel), ep in gr.edges.items()
                 if rel == "CO_MENTIONED" and s in gr.nodes and d in gr.nodes]
    if not votes and not comention:
        return []
    L = ["", "## Attribution overlap", "",
         "Actors / malware families named for IOCs of this case, counted per **distinct IOC** and per "
         "**independent source group** (the abuse.ch feeds count once, so do all VT comments): OTX, abuse.ch, "
         "public feeds, crowdsourced YARA rules, sandboxes, AV consensus, VT partner context and VT comments. "
         "Aliases are merged via the MISP galaxy, family names via Malpedia. *strong* = 3+ IOCs from 2+ groups "
         "(or 2+ IOCs from 3+ groups), *medium* = 2 IOCs or 2 groups. Names only backed by IOCs whose timing "
         "doesn't fit are listed apart: infrastructure changes hands.", ""]
    rank = {"strong": 0, "medium": 1, "single lead": 2}
    rows = sorted(votes.values(), key=lambda v: ("analyst" not in v["groups"],
                                                 rank[v["strength"]] if v["fits"] else 3, -len(v["fits"]),
                                                 -len(v["groups"]), v["kind"], v["name"]))
    good = [v for v in rows if v["fits"]]
    in_view = sum(1 for n in gr.nodes.values() if n["type"] in ("File", "Domain", "IP", "URL")
                  and (n["props"].get("cluster") or n["props"].get("pinned")))
    L += _assessment(inv, good, in_view)
    if good:
        L += ["", "| | Actor / family | IOCs | Source groups | First named | Strength |", "|---|---|---|---|---|---|"]
        for v in good[:25]:
            n = len(v["fits"])
            iocs = ", ".join(f"`{gr.nodes[i]['value'][:40]}`" for i in sorted(v["fits"])[:4]) + (" …" if n > 4 else "")
            strength = f"**{v['strength']}**" if v["strength"] == "strong" else v["strength"]
            L.append(f"| {v['kind']} | **{v['name']}** | {n}: {iocs} | {', '.join(sorted(v['groups']))} | "
                     f"{_day(v['first'])} | {strength} |")
        acts = [v for v in good if v["kind"] == "actor" and len(v["fits"]) >= 2]
        if len(acts) > 1:
            L += ["", f"> Conflicting actors ({', '.join(v['name'] for v in acts[:4])}): shared tooling, a "
                  "false flag, or community tags copied between samples. Weigh the sources, not the counts."]
        L.append("")
    stale = [v for v in rows if not v["fits"] and v["off"]]
    if stale:
        L += ["Named only by reports that don't fit when the IOC was used here (previous / next owner?): "
              + ", ".join(f"{v['name']} ({len(v['off'])})" for v in stale[:15]), ""]
    if comention:
        L += ["### Co-mentioned in VT comments", "",
              "IOCs someone listed in the same VT comment as an IOC of this case. +1 in the cluster score only: "
              "confirmed ones had other evidence too. Pivot on the unconfirmed ones from the graph page.", "",
              "| IOC of the case | Listed with | In cluster | IOCs in comment | Date |", "|---|---|---|---|---|"]
        for s, d, ep in sorted(comention, key=lambda x: (not gr.nodes[x[1]]["props"].get("cluster"), x[0]))[:40]:
            cl = "yes" if gr.nodes[d]["props"].get("cluster") else "no"
            L.append(f"| `{gr.nodes[s]['value'][:50]}` | {gr.nodes[d]['type']} `{gr.nodes[d]['value'][:60]}` | "
                     f"{cl} | {ep.get('iocs_in_comment', '')} | {_day(ep.get('date'))} |")
        L.append("")
    return L
