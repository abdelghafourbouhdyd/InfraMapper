"""Cluster confidence: decide which discovered hosts really belong to the seed's cluster.

Pivots return lots of look-alikes (same title, similar name, same favicon…). A host is only
*confirmed* once the evidence tying it to already-confirmed nodes adds up to ``min_score``:

* direct relation to the seed (its parent domain only 1) ............... 2
* strong direct relation to another confirmed host (resolves, contacts,
  drops, redirects, served by, loads from…) ............................ 1
* resolved to a dedicated (non shared-hosting) IP *during the same window*
  as a confirmed domain (passive DNS) ................................... 2
* sharing an artefact with a confirmed host, weighted by how specific it is:
  HTML body / first-party script hash / TLS certificate / SOA contact email 3,
  url-path or analyst query / imphash / vhash 2, domain-name pattern / title / favicon / JARM 1
* nameserver / mail server: 2 when it's self-hosted under a cluster domain (ns1.<cluster
  domain>), otherwise 1 — registrar DNS lists are never complete, so a third-party NS needs
  corroboration. Counted once per type; known commodity providers (Cloudflare…) count 0.
* listed in the same VT community comment as a confirmed host (even the seed) 1
* VirusTotal flags it malicious ........................................ 1

Analyst verdicts (knowledge base) override the score: *confirmed* nodes are co-seeds, *false
positive* nodes are never confirmed and weigh 0 as a shared artefact.

Confirmation is iterated to a fixpoint, so a host confirmed through the seed can confirm others.
"""

from __future__ import annotations

from . import graph as g
from .patterns import apex_of
from .pdns import overlaps, window

HOSTS = (g.DOMAIN, g.IP, g.URL, g.FILE)
PIVOTS = (g.PATTERN, g.INTEL)   # search nodes, not facts about a host

ARTEFACT_WEIGHT = {g.HTML_HASH: 3, g.SCRIPT: 3, g.CERT: 3, g.FAVICON: 1, g.TITLE: 1, g.JARM: 1,
                   g.SOA: 3, g.NS: 1, g.MX: 1}
PATTERN_WEIGHT = {"url path": 2, "custom": 2, "imphash": 2, "vhash": 2, "jarm": 1,
                  "html body": 3, "first-party script": 3}  # else 1; a "(refined)" pivot weighs as its kind
STRONG_RELS = {"RESOLVES_TO", "CONTACTS", "DROPS", "DOWNLOADED_FROM", "REDIRECTS_TO",
               "SERVED_BY", "LOADS_FROM", "SAME_AS", "HOSTED_ON", "SERVED_FROM", "SERVES",
               "CNAME_TO"}


def _fp(node: dict) -> bool:
    return node["props"].get("analyst_verdict") == "fp"


def _weight(node: dict) -> int:
    if node["props"].get("commodity") or _fp(node):   # analyst said this artefact proves nothing
        return 0
    if node["type"] in PIVOTS:
        kind = node["props"].get("kind", "").removesuffix(" (refined)")
        return PATTERN_WEIGHT.get(kind, 1)
    return ARTEFACT_WEIGHT.get(node["type"], 0)


def _label(node: dict) -> str:
    if node["type"] in PIVOTS:
        return f"{node['props'].get('kind', node['type'])} pivot"
    v = node["value"]
    return f"{node['type']} {v[:16] + '…' if len(v) > 18 else v}"


def score(gr: g.Graph, seed: str, min_score: int = 2) -> dict[str, dict]:
    """Return {node id: {"score", "evidence", "confirmed"}} for every host node."""
    adj: dict[str, list[tuple[str, str, bool]]] = {}   # node -> [(other, rel, node is source)]
    for (s, d, rel) in gr.edges:
        adj.setdefault(s, []).append((d, rel, True))
        adj.setdefault(d, []).append((s, rel, False))

    def concurrent(dom: str, ip: str, confirmed: set[str]) -> str | None:
        """A confirmed domain that sat on the same IP during an overlapping pDNS window."""
        win = window(gr.edges.get((dom, ip, "RESOLVES_TO"), {}))
        if not win:
            return None
        for peer, rel, _ in adj.get(ip, []):
            if peer == dom or peer not in confirmed or rel != "RESOLVES_TO":
                continue
            pw = window(gr.edges.get((peer, ip, "RESOLVES_TO"), {}))
            if pw and overlaps(win, pw):
                return gr.nodes[peer]["value"]
        return None

    # report triage (--from): every non-benign IOC the report lists is a seed as well
    # ... and so is everything an analyst confirmed; an analyst false positive never is
    co_seeds = {nid for nid, n in gr.nodes.items() if (n["props"].get("input_ioc") and not n["props"].get("warninglist")
                                                        or n["props"].get("analyst_verdict") == "confirmed")
                and not _fp(n) and nid != seed}
    confirmed = {seed} | co_seeds
    result: dict[str, dict] = {}
    changed = True
    while changed:
        changed = False
        zones = {apex_of(gr.nodes[c]["value"]) for c in confirmed if gr.nodes[c]["type"] == g.DOMAIN}
        for nid, node in gr.nodes.items():
            if node["type"] not in HOSTS or nid in confirmed:
                continue
            if _fp(node):
                result[nid] = {"score": 0, "evidence": ["analyst: false positive"], "confirmed": False}
                continue
            pts, why, used = 0, [], set()
            dns_best: dict[str, tuple[int, str]] = {}   # NS / MX -> best (weight, evidence)
            for other, rel, outgoing in adj.get(nid, []):
                if other in used:
                    continue
                used.add(other)
                o = gr.nodes[other]
                if other in confirmed and o["type"] in HOSTS:
                    if o["props"].get("shared_hosting") and rel == "RESOLVES_TO":
                        continue    # co-hosted on a CDN / shared IP proves nothing
                    w = 2 if other == seed or other in co_seeds else (1 if rel in STRONG_RELS else 0)
                    if rel == "HAS_SUBDOMAIN" and outgoing:
                        w = 1   # parent domain (e.g. us.com, a free-DNS zone) isn't proof by itself
                    if rel == "CO_MENTIONED":
                        w = 1   # listed together in a VT comment: someone's opinion, needs corroboration
                    if rel == "SHARES_DOMAINS":
                        w = 0   # summary edge: the shared domains' own RESOLVES_TO edges already score
                    peer = None
                    if rel == "RESOLVES_TO" and outgoing and o["type"] == g.IP and w < 2:
                        peer = concurrent(nid, other, confirmed)
                        if peer:
                            w = 2
                    if w:
                        pts += w
                        why.append(f"{rel} {o['value'][:40]}"
                                   + (f" at the same time as {peer[:40]}" if peer else "") + f" (+{w})")
                elif o["type"] not in HOSTS and not o["props"].get("broad"):
                    # shared artefact / pivot: counts if it also touches a confirmed host
                    peers = [p for p, _, _ in adj.get(other, []) if p != nid and p in confirmed]
                    w = _weight(o)
                    if o["type"] in (g.NS, g.MX) and w and peers:
                        if apex_of(o["value"]) in zones:
                            w = 2       # self-hosted under a cluster domain
                        # ns1/ns2/ns3 of one provider are one piece of evidence
                        ev = f"{o['type']} {o['value'][:40]} shared with {gr.nodes[peers[0]]['value'][:40]}"
                        dns_best[o["type"]] = max(dns_best.get(o["type"], (0, "")), (w, ev))
                    elif peers and w:
                        pts += w
                        why.append(f"{_label(o)} shared with {gr.nodes[peers[0]]['value'][:40]} (+{w})")
            for w, ev in dns_best.values():
                pts += w
                why.append(f"{ev} (+{w})")
            if (node["props"].get("vt_malicious") or 0) > 0:
                pts += 1
                why.append(f"VT malicious {node['props']['vt_malicious']} (+1)")
            result[nid] = {"score": pts, "evidence": why, "confirmed": pts >= min_score}
            if pts >= min_score:
                confirmed.add(nid)
                changed = True
    result[seed] = {"score": None, "evidence": ["seed"], "confirmed": True}
    for nid in co_seeds:
        why = "confirmed by an analyst" if gr.nodes[nid]["props"].get("analyst_verdict") == "confirmed" \
            else "listed in the input report"
        result[nid] = {"score": None, "evidence": [why], "confirmed": True}
    return result


def apply(gr: g.Graph, seed: str, min_score: int = 2) -> set[str]:
    """Tag nodes with cluster membership; returns the ids of every node in the cluster view."""
    res = score(gr, seed, min_score)
    confirmed = {n for n, r in res.items() if r["confirmed"]}
    for nid, r in res.items():
        gr.set_prop(nid, cluster=r["confirmed"], cluster_score=r["score"],
                    cluster_evidence=r["evidence"])
    # Non-host nodes are kept when they hang off a confirmed host; pivot searches only when
    # they tie at least two confirmed hosts together (otherwise they're just a query we ran).
    keep = set(confirmed)
    # hosts an analyst pivoted to (--serve) are in view too, so are their certs / reports / ASNs
    shown = confirmed | {n for n, node in gr.nodes.items() if node["props"].get("pinned")}
    for nid, node in gr.nodes.items():
        if node["type"] in HOSTS:
            continue
        linked = {d for (s, d, _) in gr.edges if s == nid} | {s for (s, d, _) in gr.edges if d == nid}
        hosts = linked & shown
        need = 2 if node["type"] in PIVOTS else 1
        in_view = len(hosts) >= need
        gr.set_prop(nid, cluster=in_view)
        if in_view:
            keep.add(nid)
    return keep
