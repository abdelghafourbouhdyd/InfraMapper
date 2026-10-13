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

The artefact weights come from ``PIVOT_RULES`` confidences (85+ -> 3, 60+ -> 2, 30+ -> 1), which the
hunting-rules page can tune. A combination rule (e.g. favicon + page title -> 80) replaces the sum of
its parts when a host shares all of them with the same confirmed host.
"""

from __future__ import annotations

from . import graph as g
from .patterns import apex_of
from .pdns import overlaps, window

HOSTS = (g.DOMAIN, g.IP, g.URL, g.FILE)
PIVOTS = (g.PATTERN, g.INTEL)   # search nodes, not facts about a host

# Built-in pivots: key -> (label, default confidence 0-100, artefact node types, pivot kinds).
# The confidence is what sharing one such artefact with a confirmed host is worth; the hunting-rules
# page can tune it and switch the pivot's search off. A "(refined)" pivot weighs as its kind; any
# other search node (domain-name patterns, regex hunts…) falls under "pattern".
PIVOT_RULES = {
    "html": ("HTML body hash", 85, {g.HTML_HASH}, {"html body"}),
    "script": ("First-party script hash", 85, {g.SCRIPT}, {"first-party script"}),
    "cert": ("TLS certificate", 85, {g.CERT}, set()),
    "soa": ("SOA contact email", 85, {g.SOA}, set()),
    "urlpath": ("URL path", 65, set(), {"url path"}),
    "custom": ("Analyst query", 65, set(), {"custom"}),
    "imphash": ("Imphash", 65, set(), {"imphash"}),
    "vhash": ("Vhash", 65, set(), {"vhash"}),
    "favicon": ("Favicon hash", 40, {g.FAVICON}, {"favicon"}),
    "title": ("Page title", 40, {g.TITLE}, {"title"}),
    "jarm": ("JARM", 40, {g.JARM}, {"jarm"}),
    "ns": ("Name server", 40, {g.NS}, set()),
    "mx": ("Mail server", 40, {g.MX}, set()),
    "pattern": ("Domain-name pattern / other search", 40, set(), set()),
}
SEARCHABLE = {"html", "script", "urlpath", "imphash", "vhash", "favicon", "title", "jarm", "pattern"}
STRONG_RELS = {"RESOLVES_TO", "CONTACTS", "DROPS", "DOWNLOADED_FROM", "REDIRECTS_TO",
               "SERVED_BY", "LOADS_FROM", "SAME_AS", "HOSTED_ON", "SERVED_FROM", "SERVES",
               "CNAME_TO"}

# analyst tuning (rules.RuleStore.apply): confidence overrides, searches switched off, combinations
_tuning: dict = {"confidence": {}, "off": set(), "combos": []}


def configure(confidence: dict[str, int] | None = None, off=(), combos: list[dict] | None = None) -> None:
    """``combos``: [{"name", "pivots": [key…], "confidence"}]: sharing all of these pivots with one
    confirmed host is worth ``confidence`` instead of the sum of the parts."""
    _tuning.update(confidence=dict(confidence or {}), off=set(off), combos=list(combos or []))


def points(confidence: int) -> int:
    """Cluster evidence points for a confidence: 85+ -> 3, 60+ -> 2, 30+ -> 1, else 0."""
    return 3 if confidence >= 85 else 2 if confidence >= 60 else 1 if confidence >= 30 else 0


def kind_key(kind: str) -> str | None:
    """Built-in pivot key for a search kind ("title", "url path (refined)"…); None for analyst searches."""
    k = (kind or "").removesuffix(" (refined)")
    if k == "custom":
        return None
    return next((key for key, (_, _, _, kinds) in PIVOT_RULES.items() if k in kinds), "pattern")


def search_enabled(kind: str) -> bool:
    """False when the analyst switched this built-in search off; analyst and regex searches always run."""
    key = kind_key(kind)
    if key == "pattern" and not (kind or "").startswith("domain pattern"):
        return True
    return key not in _tuning["off"]


def pivot_key(node: dict) -> str | None:
    if node["type"] in PIVOTS:
        return kind_key(node["props"].get("kind", "")) or "custom"
    return next((key for key, (_, _, types, _) in PIVOT_RULES.items() if node["type"] in types), None)


def pivot_confidence(node: dict) -> int:
    """What sharing this artefact is worth (0-100); 0 for non-artefacts and analyst false positives."""
    key = pivot_key(node)
    if key is None or node["props"].get("commodity") or _fp(node):
        return 0
    return _tuning["confidence"].get(key, PIVOT_RULES[key][1])


def _fp(node: dict) -> bool:
    return node["props"].get("analyst_verdict") == "fp"


def _weight(node: dict) -> int:
    return points(pivot_confidence(node))


def _label(node: dict) -> str:
    if node["type"] in PIVOTS:
        return f"{node['props'].get('kind', node['type'])} pivot"
    v = node["value"]
    return f"{node['type']} {v[:16] + '…' if len(v) > 18 else v}"


def _combo(shared: dict[str, list[tuple[int, str, set]]]) -> dict | None:
    """The combination rule this host meets (every pivot of it shared with the same confirmed host):
    the one covering the most pivots, then the highest confidence. None when no rule applies."""
    best = None
    for c in _tuning["combos"]:
        if not c["pivots"] or any(k not in shared for k in c["pivots"]):
            continue
        common = set.intersection(*(set().union(*(p for _, _, p in shared[k])) for k in c["pivots"]))
        rank = (len(c["pivots"]), c["confidence"])
        if common and (best is None or rank > best[0]):
            best = (rank, {**c, "peer": sorted(common)[0]})
    return best[1] if best else None


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
            shared: dict[str, list[tuple[int, str, set]]] = {}   # pivot key -> [(weight, evidence, confirmed peers)]
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
                    key = pivot_key(o)
                    if not peers or key is None or o["props"].get("commodity") or _fp(o):
                        continue
                    w = _weight(o)
                    ev = f"{_label(o)} shared with {gr.nodes[peers[0]]['value'][:40]}"
                    if key in ("ns", "mx"):
                        ev = f"{o['type']} {o['value'][:40]} shared with {gr.nodes[peers[0]]['value'][:40]}"
                        if w and apex_of(o["value"]) in zones:
                            w = max(w, 2)   # self-hosted under a cluster domain
                        # ns1/ns2/ns3 of one provider are one piece of evidence
                        best = shared.get(key, [(-1, "", set())])[0]
                        shared[key] = [max(best, (w, ev, set(peers)), key=lambda x: x[0])]
                    else:
                        shared.setdefault(key, []).append((w, ev, set(peers)))
            rule, covered = _combo(shared), set()
            if rule:
                covered = set(rule["pivots"])
                w = points(rule["confidence"])
                pts += w
                why.append(f"rule “{rule['name']}”: {' + '.join(PIVOT_RULES[k][0].lower() for k in rule['pivots'])} "
                           f"shared with {gr.nodes[rule['peer']]['value'][:40]} (+{w})")
            for key, items in shared.items():
                for w, ev, _ in items:
                    if key not in covered and w:
                        pts += w
                        why.append(f"{ev} (+{w})")
            if (node["props"].get("vt_malicious") or 0) > 0:
                pts += 1
                why.append(f"VT malicious {node['props']['vt_malicious']} (+1)")
            result[nid] = {"score": pts, "evidence": why, "confirmed": pts >= min_score,
                           "rule": {"name": rule["name"], "confidence": rule["confidence"],
                                    "peer": rule["peer"]} if rule else None}
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
                    cluster_evidence=r["evidence"], rule_match=r.get("rule"))
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
