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

Each pivot's weight comes from its confidence in ``PIVOT_RULES`` (85+ -> 3, 60+ -> 2, 30+ -> 1),
tunable on the hunting-rules page. Analyst pivot logic (rules.py custom rules) creates its own pivot
nodes, weighted by the rule's confidence.
"""

from __future__ import annotations

from . import graph as g
from .patterns import apex_of
from .pdns import overlaps, window

HOSTS = (g.DOMAIN, g.IP, g.URL, g.FILE)
PIVOTS = (g.PATTERN, g.INTEL)   # search nodes, not facts about a host

# Built-in pivots, all tunable from the hunting-rules page:
#   label, what it does, confidence (what sharing one such artefact with a confirmed host is worth),
#   fidelity (specificity of the artefact, scoring.py), artefact node types, search kinds, and the
#   parameters it takes. ``template`` is the search, ``{value}`` the artefact found on the host;
#   ``max_hits`` None = the run's --broad; ``steps`` None = the run's regex steps.
# A "(refined)" pivot weighs as its kind; any other search node falls under "pattern".
PIVOT_RULES = {
    "title": {"label": "Page title", "about": "urlscan search for the page title of each scan",
              "confidence": 40, "fidelity": 30, "types": {g.TITLE}, "kinds": {"title"},
              "params": {"template": 'page.title:"{value}"', "max_hits": None, "refine": True}},
    "favicon": {"label": "Favicon hash", "about": "urlscan search for the favicon's SHA-256",
                "confidence": 40, "fidelity": 50, "types": {g.FAVICON}, "kinds": {"favicon"},
                "params": {"template": "hash:{value}", "max_hits": None, "refine": True}},
    "html": {"label": "HTML body hash", "about": "urlscan search for the main HTML document's SHA-256",
             "confidence": 85, "fidelity": 85, "types": {g.HTML_HASH}, "kinds": {"html body"},
             "params": {"template": "hash:{value}", "max_hits": None, "refine": True}},
    "script": {"label": "First-party script hash", "about": "urlscan search for the site's own scripts (3 per scan)",
               "confidence": 85, "fidelity": 80, "types": {g.SCRIPT}, "kinds": {"first-party script"},
               "params": {"template": "hash:{value}", "max_hits": None, "refine": True}},
    "urlpath": {"label": "URL path", "about": "urlscan search for the distinctive part of the URL path",
                "confidence": 65, "fidelity": 30, "types": set(), "kinds": {"url path"},
                "params": {"max_hits": None, "refine": True}},
    "pattern": {"label": "Domain-name patterns", "about": "urlscan look-alike searches built from each "
                "domain name (other TLDs, name skeleton, token combos, subdomain structure)",
                "confidence": 40, "fidelity": 30, "types": set(), "kinds": set(),
                "params": {"max_hits": None}},
    "regex": {"label": "Regex hunt", "about": "regex ladder on the cluster's domain names, tightened "
              "step by step until specific enough", "confidence": 40, "fidelity": 30, "types": set(),
              "kinds": {"domain pattern (regex)"}, "params": {"steps": None}},
    "jarm": {"label": "JARM", "about": "VT Intelligence search for the TLS fingerprint (premium key, --vt-intel)",
             "confidence": 40, "fidelity": 35, "types": {g.JARM}, "kinds": {"jarm"},
             "params": {"template": "entity:domain jarm:{value}"}},
    "imphash": {"label": "Imphash", "about": "VT Intelligence search for the file's import hash (--vt-intel)",
                "confidence": 65, "fidelity": 30, "types": set(), "kinds": {"imphash"},
                "params": {"template": "imphash:{value}"}},
    "vhash": {"label": "Vhash", "about": "VT Intelligence search for the file's vhash (--vt-intel)",
              "confidence": 65, "fidelity": 30, "types": set(), "kinds": {"vhash"},
              "params": {"template": 'vhash:"{value}"'}},
    "cert": {"label": "TLS certificate", "about": "certificate shared between hosts (no search of its own)",
             "confidence": 85, "fidelity": 80, "types": {g.CERT}, "kinds": set(), "params": {}},
    "soa": {"label": "SOA contact email", "about": "SOA contact shared between domains (no search of its own)",
            "confidence": 85, "fidelity": 80, "types": {g.SOA}, "kinds": set(), "params": {}},
    "ns": {"label": "Name server", "about": "name server shared between domains", "confidence": 40,
           "fidelity": 40, "types": {g.NS}, "kinds": set(), "params": {}},
    "mx": {"label": "Mail server", "about": "mail server shared between domains", "confidence": 40,
           "fidelity": 40, "types": {g.MX}, "kinds": set(), "params": {}},
    "custom": {"label": "Analyst query", "about": "your own -q queries and graph-page searches (always run)",
               "confidence": 65, "fidelity": 30, "types": set(), "kinds": {"custom"}, "params": {}},
}
SEARCHABLE = {"title", "favicon", "html", "script", "urlpath", "pattern", "regex", "jarm", "imphash", "vhash"}
STRONG_RELS = {"RESOLVES_TO", "CONTACTS", "DROPS", "DOWNLOADED_FROM", "REDIRECTS_TO",
               "SERVED_BY", "LOADS_FROM", "SAME_AS", "HOSTED_ON", "SERVED_FROM", "SERVES",
               "CNAME_TO"}

# analyst tuning (rules.RuleStore.apply): {key: {"enabled", "confidence", "fidelity", <param>…}}
# overrides of the built-in pivots, and the enabled custom rules by id
_tuning: dict = {"pivots": {}, "custom": {}}


def configure(pivots: dict[str, dict] | None = None, custom: list[dict] | None = None) -> None:
    _tuning.update(pivots=dict(pivots or {}), custom={r["id"]: r for r in custom or []})


def custom_rules() -> list[dict]:
    return list(_tuning["custom"].values())


def setting(key: str, name: str):
    """A built-in pivot's current value of ``name`` (enabled, confidence, fidelity or a parameter)."""
    t = _tuning["pivots"].get(key) or {}
    if name in t:
        return t[name]
    if name == "enabled":
        return True
    p = PIVOT_RULES[key]
    return p[name] if name in ("confidence", "fidelity") else p["params"].get(name)


def points(confidence: int) -> int:
    """Cluster evidence points for a confidence: 85+ -> 3, 60+ -> 2, 30+ -> 1, else 0."""
    return 3 if confidence >= 85 else 2 if confidence >= 60 else 1 if confidence >= 30 else 0


def kind_key(kind: str) -> str | None:
    """Pivot key for a search kind ("title", "url path (refined)", "rule:<id>"…); None for analyst searches."""
    k = (kind or "").removesuffix(" (refined)")
    if k == "custom":
        return None
    if k.startswith("rule:"):
        return k
    return next((key for key, p in PIVOT_RULES.items() if k in p["kinds"]), "pattern")


def search_enabled(kind: str) -> bool:
    """False when the analyst switched this search off; analyst queries and regexes always run."""
    key = kind_key(kind)
    if key is None or key.startswith("rule:") or key == "pattern" and not (kind or "").startswith("domain pattern"):
        return True
    return bool(setting(key, "enabled"))


def query(key: str, value: str) -> str:
    """A built-in pivot's search for one artefact value, from its (tunable) template."""
    return setting(key, "template").replace("{value}", value)


def max_hits(kind: str, default: int) -> int:
    """Hits above which this search is too broad to expand."""
    key = kind_key(kind)
    if key and key.startswith("rule:"):
        v = (_tuning["custom"].get(key[5:]) or {}).get("max_hits")
    else:
        v = setting(key, "max_hits") if key in PIVOT_RULES else None
    return v or default


def refine_enabled(kind: str) -> bool:
    key = kind_key(kind)
    return key not in PIVOT_RULES or setting(key, "refine") is not False


def pivot_key(node: dict) -> str | None:
    if node["type"] in PIVOTS:
        return kind_key(node["props"].get("kind", "")) or "custom"
    return next((key for key, p in PIVOT_RULES.items() if node["type"] in p["types"]), None)


def _rated(node: dict, name: str) -> int | None:
    key = pivot_key(node)
    if key is None:
        return None
    if key.startswith("rule:"):   # analyst rule: current settings, else those it ran with
        r = _tuning["custom"].get(key[5:]) or node["props"]
        return r.get(name, PIVOT_RULES["pattern"][name])
    return setting(key, name)


def pivot_confidence(node: dict) -> int:
    """What sharing this artefact is worth (0-100); 0 for non-artefacts and analyst false positives."""
    if node["props"].get("commodity") or _fp(node):
        return 0
    return _rated(node, "confidence") or 0


def pivot_fidelity(node: dict) -> int | None:
    """Specificity of a pivot / artefact node (0-100); None when the node is not one."""
    return _rated(node, "fidelity")


def _fp(node: dict) -> bool:
    return node["props"].get("analyst_verdict") == "fp"


def _weight(node: dict) -> int:
    return points(pivot_confidence(node))


def _label(node: dict) -> str:
    if node["type"] in PIVOTS:
        if node["props"].get("rule"):
            return f"rule “{node['props']['rule']}” pivot"
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
                            w = max(w, 2)   # self-hosted under a cluster domain
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
