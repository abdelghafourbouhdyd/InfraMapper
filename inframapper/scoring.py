"""Fidelity and confidence scores for pivot results (heuristic, method ``heuristic-v1``).

Two separate questions, two scores on 0-100:

**Confidence**: how strongly the evidence supports that this entity is related to the
investigation (the seed and what the analyst pivoted from). It only weighs *relationship*
evidence: who observed the link, how direct the observation is, whether independent sources agree,
how recent it is, and what contradicts it.

**Fidelity**: how relevant and useful the entity is for *this* investigation: is the indicator
specific (a file hash vs. a shared IP), how close is it to the seed, does it carry threat signal,
is it recent, and how likely is it to be a false positive.

Both are **heuristic scores, not calibrated probabilities**. A confidence of 80 does not mean an
80 % chance of being right; it ranks evidence consistently and every point is explained in
``factors``. Where data is missing the score says so in ``limited`` instead of guessing.

Method
------
1. Relationship (edge) confidence, per pair of linked entities::

       item(source)  = observation strength of the relation  x  reliability of the source
       raw           = 1 - prod(1 - best item per independent source group)      (noisy-OR)
       confidence    = raw  x  freshness  x  conflict penalties

   Observation strength (``REL_STRENGTH``): a certificate served by the host (0.90) or a DNS
   resolution (0.85) is a direct observation; a string embedded in a binary (0.55) or a VT
   community comment listing both (0.45) is not. Source reliability (``SOURCES``): CT logs and
   live DNS 0.95, VirusTotal / passive DNS 0.85, urlscan 0.80, OTX 0.60, VT comments 0.45.
   Two sources in the same group (e.g. two VT relations) never count as corroboration.

2. Entity confidence: the strongest chain of relationships from the seed (product of edge
   confidences, like a "weakest links" path), then corroboration from other already-scored
   neighbours with diminishing returns (2nd support x0.5, 3rd x0.25: supports can share upstream
   evidence). Passing *through* a shared artefact costs its specificity, reusing cluster.py's
   artefact weights (HTML body / script / cert / SOA 3 -> 0.85, url path / imphash 2 -> 0.65,
   title / favicon / JARM / NS 1 -> 0.40); shared hosting, CDNs, commodity NS and noisy hubs
   pass almost nothing (0.15). One source group alone is capped at 80.

3. Fidelity = 100 x (0.30 specificity + 0.25 confidence + 0.20 context + 0.15 threat signal
   + 0.10 freshness) x false-positive risk x relevance gate. The gate (0.4 + 0.6 x confidence /
   0.4, full at confidence >= 40) stops a specific but barely-linked look-alike from ranking as
   relevant. Every term is listed with its points in ``factors``.

Analyst verdicts win: *confirmed* -> confidence >= 95, *false positive* -> confidence <= 5.
"""

from __future__ import annotations

import heapq
import math
import time
from datetime import datetime, timezone

from . import graph as g
from .cluster import HOSTS, PIVOTS, _weight as artefact_weight

METHOD = {
    "name": "heuristic-v1",
    "calibrated": False,
    "summary": "Explainable heuristic on 0-100, not a calibrated probability. Confidence = strength of the "
               "evidence linking the entity to the investigation (observation type x source reliability, "
               "independent-source corroboration, freshness, conflicts). Fidelity = usefulness for this "
               "investigation (30% specificity, 25% confidence, 20% context, 15% threat signal, 10% freshness) "
               "x false-positive risk x a relevance gate when confidence is below 40.",
    "bands": [[75, "high"], [50, "medium"], [25, "low"], [0, "very low"]],
    "weights": {"specificity": .30, "confidence": .25, "context": .20, "threat": .15, "freshness": .10},
}

# observation strength of a relation (0-1): how directly it shows the two entities are linked
REL_STRENGTH = {
    "ANALYST_PIVOT": 1.0, "REFINED_TO": 1.0, "SAME_AS": .95, "HAS_SUBDOMAIN": .95, "HOSTED_ON": .95,
    "USES_CERT": .90, "SERVES_HTML": .90, "IN_ASN": .90, "HAS_IMPHASH": .90, "HAS_VHASH": .90,
    "RESOLVES_TO": .85, "CNAME_TO": .85, "NAMED_IN_CERT": .85, "HAS_JARM": .85, "SERVES_SCRIPT": .85,
    "HAS_FAVICON": .85, "HAS_TITLE": .85, "HAS_URL": .85, "DROPS": .85, "SERVES": .85, "SERVED_FROM": .85,
    "REDIRECTS_TO": .85, "USES_NS": .85, "USES_MX": .85, "HOSTS_NS": .85,
    "CONTACTS": .80, "DOWNLOADED_FROM": .80, "SOA_CONTACT": .80, "MENTIONS": .80,
    "LOADS_FROM": .75, "SEEN_ON": .75, "MATCHES_PATTERN": .75, "MATCHES": .70,
    "REPORTED_IN": .60, "SHARES_DOMAINS": .60, "EMBEDS": .55, "LABELLED": .50, "CO_MENTIONED": .45,
}
REL_LABEL = {
    "RESOLVES_TO": "DNS resolution", "USES_CERT": "served TLS certificate", "HAS_JARM": "TLS server fingerprint",
    "CONTACTS": "sandbox network contact", "DROPS": "dropped by / drops", "EMBEDS": "string embedded in a file",
    "CO_MENTIONED": "listed together in a VT comment", "REPORTED_IN": "listed in a report / feed",
    "SEEN_ON": "search hit", "MATCHES_PATTERN": "pivot origin", "HAS_SUBDOMAIN": "parent zone",
    "HOSTED_ON": "URL host", "USES_NS": "name server", "USES_MX": "mail server", "IN_ASN": "announced by ASN",
}
# source -> (independent group, reliability 0-1); matched on the lower-cased source's prefix
SOURCES = [
    ("analyst", "Analyst", 1.0), ("structure", "Structural", 1.0), ("live dns", "Live DNS", .95),
    ("crt.sh", "Cert Transparency", .95), ("cert spotter", "Cert Transparency", .95), ("ct", "Cert Transparency", .95),
    ("vt comment", "VT community", .45), ("vt av", "VT verdicts", .55), ("vt sandbox", "VT verdicts", .60),
    ("vt yara", "VT verdicts", .60), ("vt intelligence", "VirusTotal", .85), ("vt", "VirusTotal", .85),
    ("virustotal", "VirusTotal", .85), ("shodan", "Shodan", .85), ("urlscan", "urlscan", .80),
    ("mnemonic", "Passive DNS", .85), ("circl", "Passive DNS", .85), ("pdns", "Passive DNS", .85),
    ("passive dns", "Passive DNS", .85), ("feodo", "abuse.ch", .80), ("threatfox", "abuse.ch", .80),
    ("urlhaus", "abuse.ch", .80), ("malwarebazaar", "abuse.ch", .80), ("spamhaus", "Spamhaus", .85),
    ("otx", "OTX", .60), ("greynoise", "GreyNoise", .75), ("openphish", "OpenPhish", .75),
    ("c2intel", "C2IntelFeeds", .65), ("input report", "Input report", .75), ("nrd", "NRD list", .50),
]
# relation -> source when the edge didn't record one (cases saved before sources were tracked)
DEFAULT_SOURCE = {
    "CONTACTS": "VirusTotal", "DROPS": "VirusTotal", "EMBEDS": "VirusTotal", "DOWNLOADED_FROM": "VirusTotal",
    "SERVES": "VirusTotal", "SERVED_FROM": "VirusTotal", "REDIRECTS_TO": "VirusTotal", "LABELLED": "VirusTotal",
    "HAS_IMPHASH": "VirusTotal", "HAS_VHASH": "VirusTotal", "SAME_AS": "VirusTotal", "IN_ASN": "VirusTotal",
    "USES_CERT": "VirusTotal", "HAS_JARM": "VirusTotal", "HAS_TITLE": "urlscan", "HAS_FAVICON": "urlscan",
    "SERVES_HTML": "urlscan", "SERVES_SCRIPT": "urlscan", "MATCHES_PATTERN": "urlscan", "REFINED_TO": "urlscan",
    "HAS_SUBDOMAIN": "Structural", "HOSTED_ON": "Structural", "ANALYST_PIVOT": "Analyst", "MENTIONS": "Input report",
}
# indicator specificity (0-1) by type: how uniquely it identifies attacker infrastructure
SPECIFICITY = {g.FILE: 1.0, g.URL: .85, g.HTML_HASH: .85, g.SCRIPT: .80, g.SOA: .80, g.CERT: .80,
               g.DOMAIN: .75, g.IP: .60, g.FAVICON: .50, g.NS: .40, g.MX: .40, g.JARM: .35, g.TITLE: .30,
               g.REPORT: .40, g.LABEL: .20, g.ASN: .10}
PIVOTABLE = {g.FILE, g.DOMAIN, g.IP, g.URL, g.CERT}
PRIORITY_SIGNAL = {"P1": 1.0, "P2": .85, "P3": .60, "P4": .40, "lead-strong": .55, "lead-medium": .45,
                   "lead-weak": .35, "noise": .05}
DAY = 86400


def band(score: int | None) -> str:
    if score is None:
        return "insufficient"
    return next(name for lo, name in METHOD["bands"] if score >= lo)


def source_info(src: str) -> tuple[str, float]:
    s = str(src or "").strip().lower()
    for prefix, group, rel in SOURCES:
        if s.startswith(prefix):
            return group, rel
    return (str(src) or "Unknown"), .65


def ts(v) -> int | None:
    """Epoch seconds from an int / float / ISO string; None when absent or unparseable."""
    if isinstance(v, bool) or v in (None, "", 0):
        return None
    if isinstance(v, (int, float)):
        return int(v / 1000) if v > 1e12 else int(v)
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return int((d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp())


def edge_time(p: dict) -> int | None:
    return max((t for t in (ts(p.get(k)) for k in ("last_seen", "date", "first_seen")) if t),
               default=None)


def edge_sources(rel: str, p: dict) -> tuple[list[str], bool]:
    """Sources that asserted this relation, and whether they had to be inferred from the relation."""
    out = [p["source"]] if p.get("source") else []
    out += [s for s in p.get("seen_by") or [] if s not in out]
    if out:
        return out, False
    return [DEFAULT_SOURCE.get(rel, "Unknown")], True


def freshness(t: int | None, now: float) -> tuple[float, str]:
    """Confidence multiplier for the age of the newest observation (mild: old links stay true)."""
    if not t:
        return .9, "no observation date (x0.90)"
    days = max(0, (now - t) / DAY)
    for lim, f in ((90, 1.0), (365, .9), (730, .8)):
        if days <= lim:
            return f, f"last observed {days:.0f} days ago (x{f:.2f})"
    return .7, f"last observed {days / 365:.1f} years ago: stale (x0.70)"


def _fp(n: dict) -> bool:
    return n["props"].get("analyst_verdict") == "fp"


def hub_factor(n: dict, degree: int) -> tuple[float, str | None]:
    """What passing *through* this node to reach another entity is worth (0-1)."""
    p, t = n["props"], n["type"]
    if _fp(n):
        return .05, "analyst false positive"
    if t in HOSTS:
        if p.get("shared_hosting") or p.get("warninglist") or p.get("tor_exit") or p.get("c2_fronting"):
            return .15, "shared / benign infrastructure"
        f = 1.0
    elif t in PIVOTS or t in (g.HTML_HASH, g.SCRIPT, g.CERT, g.FAVICON, g.TITLE, g.JARM, g.SOA, g.NS, g.MX):
        w = artefact_weight(n)
        f = {3: .85, 2: .65, 1: .40}.get(w, .15)
        if t == g.CERT and p.get("shared_cert"):
            f = min(f, .30)
    else:   # ASN, reports, labels: many unrelated members
        f = {g.REPORT: .35, g.LABEL: .20, g.ASN: .10}.get(t, .30)
    why = None
    if p.get("broad"):
        f *= .5
        why = "too-broad pivot"
    if degree > 25 and t not in HOSTS:   # a hub tying many entities proves less about each
        f *= max(.3, 25 / degree)
        why = why or f"hub with {degree} links"
    return f, why


class Scorer:
    def __init__(self, nodes: dict[str, dict], edges: dict[tuple[str, str, str], dict], seed: str,
                 now: float | None = None):
        self.nodes, self.edges, self.seed = nodes, edges, seed
        self.now = now or time.time()
        self.pairs: dict[frozenset, list[tuple[str, str, str, dict]]] = {}
        self.adj: dict[str, set[str]] = {}
        for (s, d, rel), p in edges.items():
            if s not in nodes or d not in nodes or s == d:
                continue
            self.pairs.setdefault(frozenset((s, d)), []).append((s, d, rel, p))
            self.adj.setdefault(s, set()).add(d)
            self.adj.setdefault(d, set()).add(s)
        self._pair_cache: dict[frozenset, dict] = {}

    # ------------------------------------------------------------------ relationships
    def pair(self, a: str, b: str) -> dict:
        """Confidence that entities a and b are related, from every edge between them."""
        key = frozenset((a, b))
        if key in self._pair_cache:
            return self._pair_cache[key]
        best: dict[str, tuple[float, str]] = {}
        inferred, times, conflicts, rels = False, [], [], []
        for s, d, rel, p in self.pairs.get(key, []):
            rels.append(rel)
            srcs, inf = edge_sources(rel, p)
            inferred |= inf
            strength = REL_STRENGTH.get(rel, .5)
            for src in srcs:
                grp, rel_w = source_info(src)
                item = strength * rel_w
                if item > best.get(grp, (0, ""))[0]:
                    best[grp] = (item, f"{REL_LABEL.get(rel, rel)} via {src}"
                                       f" (strength {strength:.2f} x reliability {rel_w:.2f})")
            t = edge_time(p)
            if t:
                times.append(t)
            if rel == "REPORTED_IN" and p.get("timing") in ("earlier", "later"):
                conflicts.append((.5, f"report dates fall {p['timing']} than the usage window: may concern "
                                      "another owner (x0.50)"))
            if rel == "RESOLVES_TO":
                dom, ip = (self.nodes[s], self.nodes[d])
                now_ips = dom["props"].get("resolves_now")
                if dom["type"] == g.DOMAIN and isinstance(now_ips, list) and now_ips and ip["value"] not in now_ips:
                    conflicts.append((.85, f"{dom['value'][:40]} resolves elsewhere now (x0.85)"))
        for nid in (a, b):
            if _fp(self.nodes[nid]):
                conflicts.append((.2, f"analyst marked {self.nodes[nid]['value'][:40]} a false positive (x0.20)"))
        raw = 1 - math.prod(1 - v for v, _ in best.values()) if best else 0.0
        last = max(times) if times else None
        fresh, fresh_why = freshness(last, self.now)
        conf = raw * fresh * math.prod(f for f, _ in conflicts)
        factors = [{"kind": "support", "label": why, "value": round(v * 100)} for v, why in
                   sorted(best.values(), reverse=True)]
        if len(best) > 1:
            factors.append({"kind": "support", "label": f"{len(best)} independent source groups agree "
                                                         f"({', '.join(sorted(best))}): combined {raw * 100:.0f}"})
        factors.append({"kind": "info" if fresh == 1 else "limit", "label": fresh_why})
        factors += [{"kind": "conflict", "label": why} for _, why in conflicts]
        limited = []
        if inferred:
            limited.append("source not recorded on this relation (inferred from its type)")
        if not last:
            limited.append("no dated observation")
        if len(best) == 1:
            limited.append("single source")
        out = {"confidence": round(min(conf, .99) * 100), "sources": sorted(best), "rels": sorted(set(rels)),
               "last_seen": last, "stale": bool(last and self.now - last > 365 * DAY), "factors": factors,
               "conflicts": [why for _, why in conflicts], "limited": limited}
        out["band"] = band(out["confidence"])
        self._pair_cache[key] = out
        return out

    # ------------------------------------------------------------------ entities
    def run(self) -> dict[str, dict]:
        """Best-first traversal from the seed (and co-seeds): each entity is scored once, from the
        neighbours scored before it, strongest first. Returns {id: internal state} for reached ids."""
        nodes, seed = self.nodes, self.seed
        start: dict[str, tuple[float, str]] = {}
        if seed in nodes:
            start[seed] = (1.0, "the seed of this investigation")
        for nid, n in nodes.items():
            p = n["props"]
            if nid == seed or _fp(n):
                continue
            if p.get("analyst_verdict") == "confirmed":
                start[nid] = (.95, "confirmed by an analyst")
            elif p.get("input_ioc") and not p.get("warninglist"):
                start[nid] = (.75, "listed in the input report")
        heap = [(-c, nid) for nid, (c, _) in start.items()]
        heapq.heapify(heap)
        best = {nid: c for nid, (c, _) in start.items()}
        done: dict[str, dict] = {}
        while heap:
            negc, u = heapq.heappop(heap)
            if u in done:
                continue
            supports = []   # (value, neighbour, factor text) from already-scored neighbours
            for v in self.adj.get(u, ()):
                if v in done and done[v]["_c"] > 0:
                    pr = self.pair(u, v)
                    hf, hwhy = (1.0, None) if v == seed else hub_factor(nodes[v], len(self.adj.get(v, ())))
                    val = done[v]["_c"] * pr["confidence"] / 100 * hf
                    if val > 0:
                        supports.append((val, v, pr, hf, hwhy))
            supports.sort(key=lambda x: -x[0])
            factors = []
            if u in start:
                c0, why0 = start[u]
                c = c0
                factors.append({"kind": "support", "label": why0, "value": round(c0 * 100)})
            else:
                c = 0.0
                for i, (val, v, pr, hf, hwhy) in enumerate(supports[:3]):
                    w = (1, .5, .25)[i]
                    c = 1 - (1 - c) * (1 - val * w)
                    vn = nodes[v]
                    label = (f"{'via' if i == 0 else 'also via'} {vn['type']} {vn['value'][:48]}: "
                             f"relation {pr['confidence']} x upstream {done[v]['_c'] * 100:.0f}"
                             + (f" x {hf:.2f} ({hwhy or 'artefact specificity'})" if hf < 1 else "")
                             + (f", corroboration weight {w}" if i else ""))
                    factors.append({"kind": "support", "label": label, "value": round(val * w * 100)})
            groups = {s for _, _, pr, _, _ in supports[:3] for s in pr["sources"]}
            limited = []
            if u not in start and len(groups) == 1 and c > .8:
                c = .8
                factors.append({"kind": "limit", "label": f"single source group ({next(iter(groups))}): capped at 80"})
            if not supports and u not in start:
                limited.append("no path to the seed")
            p = nodes[u]["props"]
            if p.get("warninglist") and u != seed:
                c *= .5
                factors.append({"kind": "conflict", "label": f"on a benign warninglist: {p['warninglist']} (x0.50)"})
            rec_parent = supports[0][1] if supports and u not in start else None
            done[u] = {"_c": c, "factors": factors, "parent": rec_parent, "limited": limited,
                       "supports": [{"id": v, "confidence": pr["confidence"]} for _, v, pr, _, _ in supports[:5]]}
            for v in self.adj.get(u, ()):
                if v in done:
                    continue
                pr = self.pair(u, v)
                hf, _ = (1.0, None) if u == seed else hub_factor(nodes[u], len(self.adj.get(u, ())))
                cand = c * pr["confidence"] / 100 * hf
                if cand > best.get(v, 0):
                    best[v] = cand
                    heapq.heappush(heap, (-cand, v))
        return done

    def _path(self, nid: str) -> list[str]:
        """Seed -> … -> nid along the strongest supports."""
        path, cur, seen = [], nid, set()
        while cur and cur not in seen:
            seen.add(cur)
            path.append(cur)
            cur = self._done[cur]["parent"] if cur in self._done else None
        return list(reversed(path))

    def _entity(self, nid: str, d: dict | None) -> dict:
        n = self.nodes[nid]
        p, t = n["props"], n["type"]
        factors_c = list(d["factors"]) if d else []
        limited = list(d["limited"]) if d else ["no path to the seed"]
        c = d["_c"] if d else None
        verdict = p.get("analyst_verdict")
        if verdict == "fp":
            c = min(c or 0, .05)
            factors_c.append({"kind": "conflict", "label": "analyst verdict: false positive (capped at 5)"})
        elif verdict == "confirmed" and nid != self.seed:
            c = max(c or 0, .95)
        if d is None and verdict != "fp":
            c = None
        conf = None if c is None else round(min(c, 1.0) * 100)
        if nid == self.seed:
            conf = 100

        # ---------- fidelity
        spec, spec_why = SPECIFICITY.get(t, .3), f"{t} indicators are " + {
            1.0: "unique", .85: "highly specific", .8: "specific", .75: "fairly specific", .6: "moderately specific"
        }.get(SPECIFICITY.get(t, .3), "weakly specific")
        if t == g.IP and p.get("hosting"):
            spec, spec_why = .45, "IP in a rented / VPN range"
        if t == g.CERT and p.get("shared_cert"):
            spec, spec_why = .30, f"certificate shared by {p['shared_cert']} domains"
        if p.get("commodity"):
            spec, spec_why = .05, "commodity provider (Cloudflare, registrar DNS…)"
        path = self._path(nid) if d else []
        hops = len(path) - 1 if d else None
        if nid == self.seed:
            ctx, ctx_why = 1.0, "the seed"
        elif hops is None or hops < 0:
            ctx, ctx_why = .1, "not connected to the seed"
        else:
            ctx = {0: 1.0, 1: 1.0, 2: .7, 3: .5}.get(hops, .3)
            ctx_why = f"{hops} hop{'s' if hops != 1 else ''} from the seed"
        if p.get("cluster") is True and nid != self.seed and ctx < .85:
            ctx, ctx_why = .85, ctx_why + "; in the confirmed cluster (cluster.py)"
        if p.get("pinned") and ctx < 1:
            ctx, ctx_why = min(1.0, ctx + .1), ctx_why + "; an analyst pivoted here"
        pri = p.get("priority")
        vt = p.get("vt_malicious") or 0
        threat, threat_why = .2, "no threat signal yet"
        if pri in PRIORITY_SIGNAL and pri != "noise":
            threat, threat_why = PRIORITY_SIGNAL[pri], f"triage priority {pri}"
        if vt >= 3 and threat < .8:
            threat, threat_why = .8, f"VirusTotal: {vt} engines flag it"
        elif vt >= 1 and threat < .5:
            threat, threat_why = .5, f"VirusTotal: {vt} engine(s) flag it"
        if p.get("analyst_verdict") == "confirmed":
            threat, threat_why = 1.0, "confirmed malicious by an analyst"
        last = self._node_last(nid)
        if last:
            days = max(0, (self.now - last) / DAY)
            fresh = 1.0 if days <= 30 else .8 if days <= 90 else .5 if days <= 365 else .25
            fresh_why = f"last activity {days:.0f} days ago"
        else:
            fresh, fresh_why = .5, "no dated activity (neutral 0.5)"
            limited.append("no dated activity")
        W = METHOD["weights"]
        terms = [("specificity", spec, spec_why), ("confidence", (c or 0), f"entity confidence {conf if conf is not None else 'n/a'}"),
                 ("context", ctx, ctx_why), ("threat", threat, threat_why), ("freshness", fresh, fresh_why)]
        base = sum(W[k] * v for k, v, _ in terms)
        risk, risk_why = 1.0, []
        for cond, f, why in ((verdict == "fp", .05, "analyst: false positive"),
                             (bool(p.get("warninglist")), .3, f"warninglist: {p.get('warninglist')}"),
                             (bool(p.get("tor_exit")), .3, "Tor exit node"),
                             (bool(p.get("c2_fronting")), .4, "legit site used for domain fronting"),
                             (bool(p.get("gn_noise")), .4, "GreyNoise: mass scanner"),
                             (t == g.IP and bool(p.get("shared_hosting")), .5, "shared hosting IP"),
                             (bool(p.get("broad")), .5, "too-broad pivot")):
            if cond:
                risk *= f
                risk_why.append(f"{why} (x{f:.2f})")
        # an entity barely tied to the investigation can't be very relevant to it, however specific
        gate = 1.0 if nid == self.seed else min(1.0, .4 + .6 * (c or 0) / .4)
        if gate < 1:
            risk_why.append(f"weak link to the investigation: confidence below 40 (x{gate:.2f})")
        fid = round(base * risk * gate * 100)
        if nid == self.seed:
            fid = max(fid, 90)
        factors_f = [{"kind": "term", "key": k, "label": why, "value": round(v * 100), "weight": W[k],
                      "points": round(W[k] * v * 100, 1)} for k, v, why in terms]
        factors_f += [{"kind": "conflict", "label": w if w.startswith("weak link") else f"false-positive risk: {w}"}
                      for w in risk_why]
        stale = bool(last and self.now - last > 365 * DAY)
        sources = sorted({s for sp in (d or {}).get("supports", [])
                          for s in self.pair(nid, sp["id"])["sources"]})
        conflicts = [f["label"] for f in factors_c if f["kind"] == "conflict"] + [
            w for w in risk_why if not w.startswith("weak link")]
        for sp in (d or {}).get("supports", [])[:3]:
            conflicts += [x for x in self.pair(nid, sp["id"])["conflicts"] if x not in conflicts]
        if len(sources) == 1 and nid != self.seed:
            limited.append("single source group")
        expandable = t in PIVOTABLE and not p.get("expanded") and verdict != "fp"
        return {"confidence": conf, "fidelity": fid, "confidence_band": band(conf), "fidelity_band": band(fid),
                "factors": {"confidence": factors_c, "fidelity": factors_f}, "hops": hops,
                "path": path, "sources": sources, "last_seen": last,
                "stale": stale, "conflicts": conflicts, "limited": sorted(set(limited)),
                "supports": (d or {}).get("supports", []),
                "recommend": bool(expandable and fid >= 55 and (conf or 0) >= 50 and not stale)}

    def _node_last(self, nid: str) -> int | None:
        p = self.nodes[nid]["props"]
        cands = [ts(p.get(k)) for k in ("last_seen", "last_active", "date")]
        for v in self.adj.get(nid, ()):
            for _, _, _, ep in self.pairs.get(frozenset((nid, v)), []):
                cands.append(edge_time(ep))
        return max((c for c in cands if c), default=None)

    def score(self) -> dict[str, dict]:
        self._done = self.run()
        return {nid: self._entity(nid, self._done.get(nid)) for nid in self.nodes}


def score_graph(nodes: dict[str, dict], edges: dict[tuple[str, str, str], dict], seed: str,
                now: float | None = None) -> dict:
    """{"method", "nodes": {id: scores}} for a graph (``Graph.nodes`` / ``Graph.edges`` shapes)."""
    return {"method": METHOD, "nodes": Scorer(nodes, edges, seed, now).score()}


def artefact_edge(kind: str, props: dict, now: float | None = None) -> dict:
    """Confidence of a collapsed 'IOC --<pivot kind>--> IOC' edge (export.pivot_view): both hosts
    share the artefact; worth the search hit x the artefact's specificity."""
    k = (kind or "").removesuffix(" (refined)").lower()
    fake = {"type": g.PATTERN, "value": k, "props": {"kind": k}}
    by_type = {"title": g.TITLE, "favicon": g.FAVICON, "htmlhash": g.HTML_HASH, "script": g.SCRIPT, "jarm": g.JARM,
               "certificate": g.CERT}
    if k in by_type:
        fake = {"type": by_type[k], "value": k, "props": {}}
    w = artefact_weight(fake)
    spec = {3: .85, 2: .65, 1: .40}.get(w, .15)
    grp, rel_w = source_info(props.get("source") or "urlscan")
    fresh, fresh_why = freshness(ts(props.get("date")), now or time.time())
    c = round(.75 * rel_w * spec * fresh * 100)
    return {"confidence": c, "band": band(c), "sources": [grp], "rels": [kind],
            "factors": [{"kind": "support", "label": f"both share a {k} (specificity {spec:.2f}) found by {grp}"},
                        {"kind": "info" if fresh == 1 else "limit", "label": fresh_why}],
            "conflicts": [], "limited": ["shared artefact: look-alike until corroborated"], "last_seen": ts(props.get("date")),
            "stale": False}
