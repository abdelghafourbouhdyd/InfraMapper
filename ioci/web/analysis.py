"""Scored pivot results of a case for the web UI (``/api/cases/<case>/pivots``) and the graphs
hunting rules run on. Reads the live pivot session when one is open (freshest), else graph.json."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from .. import graph as g
from .. import scoring

SKIP = {g.SCAN, g.PATTERN, g.INTEL}   # search plumbing, not entities an analyst triages
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


def load(case_dir: Path, live=None) -> dict:
    """{"nodes", "edges", "seed"} in Graph shapes (edges keyed by (src, dst, rel))."""
    # live session when it's free; while a background refresh / pivot holds it, the saved case (no waiting)
    if live is not None and live.lock.acquire(timeout=0.3):
        try:
            inv = live.inv
            return {"nodes": {k: {**v, "props": dict(v["props"])} for k, v in inv.g.nodes.items()},
                    "edges": dict(inv.g.edges), "seed": inv.seed_id, "live": True}
        finally:
            live.lock.release()
    gj = case_dir / "graph.json"
    mtime = gj.stat().st_mtime
    with _lock:
        hit = _cache.get(str(gj))
        if hit and hit[0] == mtime:
            return hit[1]
    data = json.loads(gj.read_text(encoding="utf-8"))
    out = {"nodes": {n["id"]: n for n in data.get("nodes", [])},
           "edges": {(e["source"], e["target"], e["rel"]): e.get("props") or {} for e in data.get("edges", [])},
           "seed": data.get("seed"), "live": False}
    with _lock:
        _cache[str(gj)] = (mtime, out)
    return out


def pivot_rows(gr: dict) -> dict:
    sc = scoring.Scorer(gr["nodes"], gr["edges"], gr["seed"])
    scores = sc.score()
    nodes = gr["nodes"]
    rows = []
    for nid, n in nodes.items():
        if n["type"] in SKIP:
            continue
        s = scores[nid]
        p = n["props"]
        links = []
        for other in sc.adj.get(nid, ()):
            o = nodes[other]
            if o["type"] == g.SCAN:
                continue
            pr = sc.pair(nid, other)
            links.append({"id": other, "type": o["type"], "value": o["value"], "rels": pr["rels"],
                          "confidence": pr["confidence"], "band": pr["band"], "sources": pr["sources"],
                          "last_seen": pr["last_seen"], "stale": pr["stale"], "conflicts": pr["conflicts"],
                          "limited": pr["limited"], "factors": pr["factors"]})
        links.sort(key=lambda x: -x["confidence"])
        rows.append({"id": nid, "type": n["type"], "value": n["value"], "seed": nid == gr["seed"],
                     "priority": p.get("priority"), "action": p.get("action"), "cluster": p.get("cluster"),
                     "expanded": bool(p.get("expanded")), "verdict": p.get("analyst_verdict"),
                     "pivot_from": p.get("pivot_from"), "families": (p.get("families") or [])[:5],
                     "vt": [p.get("vt_malicious"), p.get("vt_total")] if p.get("vt_total") else None,
                     **{k: s[k] for k in ("confidence", "fidelity", "confidence_band", "fidelity_band", "sources",
                                          "last_seen", "stale", "conflicts", "limited", "recommend", "hops", "factors")},
                     "path": [{"id": x, "type": nodes[x]["type"], "value": nodes[x]["value"]} for x in s["path"]],
                     "links": links[:25], "n_links": len(links)})
    rows.sort(key=lambda r: (not r["seed"], -(r["fidelity"] or 0), -(r["confidence"] or 0)))
    return {"items": rows, "method": scoring.METHOD, "live": gr.get("live", False), "scores": scores}
