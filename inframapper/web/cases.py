"""Read saved cases (``cases/<case>/``) for the web UI. Nothing here writes to a case."""

from __future__ import annotations

import csv
import json
import re
import threading
from datetime import datetime
from pathlib import Path

CASE_RE = re.compile(r"^(\d{8}-\d{6})_(.+)$")
DOWNLOADS = {"graph.json": "application/json", "graph.html": "text/html", "report.md": "text/markdown",
             "iocs.csv": "text/csv", "stix2.json": "application/json"}
HUNT_EXT = {".rules", ".txt"}   # KQL / SPL retro-hunt queries were dropped; older cases' copies stay hidden
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


def case_dir(out: Path, name: str) -> Path:
    """Resolve a case name safely (no path traversal)."""
    if not CASE_RE.match(name or "") or "/" in name or "\\" in name or ".." in name:
        raise LookupError("no such case")
    d = (out / name).resolve()
    if d.parent != out.resolve() or not (d / "graph.json").exists():
        raise LookupError("no such case")
    return d


def _created(name: str) -> str:
    m = CASE_RE.match(name)
    try:
        return datetime.strptime(m.group(1), "%Y%m%d-%H%M%S").isoformat() if m else ""
    except ValueError:
        return ""


def priorities(d: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    p = d / "iocs.csv"
    if p.exists():
        with p.open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                out[row.get("priority") or "?"] = out.get(row.get("priority") or "?", 0) + 1
    return out


def summary(d: Path) -> dict:
    """Small per-case summary, cached on graph.json's mtime."""
    gj = d / "graph.json"
    mtime = gj.stat().st_mtime
    with _lock:
        hit = _cache.get(str(d))
        if hit and hit[0] == mtime:
            return hit[1]
    try:
        data = json.loads(gj.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {"nodes": [], "edges": []}
    nodes = {n["id"]: n for n in data.get("nodes", [])}
    seed = nodes.get(data.get("seed")) or {}
    batch = data.get("batch")
    types: dict[str, int] = {}
    for n in nodes.values():
        types[n["type"]] = types.get(n["type"], 0) + 1
    actors, families = set(), set()
    for n in nodes.values():
        p = n.get("props") or {}
        for a in p.get("actors") or []:
            actors.add(a if isinstance(a, str) else str(a))
        for f in p.get("families") or []:
            families.add(f if isinstance(f, str) else str(f))
    s = {"name": d.name, "created": _created(d.name), "updated": datetime.fromtimestamp(mtime).isoformat(timespec="seconds"),
         "seed": seed.get("value") or (batch or {}).get("source") or d.name.split("_", 1)[-1],
         "seed_type": "report" if batch else seed.get("type", ""), "nodes": len(nodes),
         "edges": len(data.get("edges", [])), "types": types, "priorities": priorities(d),
         "pivots": len(data.get("pivots", [])), "manual_pivots": len(data.get("manual_pivots", [])),
         "batch": bool(batch), "actors": sorted(actors)[:8], "families": sorted(families)[:8],
         "seed_vt": (seed.get("props") or {}).get("vt_malicious"),
         "files": sorted(f for f in DOWNLOADS if (d / f).exists()),
         "hunt": sorted(p.name for p in (d / "hunt").glob("*") if p.suffix in HUNT_EXT) if (d / "hunt").is_dir() else []}
    with _lock:
        _cache[str(d)] = (mtime, s)
    return s


def list_cases(out: Path) -> list[dict]:
    rows = []
    for gj in out.glob("*/graph.json"):
        if CASE_RE.match(gj.parent.name):
            try:
                rows.append(summary(gj.parent))
            except OSError:
                continue
    return sorted(rows, key=lambda r: r["created"] or r["updated"], reverse=True)


def iocs(d: Path) -> list[dict]:
    p = d / "iocs.csv"
    if not p.exists():
        return []
    with p.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def hunt_files(d: Path) -> list[dict]:
    h = d / "hunt"
    if not h.is_dir():
        return []
    out = []
    for p in sorted(h.iterdir()):
        if p.suffix in HUNT_EXT and p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            out.append({"name": p.name, "lines": text.count("\n") + 1, "text": text[:200_000]})
    return out
