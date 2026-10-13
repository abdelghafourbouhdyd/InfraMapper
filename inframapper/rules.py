"""Hunting rules: saved pivoting logic, combinations of pivots, and tuning of the built-in pivots.

* A **rule** is a name, the platform it runs on, the query (a page title, favicon hash, JARM…), and
  two ratings: fidelity (how precisely the query singles out the actor's infrastructure) and
  confidence (how sure we are of what it returns).
* A **combination** says that sharing several pivots with the same confirmed host (e.g. favicon +
  page title) is worth a given confidence (0-100). The engine applies it (cluster.py, scoring.py)
  instead of adding up the parts.
* The **built-in pivots** (cluster.PIVOT_RULES) can be tuned: their confidence, and whether their
  search runs at all.

Everything lives in ``cases/hunt_rules.json`` (written atomically). ``RuleStore.apply`` hands the
combinations and tuning to the engine; the web UI calls it on start and after each change, the
command line before an investigation.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from urllib.parse import quote

from . import cluster

PLATFORMS = {
    "urlscan": {"name": "urlscan.io", "url": "https://urlscan.io/search/#{q}"},
    "vt": {"name": "VirusTotal Intelligence", "url": "https://www.virustotal.com/gui/search/{q}"},
}
RATINGS = ["low", "medium", "high"]
LIMITS = {"name": 120, "query": 500, "rules": 500}


def schema() -> dict:
    """What the rule editor offers."""
    return {"platforms": {k: v["name"] for k, v in PLATFORMS.items()}, "ratings": RATINGS, "limits": LIMITS,
            "pivots": {k: v[0] for k, v in cluster.PIVOT_RULES.items()}}


def _str(v, name: str, hi: int) -> str:
    v = str(v if v is not None else "").strip()
    if not 1 <= len(v) <= hi:
        raise ValueError(f"{name} must be 1-{hi} characters")
    return v


def _confidence(v) -> int:
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError("confidence must be a number 0-100") from None
    if not 0 <= v <= 100:
        raise ValueError("confidence must be a number 0-100")
    return v


def validate(raw: dict) -> dict:
    """Normalised copy of a rule from the editor; ValueError with a readable message otherwise."""
    if not isinstance(raw, dict):
        raise ValueError("rule must be an object")
    platform = raw.get("platform")
    if platform not in PLATFORMS:
        raise ValueError(f"unknown platform '{str(platform)[:30]}'")
    r = {"name": _str(raw.get("name"), "name", LIMITS["name"]), "platform": platform,
         "query": _str(raw.get("query"), "query", LIMITS["query"])}
    for k in ("fidelity", "confidence"):
        if raw.get(k) not in RATINGS:
            raise ValueError(f"{k} must be one of {', '.join(RATINGS)}")
        r[k] = raw[k]
    return r


def validate_combo(raw: dict) -> dict:
    """Normalised copy of a combination of pivots; ValueError otherwise."""
    if not isinstance(raw, dict):
        raise ValueError("combination must be an object")
    pivots = raw.get("pivots") or []
    if not isinstance(pivots, list) or any(p not in cluster.PIVOT_RULES for p in pivots):
        raise ValueError("unknown pivot in the combination")
    pivots = sorted(set(pivots), key=list(cluster.PIVOT_RULES).index)
    if len(pivots) < 2:
        raise ValueError("pick at least two pivots to combine")
    return {"name": _str(raw.get("name"), "name", LIMITS["name"]), "pivots": pivots,
            "confidence": _confidence(raw.get("confidence"))}


def query_link(platform: str, query: str) -> str:
    """Open-in-platform URL for a query."""
    return PLATFORMS[platform]["url"].replace("{q}", quote(query, safe=""))


SECTIONS = {"rules": (validate, "r_", "rule"), "combos": (validate_combo, "c_", "combination")}


class RuleStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        data = data if isinstance(data, dict) else {}
        return {"rules": data.get("rules") or [], "combos": data.get("combos") or [], "pivots": data.get("pivots") or {}}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 3, **data}, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    # ── saved rules and combinations ──────────────────────────────────────────
    def list(self, section: str = "rules") -> list[dict]:
        with self.lock:
            return sorted(self._load()[section], key=lambda r: r.get("name", "").lower())

    def create(self, raw: dict, section: str = "rules") -> dict:
        check, prefix, _ = SECTIONS[section]
        r = {"id": prefix + uuid.uuid4().hex[:10], **check(raw)}
        with self.lock:
            data = self._load()
            if len(data[section]) >= LIMITS["rules"]:
                raise ValueError(f"at most {LIMITS['rules']} per list")
            data[section].append(r)
            self._save(data)
        return r

    def update(self, rid: str, raw: dict, section: str = "rules") -> dict:
        check, _, what = SECTIONS[section]
        r = {"id": rid, **check(raw)}
        with self.lock:
            data = self._load()
            for i, cur in enumerate(data[section]):
                if cur["id"] == rid:
                    data[section][i] = r
                    self._save(data)
                    return r
        raise LookupError(f"no such {what}")

    def delete(self, rid: str, section: str = "rules") -> None:
        with self.lock:
            data = self._load()
            keep = [r for r in data[section] if r["id"] != rid]
            if len(keep) == len(data[section]):
                raise LookupError(f"no such {SECTIONS[section][2]}")
            data[section] = keep
            self._save(data)

    # ── built-in pivots ───────────────────────────────────────────────────────
    def pivots(self) -> list[dict]:
        """Every built-in pivot with its default and current (tuned) settings."""
        with self.lock:
            tuned = self._load()["pivots"]
        out = []
        for key, (label, default, _, _) in cluster.PIVOT_RULES.items():
            t = tuned.get(key) or {}
            out.append({"key": key, "label": label, "default": default,
                        "confidence": t.get("confidence", default), "points": cluster.points(t.get("confidence", default)),
                        "searchable": key in cluster.SEARCHABLE,
                        "search": key in cluster.SEARCHABLE and t.get("search", True), "tuned": bool(t)})
        return out

    def tune_pivot(self, key: str, raw: dict) -> dict:
        if key not in cluster.PIVOT_RULES:
            raise LookupError("no such pivot")
        t = {"confidence": _confidence(raw.get("confidence"))}
        if key in cluster.SEARCHABLE:
            t["search"] = raw.get("search", True) not in (False, "false", 0, "0")
        default = cluster.PIVOT_RULES[key][1]
        with self.lock:
            data = self._load()
            if t["confidence"] == default and t.get("search", True):
                data["pivots"].pop(key, None)   # back to the default
            else:
                data["pivots"][key] = t
            self._save(data)
        return next(p for p in self.pivots() if p["key"] == key)

    def apply(self) -> None:
        """Hand the combinations and pivot tuning to the engine (cluster.configure)."""
        with self.lock:
            data = self._load()
        tuned = {k: v for k, v in data["pivots"].items() if k in cluster.PIVOT_RULES}
        cluster.configure(confidence={k: v["confidence"] for k, v in tuned.items() if "confidence" in v},
                          off={k for k, v in tuned.items() if v.get("search") is False},
                          combos=[c for c in data["combos"] if c.get("pivots")])
