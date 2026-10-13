"""Hunting rules: saved pivoting logic.

A rule is a name, the platform it runs on, the query (a page title, favicon hash, JARM…), and two
ratings: fidelity (how precisely the query singles out the actor's infrastructure) and confidence
(how sure we are of what it returns).

Rules live in ``cases/hunt_rules.json`` (written atomically).
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from urllib.parse import quote

PLATFORMS = {
    "urlscan": {"name": "urlscan.io", "url": "https://urlscan.io/search/#{q}"},
    "vt": {"name": "VirusTotal Intelligence", "url": "https://www.virustotal.com/gui/search/{q}"},
}
RATINGS = ["low", "medium", "high"]
LIMITS = {"name": 120, "query": 500, "rules": 500}


def schema() -> dict:
    """What the rule editor offers."""
    return {"platforms": {k: v["name"] for k, v in PLATFORMS.items()}, "ratings": RATINGS, "limits": LIMITS}


def _str(v, name: str, hi: int) -> str:
    v = str(v if v is not None else "").strip()
    if not 1 <= len(v) <= hi:
        raise ValueError(f"{name} must be 1-{hi} characters")
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


def query_link(platform: str, query: str) -> str:
    """Open-in-platform URL for a query."""
    return PLATFORMS[platform]["url"].replace("{q}", quote(query, safe=""))


class RuleStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def _load(self) -> list[dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return data.get("rules", []) if isinstance(data, dict) else []

    def _save(self, rules: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 2, "rules": rules}, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def list(self) -> list[dict]:
        with self.lock:
            return sorted(self._load(), key=lambda r: r.get("name", "").lower())

    def create(self, raw: dict) -> dict:
        r = {"id": "r_" + uuid.uuid4().hex[:10], **validate(raw)}
        with self.lock:
            rules = self._load()
            if len(rules) >= LIMITS["rules"]:
                raise ValueError(f"at most {LIMITS['rules']} rules")
            rules.append(r)
            self._save(rules)
        return r

    def update(self, rid: str, raw: dict) -> dict:
        r = {"id": rid, **validate(raw)}
        with self.lock:
            rules = self._load()
            for i, cur in enumerate(rules):
                if cur["id"] == rid:
                    rules[i] = r
                    self._save(rules)
                    return r
        raise LookupError("no such rule")

    def delete(self, rid: str) -> None:
        with self.lock:
            rules = self._load()
            keep = [r for r in rules if r["id"] != rid]
            if len(keep) == len(rules):
                raise LookupError("no such rule")
            self._save(keep)
