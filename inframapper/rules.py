"""Hunting rules: tuning of the built-in pivots, and the analyst's own pivot logic.

* **Built-in pivots** (cluster.PIVOT_RULES: page title, favicon, HTML body, domain-name patterns,
  regex hunt…) can be switched off and tuned: confidence, fidelity, and each pivot's parameters
  (search template, max hits before it counts as too broad, auto-refinement, regex steps).
* **Custom rules** are new pivot logic built from *attributes* of the host being expanded, never
  from fixed values: e.g. "page title AND favicon hash" on urlscan becomes, for each host,
  ``page.title:"<its title>" AND hash:<its favicon>``. Each condition picks an attribute and a match
  method (exact, same registered domain, name contains, regex with ``{name}`` / ``{tld}``…). The
  rule's confidence and fidelity weigh what its searches find, like a built-in pivot.

The investigator runs every enabled custom rule on each host it expands (``host_attributes`` +
``render``). Everything lives in ``cases/hunt_rules.json`` (written atomically); ``RuleStore.apply``
hands it to the engine (the web UI on start and after each change, the command line before a run).
"""

from __future__ import annotations

import itertools
import json
import math
import os
import re
import threading
import uuid
from pathlib import Path

from . import cluster
from . import graph as g
from .patterns import apex_of, es_escape, host_of, split_domain, title_is_generic

PLATFORMS = {"urlscan": "urlscan.io", "vt": "VirusTotal Intelligence (premium, --vt-intel)"}
LIMITS = {"name": 120, "param": 200, "conditions": 6, "rules": 200, "values": 3, "queries": 3}


def _q(v: str) -> str:   # inside "…"
    return v.replace("\\", "\\\\").replace('"', '\\"')


def _re_lit(v: str) -> str:   # a value inside an Elasticsearch / Lucene regex
    return re.sub(r'([.?+*|{}\[\]()"\\#@&<>~/^$-])', r"\\\1", v)


def _domain_regex(param: str, domain: str) -> str:
    _, name, suffix = split_domain(domain)
    return param.replace("{name}", _re_lit(name)).replace("{tld}", _re_lit(suffix))


# attribute -> label, platform, where it comes from (help), match methods: method -> (label, needs a
# parameter, clause builder(value, param)), and the confidence / fidelity it suggests on its own.
ATTRIBUTES = {
    "title": {"label": "Page title", "platform": "urlscan", "from": "urlscan scans of the host (generic titles skipped)",
              "suggest": (40, 30), "methods": {
                  "exact": ("same title", False, lambda v, p: f'page.title:"{_q(v)}"')}},
    "favicon": {"label": "Favicon hash", "platform": "urlscan", "from": "favicon in the host's scans",
                "suggest": (40, 50), "methods": {"exact": ("same hash", False, lambda v, p: f"hash:{v}")}},
    "html": {"label": "HTML body hash", "platform": "urlscan", "from": "main HTML document in the host's scans",
             "suggest": (85, 85), "methods": {"exact": ("same hash", False, lambda v, p: f"hash:{v}")}},
    "script": {"label": "First-party script hash", "platform": "urlscan", "from": "the site's own scripts",
               "suggest": (85, 80), "methods": {"exact": ("same hash", False, lambda v, p: f"hash:{v}")}},
    "domain": {"label": "Domain name", "platform": "urlscan", "from": "the host itself",
               "suggest": (40, 30), "methods": {
                   "apex": ("same registered domain", False, lambda v, p: f"page.apexDomain:{es_escape(apex_of(v))}"),
                   "name": ("name contains the host's name", False,
                            lambda v, p: f"page.domain:*{es_escape(split_domain(v)[1])}*"),
                   "regex": ("matches a regex", True, lambda v, p: f"page.domain:/{_domain_regex(p, v)}/")}},
    "ip": {"label": "IP address", "platform": "urlscan", "from": "the host, or the IPs a domain resolves to",
           "suggest": (60, 60), "methods": {"exact": ("same IP", False, lambda v, p: f'page.ip:"{v}"')}},
    "asn": {"label": "ASN", "platform": "urlscan", "from": "ASN of the host's IPs",
            "suggest": (20, 10), "methods": {"exact": ("same ASN", False, lambda v, p: f'page.asn:"{v}"')}},
    "server": {"label": "Web server banner", "platform": "urlscan", "from": "Server header in the host's scans",
               "suggest": (20, 20), "methods": {"exact": ("same banner", False, lambda v, p: f'page.server:"{_q(v)}"')}},
    "jarm": {"label": "JARM", "platform": "vt", "entity": "domain", "from": "TLS fingerprint (VirusTotal)",
             "suggest": (40, 35), "methods": {"exact": ("same JARM", False, lambda v, p: f"jarm:{v}")}},
    "imphash": {"label": "Imphash", "platform": "vt", "entity": "file", "from": "file's import hash (VirusTotal)",
                "suggest": (65, 30), "methods": {"exact": ("same imphash", False, lambda v, p: f"imphash:{v}")}},
    "vhash": {"label": "Vhash", "platform": "vt", "entity": "file", "from": "file's vhash (VirusTotal)",
              "suggest": (65, 30), "methods": {"exact": ("same vhash", False, lambda v, p: f'vhash:"{v}"')}},
}
PLACEHOLDER = {"title": "<page title>", "favicon": "<favicon sha256>", "html": "<html sha256>",
               "script": "<script sha256>", "domain": "<domain>", "ip": "<ip>", "asn": "<ASN>",
               "server": "<server>", "jarm": "<jarm>", "imphash": "<imphash>", "vhash": "<vhash>"}


def schema() -> dict:
    """What the rules page offers."""
    return {"platforms": PLATFORMS, "limits": LIMITS,
            "attributes": {k: {"label": a["label"], "platform": a["platform"], "from": a["from"],
                               "suggest": a["suggest"],
                               "methods": {m: {"label": x[0], "param": x[1]} for m, x in a["methods"].items()}}
                           for k, a in ATTRIBUTES.items()}}


# ── host attributes ───────────────────────────────────────────────────────────

def host_attributes(nodes: dict, edges, nid: str) -> dict[str, list[str]]:
    """Values of every attribute a custom rule can use, read from the host's node and neighbours.
    ``edges``: iterable of (source, target, rel)."""
    n = nodes[nid]
    t, p = n["type"], n["props"]
    out: dict[str, list[str]] = {}

    def add(attr: str, v) -> None:
        v = str(v).strip() if v not in (None, "") else ""
        if v and v not in out.setdefault(attr, []):
            out[attr].append(v)

    nbr = [(d, rel) for (s, d, rel) in edges if s == nid and d in nodes]
    by_rel = {"HAS_TITLE": "title", "HAS_FAVICON": "favicon", "SERVES_HTML": "html", "SERVES_SCRIPT": "script",
              "HAS_JARM": "jarm"}
    for d, rel in nbr:
        if rel in by_rel:
            v = nodes[d]["value"]
            if rel != "HAS_TITLE" or not title_is_generic(v):
                add(by_rel[rel], v)
    if t in (g.DOMAIN, g.URL):
        add("domain", host_of(n["value"]) if t == g.URL else n["value"].lower())
    ips = [n] if t == g.IP else [nodes[d] for d, rel in nbr if rel == "RESOLVES_TO" and nodes[d]["type"] == g.IP]
    for ip in ips:
        add("ip", ip["value"])
        asn = ip["props"].get("asn")
        if asn:
            add("asn", asn if str(asn).upper().startswith("AS") else f"AS{asn}")
    for v in p.get("servers") or []:   # Server headers of the host's urlscan scans (investigator._us_host)
        add("server", v)
    if t == g.FILE:
        add("imphash", p.get("imphash"))
        add("vhash", p.get("vhash"))
    return {k: v[: LIMITS["values"]] for k, v in out.items()}


# ── rules ─────────────────────────────────────────────────────────────────────

def _str(v, name: str, hi: int, lo: int = 1) -> str:
    v = str(v if v is not None else "").strip()
    if not lo <= len(v) <= hi:
        raise ValueError(f"{name} must be {lo}-{hi} characters")
    return v


def _score(v, name: str) -> int:
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number 0-100") from None
    if not 0 <= v <= 100:
        raise ValueError(f"{name} must be a number 0-100")
    return v


def _opt_int(v, name: str, lo: int, hi: int) -> int | None:
    if v in (None, ""):
        return None
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number {lo}-{hi}") from None
    if not lo <= v <= hi:
        raise ValueError(f"{name} must be a number {lo}-{hi}")
    return v


def validate(raw: dict) -> dict:
    """Normalised copy of a custom rule from the editor; ValueError with a readable message otherwise."""
    if not isinstance(raw, dict):
        raise ValueError("rule must be an object")
    platform = raw.get("platform")
    if platform not in PLATFORMS:
        raise ValueError(f"unknown platform '{str(platform)[:30]}'")
    conds = raw.get("conditions") or []
    if not isinstance(conds, list) or not 1 <= len(conds) <= LIMITS["conditions"]:
        raise ValueError(f"give 1-{LIMITS['conditions']} conditions")
    out = []
    for i, c in enumerate(conds, 1):
        a = ATTRIBUTES.get((c or {}).get("attribute"))
        if not a:
            raise ValueError(f"condition {i}: unknown attribute")
        if a["platform"] != platform:
            raise ValueError(f"condition {i}: {a['label']} can't be searched on {PLATFORMS[platform]}")
        method = c.get("method") or next(iter(a["methods"]))
        if method not in a["methods"]:
            raise ValueError(f"condition {i}: unknown match method for {a['label']}")
        param = None
        if a["methods"][method][1]:
            param = _str(c.get("param"), f"condition {i}: regex", LIMITS["param"])
            try:
                re.compile(param.replace("{name}", "x").replace("{tld}", "x"))
            except re.error as exc:
                raise ValueError(f"condition {i}: invalid regex ({exc})") from None
        out.append({"attribute": c["attribute"], "method": method, "param": param})
    if platform == "vt" and len({ATTRIBUTES[c["attribute"]]["entity"] for c in out}) > 1:
        raise ValueError("VirusTotal conditions must all be about domains (JARM) or all about files (imphash / vhash)")
    return {"name": _str(raw.get("name"), "name", LIMITS["name"]), "platform": platform, "conditions": out,
            "recent_days": _opt_int(raw.get("recent_days"), "recent days", 1, 3650) if platform == "urlscan" else None,
            "max_hits": _opt_int(raw.get("max_hits"), "max hits", 1, 10000) if platform == "urlscan" else None,
            "confidence": _score(raw.get("confidence"), "confidence"),
            "fidelity": _score(raw.get("fidelity"), "fidelity"),
            "enabled": raw.get("enabled", True) not in (False, "false", 0, "0")}


def _join(rule: dict, clauses: list[str]) -> str:
    if rule["platform"] == "vt":
        return f"entity:{ATTRIBUTES[rule['conditions'][0]['attribute']]['entity']} " + " ".join(clauses)
    if rule.get("recent_days"):
        clauses = clauses + [f"date:>now-{rule['recent_days']}d"]
    return " AND ".join(clauses)


def render(rule: dict, attrs: dict[str, list[str]]) -> list[str]:
    """The searches a rule runs for one host (several values = several searches, at most 3);
    [] when the host lacks one of the rule's attributes."""
    if any(not attrs.get(c["attribute"]) for c in rule["conditions"]):
        return []
    per = [[ATTRIBUTES[c["attribute"]]["methods"][c["method"]][2](v, c["param"]) for v in attrs[c["attribute"]]]
           for c in rule["conditions"]]
    out = []
    for combo in itertools.islice(itertools.product(*per), LIMITS["queries"]):
        out.append(_join(rule, list(combo)))
    return out


def template(rule: dict) -> str:
    """The rule's search with placeholders, for display."""
    clauses = []
    for c in rule["conditions"]:
        m = c["method"]
        ph = PLACEHOLDER[c["attribute"]]
        if c["attribute"] == "domain":
            ph = {"apex": "page.apexDomain:<registered domain>", "name": "page.domain:*<name>*",
                  "regex": f"page.domain:/{c['param'] or ''}/"}[m]
            clauses.append(ph)
            continue
        clauses.append(ATTRIBUTES[c["attribute"]]["methods"][m][2](ph, c["param"]).replace('\\"', '"'))
    return _join(rule, clauses)


def suggest(conditions: list[dict]) -> dict:
    """Confidence / fidelity a rule's conditions suggest: independent evidence combined (noisy-OR)."""
    vals = [ATTRIBUTES[c["attribute"]]["suggest"] for c in conditions if c.get("attribute") in ATTRIBUTES]
    comb = lambda xs: round(min(95, 100 * (1 - math.prod(1 - x / 100 for x in xs)))) if xs else 0
    return {"confidence": comb([v[0] for v in vals]), "fidelity": comb([v[1] for v in vals])}


# ── built-in pivot tuning ─────────────────────────────────────────────────────

def validate_pivot(key: str, raw: dict) -> dict:
    """Overrides of one built-in pivot; only what differs from its defaults is kept."""
    if key not in cluster.PIVOT_RULES:
        raise LookupError("no such pivot")
    p = cluster.PIVOT_RULES[key]
    t = {"confidence": _score(raw.get("confidence", p["confidence"]), "confidence"),
         "fidelity": _score(raw.get("fidelity", p["fidelity"]), "fidelity")}
    if key in cluster.SEARCHABLE:
        t["enabled"] = raw.get("enabled", True) not in (False, "false", 0, "0")
    for name, default in p["params"].items():
        v = raw.get(name, default)
        if name == "template":
            v = _str(v, "search template", LIMITS["param"])
            if "{value}" not in v or re.search(r"\{(?!value\})", v):
                raise ValueError("the search template must contain {value} (the value found on the host) "
                                 "and no other {placeholder}")
        elif name == "max_hits":
            v = _opt_int(v, "max hits", 1, 10000)
        elif name == "steps":
            v = _opt_int(v, "regex steps", 1, 20)
        elif name == "refine":
            v = v not in (False, "false", 0, "0")
        t[name] = v
    defaults = {"confidence": p["confidence"], "fidelity": p["fidelity"], "enabled": True, **p["params"]}
    return {k: v for k, v in t.items() if v != defaults.get(k)}


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
        data["custom"] = [r for r in data.get("custom") or [] if isinstance(r, dict)]
        data["pivots"] = data.get("pivots") if isinstance(data.get("pivots"), dict) else {}
        return data   # older keys ("rules", "combos") are kept as they are, unused

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({**data, "version": 4}, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    # ── custom rules ──────────────────────────────────────────────────────────
    def list(self) -> list[dict]:
        with self.lock:
            rules = self._load()["custom"]
        return sorted(({**r, "template": template(r)} for r in rules), key=lambda r: r.get("name", "").lower())

    def create(self, raw: dict) -> dict:
        r = {"id": uuid.uuid4().hex[:10], **validate(raw)}
        with self.lock:
            data = self._load()
            if len(data["custom"]) >= LIMITS["rules"]:
                raise ValueError(f"at most {LIMITS['rules']} rules")
            data["custom"].append(r)
            self._save(data)
        return {**r, "template": template(r)}

    def update(self, rid: str, raw: dict) -> dict:
        r = {"id": rid, **validate(raw)}
        with self.lock:
            data = self._load()
            for i, cur in enumerate(data["custom"]):
                if cur.get("id") == rid:
                    data["custom"][i] = r
                    self._save(data)
                    return {**r, "template": template(r)}
        raise LookupError("no such rule")

    def delete(self, rid: str) -> None:
        with self.lock:
            data = self._load()
            keep = [r for r in data["custom"] if r.get("id") != rid]
            if len(keep) == len(data["custom"]):
                raise LookupError("no such rule")
            data["custom"] = keep
            self._save(data)

    # ── built-in pivots ───────────────────────────────────────────────────────
    def pivots(self) -> list[dict]:
        """Every built-in pivot with its defaults and current settings."""
        with self.lock:
            tuned = self._load()["pivots"]
        out = []
        for key, p in cluster.PIVOT_RULES.items():
            t = tuned.get(key) or {}
            cur = {"confidence": p["confidence"], "fidelity": p["fidelity"], "enabled": True, **p["params"], **t}
            out.append({"key": key, "label": p["label"], "about": p["about"], "searchable": key in cluster.SEARCHABLE,
                        "defaults": {"confidence": p["confidence"], "fidelity": p["fidelity"], **p["params"]},
                        "params": list(p["params"]), "current": cur, "points": cluster.points(cur["confidence"]),
                        "tuned": sorted(t)})
        return out

    def tune_pivot(self, key: str, raw: dict) -> dict:
        t = validate_pivot(key, raw or {})
        with self.lock:
            data = self._load()
            if t:
                data["pivots"][key] = t
            else:
                data["pivots"].pop(key, None)   # back to the defaults
            self._save(data)
        return next(p for p in self.pivots() if p["key"] == key)

    def apply(self) -> None:
        """Hand the pivot tuning and the enabled custom rules to the engine."""
        with self.lock:
            data = self._load()
        rules = []
        for r in data["custom"]:
            try:
                rules.append({"id": r["id"], **validate(r)})
            except (KeyError, ValueError):
                continue   # hand-edited and broken: skipped rather than crash a run
        cluster.configure(pivots={k: v for k, v in data["pivots"].items() if k in cluster.PIVOT_RULES},
                          custom=[r for r in rules if r["enabled"]])
