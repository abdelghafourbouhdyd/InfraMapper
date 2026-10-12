"""Custom hunting rules: match entities of a case graph, explain each match, act on the matches.

A rule targets one indicator type (or any) and combines

* **conditions** on the entity itself (value, TLD, ASN, VT detections, certificate issuer,
  open ports, families, fidelity / confidence scores…), and
* **relations**: "has at least N neighbours over relation R (in / out) whose own conditions hold",
  e.g. *a certificate served by an IP that VirusTotal flags*, *a domain that resolves to an IP in
  AS 9009 within its first 30 days*.

``match: all`` needs every condition and relation, ``any`` needs one. Every match carries the
reason for each clause that held, with the actual value seen, so an analyst can see *why*.

Rules don't have their own crawler. Their action runs through the existing pivot engine
(server.PivotServer): ``pivot`` expands the matched entities with the chosen sources, ``query``
runs a urlscan search built from a template (``page.title:"{prop:title}"``) hung off each match.

Rules live in ``cases/hunt_rules.json`` (written atomically).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import graph as g
from .patterns import apex_of, host_of, is_ip

TYPES = [g.DOMAIN, g.IP, g.URL, g.FILE, g.CERT, g.JARM, g.FAVICON, g.TITLE, g.HTML_HASH, g.SCRIPT,
         g.NS, g.MX, g.SOA, g.ASN, g.REPORT]
RELS = ["RESOLVES_TO", "USES_CERT", "HAS_JARM", "CONTACTS", "DROPS", "DOWNLOADED_FROM", "EMBEDS", "HAS_URL",
        "HAS_SUBDOMAIN", "HOSTED_ON", "REDIRECTS_TO", "SERVES", "SERVED_FROM", "IN_ASN", "USES_NS", "USES_MX",
        "SOA_CONTACT", "HAS_TITLE", "HAS_FAVICON", "SERVES_HTML", "SERVES_SCRIPT", "REPORTED_IN", "CO_MENTIONED",
        "SEEN_ON", "MATCHES_PATTERN", "CNAME_TO", "LOADS_FROM"]
SOURCES = ["vt", "urlscan", "pdns", "ct"]
CATEGORIES = ["infrastructure", "phishing", "malware", "c2", "certificate", "dns", "reputation", "other"]
LIMITS = {"conditions": 20, "relations": 5, "rel_conditions": 10, "value": 500, "regex": 300, "list": 200,
          "tags": 20, "tag": 40, "name": 120, "description": 2000, "category": 60, "max": 25}
# query platforms for the "query" action: run through the pivot engine, hits join the case and get scored
PLATFORMS = {
    "urlscan": {"name": "urlscan.io", "url": "https://urlscan.io/search/#{q}",
                "help": "Elasticsearch syntax: field:value, quoted phrases, AND / OR / NOT, wildcards.",
                "examples": [['page.title:"{prop:urlscan_title}"', "same page title"],
                             ["hash:{value}", "same favicon / HTML / script (on those nodes)"],
                             ["page.domain:*{apex}* AND NOT page.domain:{apex}", "look-alikes of the domain"],
                             ['page.ip:"{value}"', "pages served by this IP"]]},
    "vt": {"name": "VirusTotal Intelligence", "url": "https://www.virustotal.com/gui/search/{q}",
           "help": "VT Intelligence modifiers (premium key). entity:, jarm:, imphash:, ssl_serial: …",
           "examples": [["entity:domain jarm:{value}", "domains with this JARM (on JARM nodes)"],
                        ["entity:file imphash:{prop:imphash}", "files with the same imphash"],
                        ["entity:url url:{apex}", "URLs on the domain"],
                        ["entity:ip ssl_subject:{prop:subject_cn}", "IPs serving a cert with this CN"]]},
}
PROP_RE = re.compile(r"^prop:[a-z][a-z0-9_]{0,39}$")
PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")
ALLOWED_PH = re.compile(r"^(value|apex|host|prop:[a-z][a-z0-9_]{0,39})$")


def _host(n: dict) -> str:
    v = n["value"]
    return host_of(v) if n["type"] == g.URL else v.lower()


def _days_since(v) -> float | None:
    if isinstance(v, (int, float)) and v > 0:
        return round((time.time() - v) / 86400, 1)
    return None


def _list(*vals) -> list:
    out = []
    for v in vals:
        if isinstance(v, list):
            out += [x for x in v if x not in (None, "")]
        elif v not in (None, ""):
            out.append(v)
    return out


# field -> (label, kind, getter(node, ctx)); kind drives the allowed operators and the editor
FIELDS: dict[str, tuple[str, str, object]] = {
    "value": ("Value", "str", lambda n, c: n["value"]),
    "tld": ("TLD", "str", lambda n, c: _host(n).rsplit(".", 1)[-1] if "." in _host(n) and not is_ip(_host(n)) else None),
    "apex": ("Registered domain", "str", lambda n, c: apex_of(_host(n)) if n["type"] in (g.DOMAIN, g.URL) else None),
    "vt_malicious": ("VT malicious engines", "num", lambda n, c: n["props"].get("vt_malicious")),
    "asn": ("ASN", "str", lambda n, c: str(n["props"]["asn"]) if n["props"].get("asn") else None),
    "as_owner": ("AS owner / org", "str", lambda n, c: n["props"].get("as_owner") or n["props"].get("shodan_org")),
    "country": ("Country", "str", lambda n, c: n["props"].get("country")),
    "registrar": ("Registrar", "str", lambda n, c: n["props"].get("registrar")),
    "age_days": ("Domain age (days)", "num", lambda n, c: _days_since(n["props"].get("created"))),
    "issuer": ("Certificate issuer", "str", lambda n, c: n["props"].get("issuer")),
    "subject_cn": ("Certificate subject CN", "str", lambda n, c: n["props"].get("subject_cn")),
    "san": ("Certificate SAN names", "list", lambda n, c: _list(n["props"].get("san"))),
    "title": ("Page title", "str", lambda n, c: n["props"].get("title") or n["props"].get("urlscan_title")
              or (n["value"] if n["type"] == g.TITLE else None)),
    "file_type": ("File type", "str", lambda n, c: n["props"].get("file_type")),
    "name": ("File name", "str", lambda n, c: n["props"].get("name")),
    "label": ("Threat label", "str", lambda n, c: n["props"].get("label")),
    "families": ("Malware families", "list", lambda n, c: _list(n["props"].get("families"), n["props"].get("analyst_family"))),
    "actors": ("Actors", "list", lambda n, c: _list(n["props"].get("actors"), n["props"].get("analyst_actor"))),
    "tags": ("Tags", "list", lambda n, c: _list(n["props"].get("tags"), n["props"].get("shodan_tags"))),
    "open_ports": ("Open ports", "list", lambda n, c: _list(n["props"].get("open_ports"), n["props"].get("shodan_ports"))),
    "cpes": ("CPEs (InternetDB)", "list", lambda n, c: _list(n["props"].get("cpes"))),
    "priority": ("Triage priority", "str", lambda n, c: n["props"].get("priority")),
    "verdict": ("Analyst verdict", "str", lambda n, c: n["props"].get("analyst_verdict")),
    "cluster": ("In confirmed cluster", "bool", lambda n, c: bool(n["props"].get("cluster"))),
    "shared_hosting": ("Shared hosting", "bool", lambda n, c: bool(n["props"].get("shared_hosting"))),
    "expanded": ("Already pivoted", "bool", lambda n, c: bool(n["props"].get("expanded"))),
    "confidence": ("Confidence score", "num", lambda n, c: (c["scores"].get(n["id"]) or {}).get("confidence")),
    "fidelity": ("Fidelity score", "num", lambda n, c: (c["scores"].get(n["id"]) or {}).get("fidelity")),
    "degree": ("Number of links", "num", lambda n, c: len(c["adj"].get(n["id"], ()))),
}
OPS = {
    "str": ["eq", "neq", "contains", "not_contains", "startswith", "endswith", "regex", "in", "not_in", "exists",
            "not_exists"],
    "num": ["eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "exists", "not_exists"],
    "list": ["contains", "not_contains", "eq", "in", "regex", "exists", "not_exists"],
    "bool": ["eq"],
}
OP_LABEL = {"eq": "=", "neq": "≠", "contains": "contains", "not_contains": "does not contain", "startswith": "starts with",
            "endswith": "ends with", "regex": "matches regex", "in": "is one of", "not_in": "is not one of",
            "gt": ">", "gte": "≥", "lt": "<", "lte": "≤", "exists": "is set", "not_exists": "is not set"}
NEGATIVE = {"neq", "not_contains", "not_in", "not_exists"}


def field_kind(field: str) -> str:
    return FIELDS[field][1] if field in FIELDS else "str"


def schema() -> dict:
    """What the rule editor offers."""
    return {"types": TYPES, "rels": RELS, "sources": SOURCES, "categories": CATEGORIES, "limits": LIMITS,
            "platforms": {k: {x: v[x] for x in ("name", "help", "examples")} for k, v in PLATFORMS.items()},
            "fields": [{"id": k, "label": v[0], "kind": v[1]} for k, v in FIELDS.items()],
            "ops": OPS, "op_labels": OP_LABEL, "templates": TEMPLATES}


# ── validation ─────────────────────────────────────────────────────────────────

def _str(v, name: str, lo: int, hi: int) -> str:
    v = str(v if v is not None else "").strip()
    if not lo <= len(v) <= hi:
        raise ValueError(f"{name} must be {lo}-{hi} characters")
    return v


def _condition(c: dict, where: str) -> dict:
    if not isinstance(c, dict):
        raise ValueError(f"{where}: condition must be an object")
    field = str(c.get("field") or "")
    if field not in FIELDS and not PROP_RE.match(field):
        raise ValueError(f"{where}: unknown field '{field[:40]}'")
    kind = field_kind(field)
    op = str(c.get("op") or "")
    if op not in OPS[kind]:
        raise ValueError(f"{where}: operator '{op[:20]}' does not apply to {FIELDS.get(field, (field,))[0]}")
    value = c.get("value")
    if op in ("exists", "not_exists"):
        value = None
    elif op in ("in", "not_in"):
        items = value if isinstance(value, list) else re.split(r"[\n,]+", str(value or ""))
        items = [str(x).strip() for x in items if str(x).strip()]
        if not items or len(items) > LIMITS["list"]:
            raise ValueError(f"{where}: give 1-{LIMITS['list']} values")
        if kind == "num":
            try:
                items = [float(x) for x in items]
            except ValueError:
                raise ValueError(f"{where}: values must be numbers") from None
        value = items
    elif kind == "num":
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{where}: value must be a number") from None
    elif kind == "bool":
        value = value in (True, "true", "1", 1, "yes", "on")
    else:
        value = _str(value, f"{where}: value", 1, LIMITS["regex"] if op == "regex" else LIMITS["value"])
        if op == "regex":
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"{where}: invalid regex ({exc})") from None
    return {"field": field, "op": op, "value": value}


def validate(raw: dict) -> dict:
    """Normalised copy of a rule from the editor; ValueError with a readable message otherwise."""
    if not isinstance(raw, dict):
        raise ValueError("rule must be an object")
    r = {"name": _str(raw.get("name"), "name", 1, LIMITS["name"]),
         "description": str(raw.get("description") or "").strip()[: LIMITS["description"]],
         "category": str(raw.get("category") or "other").strip()[: LIMITS["category"]] or "other",
         "enabled": raw.get("enabled", True) not in (False, "false", 0, "0")}
    tags = raw.get("tags") or []
    if isinstance(tags, str):
        tags = re.split(r"[,\s]+", tags)
    tags = list(dict.fromkeys(str(t).strip().lower() for t in tags if str(t).strip()))
    if len(tags) > LIMITS["tags"] or any(len(t) > LIMITS["tag"] for t in tags):
        raise ValueError(f"at most {LIMITS['tags']} tags of {LIMITS['tag']} characters")
    r["tags"] = tags
    target = str(raw.get("target") or "any")
    if target != "any" and target not in TYPES:
        raise ValueError(f"unknown indicator type '{target[:30]}'")
    r["target"] = target
    r["match"] = "any" if raw.get("match") == "any" else "all"
    conds = raw.get("conditions") or []
    rels = raw.get("relations") or []
    if not isinstance(conds, list) or not isinstance(rels, list):
        raise ValueError("conditions and relations must be lists")
    if len(conds) > LIMITS["conditions"] or len(rels) > LIMITS["relations"]:
        raise ValueError(f"at most {LIMITS['conditions']} conditions and {LIMITS['relations']} relations")
    r["conditions"] = [_condition(c, f"condition {i + 1}") for i, c in enumerate(conds)]
    r["relations"] = []
    for i, rel in enumerate(rels):
        where = f"relation {i + 1}"
        if not isinstance(rel, dict):
            raise ValueError(f"{where} must be an object")
        name = str(rel.get("rel") or "any")
        if name != "any" and name not in RELS:
            raise ValueError(f"{where}: unknown relation '{name[:30]}'")
        tt = str(rel.get("target_type") or "any")
        if tt != "any" and tt not in TYPES:
            raise ValueError(f"{where}: unknown type '{tt[:30]}'")
        rc = rel.get("conditions") or []
        if len(rc) > LIMITS["rel_conditions"]:
            raise ValueError(f"{where}: at most {LIMITS['rel_conditions']} conditions")
        try:
            mn = int(rel.get("min") or 1)
        except (TypeError, ValueError):
            raise ValueError(f"{where}: minimum must be a number") from None
        r["relations"].append({"rel": name, "direction": rel.get("direction") if rel.get("direction") in ("in", "out") else "any",
                               "target_type": tt, "match": "any" if rel.get("match") == "any" else "all",
                               "min": max(1, min(mn, 1000)),
                               "conditions": [_condition(c, f"{where}, condition {j + 1}") for j, c in enumerate(rc)]})
    for k in ("min_confidence", "min_fidelity"):
        v = raw.get(k)
        if v in (None, ""):
            r[k] = None
            continue
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"{k.replace('_', ' ')} must be 0-100") from None
        if not 0 <= v <= 100:
            raise ValueError(f"{k.replace('_', ' ')} must be 0-100")
        r[k] = v
    if not (r["conditions"] or r["relations"] or r["target"] != "any"
            or r["min_confidence"] is not None or r["min_fidelity"] is not None):
        raise ValueError("add at least one condition, relation or score threshold, or pick an indicator type")
    a = raw.get("action") or {}
    atype = a.get("type") if a.get("type") in ("none", "pivot", "query") else "none"
    act = {"type": atype}
    if atype == "pivot":
        srcs = [s for s in (a.get("sources") or []) if s in SOURCES]
        if not srcs:
            raise ValueError("pick at least one data source for the pivot action")
        act["sources"] = list(dict.fromkeys(srcs))
    if atype == "query":
        plat = a.get("platform") or "urlscan"
        if plat not in PLATFORMS:
            raise ValueError(f"unknown query platform '{str(plat)[:30]}'")
        act["platform"] = plat
        q = _str(a.get("query"), "query template", 3, 400)
        for ph in PLACEHOLDER_RE.findall(q):
            if not ALLOWED_PH.match(ph):
                raise ValueError(f"unknown placeholder {{{ph[:40]}}}: use {{value}}, {{apex}}, {{host}} or {{prop:name}}")
        act["query"] = q
    if atype != "none":
        try:
            act["max"] = max(1, min(int(a.get("max") or 5), LIMITS["max"]))
        except (TypeError, ValueError):
            raise ValueError("max actions must be a number") from None
    r["action"] = act
    return r


# ── evaluation ─────────────────────────────────────────────────────────────────

def _get(field: str, n: dict, ctx: dict):
    if field in FIELDS:
        return FIELDS[field][2](n, ctx)
    v = n["props"].get(field[5:])
    return v if not isinstance(v, dict) else json.dumps(v)


def _test_one(op: str, actual, want) -> bool:
    """Does one value satisfy the *positive* form of ``op`` (neq -> eq, not_in -> in…)?"""
    if op in ("gt", "gte", "lt", "lte") or (isinstance(want, float) and op in ("eq", "neq")):
        try:
            a = float(actual)
        except (TypeError, ValueError):
            return False
        return {"gt": a > want, "gte": a >= want, "lt": a < want, "lte": a <= want,
                "eq": a == want, "neq": a == want}[op]
    a = str(actual).lower()
    if op == "regex":
        return re.search(want, str(actual), re.I) is not None
    if op in ("in", "not_in"):
        if want and isinstance(want[0], float):
            try:
                return float(actual) in want
            except (TypeError, ValueError):
                return False
        return a in {str(w).lower() for w in want}
    w = str(want).lower()
    return {"eq": a == w, "neq": a == w, "contains": w in a, "not_contains": w in a,
            "startswith": a.startswith(w), "endswith": a.endswith(w)}[op]


def check(cond: dict, n: dict, ctx: dict) -> tuple[bool, str]:
    """(holds, explanation with the value that was seen)."""
    field, op, want = cond["field"], cond["op"], cond["value"]
    actual = _get(field, n, ctx)
    label = FIELDS.get(field, (field,))[0]
    shown = actual if not isinstance(actual, list) else ", ".join(map(str, actual[:6])) + ("…" if len(actual) > 6 else "")
    want_s = (", ".join(str(int(x) if isinstance(x, float) and x.is_integer() else x) for x in want[:8])
              if isinstance(want, list) else (int(want) if isinstance(want, float) and want.is_integer() else want))
    empty = actual in (None, "", [])
    if op == "exists":
        return not empty, f"{label} is set ({shown})" if not empty else f"{label} is not set"
    if op == "not_exists":
        return empty, f"{label} is not set" if empty else f"{label} is set ({shown})"
    if cond["field"] in FIELDS and field_kind(field) == "bool":
        ok = bool(actual) == bool(want)
        return ok, f"{label} is {'yes' if actual else 'no'}"
    if empty:
        return op in NEGATIVE and op != "not_exists", f"{label} is not set"
    vals = actual if isinstance(actual, list) else [actual]
    if op in NEGATIVE:
        hit = any(_test_one(op, v, want) for v in vals)   # _test_one answers the positive form
        ok = not hit
    else:
        ok = any(_test_one(op, v, want) for v in vals)
    return ok, f"{label} {OP_LABEL[op]} {want_s}: seen {shown!s:.120}"


def _clauses(conds: list[dict], n: dict, ctx: dict, mode: str) -> tuple[bool, list[str], list[str]]:
    held, failed = [], []
    for c in conds:
        ok, why = check(c, n, ctx)
        (held if ok else failed).append(why)
    if not conds:
        return True, held, failed
    return (bool(held) if mode == "any" else not failed), held, failed


def _relation(rel: dict, n: dict, ctx: dict) -> tuple[bool, str]:
    nodes, nid = ctx["nodes"], n["id"]
    hits = []
    for (s, d, r) in ctx["out"].get(nid, []) + ctx["inc"].get(nid, []):
        outgoing = s == nid
        other = d if outgoing else s
        if rel["rel"] != "any" and r != rel["rel"]:
            continue
        if rel["direction"] == "out" and not outgoing or rel["direction"] == "in" and outgoing:
            continue
        o = nodes.get(other)
        if not o or rel["target_type"] != "any" and o["type"] != rel["target_type"]:
            continue
        ok, held, _ = _clauses(rel["conditions"], o, ctx, rel["match"])
        if ok:
            hits.append((o, r, held))
    arrow = {"out": "→", "in": "←"}.get(rel["direction"], "↔")
    desc = f"{rel['rel'] if rel['rel'] != 'any' else 'any relation'} {arrow} {rel['target_type'] if rel['target_type'] != 'any' else 'any type'}"
    if len(hits) < rel["min"]:
        return False, f"{desc}: {len(hits)} matching neighbour(s), need {rel['min']}"
    sample = "; ".join(f"{o['type']} {o['value'][:50]}" + (f" ({', '.join(h)})" if h else "") for o, _, h in hits[:3])
    more = f" +{len(hits) - 3} more" if len(hits) > 3 else ""
    return True, f"{desc}: {len(hits)} matching neighbour(s): {sample}{more}"


def context(nodes: dict, edges, scores: dict | None = None) -> dict:
    """Indexes a rule evaluation needs. ``edges``: {(s, d, rel): props} or an iterable of keys."""
    out: dict[str, list] = {}
    inc: dict[str, list] = {}
    adj: dict[str, set] = {}
    for (s, d, r) in edges:
        out.setdefault(s, []).append((s, d, r))
        inc.setdefault(d, []).append((s, d, r))
        adj.setdefault(s, set()).add(d)
        adj.setdefault(d, set()).add(s)
    return {"nodes": nodes, "out": out, "inc": inc, "adj": adj, "scores": scores or {}}


def evaluate(rule: dict, ctx: dict, limit: int = 1000) -> tuple[list[dict], int]:
    """([match], entities evaluated). Each match explains which clauses held."""
    matches, evaluated = [], 0
    for nid, n in ctx["nodes"].items():
        if rule["target"] != "any" and n["type"] != rule["target"]:
            continue
        if n["type"] == g.SCAN:
            continue
        evaluated += 1
        sc = ctx["scores"].get(nid) or {}
        gate_why = []
        if rule.get("min_confidence") is not None:
            if (sc.get("confidence") or 0) < rule["min_confidence"]:
                continue
            gate_why.append(f"confidence {sc.get('confidence')} ≥ {rule['min_confidence']}")
        if rule.get("min_fidelity") is not None:
            if (sc.get("fidelity") or 0) < rule["min_fidelity"]:
                continue
            gate_why.append(f"fidelity {sc.get('fidelity')} ≥ {rule['min_fidelity']}")
        ok_c, held, failed = _clauses(rule["conditions"], n, ctx, rule["match"])
        rel_held, rel_failed = [], []
        for rel in rule["relations"]:
            ok, why = _relation(rel, n, ctx)
            (rel_held if ok else rel_failed).append(why)
        if rule["match"] == "any":
            ok = bool(held or rel_held) or (not rule["conditions"] and not rule["relations"])
        else:
            ok = ok_c and not rel_failed
        if not ok:
            continue
        matches.append({"id": nid, "type": n["type"], "value": n["value"],
                        "reasons": ([f"type is {n['type']}"] if rule["target"] != "any" else []) + gate_why + held + rel_held,
                        "unmet": failed + rel_failed if rule["match"] == "any" else [],
                        "confidence": sc.get("confidence"), "fidelity": sc.get("fidelity"),
                        "priority": n["props"].get("priority"), "expanded": bool(n["props"].get("expanded"))})
        if len(matches) >= limit:
            break
    matches.sort(key=lambda m: (-(m["fidelity"] or 0), -(m["confidence"] or 0), m["value"]))
    return matches, evaluated


def render_query(template: str, n: dict) -> str | None:
    """Fill a query template from an entity; None when a placeholder has no value on it."""
    def val(ph: str) -> str | None:
        if ph == "value":
            v = n["value"]
        elif ph == "host":
            v = _host(n)
        elif ph == "apex":
            v = apex_of(_host(n)) if n["type"] in (g.DOMAIN, g.URL) else None
        else:
            v = n["props"].get(ph[5:])
            if isinstance(v, list):
                v = v[0] if v else None
        if v in (None, "") or isinstance(v, dict):
            return None
        return str(v).replace("\\", "\\\\").replace('"', '\\"')
    missing = False

    def sub(m):
        nonlocal missing
        v = val(m.group(1))
        if v is None:
            missing = True
            return ""
        return v
    q = PLACEHOLDER_RE.sub(sub, template)
    return None if missing or not q.strip() else q[:500]


def query_link(platform: str, query: str) -> str:
    """Open-in-platform URL for a rendered query."""
    from urllib.parse import quote
    return PLATFORMS[platform]["url"].replace("{q}", quote(query, safe=""))


TEMPLATES = [
    {"name": "Certificate served by a flagged IP", "category": "certificate", "tags": ["tls", "pivot"], "target": g.CERT,
     "description": "TLS certificates presented by an IP that VirusTotal flags: pivot on the certificate to find "
                    "the actor's other servers (CT logs, VT).",
     "match": "all", "conditions": [], "relations": [{"rel": "USES_CERT", "direction": "in", "target_type": g.IP,
                                                       "match": "all", "min": 1, "conditions": [
                                                           {"field": "vt_malicious", "op": "gte", "value": 1}]}],
     "action": {"type": "pivot", "sources": ["ct", "vt"], "max": 5}},
    {"name": "Young domain on a confirmed IP", "category": "infrastructure", "tags": ["nrd"], "target": g.DOMAIN,
     "description": "Domains registered in the last 60 days that resolve to a dedicated (not shared-hosting / CDN) "
                    "IP of the confirmed cluster.",
     "match": "all", "conditions": [{"field": "age_days", "op": "lte", "value": 60}],
     "relations": [{"rel": "RESOLVES_TO", "direction": "out", "target_type": g.IP, "match": "all", "min": 1,
                    "conditions": [{"field": "cluster", "op": "eq", "value": True},
                                   {"field": "shared_hosting", "op": "eq", "value": False},
                                   {"field": "as_owner", "op": "not_contains", "value": "cloudflare"}]}],
     "action": {"type": "pivot", "sources": ["vt", "urlscan", "pdns"], "max": 5}},
    {"name": "Samples talking to P1/P2 infrastructure", "category": "malware", "tags": ["c2"], "target": g.FILE,
     "description": "Files whose sandbox runs contact a host already triaged P1 or P2.",
     "match": "all", "conditions": [],
     "relations": [{"rel": "CONTACTS", "direction": "out", "target_type": "any", "match": "all", "min": 1,
                    "conditions": [{"field": "priority", "op": "in", "value": ["P1", "P2"]}]}],
     "action": {"type": "none"}},
    {"name": "Phishing kit reuse by page title", "category": "phishing", "tags": ["kit", "urlscan"], "target": g.DOMAIN,
     "description": "Confirmed domains with a page title: search urlscan for other sites with the same title.",
     "match": "all", "conditions": [{"field": "cluster", "op": "eq", "value": True},
                                    {"field": "title", "op": "exists", "value": None}],
     "relations": [], "min_fidelity": 50,
     "action": {"type": "query", "platform": "urlscan", "query": 'page.title:"{prop:urlscan_title}"', "max": 3}},
    {"name": "JARM fingerprint hunt on VT Intelligence", "category": "infrastructure", "tags": ["jarm", "vt"],
     "target": g.JARM,
     "description": "JARM fingerprints of cluster servers: VT Intelligence search for domains with the same TLS "
                    "configuration (premium VT key; JARM alone is weak: corroborate the hits).",
     "match": "all", "conditions": [],
     "relations": [{"rel": "HAS_JARM", "direction": "in", "target_type": "any", "match": "all", "min": 1,
                    "conditions": [{"field": "cluster", "op": "eq", "value": True}]}],
     "action": {"type": "query", "platform": "vt", "query": "entity:domain jarm:{value}", "max": 5}},
    {"name": "Unpivoted high-fidelity leads", "category": "other", "tags": ["triage"], "target": "any",
     "description": "Entities that score well but nobody has expanded yet: the next pivots worth running.",
     "match": "all", "conditions": [{"field": "expanded", "op": "eq", "value": False}], "relations": [],
     "min_fidelity": 60, "min_confidence": 50, "action": {"type": "pivot", "sources": ["vt", "urlscan", "pdns", "ct"], "max": 3}},
]


# ── storage ────────────────────────────────────────────────────────────────────

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
        tmp.write_text(json.dumps({"version": 1, "rules": rules}, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def list(self) -> list[dict]:
        with self.lock:
            return sorted(self._load(), key=lambda r: (not r.get("enabled", True), r.get("name", "").lower()))

    def get(self, rid: str) -> dict:
        for r in self.list():
            if r["id"] == rid:
                return r
        raise LookupError("no such rule")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def create(self, raw: dict) -> dict:
        r = validate(raw)
        r.update(id="r_" + uuid.uuid4().hex[:10], created=self._now(), updated=self._now(), last_run=None)
        with self.lock:
            rules = self._load()
            if len(rules) >= 500:
                raise ValueError("at most 500 rules")
            rules.append(r)
            self._save(rules)
        return r

    def update(self, rid: str, raw: dict) -> dict:
        r = validate(raw)
        with self.lock:
            rules = self._load()
            for i, cur in enumerate(rules):
                if cur["id"] == rid:
                    rules[i] = {**r, "id": rid, "created": cur.get("created"), "updated": self._now(),
                                "last_run": cur.get("last_run")}
                    self._save(rules)
                    return rules[i]
        raise LookupError("no such rule")

    def patch(self, rid: str, **fields) -> dict:
        with self.lock:
            rules = self._load()
            for cur in rules:
                if cur["id"] == rid:
                    cur.update(fields)
                    self._save(rules)
                    return cur
        raise LookupError("no such rule")

    def duplicate(self, rid: str) -> dict:
        src = self.get(rid)
        return self.create({**src, "name": (src["name"] + " (copy)")[: LIMITS["name"]], "enabled": False})

    def delete(self, rid: str) -> None:
        with self.lock:
            rules = self._load()
            keep = [r for r in rules if r["id"] != rid]
            if len(keep) == len(rules):
                raise LookupError("no such rule")
            self._save(keep)
