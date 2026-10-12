"""Sharing / detection exports: STIX 2.1 bundle and hunt content (Suricata rules, plain IOC lists).

Only actionable IOCs go out (P1 / P2 / P3 and strong / medium new-domain leads). ``noise`` never
leaves the case: pushing a CDN or Tor exit into a TIP is how false attribution spreads.
IDs are deterministic (uuid5 of the value), so re-exporting an updated case into OpenCTI / MISP
updates the same objects instead of duplicating them.
"""

from __future__ import annotations

import ipaddress
import json
import uuid
import zlib
from datetime import datetime, timezone
from pathlib import Path

from . import graph as g
from .feeds import triage_all

NS = uuid.UUID("7c3f7f0e-6a36-4d57-9f3e-2f1c0a9b5e11")   # this tool's uuid5 namespace
# OASIS STIX 2.1 TLP marking definitions (TLP 1.0 ids; CLEAR maps to WHITE)
TLP = {
    "clear": ("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "white"),
    "white": ("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "white"),
    "green": ("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", "green"),
    "amber": ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "amber"),
    "red": ("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", "red"),
}
CONFIDENCE = {"P1": 85, "P2": 70, "P3": 50, "lead-strong": 40, "lead-medium": 25}


def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, f'{kind}:{key}')}"


def _q(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def _pattern(ntype: str, value: str) -> str | None:
    if ntype == g.IP:
        try:
            ver = ipaddress.ip_address(value).version
        except ValueError:
            return None
        return f"[ipv{ver}-addr:value = '{value}']"
    if ntype == g.DOMAIN:
        return f"[domain-name:value = '{_q(value)}']"
    if ntype == g.URL:
        return f"[url:value = '{_q(value)}']"
    if ntype == g.FILE:
        algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(value))
        return f"[file:hashes.'{algo}' = '{value}']" if algo else None
    return None


def _hashes(ntype: str, value: str, props: dict) -> dict[str, str]:
    if ntype != g.FILE:
        return {}
    out = {k: props[k].lower() for k in ("md5", "sha1", "sha256") if props.get(k)}
    algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value))
    if algo:
        out[algo] = value.lower()
    return out


OPINION_SOURCES = {"VT comment", "VT AV consensus", "VT sandbox"}


def actionable(inv) -> list[dict]:
    """[{type, value, priority, action, reasons, families, refs}] for everything worth sharing / hunting."""
    gr, out = inv.g, []
    rows = triage_all(gr)
    in_view = {n["value"] for n, *_ in rows}
    for n, pri, action, why in rows:
        if pri == "noise":
            continue
        reps = [gr.nodes[d]["props"] for (s, d, rel) in gr.edges
                if rel == "REPORTED_IN" and s == n["id"] and d in gr.nodes]
        fams = sorted({m for r in reps for m in r.get("malware") or [] if m and m != "unknown"})
        # a community comment naming an actor isn't attribution you ship to other teams
        actors = sorted({r["actor"] for r in reps if r.get("actor") and r.get("source") not in OPINION_SOURCES})
        refs = [{"source_name": r.get("source") or "report", "description": (r.get("name") or "")[:200],
                 **({"url": r["url"]} if r.get("url") else {})} for r in reps if r.get("source") != "Input report"]
        p = n["props"]
        out.append({"type": n["type"], "value": n["value"], "priority": pri, "action": action, "reasons": why,
                    "families": fams, "actors": actors, "refs": refs[:10],
                    "hashes": _hashes(n["type"], n["value"], p)})
    for x in getattr(inv, "new_domains", []) or []:
        if x["domain"] not in in_view and x.get("strength") in ("strong", "medium"):
            out.append({"type": g.DOMAIN, "value": x["domain"], "priority": f"lead-{x['strength']}",
                        "action": x["action"], "reasons": x["reasons"], "families": [], "actors": [],
                        "refs": [], "hashes": {}})
    return out


# ---------------------------------------------------------------------- STIX 2.1
def write_stix(inv, path: Path, title: str, tlp: str = "amber") -> int:
    items = actionable(inv)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    mark_id, mark_name = TLP.get(tlp.lower(), TLP["amber"])
    ident = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", "inframapper"),
             "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
             "name": "InfraMapper", "identity_class": "system"}
    marking = {"type": "marking-definition", "spec_version": "2.1", "id": mark_id,
               "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
               "name": f"TLP:{mark_name.upper()}", "definition": {"tlp": mark_name}}
    common = {"spec_version": "2.1", "created": now, "modified": now, "created_by_ref": ident["id"],
              "object_marking_refs": [mark_id]}
    objs, refs = [ident, marking], []
    malware: dict[str, dict] = {}
    actors: dict[str, dict] = {}
    for it in items:
        pat = _pattern(it["type"], it["value"])
        if not pat:
            continue
        if it["type"] == g.FILE and len(it["hashes"]) > 1:   # all known hashes of the sample in one pattern
            parts = [f"file:hashes.'{a}' = '{it['hashes'][k]}'"
                     for k, a in (("sha256", "SHA-256"), ("sha1", "SHA-1"), ("md5", "MD5")) if it["hashes"].get(k)]
            pat = "[" + " OR ".join(parts) + "]"
        ind = {"type": "indicator", "id": _sid("indicator", f"{it['type']}:{it['value'].lower()}"), **common,
               "name": f"{it['type']} {it['value'][:120]}",
               "description": f"{it['priority']}: {it['action']}. " + "; ".join(it["reasons"])[:900],
               "indicator_types": ["malicious-activity"] if it["priority"] in ("P1", "P2") else ["anomalous-activity"],
               "pattern": pat, "pattern_type": "stix", "valid_from": now,
               "confidence": CONFIDENCE.get(it["priority"], 30),
               "labels": [it["priority"]] + it["families"][:5],
               "x_inframapper_priority": it["priority"], "x_inframapper_action": it["action"]}
        if it["refs"]:
            ind["external_references"] = it["refs"]
        objs.append(ind)
        refs.append(ind["id"])
        for fam in it["families"]:
            m = malware.setdefault(fam, {"type": "malware", "id": _sid("malware", fam.lower()), **common,
                                         "name": fam, "is_family": True})
            rel = {"type": "relationship", "id": _sid("relationship", f"{ind['id']}>{m['id']}"), **common,
                   "relationship_type": "indicates", "source_ref": ind["id"], "target_ref": m["id"]}
            objs.append(rel)
            refs.append(rel["id"])
        for actor in it["actors"]:
            a = actors.setdefault(actor, {"type": "threat-actor", "id": _sid("threat-actor", actor.lower()),
                                          **common, "name": actor, "threat_actor_types": ["unknown"]})
            rel = {"type": "relationship", "id": _sid("relationship", f"{ind['id']}>{a['id']}"), **common,
                   "relationship_type": "indicates", "source_ref": ind["id"], "target_ref": a["id"],
                   "description": "public reporting names this actor (not verified by this case)"}
            objs.append(rel)
            refs.append(rel["id"])
    objs += list(malware.values()) + list(actors.values())
    refs += [o["id"] for o in (*malware.values(), *actors.values())]
    if refs:
        objs.append({"type": "grouping", "id": _sid("grouping", title), **common, "name": title,
                     "context": "suspicious-activity",
                     "description": "InfraMapper case: triaged IOCs (noise excluded), P1 live / P2 reported / "
                                    "P3 corroborated by this investigation only.",
                     "object_refs": refs})
    path.write_text(json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}, indent=2))
    return sum(1 for o in objs if o["type"] == "indicator")


# ------------------------------------------------------------------ hunt content
def _split(items: list[dict]) -> dict[str, list[str]]:
    out = {"ip": [], "domain": [], "url": [], "md5": [], "sha1": [], "sha256": []}
    for it in items:
        t, v = it["type"], it["value"]
        if t == g.IP:
            out["ip"].append(v)
        elif t == g.DOMAIN:
            out["domain"].append(v.lower())
        elif t == g.URL:
            out["url"].append(v)
        elif t == g.FILE:
            for k, h in it["hashes"].items():
                out[k].append(h)
    return {k: sorted(set(v)) for k, v in out.items()}


def suricata_rules(items: list[dict]) -> str:
    """DNS / TLS SNI / HTTP Host rules for domains, IP rules for dedicated IPs. Local sid range."""
    lines = ["# InfraMapper: Suricata 7 rules (local sid range 9100000-9999999). Review before deploying.",
             "# P1 = live on a public feed, P2 = reported / reputation, P3 = this investigation only."]
    used: set[int] = set()

    def sid(key: str) -> int:
        n = 9_100_000 + zlib.crc32(key.encode()) % 900_000
        while n in used:
            n += 1
        used.add(n)
        return n

    for it in items:
        v, pri = it["value"], it["priority"]
        tag = (f" {', '.join(it['families'][:2])}" if it["families"] else "")
        if it["type"] == g.DOMAIN:
            d = v.lower().replace('"', "")
            for proto, buf in (("dns", "dns.query"), ("tls", "tls.sni"), ("http", "http.host")):
                src = "$HOME_NET any -> any any" if proto == "dns" else "$HOME_NET any -> $EXTERNAL_NET any"
                lines.append(f'alert {proto} {src} (msg:"InfraMapper {pri}{tag} {proto.upper()} {d}"; {buf}; dotprefix; '
                             f'content:".{d}"; nocase; endswith; classtype:trojan-activity; '
                             f'metadata:inframapper_priority {pri}; sid:{sid(proto + d)}; rev:1;)')
        elif it["type"] == g.IP:
            lines.append(f'alert ip $HOME_NET any -> {v} any (msg:"InfraMapper {pri}{tag} traffic to {v}"; '
                         f'classtype:trojan-activity; metadata:inframapper_priority {pri}; sid:{sid("ip" + v)}; rev:1;)')
    return "\n".join(lines) + "\n"


def write_hunt(inv, outdir: Path) -> dict[str, int]:
    items = actionable(inv)
    s = _split(items)
    d = outdir / "hunt"
    d.mkdir(exist_ok=True)
    (d / "suricata.rules").write_text(suricata_rules(items))
    for k in ("ip", "domain", "url", "sha256", "sha1", "md5"):   # plain lists for firewalls / EDR imports
        if s[k]:
            (d / f"{k}.txt").write_text("\n".join(s[k]) + "\n")
    return {k: len(v) for k, v in s.items() if v}


def write_all(inv, outdir: Path, title: str, tlp: str = "amber") -> None:
    write_stix(inv, outdir / "stix2.json", title, tlp)
    write_hunt(inv, outdir)
