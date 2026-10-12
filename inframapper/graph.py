"""In-memory property graph: nodes keyed by type+value, edges keyed by (src, dst, rel)."""

from __future__ import annotations

# Node types used across the tool (also drives HTML colours)
FILE, DOMAIN, IP, URL = "File", "Domain", "IP", "URL"
ASN, CERT, JARM, LABEL = "ASN", "Certificate", "JARM", "ThreatLabel"
FAVICON, TITLE, HTML_HASH, SCRIPT, PATTERN, SCAN = (
    "Favicon", "Title", "HtmlHash", "Script", "Pattern", "Scan")
INTEL = "IntelQuery"
NS, MX, SOA = "NameServer", "MailServer", "SoaEmail"   # passive / live DNS
REPORT = "Report"   # prior public reporting (OTX pulse, ThreatFox / MalwareBazaar family)


def node_id(ntype: str, value: str) -> str:
    return f"{ntype}:{value.strip().lower()}"


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple[str, str, str], dict] = {}

    def add_node(self, ntype: str, value: str, **props) -> str:
        nid = node_id(ntype, value)
        node = self.nodes.setdefault(
            nid, {"id": nid, "type": ntype, "value": value, "props": {}})
        for k, v in props.items():
            if v is None or v == "" or v == [] or v == {}:
                continue
            cur = node["props"].get(k)
            if isinstance(cur, list) and isinstance(v, list):
                node["props"][k] = cur + [x for x in v if x not in cur]
            else:
                node["props"][k] = v
        return nid

    def add_edge(self, src: str, dst: str, rel: str, **props) -> None:
        if src == dst:
            return
        edge = self.edges.setdefault((src, dst, rel), {})
        seen_by = props.pop("seen_by", None)
        edge.update({k: v for k, v in props.items() if v not in (None, "")})
        if seen_by:   # every source that observed this relation: independent corroboration (scoring.py)
            cur = edge.setdefault("seen_by", [])
            cur.extend(s for s in seen_by if s not in cur)

    def set_prop(self, nid: str, **props) -> None:
        if nid in self.nodes:
            self.nodes[nid]["props"].update(props)

    def to_dict(self) -> dict:
        return {
            "nodes": list(self.nodes.values()),
            "edges": [{"source": s, "target": d, "rel": r, "props": p}
                      for (s, d, r), p in self.edges.items()],
        }
