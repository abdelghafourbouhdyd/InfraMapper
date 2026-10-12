"""Hosting pivot: IP -> the domains it hosted -> every other IP those domains lived on -> which of
those IPs share several of the same domains, and when.

An operator moves its domains between its own servers: a domain re-pointed from IP A to IP S within
days, or several domains sitting on A and S at the same time, ties S to A far better than a single
shared name (which is often a re-registration or a parking / sinkhole move years apart). Shared
hosting, CDNs, parking and sinkholes host hundreds of unrelated domains, so an IP with more than
``broad`` domains in passive DNS never counts.

Pure functions over passive-DNS records ({"rrname", "rrtype", "rdata", "first", "last"}); the
Investigator does the fetching and writes the graph.
"""

from __future__ import annotations

import ipaddress

from .pdns import norm_ip, overlaps

MOVE_GAP = 30 * 86400      # re-pointed within a month = the same hands moving it
FASTFLUX = 20              # domain seen on more IPs than this = fast flux / CDN: its IPs aren't siblings


def ips_of(records: list[dict], domain: str) -> dict[str, tuple[int, int]]:
    """{ip: (first, last)} a domain resolved to."""
    out: dict[str, tuple[int, int]] = {}
    for r in records:
        if r["rrtype"] in ("a", "aaaa") and r["rrname"] == domain and r["rdata"]:
            f, l = out.get(r["rdata"], (0, 0))
            first = min(x for x in (f, r["first"]) if x) if (f or r["first"]) else 0
            out[r["rdata"]] = (first, max(l, r["last"] or 0))
    return out


def domains_of(records: list[dict], ip: str) -> dict[str, tuple[int, int]]:
    """{domain: (first, last)} that resolved to an IP (reverse pDNS)."""
    out: dict[str, tuple[int, int]] = {}
    for r in records:
        if r["rrtype"] in ("a", "aaaa") and norm_ip(r["rdata"]) == norm_ip(ip) and r["rrname"]:
            f, l = out.get(r["rrname"], (0, 0))
            first = min(x for x in (f, r["first"]) if x) if (f or r["first"]) else 0
            out[r["rrname"]] = (first, max(l, r["last"] or 0))
    return out


def relation(on_anchor: tuple[int, int] | None, on_sibling: tuple[int, int] | None) -> str:
    """How one domain's time on the anchor IP relates to its time on the sibling IP."""
    if not on_anchor or not on_sibling or not on_anchor[0] or not on_sibling[0]:
        return "shared (dates unknown)"
    if overlaps(on_anchor, on_sibling):
        return "concurrent"
    if on_sibling[0] > on_anchor[1]:
        gap = on_sibling[0] - on_anchor[1]
        return f"moved anchor → here ({gap // 86400} d)" if gap <= MOVE_GAP else f"here {gap // 86400} d after anchor"
    gap = on_anchor[0] - on_sibling[1]
    return f"moved here → anchor ({gap // 86400} d)" if gap <= MOVE_GAP else f"here {gap // 86400} d before anchor"


def is_tight(rel: str) -> bool:
    """Concurrent, or moved within MOVE_GAP: the timing an operator's own infrastructure has."""
    return rel == "concurrent" or rel.startswith("moved")


def siblings(anchor: str, anchor_domains: dict[str, tuple[int, int]],
             domain_ips: dict[str, dict[str, tuple[int, int]]]) -> dict[str, dict[str, str]]:
    """{sibling ip: {shared domain: relation}} from the hosting history of the anchor's domains."""
    out: dict[str, dict[str, str]] = {}
    fam = _family(anchor)
    for d, ips in domain_ips.items():
        if len(ips) > FASTFLUX:
            continue
        for ip, win in ips.items():
            # a domain's AAAA next to its A record is dual-stack on the same host, not another server
            if norm_ip(ip) != norm_ip(anchor) and _family(ip) == fam:
                out.setdefault(ip, {})[d] = relation(anchor_domains.get(d), win)
    return out


def _family(ip: str) -> int | None:
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


def verdict(shared: dict[str, str], total_domains: int | None, broad: int) -> str:
    """linked / possible / weak / shared hosting / unverified for one sibling IP.

    ``total_domains`` None = the reverse lookup gave nothing (pDNS quota out, or no data for an IP
    forward pDNS just showed): it could be shared hosting, so it never counts as dedicated."""
    if total_domains is None:
        return "unverified"
    if total_domains > broad:
        return "shared hosting"
    tight = sum(1 for r in shared.values() if is_tight(r))
    if len(shared) >= 2 and tight >= 1 or len(shared) >= 3:
        return "linked"
    if tight:
        return "possible"
    return "weak"
