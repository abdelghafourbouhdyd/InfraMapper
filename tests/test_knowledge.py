from pathlib import Path

from ioci import graph as g
from ioci.export import attribution_votes, case_attribution
from ioci.feeds import triage
from ioci.investigator import Config, Investigator
from ioci.knowledge import Knowledge


def case(tmp_path: Path, name: str, kb: Knowledge) -> Investigator:
    """seed domain -> dedicated IP -> a second domain on it; plus a CDN IP and an unconfirmed look-alike."""
    inv = Investigator(None, None, Config())
    inv.kb = kb
    inv.seed_id = inv.g.add_node(g.DOMAIN, f"{name}.com", seed=True, depth=0)
    ip = inv.g.add_node(g.IP, "45.9.148.12")
    inv.g.add_edge(inv.seed_id, ip, "RESOLVES_TO")
    cert = inv.g.add_node(g.CERT, "aa" * 32)
    inv.g.add_edge(inv.seed_id, cert, "HAS_CERT")
    cdn = inv.g.add_node(g.IP, "104.16.1.1", shared_hosting=True)
    inv.g.add_edge(inv.seed_id, cdn, "RESOLVES_TO")
    inv.g.add_node(g.DOMAIN, "lookalike.net")
    inv.recluster()
    (tmp_path / name).mkdir(exist_ok=True)
    return inv


def test_memory_across_cases(tmp_path):
    kb = Knowledge(tmp_path / "knowledge.db")
    first = case(tmp_path, "alpha", kb)
    kb.index_case(first, tmp_path / "alpha", {"actors": ["APT28"], "families": []})
    second = case(tmp_path, "beta", kb)
    assert second.cross_case("beta") >= 2
    ip = second.g.nodes["IP:45.9.148.12"]["props"]
    assert ip["seen_cases"] == 1 and ip["seen_in"][0]["actors"] == ["APT28"]
    assert second.g.nodes[f"Certificate:{'aa' * 32}"]["props"]["seen_cases"] == 1
    # shared hosting and unconfirmed candidates are never remembered: they'd link unrelated cases
    assert "seen_in" not in second.g.nodes["IP:104.16.1.1"]["props"]
    assert "seen_in" not in second.g.nodes["Domain:lookalike.net"]["props"]


def test_false_positive_everywhere(tmp_path):
    kb = Knowledge(tmp_path / "knowledge.db")
    inv = case(tmp_path, "alpha", kb)
    ip = inv.g.nodes["IP:45.9.148.12"]
    assert ip["props"]["cluster"] is True
    kb.set_verdict(ip, "fp", note="sinkhole")
    other = case(tmp_path, "beta", kb)          # a different case: the verdict applies there too
    p = other.g.nodes["IP:45.9.148.12"]["props"]
    assert p["cluster"] is False and p["cluster_evidence"] == ["analyst: false positive"]
    p["pinned"] = True                          # even when shown, it's triaged as noise
    assert triage(other.g, "IP:45.9.148.12")[0] == "noise"
    kb.clear_verdict("IP:45.9.148.12")
    other.recluster()
    assert other.g.nodes["IP:45.9.148.12"]["props"]["cluster"] is True
    assert "analyst_verdict" not in other.g.nodes["IP:45.9.148.12"]["props"]


def test_confirmed_is_a_seed_and_actor_label_attributes(tmp_path):
    kb = Knowledge(tmp_path / "knowledge.db")
    inv = case(tmp_path, "alpha", kb)
    look = inv.g.nodes["Domain:lookalike.net"]
    assert look["props"]["cluster"] is False
    kb.set_verdict(look, "confirmed", actor="Fancy Bear", note="same operator, see ticket 42")
    inv.recluster()
    assert look["props"]["cluster"] is True
    assert look["props"]["cluster_evidence"] == ["confirmed by an analyst"]
    votes = attribution_votes(inv)
    assert votes[("actor", "fancybear")]["groups"] == {"analyst"}
    assert case_attribution(inv)["actors"] == ["Fancy Bear"]
    kb.set_verdict(look, "confirmed", actor=None)   # label removed: its report node goes too
    inv.recluster()
    assert not any(n["props"].get("source") == "Analyst" for n in inv.g.nodes.values())


def test_family_label(tmp_path):
    from ioci import share
    kb = Knowledge(tmp_path / "knowledge.db")
    inv = case(tmp_path, "alpha", kb)
    ip = inv.g.nodes["IP:45.9.148.12"]
    kb.set_verdict(ip, "confirmed", family="Cobalt Strike", note="beacon config extracted")
    inv.recluster()
    assert ip["props"]["analyst_family"] == "Cobalt Strike"
    assert attribution_votes(inv)[("malware", "cobaltstrike")]["groups"] == {"analyst"}
    assert case_attribution(inv)["families"] == ["Cobalt Strike"]
    inv.tlp = "amber"
    row = next(r for r in share.actionable(inv) if r["value"] == "45.9.148.12")
    assert row["families"] == ["Cobalt Strike"]          # exported to STIX / iocs.csv
    kb.set_verdict(ip, "fp", actor="APT28", family="Cobalt Strike")   # an FP carries no labels
    inv.recluster()
    assert "analyst_family" not in ip["props"] and "analyst_actor" not in ip["props"]


def test_old_knowledge_db_is_upgraded(tmp_path):
    import sqlite3
    db = sqlite3.connect(tmp_path / "knowledge.db")
    db.execute("CREATE TABLE verdicts (nid TEXT PRIMARY KEY, type TEXT, value TEXT, verdict TEXT, actor TEXT, "
               "note TEXT, case_id TEXT, updated INTEGER)")
    db.execute("INSERT INTO verdicts VALUES ('IP:1.2.3.4', 'IP', '1.2.3.4', 'fp', NULL, 'old', 'c', 1)")
    db.commit()
    db.close()
    kb = Knowledge(tmp_path / "knowledge.db")
    assert kb.verdicts(["IP:1.2.3.4"])["IP:1.2.3.4"]["verdict"] == "fp"
    kb.set_verdict({"id": "IP:5.6.7.8", "type": "IP", "value": "5.6.7.8"}, None, family="Lumma")
    assert kb.verdicts(["IP:5.6.7.8"])["IP:5.6.7.8"]["family"] == "Lumma"
