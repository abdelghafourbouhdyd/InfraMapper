import pytest

from inframapper import graph as g, rules
from inframapper.scoring import Scorer


def graph():
    gr = g.Graph()
    seed = gr.add_node(g.DOMAIN, "login-secure.top", seed=True, cluster=True, urlscan_title='Sign "in"')
    bad_ip = gr.add_node(g.IP, "198.51.100.7", vt_malicious=4, asn=9009, cluster=True)
    good_ip = gr.add_node(g.IP, "192.0.2.80", vt_malicious=0, asn=13335)
    cert = gr.add_node(g.CERT, "e" * 64, issuer="Let's Encrypt", subject_cn="login-secure.top")
    cert2 = gr.add_node(g.CERT, "f" * 64, issuer="DigiCert")
    gr.add_edge(seed, bad_ip, "RESOLVES_TO", source="vt")
    gr.add_edge(bad_ip, cert, "USES_CERT", seen_by=["urlscan"])
    gr.add_edge(good_ip, cert2, "USES_CERT", seen_by=["VirusTotal"])
    gr.add_edge(seed, good_ip, "RESOLVES_TO", source="vt")
    return gr, seed, bad_ip, cert, cert2


def ctx(gr, seed):
    return rules.context(gr.nodes, gr.edges, Scorer(gr.nodes, gr.edges, seed).score())


def test_relation_rule_matches_and_explains():
    gr, seed, bad_ip, cert, cert2 = graph()
    rule = rules.validate(rules.TEMPLATES[0])   # certificate served by a flagged IP
    matches, n = rules.evaluate(rule, ctx(gr, seed))
    assert [m["id"] for m in matches] == [cert]
    assert n == 2   # only certificates were evaluated
    why = " | ".join(matches[0]["reasons"])
    assert "USES_CERT ← IP" in why and "198.51.100.7" in why and "VT malicious engines ≥ 1: seen 4" in why


def test_conditions_ops_and_any_mode():
    gr, seed, bad_ip, *_ = graph()
    c = ctx(gr, seed)
    r = rules.validate({"name": "t", "target": "IP", "match": "all",
                        "conditions": [{"field": "asn", "op": "in", "value": "9009, 1234"},
                                       {"field": "value", "op": "regex", "value": r"^198\."}]})
    assert [m["id"] for m in rules.evaluate(r, c)[0]] == [bad_ip]
    r = rules.validate({"name": "t", "target": "IP", "match": "any",
                        "conditions": [{"field": "asn", "op": "eq", "value": "13335"},
                                       {"field": "vt_malicious", "op": "gte", "value": 3}]})
    assert len(rules.evaluate(r, c)[0]) == 2
    r = rules.validate({"name": "t", "target": "IP", "conditions": [{"field": "vt_malicious", "op": "neq", "value": 4}]})
    assert [m["value"] for m in rules.evaluate(r, c)[0]] == ["192.0.2.80"]
    r = rules.validate({"name": "t", "target": "Certificate",
                        "conditions": [{"field": "issuer", "op": "not_contains", "value": "encrypt"}]})
    assert [m["value"] for m in rules.evaluate(r, c)[0]] == ["f" * 64]


def test_score_gates():
    gr, seed, *_ = graph()
    c = ctx(gr, seed)
    r = rules.validate({"name": "t", "target": "any", "min_confidence": 100})
    ms = rules.evaluate(r, c)[0]
    assert [m["id"] for m in ms] == [seed]          # only the seed is at 100
    assert "confidence 100 ≥ 100" in ms[0]["reasons"]


@pytest.mark.parametrize("bad, msg", [
    ({"name": ""}, "name"),
    ({"name": "x", "conditions": [{"field": "__class__", "op": "eq", "value": 1}]}, "unknown field"),
    ({"name": "x", "conditions": [{"field": "vt_malicious", "op": "regex", "value": "a"}]}, "does not apply"),
    ({"name": "x", "conditions": [{"field": "value", "op": "regex", "value": "("}]}, "invalid regex"),
    ({"name": "x", "conditions": [{"field": "vt_malicious", "op": "gt", "value": "lots"}]}, "number"),
    ({"name": "x", "target": "Spaceship"}, "unknown indicator type"),
    ({"name": "x"}, "at least one"),
    ({"name": "x", "target": "IP", "action": {"type": "query", "query": "page.ip:{__import__}"}}, "placeholder"),
    ({"name": "x", "target": "IP", "action": {"type": "pivot", "sources": ["evil"]}}, "data source"),
])
def test_validation_errors(bad, msg):
    with pytest.raises(ValueError, match=msg):
        rules.validate(bad)


def test_render_query_escapes_and_requires_values():
    gr, seed, *_ = graph()
    n = gr.nodes[seed]
    assert rules.render_query('page.title:"{prop:urlscan_title}" AND page.domain:{apex}', n) == \
        'page.title:"Sign \\"in\\"" AND page.domain:login-secure.top'
    assert rules.render_query("hash:{prop:missing}", n) is None


def test_query_platforms():
    assert set(rules.PLATFORMS) == {"urlscan", "vt"}
    r = rules.validate({"name": "x", "target": "JARM", "action": {"type": "query", "platform": "vt", "query": "entity:domain jarm:{value}"}})
    assert r["action"]["platform"] == "vt"
    # older rules / no platform given = urlscan, as before
    assert rules.validate({"name": "x", "target": "IP", "action": {"type": "query", "query": "page.ip:{value}"}})["action"]["platform"] == "urlscan"
    for removed in ("shodan", "validin", "censys", "fofa"):
        with pytest.raises(ValueError, match="platform"):
            rules.validate({"name": "x", "target": "IP", "action": {"type": "query", "platform": removed, "query": "x:{value}"}})
    assert rules.query_link("vt", 'entity:domain jarm:"a b"') == \
        "https://www.virustotal.com/gui/search/entity%3Adomain%20jarm%3A%22a%20b%22"
    assert "shodan" not in rules.SOURCES


def test_store_crud(tmp_path):
    st = rules.RuleStore(tmp_path / "r.json")
    r = st.create(rules.TEMPLATES[1])
    assert st.get(r["id"])["name"] == rules.TEMPLATES[1]["name"]
    dup = st.duplicate(r["id"])
    assert dup["enabled"] is False and dup["name"].endswith("(copy)")
    st.patch(r["id"], enabled=False)
    upd = st.update(r["id"], {**r, "name": "renamed"})
    assert upd["name"] == "renamed" and upd["created"] == r["created"]
    st.delete(dup["id"])
    assert [x["id"] for x in st.list()] == [r["id"]]
    with pytest.raises(LookupError):
        st.delete("nope")


def test_all_templates_are_valid():
    for t in rules.TEMPLATES:
        rules.validate(t)
