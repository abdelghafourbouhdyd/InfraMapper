import json

import pytest

from inframapper import cluster, graph as g, rules
from inframapper.investigator import Config, Investigator
from inframapper.scoring import Scorer

KIT = {"name": "Kit reuse", "platform": "urlscan", "confidence": 80, "fidelity": 70,
       "conditions": [{"attribute": "title", "method": "exact"}, {"attribute": "favicon", "method": "exact"}]}


@pytest.fixture(autouse=True)
def reset_tuning():
    yield
    cluster.configure()


def host_graph():
    gr = g.Graph()
    d = gr.add_node(g.DOMAIN, "login-acme.top", seed=True, servers=["nginx"])
    ip = gr.add_node(g.IP, "198.51.100.7", asn=9009)
    gr.add_edge(d, ip, "RESOLVES_TO")
    gr.add_edge(d, gr.add_node(g.TITLE, 'Sign "in"'), "HAS_TITLE")
    gr.add_edge(d, gr.add_node(g.TITLE, "404 Not Found"), "HAS_TITLE")   # generic: never a pivot value
    gr.add_edge(d, gr.add_node(g.FAVICON, "f" * 64), "HAS_FAVICON")
    return gr, d


# ── custom pivot logic ──────────────────────────────────────────────────────

def test_host_attributes_come_from_the_host_and_its_neighbours():
    gr, d = host_graph()
    a = rules.host_attributes(gr.nodes, gr.edges, d)
    assert a == {"title": ['Sign "in"'], "favicon": ["f" * 64], "domain": ["login-acme.top"],
                 "ip": ["198.51.100.7"], "asn": ["AS9009"], "server": ["nginx"]}


def test_render_fills_the_rule_with_each_hosts_values():
    gr, d = host_graph()
    r = rules.validate(KIT)
    attrs = rules.host_attributes(gr.nodes, gr.edges, d)
    assert rules.render(r, attrs) == ['page.title:"Sign \\"in\\"" AND hash:' + "f" * 64]
    assert rules.render(r, {"title": ["x"]}) == []   # no favicon on this host: rule doesn't apply
    r = rules.validate({**KIT, "recent_days": 90})
    assert rules.render(r, {"title": ["a", "b"], "favicon": ["1", "2"]}) == [
        'page.title:"a" AND hash:1 AND date:>now-90d', 'page.title:"a" AND hash:2 AND date:>now-90d',
        'page.title:"b" AND hash:1 AND date:>now-90d']   # at most 3 searches per host
    rx = rules.validate({**KIT, "conditions": [{"attribute": "domain", "method": "regex", "param": "secure-{name}[0-9]*"}]})
    assert rules.render(rx, {"domain": ["login-acme.top"]}) == ["page.domain:/secure-login\\-acme[0-9]*/"]
    vt = rules.validate({**KIT, "platform": "vt", "conditions": [{"attribute": "imphash"}]})
    assert rules.render(vt, {"imphash": ["abc"]}) == ["entity:file imphash:abc"]


def test_template_and_suggestion():
    r = rules.validate(KIT)
    assert rules.template(r) == 'page.title:"<page title>" AND hash:<favicon sha256>'
    assert rules.suggest(r["conditions"]) == {"confidence": 64, "fidelity": 65}   # 40+40, 30+50 combined


@pytest.mark.parametrize("bad, msg", [
    ({"name": ""}, "name"),
    ({"platform": "shodan"}, "platform"),
    ({"conditions": []}, "conditions"),
    ({"conditions": [{"attribute": "nope"}]}, "unknown attribute"),
    ({"conditions": [{"attribute": "jarm"}]}, "can't be searched"),
    ({"conditions": [{"attribute": "domain", "method": "regex", "param": "("}]}, "invalid regex"),
    ({"conditions": [{"attribute": "domain", "method": "regex"}]}, "regex"),
    ({"platform": "vt", "conditions": [{"attribute": "jarm"}, {"attribute": "imphash"}]}, "all about"),
    ({"confidence": 101}, "confidence"),
    ({"fidelity": "high"}, "fidelity"),
])
def test_validation_errors(bad, msg):
    with pytest.raises(ValueError, match=msg):
        rules.validate({**KIT, **bad})


def test_rule_pivot_runs_per_host_and_weighs_its_hits():
    queries = []

    class US:
        def search(self, q, size=100):
            queries.append(q)
            return (2, [{"page": {"domain": "kit-copy.top"}, "task": {"time": "2026-09-01T00:00:00Z"}},
                        {"page": {"domain": "login-acme.top"}, "task": {}}]) if q.startswith("page.title") else (0, [])

    cluster.configure(custom=[{"id": "r1", **rules.validate(KIT)}])
    inv = Investigator(None, US(), Config())
    gr, d = host_graph()
    inv.g, inv.seed_id = gr, d
    inv._rule_pivots(d, 0)
    q = 'page.title:"Sign \\"in\\"" AND hash:' + "f" * 64
    assert queries == [q]
    pid = g.node_id(g.PATTERN, q)
    assert inv.g.nodes[pid]["props"]["rule"] == "Kit reuse"
    hit = g.node_id(g.DOMAIN, "kit-copy.top")
    assert (pid, hit, "SEEN_ON") in inv.g.edges
    # the rule's confidence 80 = 2 points: the copy joins the cluster through the rule alone
    r = cluster.score(inv.g, d)[hit]
    assert r["confirmed"] and any("rule “Kit reuse”" in e for e in r["evidence"])
    assert Scorer(inv.g.nodes, inv.g.edges, d).score()[pid]["factors"]["fidelity"][0]["label"] == \
        "pivot fidelity 70 (hunting rules)"
    inv._rule_pivots(d, 0)
    assert len(queries) == 1   # same values again: not searched twice


# ── built-in pivots ─────────────────────────────────────────────────────────

def shared_graph(shared=("favicon", "title")):
    gr = g.Graph()
    seed = gr.add_node(g.DOMAIN, "seed.example", seed=True)
    other = gr.add_node(g.DOMAIN, "other.example")
    for kind, typ, rel in (("favicon", g.FAVICON, "HAS_FAVICON"), ("title", g.TITLE, "HAS_TITLE")):
        if kind in shared:
            a = gr.add_node(typ, kind + "-value")
            gr.add_edge(seed, a, rel)
            gr.add_edge(other, a, rel)
    return gr, seed, other


def test_built_in_defaults_are_unchanged():
    gr, seed, other = shared_graph()
    r = cluster.score(gr, seed)[other]
    assert r["score"] == 2 and r["confirmed"]   # favicon 1 + title 1
    assert cluster.query("title", "x") == 'page.title:"x"' and cluster.max_hits("title", 250) == 250
    assert cluster.search_enabled("title") and cluster.refine_enabled("favicon")


def test_tuned_built_in_pivots():
    cluster.configure(pivots={"title": {"confidence": 10, "template": 'page.title:"{value}" AND date:>now-30d',
                                        "max_hits": 50, "refine": False},
                              "favicon": {"enabled": False}, "regex": {"enabled": False, "steps": 2}})
    gr, seed, other = shared_graph()
    assert cluster.score(gr, seed)[other]["score"] == 1   # title ignored now
    assert cluster.query("title", "x") == 'page.title:"x" AND date:>now-30d'
    assert cluster.max_hits("title (refined)", 250) == 50 and not cluster.refine_enabled("title")
    assert not cluster.search_enabled("favicon") and not cluster.search_enabled("domain pattern (regex)")
    assert cluster.search_enabled("custom regex") and cluster.search_enabled("custom")   # analyst searches
    assert cluster.setting("regex", "steps") == 2


# ── store ───────────────────────────────────────────────────────────────────

def test_store(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"version": 2, "rules": [{"id": "r_old", "name": "old"}]}))
    st = rules.RuleStore(path)
    r = st.create(KIT)
    assert st.list() == [r] and r["template"].startswith('page.title:"<page title>"')
    assert st.update(r["id"], {**KIT, "enabled": False})["enabled"] is False
    st.apply()
    assert cluster.custom_rules() == []   # disabled rules don't run
    p = st.tune_pivot("title", {"confidence": 10, "fidelity": 20, "enabled": False, "max_hits": "",
                                "template": 'page.title:"{value}"', "refine": True})
    assert p["tuned"] == ["confidence", "enabled", "fidelity"] and p["points"] == 0
    st.apply()
    assert not cluster.search_enabled("title") and cluster.setting("title", "fidelity") == 20
    with pytest.raises(ValueError, match="template"):
        st.tune_pivot("title", {"template": "page.title:x"})
    with pytest.raises(ValueError, match="template"):
        st.tune_pivot("title", {"template": "{value} {other}"})
    with pytest.raises(LookupError):
        st.tune_pivot("nope", {})
    assert st.tune_pivot("title", {})["tuned"] == []   # back to the defaults
    st.delete(r["id"])
    assert st.list() == []
    assert json.loads(path.read_text())["rules"] == [{"id": "r_old", "name": "old"}]   # older data kept
