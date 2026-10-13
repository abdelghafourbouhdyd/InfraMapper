import pytest

from inframapper import cluster, graph as g, rules
from inframapper.scoring import Scorer

RULE = {"name": "Kit page title", "platform": "urlscan", "query": 'page.title:"Sign in"',
        "fidelity": "high", "confidence": "medium"}


def test_validate_keeps_only_the_five_fields():
    assert rules.validate({**RULE, "description": "dropped", "conditions": []}) == RULE


@pytest.mark.parametrize("bad, msg", [
    ({"name": ""}, "name"),
    ({"platform": "shodan"}, "platform"),
    ({"query": "  "}, "query"),
    ({"fidelity": "certain"}, "fidelity"),
    ({"confidence": None}, "confidence"),
])
def test_validation_errors(bad, msg):
    with pytest.raises(ValueError, match=msg):
        rules.validate({**RULE, **bad})


def test_query_link():
    assert rules.query_link("vt", 'entity:domain jarm:"a b"') == \
        "https://www.virustotal.com/gui/search/entity%3Adomain%20jarm%3A%22a%20b%22"


def test_store_crud(tmp_path):
    st = rules.RuleStore(tmp_path / "r.json")
    r = st.create(RULE)
    assert st.list() == [r]
    upd = st.update(r["id"], {**RULE, "name": "renamed"})
    assert upd == {**RULE, "id": r["id"], "name": "renamed"}
    st.delete(r["id"])
    assert st.list() == []
    with pytest.raises(LookupError):
        st.delete("nope")


@pytest.fixture(autouse=True)
def reset_tuning():
    yield
    cluster.configure()


def kit_graph(shared=("favicon", "title")):
    """seed.example and other.example; other shares the seed's favicon and / or page title."""
    gr = g.Graph()
    seed = gr.add_node(g.DOMAIN, "seed.example", seed=True)
    other = gr.add_node(g.DOMAIN, "other.example")
    for kind, typ, rel in (("favicon", g.FAVICON, "HAS_FAVICON"), ("title", g.TITLE, "HAS_TITLE")):
        if kind in shared:
            a = gr.add_node(typ, kind + "-value")
            gr.add_edge(seed, a, rel)
            gr.add_edge(other, a, rel)
    return gr, seed, other


def test_default_pivots_unchanged(tmp_path):
    # favicon (40 -> 1 point) + title (40 -> 1 point) = 2: joins the cluster, as before the tuning
    gr, seed, other = kit_graph()
    r = cluster.score(gr, seed)[other]
    assert r["score"] == 2 and r["confirmed"] and r["rule"] is None
    pts = {p["key"]: p["points"] for p in rules.RuleStore(tmp_path / "r.json").pivots()}
    assert (pts["html"], pts["urlpath"], pts["favicon"]) == (3, 2, 1)


def test_combination_replaces_the_parts():
    gr, seed, other = kit_graph()
    cluster.configure(combos=[{"name": "kit", "pivots": ["favicon", "title"], "confidence": 20}])
    r = cluster.score(gr, seed)[other]
    assert r["score"] == 0 and not r["confirmed"] and r["rule"]["name"] == "kit"
    cluster.configure(combos=[{"name": "kit", "pivots": ["favicon", "title"], "confidence": 90}])
    cluster.apply(gr, seed)
    assert gr.nodes[other]["props"]["cluster_score"] == 3
    assert any("rule “kit”" in e for e in gr.nodes[other]["props"]["cluster_evidence"])
    sc = Scorer(gr.nodes, gr.edges, seed).score()[other]
    assert sc["confidence"] == 90
    assert any("hunting rule “kit”" in f["label"] for f in sc["factors"]["confidence"])


def test_combination_needs_every_pivot():
    gr, seed, other = kit_graph(shared=("title",))
    cluster.configure(combos=[{"name": "kit", "pivots": ["favicon", "title"], "confidence": 90}])
    r = cluster.score(gr, seed)[other]
    assert r["rule"] is None and r["score"] == 1 and not r["confirmed"]


def test_tuned_pivot_confidence_and_search_switch():
    gr, seed, other = kit_graph()
    cluster.configure(confidence={"title": 10})   # title ignored: favicon alone is 1 point
    assert cluster.score(gr, seed)[other]["score"] == 1
    cluster.configure(off={"title", "pattern"})
    assert not cluster.search_enabled("title") and not cluster.search_enabled("title (refined)")
    assert not cluster.search_enabled("domain pattern (name skeleton)")
    assert cluster.search_enabled("favicon") and cluster.search_enabled("custom")
    assert cluster.search_enabled("regex ladder")   # analyst regex hunts always run


def test_store_combos_and_pivot_tuning(tmp_path):
    st = rules.RuleStore(tmp_path / "r.json")
    with pytest.raises(ValueError, match="at least two"):
        st.create({"name": "x", "pivots": ["title"], "confidence": 50}, "combos")
    with pytest.raises(ValueError, match="unknown pivot"):
        st.create({"name": "x", "pivots": ["title", "nope"], "confidence": 50}, "combos")
    with pytest.raises(ValueError, match="0-100"):
        st.create({"name": "x", "pivots": ["title", "favicon"], "confidence": 150}, "combos")
    c = st.create({"name": "kit", "pivots": ["title", "favicon"], "confidence": 80}, "combos")
    assert c["pivots"] == ["favicon", "title"] and st.list("combos") == [c]
    p = st.tune_pivot("title", {"confidence": 10, "search": False})
    assert p["confidence"] == 10 and p["search"] is False and p["tuned"] and p["points"] == 0
    st.apply()
    gr, seed, other = kit_graph()
    assert cluster.score(gr, seed)[other]["rule"]["confidence"] == 80
    assert not cluster.search_enabled("title")
    assert st.tune_pivot("title", {"confidence": 40, "search": True})["tuned"] is False   # back to default
    with pytest.raises(LookupError):
        st.tune_pivot("nope", {"confidence": 1})
    st.delete(c["id"], "combos")
    assert st.list("combos") == []
