import pytest

from inframapper import rules

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
