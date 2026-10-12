from ioci import graph as g
from ioci import regex_hunt as rh
from ioci.investigator import Config, Investigator, regex_query


def test_regex_query():
    assert regex_query(".*-okta-[a-z]+") == "page.domain:/.*-okta-[a-z]+/"
    assert regex_query("  ^login[0-9]+\\.com$ ") == "page.domain:/login[0-9]+\\.com/"   # anchors: urlscan matches the whole name
    assert regex_query("/evil.*/") == "page.domain:/evil.*/"                          # /.../ wrapper accepted
    assert regex_query("a/b") == "page.domain:/a\\/b/" and regex_query("a\\/b") == "page.domain:/a\\/b/"
    assert regex_query("cost\\$") == "page.domain:/cost\\$/"                          # escaped $ is kept
    assert regex_query("  ") == "" and regex_query("^$") == ""


def hits(domains, time="2026-09-01T00:00:00Z"):
    return [{"page": {"domain": d, "ip": "1.2.3.4"}, "task": {"time": time}} for d in domains]


class FakeURLScan:
    """query -> (total, sample); anything unknown -> nothing."""
    def __init__(self, answer):
        self.answer, self.queries = answer, []

    def search(self, query, size=100):
        self.queries.append(query)
        return self.answer(query)


def case(us, seed="acmesec.info"):
    inv = Investigator(None, us, Config())
    inv.seed_id = inv.g.add_node(g.DOMAIN, seed, seed=True, depth=0)
    return inv


def test_keyword_and_broad_start():
    assert rh.keyword(["acmesec.info", "acmesec-login.com"]) == "acmesec"
    assert rh.keyword(["secure-login-paypalx.com"]) == "paypalx"     # kit words (secure, login) are poor anchors
    assert rh.start(["acmesec.info"]).query() == "page.domain:/.*acmesec.*/"


def test_user_regex_small_enough_is_pivoted_directly():
    q = "page.domain:/.*-okta-[a-z]+\\.com/"
    us = FakeURLScan(lambda x: (2, hits(["corp-okta-sso.com", "acme-okta-login.com"])) if x == q else (0, []))
    inv = case(us, "corp-okta-sso.com")
    pids = inv.regex_pivot([".*-okta-[a-z]+\\.com", "", "nothing[0-9]+"])
    assert len(pids) == 1 and inv.g.nodes[pids[0]]["props"]["kind"] == "custom regex"
    assert (pids[0], "Domain:acme-okta-login.com", "SEEN_ON") in inv.g.edges
    assert [L["steps"][0]["decision"] for L in inv.regex_ladders] == ["best pivot", "start"]   # 2nd: 0 hits
    inv.regex_pivot([".*-okta-[a-z]+\\.com"])   # same regex again: not searched twice
    assert us.queries.count(q) == 2              # the ladder's search + the pivot's (cached in real use)


def test_ladder_refines_from_what_the_hits_show():
    brand = [f"cdn{i}.acmesecurity.com" for i in range(60)]            # one legit site swamps the broad search
    kit = [f"acmesec-login{i}.com" for i in range(40)]

    def answer(q):
        if "acmesecurity" in q:
            return 120, hits(kit)
        if q == "page.domain:/.*acmesec.*/":
            return 3000, hits(brand + kit)
        return 0, []
    us = FakeURLScan(answer)
    inv = case(us)
    pids = inv.regex_hunt()
    lad = inv.regex_ladders[0]
    assert [s["label"] for s in lad["steps"]] == ["broad", "exclude acmesecurity.com"]
    assert "60/100 hits are acmesecurity.com" in lad["steps"][1]["why"]
    assert lad["best"] == 1 and lad["steps"][1]["decision"] == "best pivot"
    assert len(pids) == 1 and "NOT page.domain:" in inv.g.nodes[pids[0]]["value"]
    assert (pids[0], "Domain:acmesec-login3.com", "SEEN_ON") in inv.g.edges


def test_capped_count_switches_to_the_actors_specific_word():
    known = ["acmesec.info", "acmesec-login.com", "members-acme.com"]
    step = rh.Step(base=".*acme.*", kw="acme")
    got = {lb: s for lb, _, s in rh.refinements(step, known, hits(["x.acme.com", "acme161.ru"]), capped=True)}
    assert "specific word 'acmesec'" in got and got["specific word 'acmesec'"].query() == "page.domain:/.*acmesec.*/"
    assert not rh.refinements(step, known, hits(["x.acme.com", "acme161.ru"]))[0][0].startswith("specific")   # not capped
    assert "NOT page.domain:/(.*\\.)?chatgpt\\.site/" in rh.Step(base=".*a.*", kw="a", exclude=("chatgpt.site",)).query()


def test_refinements_keep_known_domains_and_need_a_reason():
    known = ["acmesec.info"]
    step = rh.start(known)
    subs = hits([f"x{i}.acmesec-cdn.net" for i in range(10)])
    labels = [label for label, _, _ in rh.refinements(step, known, subs)]
    assert "no subdomains" in labels and "TLD .info" in labels
    for _, _, nxt in rh.refinements(step, known, subs):
        assert nxt.matches("acmesec.info")                           # never drops the actor's own domain
    assert rh.refinements(step, known, hits(["acmesec.info"] * 5 + ["acmesec.site"])) == []   # nothing to fix
    # no known actor names: only what the hits alone justify (one site swamping them), no naming claims
    assert [lb for lb, _, _ in rh.refinements(rh.start([], "acme.*"), [], subs)] == ["exclude acmesec-cdn.net"]
