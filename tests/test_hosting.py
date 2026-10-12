from ioci import hosting

D = 86400


def rec(name, ip, first, last):
    return {"rrname": name, "rrtype": "a", "rdata": ip, "first": first * D, "last": last * D}


def test_relation_timing():
    assert hosting.relation((100 * D, 200 * D), (150 * D, 300 * D)) == "concurrent"
    assert hosting.relation((100 * D, 200 * D), (210 * D, 300 * D)) == "moved anchor → here (10 d)"
    assert hosting.relation((100 * D, 200 * D), (600 * D, 700 * D)) == "here 400 d after anchor"
    assert hosting.relation((500 * D, 600 * D), (100 * D, 490 * D)) == "moved here → anchor (10 d)"


def test_siblings_and_verdicts():
    anchor = "45.9.148.12"
    anchor_doms = {"a.com": (100 * D, 200 * D), "b.com": (100 * D, 200 * D), "c.com": (100 * D, 200 * D)}
    domain_ips = {
        "a.com": hosting.ips_of([rec("a.com", anchor, 100, 200), rec("a.com", "5.5.5.5", 205, 300)], "a.com"),
        "b.com": hosting.ips_of([rec("b.com", anchor, 100, 200), rec("b.com", "5.5.5.5", 150, 250)], "b.com"),
        "c.com": hosting.ips_of([rec("c.com", anchor, 100, 200), rec("c.com", "9.9.9.9", 900, 950)], "c.com"),
    }
    sibs = hosting.siblings(anchor, anchor_doms, domain_ips)
    assert set(sibs["5.5.5.5"]) == {"a.com", "b.com"}
    assert hosting.verdict(sibs["5.5.5.5"], 6, 25) == "linked"          # moved + concurrent
    assert hosting.verdict(sibs["9.9.9.9"], 3, 25) == "weak"            # one name, 700 days later
    assert hosting.verdict(sibs["5.5.5.5"], 400, 25) == "shared hosting"
    assert hosting.verdict({"a.com": "concurrent"}, 4, 25) == "possible"


def test_fast_flux_domains_ignored():
    ips = {f"1.1.1.{i}": (D, 2 * D) for i in range(hosting.FASTFLUX + 1)}
    assert hosting.siblings("2.2.2.2", {"ff.com": (D, 2 * D)}, {"ff.com": ips}) == {}


def test_dual_stack_and_unknown_reverse():
    anchor = "92.113.28.183"
    doms = {"a.com": (100 * D, 200 * D)}
    v6 = "2a02:4780:0027:1690:0000:33eb:60f7:0009"          # padded, as pDNS returns it
    sibs = hosting.siblings(anchor, doms, {"a.com": {v6: (100 * D, 200 * D), "5.5.5.5": (100 * D, 200 * D)}})
    assert list(sibs) == ["5.5.5.5"]                       # the AAAA of the same site isn't a sibling server
    assert hosting.verdict({"a.com": "concurrent", "b.com": "concurrent"}, None, 25) == "unverified"
    assert hosting.domains_of([rec("x.com", v6, 1, 2)], "2a02:4780:27:1690:0:33eb:60f7:9") == {"x.com": (D, 2 * D)}
