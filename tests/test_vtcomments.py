from ioci.vtcomments import ActorNames, comment_reports, parse


def actors():
    a = ActorNames(None)   # no download: a small galaxy slice
    a._load([{"value": "APT28", "synonyms": ["Fancy Bear", "Forest Blizzard", "Sofacy"]},
             {"value": "Lazarus Group", "synonyms": ["Hidden Cobra", "Diamond Sleet"]},
             {"value": "Gold", "synonyms": []}])
    a._load_families([{"value": "Cobalt Strike", "synonyms": ["cobeacon"]},
                      {"value": "Pay2Key", "synonyms": ["Cobalt"]}, {"value": "BumbleBee", "synonyms": []},
                      {"value": "WannaCryptor", "synonyms": ["WannaCry", "Wanna Decryptor"]}])
    return a


def test_actor_aliases_merge():
    p = parse("Fancy Bear infra, same as #apt28 and Forest Blizzard reporting", [], actors())
    assert p["actors"] == ["APT28"]


def test_codenames_without_galaxy():
    p = parse("Overlaps with UNC4736 and Storm-0558 tooling", [], ActorNames(None))
    assert set(p["actors"]) == {"UNC4736", "Storm-0558"}


def test_short_plain_word_alias_ignored():
    assert parse("Gold star for this sample", [], actors())["actors"] == []


def test_families_normalised_and_tactic_tags_dropped():
    text = ("FileScan.IO Analysis:\nVerdict: MALICIOUS\nMalware family: wannacry\n"
            "#ransomware #CobaltStrike #persistence #defense_evasion #jaffacakes118")
    p = parse(text, ["c2"], actors())
    assert p["malware"] == ["Cobalt Strike", "WannaCryptor"]
    assert p["actors"] == []


def test_sandbox_links_are_references_not_iocs():
    h = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
    text = (f"https://centralbox.dev/analysis/{h} https://mwdb.cert.pl/file/{h} "
            f"https://malshare.com/sample.php?hash={h} killswitch www.xl6qa6segf[.]com")
    p = parse(text, [], actors())
    assert p["iocs"] == [("domain", "www.xl6qa6segf.com")]
    assert len(p["references"]) == 3


def test_comentions_and_references():
    text = ("#Lazarus C2 cluster: update-cdn[.]top, 45.9.148[.]12 and "
            "hxxps://login-sso[.]online/a.php. Writeup: https://blog.vendor-labs.com/lazarus-2026")
    p = parse(text, [], actors())
    assert p["actors"] == ["Lazarus Group"]
    assert ("domain", "update-cdn.top") in p["iocs"] and ("ip", "45.9.148.12") in p["iocs"]
    assert p["references"] == ["https://blog.vendor-labs.com/lazarus-2026"]
    assert not any("vendor-labs" in v for _, v in p["iocs"])


class FakeVT:
    def __init__(self, comments):
        self.comments = comments

    def _get(self, path, params=None):
        return {"data": [{"id": f"c{i}", "attributes": a} for i, a in enumerate(self.comments)]}


def test_comment_reports_grouped_and_bulk_dumps_skipped():
    bulk = " ".join(f"10.{i}.1.1 evil{i}[.]top" for i in range(30))
    vt = FakeVT([
        {"text": "APT28 C2, see also cdn-sync[.]online", "date": 1700000000, "votes": {"positive": 1}},
        {"text": "#fancybear again", "tags": ["apt28"], "date": 1690000000, "votes": {}},
        {"text": "APT28 " + bulk, "date": 1710000000, "votes": {}},
        {"text": "Lazarus Group!", "date": 1710000000, "votes": {"negative": 3}},   # voted down
    ])
    reports, co = comment_reports(vt, "domains", "evil.com", actors(), self_value="evil.com")
    assert [r["actor"] for r in reports] == ["APT28"]
    assert reports[0]["comments"] == 3 and reports[0]["date"] == 1690000000
    assert [c["value"] for c in co] == ["cdn-sync.online"]


def test_vt_limiter_bursts_then_waits(monkeypatch):
    from ioci import clients
    now = [1000.0]
    slept = []
    monkeypatch.setattr(clients.time, "time", lambda: now[0])
    monkeypatch.setattr(clients.time, "sleep", lambda s: (slept.append(s), now.__setitem__(0, now[0] + s)))
    lim = clients._Limiter(4)
    for _ in range(4):
        lim.wait()
    assert slept == []                 # the free quota's 4 calls go out at once
    lim.wait()
    assert 59 < sum(slept) < 61        # the 5th waits for the window to roll over


def test_object_reports_yara_sandbox_av():
    from ioci.vtcomments import object_reports
    attrs = {"crowdsourced_yara_results": [
                {"rule_name": "APT_MAL_Sofacy_Zebrocy_Go", "ruleset_name": "apt_sofacy", "author": "Florian Roth",
                 "match_date": 1700000000, "source": "https://github.com/Neo23x0/signature-base"},
                {"rule_name": "HKTL_Cobalt_Strike_Beacon", "author": "X", "description": "Detects Cobalt Strike"},
                {"rule_name": "MAL_BumbleBee_Loader"}],
             "sandbox_verdicts": {"Zenbox": {"sandbox_name": "Zenbox", "malware_names": ["WannaCry", "Generic"]}},
             "popular_threat_classification": {"popular_threat_name": [{"value": "wannacry", "count": 12},
                                                                       {"value": "agent", "count": 9}]}}
    names = {r["name"] for r in object_reports(attrs, actors(), "files", "abc")}
    # no "Cobalt" actor / Pay2Key ("Cobalt" synonym) from the Cobalt Strike rule
    assert names == {"VT YARA: APT28", "VT YARA: Cobalt Strike", "VT YARA: BumbleBee", "VT sandbox: WannaCryptor",
                     "VT AV consensus: WannaCryptor"}


def test_assessment_strength_uses_independent_groups():
    from ioci.export import _strength
    assert _strength(1, 3) == "medium"      # one sample, YARA + sandbox + AV agree on the family
    assert _strength(3, 1) == "medium"      # three IOCs, all from abuse.ch only
    assert _strength(3, 2) == "strong"
    assert _strength(1, 1) == "single lead"


def test_article_links_are_reports_not_iocs():
    from ioci.vtcomments import article_name, is_article
    jamf = "https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/"
    zs = "https://www.zscaler.com/blogs/security-research/claudefix-shared-claude-chats-meet-clickfix"
    assert is_article(jamf) and is_article(zs)
    assert not is_article("https://centralbox.dev/analysis/" + "a" * 64)      # sandbox page, not a report
    assert not is_article("https://evil-cdn.top/api/v2/gate.php")
    assert article_name(jamf) == "jamf.com: macsync stealer evolution code signed swift malware analysis"
    vt = FakeVT([{"text": f"MacSync stealer C2, see {jamf} and evil-cdn[.]top", "date": 1790000000, "votes": {}}])
    reports, co = comment_reports(vt, "domains", "clausdoom.es", actors(), self_value="clausdoom.es")
    linked = [r for r in reports if r.get("linked_article")]
    assert linked and linked[0]["url"] == jamf and linked[0]["date"] == 1790000000
    assert [c["value"] for c in co] == ["evil-cdn.top"]                      # the article isn't a co-mentioned IOC


def test_old_case_article_url_becomes_report(tmp_path):
    from ioci import graph as g
    from ioci.investigator import Config, Investigator
    inv = Investigator(None, None, Config())
    dom = inv.g.add_node(g.DOMAIN, "clausdoom.es", seed=True)
    inv.seed_id = dom
    url = "https://www.jamf.com/blog/macsync-stealer-evolution/"
    u = inv.g.add_node(g.URL, url, co_mentioned=True)
    inv.g.add_edge(dom, u, "CO_MENTIONED", date=1790000000)
    host = inv.g.add_node(g.DOMAIN, "www.jamf.com", co_mentioned=True)
    inv.g.add_edge(dom, host, "CO_MENTIONED", date=1790000000)
    assert inv._articles_to_reports() == 1
    assert g.node_id(g.URL, url) not in inv.g.nodes
    assert "Domain:www.jamf.com" not in inv.g.nodes                          # the article's site went too
    rep = inv.g.nodes[g.node_id(g.REPORT, f"vtref:{url}")]
    assert (dom, rep["id"], "REPORTED_IN") in inv.g.edges
    assert inv.timelines[dom][0]["reported"] == "jamf.com: macsync stealer evolution"
