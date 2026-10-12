from inframapper import graph as g
from inframapper.investigator import Config, Investigator
from inframapper.knowledge import Knowledge
from inframapper.reports import analyse, parse_feed, to_stix
from inframapper.vtcomments import ActorNames

RSS = b"""<?xml version="1.0"?><rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>
<item><title>Lumma returns</title><link>https://vendor.example/lumma</link>
<pubDate>Mon, 28 Sep 2026 10:00:00 +0000</pubDate><content:encoded><![CDATA[<p>full text</p>]]></content:encoded></item>
</channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>APT28 again</title>
<link rel="alternate" href="https://vendor.example/apt28"/><published>2026-09-20T08:00:00Z</published>
<summary>short</summary></entry></feed>"""


class FakeAttack:
    t = {"T1059.001": ("PowerShell", ["execution"]), "T1566": ("Phishing", ["initial-access"])}

    def find(self, text):
        import re
        return sorted({x for x in re.findall(r"T1\d{3}(?:\.\d{3})?", text) if x in self.t})


def names():
    n = ActorNames(None)
    n._load([{"value": "APT28", "synonyms": ["Fancy Bear"]}, {"value": "Lazarus Group", "synonyms": []}])
    n._load_families([{"value": "Lumma", "synonyms": ["LummaC2"]}, {"value": "Cobalt Strike", "synonyms": []}])
    return n


def test_parse_rss_and_atom():
    r, a = parse_feed(RSS)[0], parse_feed(ATOM)[0]
    assert (r["url"], r["published"], "full text" in r["content"]) == ("https://vendor.example/lumma", 1790589600, True)
    assert (a["url"], a["published"]) == ("https://vendor.example/apt28", 1789891200)


TEXT = """Lumma stealer campaign. LummaC2 beacons to update-cdn[.]top and 45.9.148[.]12.
SHA256 7d6f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f. Unlike Lazarus Group, this actor
uses T1566 then T1059.001 (and T9999, which isn't ATT&CK). Exploits CVE-2024-3400.
rule Lumma_Loader {
  strings: $a = "lumma"
  condition: $a
}"""


def test_analyse_keeps_repeated_names_and_stated_ttps():
    item = {"url": "https://vendor.example/lumma", "title": "Lumma returns", "published": 1790589600}
    a = analyse(item, TEXT, set(), names(), FakeAttack(), None, None, {"vendor.example"})
    assert a["families"] == ["Lumma"]        # named twice (Lumma, LummaC2) + in the title
    assert a["actors"] == []                 # Lazarus mentioned once, as a comparison
    assert a["ttps"] == ["T1059.001", "T1566"]
    assert ("Domain", "update-cdn.top") in a["iocs"] and ("IP", "45.9.148.12") in a["iocs"]
    assert a["cves"] == ["CVE-2024-3400"] and len(a["yara"]) == 1


def test_stix_relationships_only_when_unambiguous():
    item = {"url": "https://vendor.example/lumma", "title": "Lumma returns", "published": 1790589600}
    a = analyse(item, TEXT, set(), names(), FakeAttack(), None, None, {"vendor.example"})
    b = to_stix("Vendor", item, a, FakeAttack())
    objs = b["objects"]
    report = objs[0]
    assert report["type"] == "report" and set(report["object_refs"]) <= {o["id"] for o in objs}
    types = {o["type"] for o in objs}
    assert {"identity", "malware", "attack-pattern", "vulnerability", "indicator", "relationship"} <= types
    yara = [o for o in objs if o.get("pattern_type") == "yara"]
    assert yara and "rule Lumma_Loader" in yara[0]["pattern"]
    ind = [o for o in objs if o["type"] == "indicator"]
    rels = [o for o in objs if o["type"] == "relationship" and o["relationship_type"] == "indicates"]
    assert len(rels) == len(ind)             # one family named: every indicator indicates it
    a["families"] = ["Lumma", "Cobalt Strike"]
    b2 = to_stix("Vendor", item, a, FakeAttack())
    assert not [o for o in b2["objects"] if o["type"] == "relationship" and o["relationship_type"] == "indicates"]
    # deterministic ids: the same report ingested twice is the same bundle
    assert to_stix("Vendor", item, a, FakeAttack())["objects"][0]["id"] == b2["objects"][0]["id"]


def test_investigation_matches_dataset(tmp_path):
    kb = Knowledge(tmp_path / "knowledge.db")
    kb.add_report({"report_id": "report--1", "source": "Vendor", "title": "Lumma returns", "url": "https://v/1",
                   "published": 1790589600, "actors": [], "families": ["Lumma"], "ttps": ["T1566"], "cves": []},
                  [(g.IP, "45.9.148.12")])
    inv = Investigator(None, None, Config())
    inv.kb = kb
    n = inv.g.nodes[inv.g.add_node(g.IP, "45.9.148.12")]
    reps = inv._dataset_reports(n)
    assert reps[0]["source"] == "Vendor" and reps[0]["malware"] == ["Lumma"] and reps[0]["date"] == 1790589600
    assert kb.search_reports("lumma")[0]["title"] == "Lumma returns"
    assert kb.search_reports("45.9.148.12")[0]["url"] == "https://v/1"
    inv.batch = {"source": "https://v/1"}    # --from that very report: not "previously reported"
    assert inv._dataset_reports(n) == []
