from ioci import graph as g
from ioci.ai import quoted, validate, _norm
from ioci.reports import merge_ai, to_stix
from ioci.vtcomments import ActorNames


class FakeAttack:
    t = {"T1059.001": ("PowerShell", ["execution"]), "T1566.002": ("Spearphishing Link", ["initial-access"])}


TEXT = """The actor sent phishing emails with a link to a fake donation page. The loader runs a
PowerShell command that downloads the second stage from evil-cdn.top, which also acts as the C2.
Victim site example-victim.org was compromised. Researchers used VirusTotal to pivot."""
IOCS = [(g.DOMAIN, "evil-cdn.top"), (g.DOMAIN, "example-victim.org"), (g.DOMAIN, "virustotal.com")]


def names():
    n = ActorNames(None)
    n._load([{"value": "APT28", "synonyms": ["Fancy Bear"]}])
    n._load_families([{"value": "Lumma", "synonyms": []}])
    return n


RAW = {"report_type": "threat-research", "summary": "APT28 phishing.", "key_findings": ["a"], "sectors": ["NGO"],
       "countries": ["US"],
       "ttps": [{"id": "T1566.002", "evidence": "sent phishing emails with a link to a fake donation page"},
                {"id": "t1059.001", "evidence": "runs a PowerShell command that downloads the second stage"},
                {"id": "T1059.001", "evidence": "a sentence the report never says"},          # not quoted
                {"id": "T9999", "evidence": "The actor sent phishing emails"}],             # not ATT&CK
       "actors": [{"name": "Fancy Bear", "confidence": "high", "evidence": "The actor sent phishing emails"},
                  {"name": "Lazarus", "confidence": "high", "evidence": "invented quote about Lazarus"}],
       "families": [],
       "ioc_roles": [{"value": "evil-cdn.top", "role": "c2"}, {"value": "EXAMPLE-VICTIM.org", "role": "compromised"},
                     {"value": "virustotal.com", "role": "benign-reference"},
                     {"value": "never-extracted.com", "role": "c2"}]}                          # model can't add IOCs


def test_quoted_tolerates_layout_not_invention():
    tn = _norm(TEXT)
    assert quoted("runs a  PowerShell\ncommand that downloads", tn)          # whitespace differs
    assert quoted("sent phishing emails ... downloads the second stage", tn)  # '...' joins two real quotes
    assert not quoted("runs a PowerShell script", tn)
    assert not quoted("short", tn)                                          # too short to prove anything


def test_validate_keeps_only_what_the_report_backs():
    v = validate(RAW, TEXT, IOCS, FakeAttack(), names())
    assert sorted(v["ttps"]) == ["T1059.001", "T1566.002"]
    assert [a["name"] for a in v["actors"]] == ["APT28"]                   # alias normalised, invented one gone
    assert v["roles"] == {"evil-cdn.top": "c2", "example-victim.org": "compromised", "virustotal.com": "benign-reference"}
    assert v["dropped"] == {"ttps": 2, "names": 1, "roles": 1}


def test_merge_and_stix_use_roles():
    a = {"iocs": list(IOCS), "ttps": [], "actors": ["Lazarus"], "families": ["Lumma"], "cves": [],
         "fingerprints": [], "aliases": {}, "yara": []}
    m = merge_ai(a, validate(RAW, TEXT, IOCS, FakeAttack(), names()), "sonnet")
    assert (g.DOMAIN, "virustotal.com") not in m["iocs"]                   # benign reference leaves the dataset
    assert m["actors"] == ["APT28"] and m["families"] == []                # the AI's reading replaces heuristics
    m["families"] = ["Lumma"]                                               # one family: attacker IOCs indicate it
    b = to_stix("Vendor", {"url": "https://v/1", "title": "t", "published": 1790589600}, m, FakeAttack())
    ind = {o["name"]: o for o in b["objects"] if o["type"] == "indicator"}
    assert ind["evil-cdn.top"]["x_ioci_role"] == "c2"
    assert ind["example-victim.org"]["indicator_types"] == ["compromised"]
    indicates = {o["source_ref"] for o in b["objects"] if o.get("relationship_type") == "indicates"}
    assert ind["evil-cdn.top"]["id"] in indicates and ind["example-victim.org"]["id"] not in indicates
    uses = [o for o in b["objects"] if o.get("relationship_type") == "uses"]
    assert uses and all(o.get("description") for o in uses if "attack-pattern" in o["target_ref"])
    assert b["objects"][0]["description"].startswith("APT28 phishing.")
