import json

from ioci import cluster, graph as g, share
from ioci.investigator import Config, Investigator


def batch_case():
    inv = Investigator(None, None, Config(use_vt=False, use_urlscan=False, use_pdns=False))
    inv.seed_id = inv.g.add_node(g.REPORT, "report.md", source="Input report", seed=True)
    for t, v, extra in [(g.IP, "50.16.16.211", {}), (g.DOMAIN, "evil-cdn.top", {"dns_dead": True}),
                        (g.IP, "8.8.8.8", {"warninglist": "public DNS resolvers"}),
                        (g.FILE, "a" * 64, {"md5": "b" * 32}), (g.URL, "http://x.top/it's", {})]:
        nid = inv.g.add_node(t, v, input_ioc=True, pinned=True, **extra)
        inv.g.add_edge(inv.seed_id, nid, "MENTIONS")
    rid = inv.g.add_node(g.REPORT, "feodo:qakbot", source="Feodo Tracker", name="Feodo: QakBot", malware=["QakBot"])
    inv.g.add_edge(g.node_id(g.IP, "50.16.16.211"), rid, "REPORTED_IN", source="Feodo Tracker", current=True)
    inv.batch = {"source": "report.md", "iocs": 5}
    return inv


def test_triage_priorities():
    inv = batch_case()
    pri = {i["value"]: i["priority"] for i in share.actionable(inv)}
    assert pri["50.16.16.211"] == "P1"
    assert pri["evil-cdn.top"] == "P3"
    assert "8.8.8.8" not in pri          # noise is never exported


def test_dead_domain_reason():
    inv = batch_case()
    it = next(i for i in share.actionable(inv) if i["value"] == "evil-cdn.top")
    assert any("no longer resolves" in r for r in it["reasons"])


def test_co_seeds_confirm_neighbours():
    inv = batch_case()
    new = inv.g.add_node(g.DOMAIN, "found-by-pivot.top")
    inv.g.add_edge(new, g.node_id(g.IP, "50.16.16.211"), "RESOLVES_TO")
    res = cluster.score(inv.g, inv.seed_id)
    assert res[new]["confirmed"]
    # a benign input IOC is not a co-seed: it can't pull its neighbours in
    other = inv.g.add_node(g.DOMAIN, "dns.google")
    inv.g.add_edge(other, g.node_id(g.IP, "8.8.8.8"), "RESOLVES_TO")
    assert not cluster.score(inv.g, inv.seed_id)[other]["confirmed"]


def test_stix_bundle(tmp_path):
    inv = batch_case()
    n = share.write_stix(inv, tmp_path / "b.json", "case", "green")
    b = json.loads((tmp_path / "b.json").read_text())
    inds = [o for o in b["objects"] if o["type"] == "indicator"]
    assert n == len(inds) == 4
    pats = {o["pattern"] for o in inds}
    assert "[ipv4-addr:value = '50.16.16.211']" in pats
    assert "[url:value = 'http://x.top/it\\'s']" in pats                  # quote escaped
    assert any("SHA-256" in p and "MD5" in p for p in pats)              # all hashes of the sample
    assert any(o["type"] == "malware" and o["name"] == "QakBot" for o in b["objects"])
    assert all(o["object_marking_refs"] == [share.TLP["green"][0]] for o in inds)
    # deterministic ids: same case, same indicator ids
    share.write_stix(inv, tmp_path / "c.json", "case", "green")
    ids = lambda p: {o["id"] for o in json.loads(p.read_text())["objects"] if o["type"] == "indicator"}
    assert ids(tmp_path / "b.json") == ids(tmp_path / "c.json")


def test_hunt_files(tmp_path):
    inv = batch_case()
    counts = share.write_hunt(inv, tmp_path)
    assert counts["ip"] == 1 and counts["domain"] == 1
    ips = (tmp_path / "hunt" / "ip.txt").read_text()
    assert "50.16.16.211" in ips and "8.8.8.8" not in ips          # noise is never exported
    assert {p.suffix for p in (tmp_path / "hunt").iterdir()} == {".rules", ".txt"}   # no KQL / SPL any more
    rules = (tmp_path / "hunt" / "suricata.rules").read_text().splitlines()
    sids = [r.split("sid:")[1].split(";")[0] for r in rules if r.startswith("alert")]
    assert len(sids) == len(set(sids)) == 4   # 3 domain rules + 1 IP rule
