import time

from inframapper import graph as g, scoring

NOW = time.time()
DAY = 86400


def case():
    gr = g.Graph()
    seed = gr.add_node(g.IP, "203.0.113.10", seed=True)
    return gr, seed


def test_corroborated_cert_beats_single_source():
    """IP -> certificate seen by VT and urlscan outranks one seen by VT alone (independent sources)."""
    gr, seed = case()
    a = gr.add_node(g.CERT, "a" * 64)
    b = gr.add_node(g.CERT, "b" * 64)
    gr.add_edge(seed, a, "USES_CERT", seen_by=["VirusTotal"])
    gr.add_edge(seed, a, "USES_CERT", seen_by=["urlscan"], date=int(NOW - 3 * DAY))
    gr.add_edge(seed, b, "USES_CERT", seen_by=["VirusTotal"], date=int(NOW - 3 * DAY))
    sc = scoring.Scorer(gr.nodes, gr.edges, seed, NOW)
    res = sc.score()
    assert gr.edges[(seed, a, "USES_CERT")]["seen_by"] == ["VirusTotal", "urlscan"]   # merged, not overwritten
    assert res[a]["confidence"] > res[b]["confidence"]
    assert sc.pair(seed, a)["sources"] == ["VirusTotal", "urlscan"]
    assert any("independent source groups agree" in f["label"] for f in sc.pair(seed, a)["factors"])
    assert "single source" in sc.pair(seed, b)["limited"]


def test_stale_and_conflicting_evidence_lower_confidence():
    gr, _ = case()
    seed = gr.add_node(g.DOMAIN, "evil.example", seed=True, resolves_now=["198.51.100.9"])
    fresh = gr.add_node(g.IP, "198.51.100.9")
    old = gr.add_node(g.IP, "198.51.100.200")
    gr.add_edge(seed, fresh, "RESOLVES_TO", source="Mnemonic", first_seen=int(NOW - 20 * DAY), last_seen=int(NOW - DAY))
    gr.add_edge(seed, old, "RESOLVES_TO", source="Mnemonic", first_seen=int(NOW - 1000 * DAY),
                last_seen=int(NOW - 900 * DAY))
    sc = scoring.Scorer(gr.nodes, gr.edges, seed, NOW)
    res = sc.score()
    assert res[fresh]["confidence"] > res[old]["confidence"]
    assert sc.pair(seed, old)["stale"] and not sc.pair(seed, fresh)["stale"]
    assert any("resolves elsewhere now" in c for c in sc.pair(seed, old)["conflicts"])


def test_shared_artefact_specificity_and_hubs():
    """Same HTML body (specific) links stronger than the same page title (generic); a shared-hosting
    IP passes almost nothing to its other domains."""
    gr = g.Graph()
    seed = gr.add_node(g.DOMAIN, "kit-a.example", seed=True)
    html = gr.add_node(g.HTML_HASH, "c" * 64)
    title = gr.add_node(g.TITLE, "Sign in")
    by_html = gr.add_node(g.DOMAIN, "kit-b.example")
    by_title = gr.add_node(g.DOMAIN, "random-shop.example")
    gr.add_edge(seed, html, "SERVES_HTML")
    gr.add_edge(by_html, html, "SERVES_HTML")
    gr.add_edge(seed, title, "HAS_TITLE")
    gr.add_edge(by_title, title, "HAS_TITLE")
    ip = gr.add_node(g.IP, "192.0.2.50", shared_hosting=True)
    neighbour = gr.add_node(g.DOMAIN, "unrelated-tenant.example")
    gr.add_edge(seed, ip, "RESOLVES_TO", source="vt")
    gr.add_edge(neighbour, ip, "RESOLVES_TO", source="vt")
    res = scoring.Scorer(gr.nodes, gr.edges, seed, NOW).score()
    assert res[by_html]["confidence"] > 2 * res[by_title]["confidence"]
    assert res[neighbour]["confidence"] < 15
    assert res[neighbour]["fidelity"] < res[by_html]["fidelity"]
    # every number is explained
    assert any("artefact specificity" in f["label"] for f in res[by_title]["factors"]["confidence"])
    terms = {f["key"] for f in res[by_html]["factors"]["fidelity"] if f["kind"] == "term"}
    assert terms == {"specificity", "confidence", "context", "threat", "freshness"}


def test_analyst_verdicts_and_insufficient_data():
    gr, seed = case()
    fp = gr.add_node(g.DOMAIN, "cdn.example", analyst_verdict="fp")
    ok = gr.add_node(g.DOMAIN, "c2.example", analyst_verdict="confirmed")
    lone = gr.add_node(g.DOMAIN, "orphan.example")      # no edge at all
    gr.add_edge(fp, seed, "RESOLVES_TO", source="vt")
    res = scoring.Scorer(gr.nodes, gr.edges, seed, NOW).score()
    assert res[fp]["confidence"] <= 5
    assert res[ok]["confidence"] >= 95
    assert res[lone]["confidence"] is None and res[lone]["confidence_band"] == "insufficient"
    assert "no path to the seed" in res[lone]["limited"]
    assert res[seed]["confidence"] == 100


def test_method_is_declared_heuristic():
    assert scoring.METHOD["calibrated"] is False
    assert abs(sum(scoring.METHOD["weights"].values()) - 1) < 1e-9
    assert scoring.band(80) == "high" and scoring.band(10) == "very low" and scoring.band(None) == "insufficient"


def test_recommend_next_pivot():
    gr, seed = case()
    f = gr.add_node(g.FILE, "d" * 64, vt_malicious=12, priority="P2")
    gr.add_edge(f, seed, "CONTACTS")
    gr.add_edge(f, seed, "CONTACTS", seen_by=["urlscan"])
    gr.edges[(f, seed, "CONTACTS")]["date"] = int(NOW - 5 * DAY)
    res = scoring.Scorer(gr.nodes, gr.edges, seed, NOW).score()
    assert res[f]["recommend"] is True
    gr.set_prop(f, expanded=True)
    assert scoring.Scorer(gr.nodes, gr.edges, seed, NOW).score()[f]["recommend"] is False


def test_view_data_carries_scores():
    from inframapper.export import view_data
    from inframapper.investigator import Config, Investigator
    inv = Investigator(None, None, Config(use_vt=False, use_urlscan=False, use_pdns=False))
    inv.seed_id = inv.g.add_node(g.DOMAIN, "seed.example", seed=True)
    ip = inv.g.add_node(g.IP, "192.0.2.1")
    inv.g.add_edge(inv.seed_id, ip, "RESOLVES_TO", source="Mnemonic")
    data = view_data(inv, "t")
    assert data["scores"][ip]["confidence"] > 0
    assert data["scoring"]["calibrated"] is False
    assert all("score" in e["props"] for e in data["edges"])
