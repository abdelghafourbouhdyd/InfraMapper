import json
import threading
import time

from ioci import graph as g
from ioci.investigator import Config, Investigator
from ioci.server import PivotServer


def make_case(tmp_path):
    d = tmp_path / "20260101-120000_seed.example"
    d.mkdir()
    gr = g.Graph()
    seed = gr.add_node(g.DOMAIN, "seed.example", seed=True)
    ip = gr.add_node(g.IP, "198.51.100.7")
    gr.add_edge(seed, ip, "RESOLVES_TO", source="Mnemonic")
    (d / "graph.json").write_text(json.dumps({**gr.to_dict(), "seed": seed}), encoding="utf-8")
    return d


def test_graph_opens_while_slow_refresh_runs(tmp_path):
    """Opening a case must not wait for prior-reporting / VT-comment catch-up (minutes at 4 VT req/min)."""
    d = make_case(tmp_path)
    inv = Investigator(None, None, Config(use_vt=False, use_urlscan=False, use_pdns=False))
    release = threading.Event()

    def slow_check():
        release.wait(10)   # stands in for rate-limited VT comments / feed lookups
        inv.g.add_node(g.REPORT, "feodo:x", source="Feodo Tracker", name="new report")
        return 1
    inv.check_reporting = slow_check
    t = time.time()
    srv = PivotServer(inv, d, None, None, None)
    assert time.time() - t < 2 and srv.status()["refreshing"] is True
    t = time.time()
    html = srv.page()                       # the lock is held by the refresh: snapshot, no waiting
    assert time.time() - t < 2 and "seed.example" in html
    assert "seed.example" in json.dumps(srv.data())
    release.set()
    for _ in range(100):
        if not srv.status()["refreshing"]:
            break
        time.sleep(0.05)
    st = srv.status()
    assert st["refreshing"] is False and st["refresh_error"] is None and st["refreshed"]
    assert "new report" in json.dumps(srv.data())            # refresh result is served afterwards
    assert "feodo:x" in (d / "graph.json").read_text()        # …and saved


def test_refresh_failure_keeps_case_usable(tmp_path):
    d = make_case(tmp_path)
    inv = Investigator(None, None, Config(use_vt=False, use_urlscan=False, use_pdns=False))
    inv.check_reporting = lambda: (_ for _ in ()).throw(RuntimeError("network down"))
    srv = PivotServer(inv, d, None, None, None)
    for _ in range(100):
        if not srv.status()["refreshing"]:
            break
        time.sleep(0.05)
    assert "network down" in srv.status()["refresh_error"]
    assert "seed.example" in srv.page()
