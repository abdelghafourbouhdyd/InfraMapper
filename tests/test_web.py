import json

import pytest

from inframapper import graph as g
from inframapper import keycheck

CASE = "20260101-120000_seed.example"
SECRET = "vt_secret_value_0123456789abcdef"
H = {"X-InfraMapper": "1"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    for p in keycheck.PROVIDERS:
        for k in p["keys"]:
            monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("INFRAMAPPER_WEB_PASSWORD", raising=False)
    monkeypatch.setattr(keycheck, "MIN_INTERVAL", 0)
    out = tmp_path / "cases"
    d = out / CASE
    d.mkdir(parents=True)
    gr = g.Graph()
    seed = gr.add_node(g.DOMAIN, "seed.example", seed=True, cluster=True)
    ip = gr.add_node(g.IP, "198.51.100.7", vt_malicious=5, vt_total=90, cluster=True, priority="P2")
    cert = gr.add_node(g.CERT, "a" * 64, issuer="R3")
    gr.add_edge(seed, ip, "RESOLVES_TO", source="Mnemonic", last_seen=1767225600)
    gr.add_edge(ip, cert, "USES_CERT", seen_by=["urlscan", "VirusTotal"])
    (d / "graph.json").write_text(json.dumps({**gr.to_dict(), "seed": seed}), encoding="utf-8")
    from inframapper.web.app import create_app
    app = create_app(tmp_path, out)
    app.config["TESTING"] = True
    return app.test_client()


def test_pages_render(client):
    for path in ("/", "/rules", "/settings", f"/cases/{CASE}", "/cases"):
        r = client.get(path)
        assert r.status_code == 200, path
    assert b"Hunting rules" in client.get("/").data


def test_post_needs_csrf_header(client):
    assert client.post("/api/rules", json={}).status_code == 403


def test_keys_are_masked_and_never_returned(client, monkeypatch):
    monkeypatch.setattr(keycheck, "_http", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network")))
    r = client.post("/api/keys/save", json={"provider": "virustotal", "values": {"VT_API_KEY": SECRET}}, headers=H)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert SECRET not in body
    vt = next(p for p in r.get_json()["providers"] if p["id"] == "virustotal")
    assert vt["fields"][0]["hint"].endswith(SECRET[-4:]) and vt["state"]["status"] == "untested"
    assert SECRET not in client.get("/api/keys").get_data(as_text=True)
    assert SECRET not in client.get("/api/settings").get_data(as_text=True)
    # a key from another provider can't be written through this one
    r = client.post("/api/keys/save", json={"provider": "otx", "values": {"VT_API_KEY": "x"}}, headers=H)
    assert r.status_code == 400
    r = client.post("/api/keys/save", json={"provider": "otx", "values": {"OTX_API_KEY": 'bad"quote'}}, headers=H)
    assert r.status_code == 400
    # only the four kept providers are offered; removed ones are rejected
    assert [p["id"] for p in client.get("/api/keys").get_json()["providers"]] == ["virustotal", "urlscan", "otx", "abusech"]
    for gone in ("shodan", "validin", "greynoise"):
        assert client.post("/api/keys/test", json={"provider": gone}, headers=H).status_code == 400


def test_pivot_scores_api(client):
    r = client.get(f"/api/cases/{CASE}/pivots")
    assert r.status_code == 200
    d = r.get_json()
    assert d["method"]["calibrated"] is False
    rows = {x["value"]: x for x in d["items"]}
    assert rows["seed.example"]["seed"] and rows["seed.example"]["confidence"] == 100
    cert = rows["a" * 64]
    assert cert["sources"] == ["VirusTotal", "urlscan"]
    assert cert["path"][0]["value"] == "seed.example" and len(cert["path"]) == 3
    assert any(f["kind"] == "term" for f in cert["factors"]["fidelity"])


def test_rule_lifecycle(client):
    rule = {"name": "same IP", "platform": "urlscan", "confidence": 60, "fidelity": 60,
            "conditions": [{"attribute": "ip", "method": "exact"}]}
    r = client.post("/api/rules", json={**rule, "name": ""}, headers=H)
    assert r.status_code == 400 and "name" in r.get_json()["error"]
    # preview: the form's search shape, then filled per confirmed host of a case (nothing searched)
    p = client.post("/api/rules/preview", json={"rule": {**rule, "name": "", "confidence": ""}}, headers=H).get_json()
    assert p["template"] == 'page.ip:"<ip>"' and p["suggest"]["confidence"] == 60
    p = client.post("/api/rules/preview", json={"rule": rule, "case": CASE}, headers=H).get_json()
    assert {"matched", "missing", "hosts"} <= set(p)
    created = client.post("/api/rules", json=rule, headers=H).get_json()
    d = client.get("/api/rules").get_json()
    assert d["items"][0]["id"] == created["id"] and d["items"][0]["template"] == 'page.ip:"<ip>"'
    assert {"title", "favicon", "regex", "pattern"} <= {x["key"] for x in d["pivots"]}
    assert client.post(f"/api/rules/{created['id']}", json={**rule, "fidelity": 20}, headers=H).get_json()["fidelity"] == 20
    assert client.post(f"/api/rules/{created['id']}/delete", headers=H).get_json() == {"ok": True}
    # built-in pivot tuning
    t = client.post("/api/pivots/title", json={"confidence": 10, "enabled": False}, headers=H).get_json()
    assert t["points"] == 0 and t["current"]["enabled"] is False
    assert client.post("/api/pivots/title", json={}, headers=H).get_json()["tuned"] == []
    assert client.post("/api/pivots/title", json={"template": "nope"}, headers=H).status_code == 400
    assert client.post("/api/pivots/nope", json={}, headers=H).status_code == 404
    assert client.post("/api/rules/nope/delete", headers=H).status_code == 404
