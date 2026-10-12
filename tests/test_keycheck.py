import json

import pytest
import requests

from ioci import keycheck
from ioci.keycheck import redact

SECRET = "sk_live_9f8e7d6c5b4a39281706"


class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


@pytest.fixture
def checker(tmp_path, monkeypatch):
    for p in keycheck.PROVIDERS:
        for k in p["keys"]:
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(keycheck, "MIN_INTERVAL", 0)
    return keycheck.KeyChecker(tmp_path)


def test_only_kept_providers():
    assert [p["id"] for p in keycheck.PROVIDERS] == ["virustotal", "urlscan", "otx", "abusech"]
    assert set(keycheck.CHECKS) == {"virustotal", "urlscan", "otx", "abusech"}


def test_virustotal_valid_with_quota(checker, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", SECRET)
    monkeypatch.setattr(keycheck, "_http", lambda *a, **k: Resp(200, {"data": {
        "api_requests_daily": {"user": {"used": 100, "allowed": 500}},
        "api_requests_hourly": {"user": {"used": 3, "allowed": 240}}}}))
    r = checker.test("virustotal")
    assert r["status"] == "valid" and r["plan"] == "public (free)"
    assert {"label": "requests / day", "used": 100, "limit": 500, "remaining": 400} in r["quota"]
    assert checker.status()["virustotal"]["status"] == "valid"        # cached for this key…
    monkeypatch.setenv("VT_API_KEY", SECRET + "x")
    assert checker.status()["virustotal"]["status"] == "untested"     # …but not for a replaced one
    assert SECRET not in (checker.path.read_text())                   # only a short hash is stored


def test_malwarebazaar_check(checker, monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY", SECRET)
    calls = []
    monkeypatch.setattr(keycheck, "_http", lambda m, url, **k: calls.append((m, url, k["headers"]["Auth-Key"]))
                        or Resp(200, {"query_status": "hash_not_found"}))
    r = checker.test("abusech")
    assert calls == [("POST", "https://mb-api.abuse.ch/api/v1/", SECRET)]
    assert r["status"] == "valid" and "MalwareBazaar" in r["message"]
    monkeypatch.setattr(keycheck, "_http", lambda *a, **k: Resp(401))
    assert checker.test("abusech")["status"] == "invalid"


def test_invalid_key_and_no_leak(checker, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", SECRET)
    monkeypatch.setattr(keycheck, "_http", lambda *a, **k: Resp(401, {"error": {"code": "WrongCredentialsError"}}))
    r = checker.test("virustotal")
    assert r["status"] == "invalid" and "rejected" in r["message"]
    assert SECRET not in json.dumps(r)


def test_connection_error_is_redacted(checker, monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", SECRET)

    def boom(*a, **k):
        raise requests.exceptions.SSLError(f"HTTPSConnectionPool: /users/me?key={SECRET} (bad handshake)")
    monkeypatch.setattr(keycheck, "_http", boom)
    r = checker.test("otx")
    assert r["status"] == "error"
    assert SECRET not in json.dumps(r)


def test_keyless_and_missing(checker):
    st = checker.status()
    assert st["urlscan"]["status"] == "keyless"
    assert st["otx"]["status"] == "not_configured"
    assert checker.test("otx")["status"] == "not_configured"


def test_rate_limited_and_unsaved_override(checker, monkeypatch):
    calls = []

    def fake(method, url, **k):
        calls.append(k.get("headers", {}).get("API-Key"))
        return Resp(429)
    monkeypatch.setattr(keycheck, "_http", fake)
    r = checker.test("urlscan", {"URLSCAN_API_KEY": "candidate-key-123456"})
    assert r["status"] == "rate_limited"
    assert calls == ["candidate-key-123456"]
    assert not checker.path.exists()   # trying an unsaved key never stores a status


def test_mask_and_redact():
    assert keycheck.mask("VT_API_KEY", SECRET) == "••••••••" + SECRET[-4:]
    assert keycheck.mask("VT_API_KEY", "short") == "••••••••"
    assert keycheck.mask("VT_RPM", "4") == "4"
    assert keycheck.mask("VT_API_KEY_BACKUP", "aaaa1111,bbbb2222") == "2 keys · ••••1111, ••••2222"
    assert redact(f"GET https://x/?key={SECRET}&q=1") == "GET https://x/?key=***&q=1"
    assert redact(f"token {SECRET} here", SECRET) == "token *** here"
