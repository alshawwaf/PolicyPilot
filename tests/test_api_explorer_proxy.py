"""The API-explorer Try-it-out proxy: auth-gated, SSRF-allowlisted to the user's own saved servers,
strips the portal cookie, and forwards to the real target. httpx + auth + allowlist are monkeypatched so
the test is hermetic (no network, no DB)."""
import types

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db import get_db
from app.routers import ui

_CALLS: dict = {}


class _FakeResp:
    status_code = 201
    content = b'{"sid":"abc"}'
    headers = {"content-type": "application/json"}


class _FakeClient:
    def __init__(self, **kw):
        _CALLS["client_kw"] = kw

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, content=None, headers=None):
        _CALLS.update(method=method, url=url, headers=dict(headers or {}), content=content)
        return _FakeResp()


def _client(monkeypatch, *, user=True, allow=None):
    _CALLS.clear()
    monkeypatch.setattr(ui, "get_user_or_none",
                        lambda req, db: types.SimpleNamespace(id=1) if user else None)
    monkeypatch.setattr(ui, "_explorer_proxy_targets", lambda db, u: (allow or {}))
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    app = FastAPI()
    app.include_router(ui.router)
    app.dependency_overrides[get_db] = lambda: None
    return TestClient(app)


def test_requires_auth(monkeypatch):
    c = _client(monkeypatch, user=False)
    assert c.post("/api-explorer/proxy", headers={"x-dcsim-target": "https://h/web_api"}).status_code == 401


def test_missing_or_bad_target(monkeypatch):
    c = _client(monkeypatch)
    assert c.post("/api-explorer/proxy").status_code == 400                       # no target
    assert c.post("/api-explorer/proxy", headers={"x-dcsim-target": "ftp://h/x"}).status_code == 400


def test_malformed_target_is_400_not_500(monkeypatch):
    # a hostile X-Dcsim-Target (bad IPv6 / out-of-range port) must be a clean 400, never a 500
    c = _client(monkeypatch, allow={"good.host:443": types.SimpleNamespace(cert_pem="")})
    for bad in ("https://[bad", "https://host:99999/x", "http://host:notaport/x"):
        assert c.post("/api-explorer/proxy", headers={"x-dcsim-target": bad}).status_code == 400


def test_strips_hop_by_hop_headers(monkeypatch):
    c = _client(monkeypatch, allow={"good.host:443": types.SimpleNamespace(cert_pem="")})
    c.post("/api-explorer/proxy",
           headers={"x-dcsim-target": "https://good.host/web_api/x", "transfer-encoding": "chunked",
                    "te": "trailers", "upgrade": "h2c", "content-type": "application/json"},
           content=b"{}")
    fwd = {k.lower() for k in _CALLS["headers"]}
    assert not ({"transfer-encoding", "te", "upgrade"} & fwd)   # no request-smuggling framing headers


def test_rejects_non_saved_host_ssrf(monkeypatch):
    # an attacker-typed target that isn't a saved server must be refused, and never forwarded
    c = _client(monkeypatch, allow={"good.host:443": types.SimpleNamespace(cert_pem="")})
    r = c.post("/api-explorer/proxy", headers={"x-dcsim-target": "http://169.254.169.254/latest/meta-data"})
    assert r.status_code == 403 and "not one of your saved servers" in r.json()["error"]
    assert "method" not in _CALLS                                                # httpx never called


def test_forwards_to_saved_host_and_strips_cookie(monkeypatch):
    c = _client(monkeypatch, allow={"good.host:443": types.SimpleNamespace(cert_pem="")})
    r = c.post("/api-explorer/proxy",
               headers={"x-dcsim-target": "https://good.host/web_api/login",
                        "cookie": "session=secret", "x-chkp-sid": "SID123",
                        "content-type": "application/json"},
               content=b'{"user":"admin"}')
    assert r.status_code == 201 and r.json()["sid"] == "abc"                      # upstream response relayed
    assert _CALLS["method"] == "POST" and _CALLS["url"] == "https://good.host/web_api/login"
    assert _CALLS["content"] == b'{"user":"admin"}'
    fwd = {k.lower(): v for k, v in _CALLS["headers"].items()}
    assert "cookie" not in fwd and "x-dcsim-target" not in fwd                    # portal cookie never leaks
    assert fwd.get("x-chkp-sid") == "SID123"                                      # CP session header passes
    assert _CALLS["client_kw"]["follow_redirects"] is False                       # no redirect-based SSRF


def test_default_port_match(monkeypatch):
    # a target with no explicit port matches a saved server on 443 (default)
    c = _client(monkeypatch, allow={"sms.lab:443": types.SimpleNamespace(cert_pem="")})
    r = c.post("/api-explorer/proxy", headers={"x-dcsim-target": "https://sms.lab/web_api/show-hosts"},
               content=b"{}")
    assert r.status_code == 201 and _CALLS["url"] == "https://sms.lab/web_api/show-hosts"
