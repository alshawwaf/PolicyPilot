"""The general REST API (/api/v1): api-scope key auth (401 without), thin wrapper over mcp_tools, and the
error→status mapping. mcp_tools + api_keys are monkeypatched so these stay pure (no DB / no SMS)."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers import api_v1


def _client(monkeypatch, *, valid="good"):
    monkeypatch.setattr(api_v1.api_keys, "verify", lambda p, scope: p == valid and scope == "api")
    app = FastAPI()
    app.include_router(api_v1.router)
    return TestClient(app)


def test_requires_api_key(monkeypatch):
    c = _client(monkeypatch)
    assert c.get("/dbapi/v1/servers").status_code == 401                 # no header
    assert c.get("/dbapi/v1/servers", headers={"Authorization": "Bearer wrong"}).status_code == 401
    monkeypatch.setattr(api_v1.mcp_tools, "list_management_servers", lambda: {"servers": []})
    assert c.get("/dbapi/v1/servers", headers={"Authorization": "Bearer good"}).status_code == 200


def test_decide_wraps_mcp_tools(monkeypatch):
    c = _client(monkeypatch)
    seen = {}
    monkeypatch.setattr(api_v1.mcp_tools, "decide_access",
                        lambda **kw: seen.update(kw) or {"outcome": "create", "ok": True})
    r = c.post("/dbapi/v1/access/decide", headers={"Authorization": "Bearer good"},
               json={"server_id": 1, "source": "10.1.1.5", "destination": "Any", "service": "https"})
    assert r.status_code == 200 and r.json()["outcome"] == "create"
    assert seen["server_id"] == 1 and seen["service"] == "https" and seen["layer"] == "Network"


def test_apply_passes_publish_flag(monkeypatch):
    c = _client(monkeypatch)
    seen = {}
    monkeypatch.setattr(api_v1.mcp_tools, "apply_access",
                        lambda **kw: seen.update(kw) or {"outcome": "create", "published": kw["publish"]})
    r = c.post("/dbapi/v1/access/apply", headers={"Authorization": "Bearer good"},
               json={"server_id": 1, "source": "10.1.1.5", "destination": "Any", "port": "443",
                     "publish": True})
    assert r.status_code == 200 and r.json()["published"] is True and seen["publish"] is True


def test_apply_forwards_all_columns(monkeypatch):
    # REST parity: every access-rule column the MCP tool / webhook accept must also reach apply_access via
    # the REST body (else decide/apply silently ignore the very column the caller requested).
    c = _client(monkeypatch)
    seen = {}
    monkeypatch.setattr(api_v1.mcp_tools, "apply_access",
                        lambda **kw: seen.update(kw) or {"outcome": "create", "published": False})
    r = c.post("/dbapi/v1/access/apply", headers={"Authorization": "Bearer good"},
               json={"server_id": 1, "source": "10.1.1.5", "destination": "Any", "port": "3389",
                     "action": "Ask", "captive_portal": True, "action_limit": "L1",
                     "content": ["Source Code"], "content_direction": "down", "content_negate": True,
                     "time_objects": ["Off_Work"], "install_on": ["GW1"], "vpn": ["MyComm"],
                     "source_kind": "ip", "destination_kind": "ip", "publish": False})
    assert r.status_code == 200
    assert seen["action"] == "Ask" and seen["captive_portal"] is True and seen["action_limit"] == "L1"
    assert seen["content"] == ["Source Code"] and seen["content_direction"] == "down"
    assert seen["content_negate"] is True and seen["time_objects"] == ["Off_Work"]
    assert seen["install_on"] == ["GW1"] and seen["vpn"] == ["MyComm"]


def test_decide_forwards_columns(monkeypatch):
    c = _client(monkeypatch)
    seen = {}
    monkeypatch.setattr(api_v1.mcp_tools, "decide_access",
                        lambda **kw: seen.update(kw) or {"outcome": "create"})
    c.post("/dbapi/v1/access/decide", headers={"Authorization": "Bearer good"},
           json={"server_id": 1, "source": "10.1.1.5", "destination": "Any", "port": "443",
                 "action": "Drop", "install_on": ["GW1"]})
    assert seen["action"] == "Drop" and seen["install_on"] == ["GW1"]
    assert "publish" not in seen and "ticket_id" not in seen   # decide must not receive apply-only fields


def test_error_maps_to_status(monkeypatch):
    c = _client(monkeypatch)
    monkeypatch.setattr(api_v1.mcp_tools, "list_access_layers",
                        lambda sid: {"error": "management server 9 not found"})
    r = c.get("/dbapi/v1/layers?server_id=9", headers={"Authorization": "Bearer good"})
    assert r.status_code == 404                                        # "not found" -> 404
    monkeypatch.setattr(api_v1.mcp_tools, "decide_access", lambda **kw: {"ok": False, "error": "bad ip"})
    r2 = c.post("/dbapi/v1/access/decide", headers={"Authorization": "Bearer good"},
                json={"server_id": 1, "source": "x", "destination": "Any", "service": "https"})
    assert r2.status_code == 400                                       # other error -> 400


def test_correlate_endpoints(monkeypatch):
    c = _client(monkeypatch)
    monkeypatch.setattr(api_v1.mcp_tools, "correlate_service", lambda sid, name: {"match": name})
    r = c.post("/dbapi/v1/access/correlate/service", headers={"Authorization": "Bearer good"},
               json={"server_id": 1, "name": "https"})
    assert r.status_code == 200 and r.json()["match"] == "https"
