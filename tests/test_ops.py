"""Ops endpoints — /healthz (liveness) and /version (build + MCP capability for agents and ops)."""
from fastapi.testclient import TestClient

import app.main


def test_healthz_and_version():
    c = TestClient(app.main.app)
    assert c.get("/healthz").json()["status"] == "ok"
    v = c.get("/version").json()
    assert v["version"] == app.main.__version__
    assert v["mcp_tools"] == 27          # 19 mgmt (incl. correlate time/content/limit/access-role/zone/user-check) + 8 DL
    assert v["name"] == "PolicyPilot"
