"""Ops endpoints — /healthz (liveness) and /version (build + MCP capability for agents and ops)."""
from fastapi.testclient import TestClient

import app.main


def test_healthz_and_version():
    c = TestClient(app.main.app)
    assert c.get("/healthz").json()["status"] == "ok"
    v = c.get("/version").json()
    assert v["version"] == app.main.__version__
    assert v["mcp_tools"] == 30          # 22 mgmt (adds packages_needing_install) + 8 DL
    assert v["name"] == "PolicyPilot"


def test_version_exposes_build_identity(monkeypatch):
    # /version + the About menu carry a build id so ops can confirm the deployed commit.
    from app import build
    monkeypatch.setenv("PILOT_BUILD_SHA", "abc1234")
    assert build.build_sha() == "abc1234"
    monkeypatch.delenv("PILOT_BUILD_SHA", raising=False)
    assert build.build_sha() == "dev"           # graceful default in dev / no build-arg
    v = TestClient(app.main.app).get("/version").json()
    assert "build" in v and "built_at" in v
