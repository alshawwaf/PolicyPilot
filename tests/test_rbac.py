"""Per-key RBAC: read-only vs write capability on an API key, enforced via the authz contextvar that the
MCP bearer guard / REST dep / webhook set, and the _write_tool decorator that reads it."""
import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import mcp_server, models  # noqa: F401
from app.db import Base
from app.services import api_keys, authz, mcp_tools


# --- authz contextvar -----------------------------------------------------------------------------
def test_authz_default_is_write_and_set_reset_round_trips():
    assert authz.can_write() is True                 # default: writes allowed (back-compat)
    tok = authz.set_can_write(False)
    assert authz.can_write() is False
    authz.reset_can_write(tok)
    assert authz.can_write() is True


# --- _write_tool decorator ------------------------------------------------------------------------
def test_write_tool_refuses_only_when_readonly():
    calls = {"n": 0}

    @mcp_tools._write_tool
    def _w(x):
        calls["n"] += 1
        return {"ok": True, "x": x}

    assert _w(1) == {"ok": True, "x": 1} and calls["n"] == 1     # default context allows
    tok = authz.set_can_write(False)
    try:
        out = _w(2)
    finally:
        authz.reset_can_write(tok)
    assert out["ok"] is False and "read-only" in out["error"] and calls["n"] == 1   # body NOT run


def test_real_write_tools_are_decorated():
    # Every state-changing tool must carry the read-only guard (functools.wraps leaves __wrapped__).
    for name in ("apply_access", "remove_access", "amend_access_rule", "revert_change",
                 "add_dynamic_rule", "remove_dynamic_rule", "import_dynamic_layer", "push_dynamic_layer"):
        fn = getattr(mcp_tools, name)
        assert hasattr(fn, "__wrapped__"), f"{name} is not wrapped by _write_tool"
    tok = authz.set_can_write(False)
    try:
        assert "read-only" in mcp_tools.apply_access(1, "10.0.0.1", "Any", "Network", port="443")["error"]
        assert "read-only" in mcp_tools.push_dynamic_layer("L", gateway="GW")["error"]
    finally:
        authz.reset_can_write(tok)


def test_read_tools_are_not_gated():
    # A read tool must work under a read-only context (it just has no DB here -> returns its own shape).
    tok = authz.set_can_write(False)
    try:
        assert "servers" in mcp_tools.list_management_servers()   # no read-only refusal
    finally:
        authz.reset_can_write(tok)


# --- MCP bearer guard sets the capability around the inner call ------------------------------------
def _drive_guard(caps_fn, rate_fn=None):
    """Run one HTTP request through _BearerGuard with a fake inner app that records authz.can_write()
    AT DISPATCH TIME. Returns (inner_can_write_or_None, response_status)."""
    seen = {"can_write": None, "status": None}

    async def inner(scope, receive, send):
        seen["can_write"] = authz.can_write()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    guard = mcp_server._BearerGuard(inner, verify_fn=lambda p: True, enabled_fn=lambda: True,
                                    caps_fn=caps_fn, rate_fn=rate_fn)
    scope = {"type": "http", "headers": [(b"authorization", b"Bearer k")]}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg.get("type") == "http.response.start":
            seen["status"] = msg["status"]

    asyncio.run(guard(scope, receive, send))
    return seen["can_write"], seen["status"]


def test_guard_propagates_readonly_capability_to_inner_call():
    assert _drive_guard(lambda p: False)[0] is False  # read-only key -> inner sees can_write False
    assert _drive_guard(lambda p: True)[0] is True
    assert _drive_guard(None)[0] is True              # no caps_fn -> writes allowed (back-compat)
    assert authz.can_write() is True                 # and it's reset after the request


def test_guard_rate_limit_returns_429_before_dispatch():
    cw, status = _drive_guard(lambda p: True, rate_fn=lambda p: False)   # over the cap
    assert status == 429 and cw is None              # inner app was never reached
    cw2, status2 = _drive_guard(lambda p: True, rate_fn=lambda p: True)  # within the cap
    assert status2 == 200 and cw2 is True


# --- api_keys.authorize carries can_write ---------------------------------------------------------
@pytest.fixture()
def keydb(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    monkeypatch.setattr(api_keys, "SessionLocal", S)
    api_keys._bust()
    yield S
    api_keys._bust()


def test_authorize_returns_capability(keydb):
    _, rw = api_keys.generate("writer", "mcp", can_write=True)
    _, ro = api_keys.generate("reader", "mcp", can_write=False)
    assert api_keys.authorize(rw, "mcp") == {"id": api_keys.authorize(rw, "mcp")["id"], "can_write": True}
    assert api_keys.authorize(ro, "mcp")["can_write"] is False
    assert api_keys.authorize("nope", "mcp") is None
    assert api_keys.verify(rw, "mcp") is True and api_keys.verify(ro, "mcp") is True  # both still authenticate


def test_generate_defaults_to_write(keydb):
    _, secret = api_keys.generate("default", "mcp")
    assert api_keys.authorize(secret, "mcp")["can_write"] is True
