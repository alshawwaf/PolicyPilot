"""MCP agent tools + the SDK-independent glue (bearer guard, publish gate). No `mcp` SDK needed — the
tool logic and the ASGI guard are pure; the FastMCP wiring is verified separately once the SDK is
installed via Artifactory."""
import asyncio
import types

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import mcp_server
from app import models  # noqa: F401 — registers tables on Base.metadata
from app.db import Base
from app.services import access_automation as aa
from app.services import app_settings, change_log, gaia_client, mcp_tools, mgmt_creds
from app.models import AppliedChange, ManagementServer


def _fake_server(monkeypatch):
    monkeypatch.setattr(mcp_tools, "_server_secret",
                        lambda db, sid: (types.SimpleNamespace(id=sid, host="h"), "secret"))


# --- decide_access (preview, read-only) -----------------------------------------------------------
def test_decide_access_builds_request_and_previews(monkeypatch):
    _fake_server(monkeypatch)
    seen = {}
    monkeypatch.setattr(aa, "preview", lambda srv, sec, req, layer, package=None: seen.update(req=req, layer=layer) or {"ok": True, "outcome": "create"})
    out = mcp_tools.decide_access(1, "10.1.1.5", "Any", "Network", service="icmp")
    assert out["outcome"] == "create"
    assert seen["req"].service == "icmp" and seen["layer"] == "Network"


def test_decide_access_signals_autopilot_from_toggle(monkeypatch):
    # The Autopilot lab-demo toggle (aa_autopilot) must surface in the tool result so a prompt-driven agent
    # knows it may apply+publish in one turn. Toggle off (or read failure) -> autopilot False (agent confirms).
    _fake_server(monkeypatch)
    monkeypatch.setattr(aa, "preview", lambda *a, **k: {"ok": True, "outcome": "widen"})
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "aa_autopilot" else None)
    assert mcp_tools.decide_access(1, "10.1.1.5", "Any", "Network", application="Facebook")["autopilot"] is True
    monkeypatch.setattr(app_settings, "get", lambda k: False if k == "aa_autopilot" else None)
    assert mcp_tools.decide_access(1, "10.1.1.5", "Any", "Network", application="Facebook")["autopilot"] is False


def test_decide_access_bad_input_returns_error_not_raise(monkeypatch):
    _fake_server(monkeypatch)
    monkeypatch.setattr(aa, "preview", lambda *a, **k: {"ok": True})
    out = mcp_tools.decide_access(1, "not-an-ip", "Any", "Network", port="443")
    assert out["ok"] is False and "error" in out


# --- apply_access publish gate --------------------------------------------------------------------
def test_apply_publish_blocked_when_setting_off(monkeypatch):
    monkeypatch.setattr(app_settings, "get", lambda k: False if k == "mcp_allow_publish" else None)
    called = {"execute": False}
    monkeypatch.setattr(aa, "execute", lambda *a, **k: called.update(execute=True))
    out = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443", publish=True)
    assert out["ok"] is False and out["published"] is False and "disabled" in out["error"]
    assert called["execute"] is False               # never reaches the SMS


def test_apply_publish_allowed_when_setting_on(monkeypatch):
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "mcp_allow_publish" else None)
    _fake_server(monkeypatch)
    seen = {}
    monkeypatch.setattr(aa, "execute", lambda srv, sec, req, layer, package=None, ticket_id="", publish=False: seen.update(publish=publish) or {"ok": True, "published": publish})
    out = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443", publish=True)
    assert out["published"] is True and seen["publish"] is True


@pytest.fixture()
def idemdb(monkeypatch):
    """An in-memory DB wired into BOTH the change-log path and the idempotency store, so an apply test that
    publishes stays fully isolated from any real database."""
    from app.services import idempotency
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    monkeypatch.setattr(mcp_tools, "SessionLocal", S)
    monkeypatch.setattr(idempotency, "SessionLocal", S)
    return S


def test_apply_idempotency_key_replays_committed_result(monkeypatch, idemdb):
    # A retry with the same idempotency_key must REPLAY the first committed result, never publish twice.
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "mcp_allow_publish" else None)
    _fake_server(monkeypatch)
    calls = {"n": 0}

    def _execute(srv, sec, req, layer, package=None, ticket_id="", publish=False):
        calls["n"] += 1
        return {"ok": True, "published": True, "rule_name": "r1", "call": calls["n"]}

    monkeypatch.setattr(aa, "execute", _execute)
    first = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443",
                                  publish=True, idempotency_key="ticket-42")
    assert first["published"] is True and calls["n"] == 1 and "idempotent_replay" not in first
    second = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443",
                                   publish=True, idempotency_key="ticket-42")
    assert second["idempotent_replay"] is True and second["call"] == 1   # the FIRST result, replayed
    assert calls["n"] == 1                                                # the SMS was NOT hit again


def test_apply_idempotency_key_conflicts_on_a_different_request(monkeypatch, idemdb):
    # Review MEDIUM: a key reused for a genuinely DIFFERENT request must NOT replay the first result — it
    # must CONFLICT (fail loud), so the tool never reports the earlier change's rule as applied for a change
    # that never actually ran. The SAME request under the same key still replays cleanly.
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "mcp_allow_publish" else None)
    _fake_server(monkeypatch)
    calls = {"n": 0}

    def _execute(srv, sec, req, layer, package=None, ticket_id="", publish=False):
        calls["n"] += 1
        return {"ok": True, "published": True, "rule_name": f"r{calls['n']}"}

    monkeypatch.setattr(aa, "execute", _execute)
    a = mcp_tools.apply_access(1, "10.0.0.1", "10.0.0.2", "Network", port="443",
                              publish=True, idempotency_key="chg-1")
    assert a["published"] is True and calls["n"] == 1
    # same key, DIFFERENT request -> conflict, and execute() is NOT called again
    b = mcp_tools.apply_access(1, "10.0.0.9", "10.0.0.99", "Network", port="22",
                              publish=True, idempotency_key="chg-1")
    assert b.get("idempotency_conflict") is True and b["ok"] is False and calls["n"] == 1
    # same key, SAME request -> clean replay (not a conflict)
    c = mcp_tools.apply_access(1, "10.0.0.1", "10.0.0.2", "Network", port="443",
                              publish=True, idempotency_key="chg-1")
    assert c.get("idempotent_replay") is True and calls["n"] == 1
    # a request differing ONLY in an action-settings / content-direction field is a DIFFERENT change too
    # (verification found these fields missing from the fingerprint -> a silent replay)
    d = mcp_tools.apply_access(1, "10.0.0.1", "10.0.0.2", "Network", port="443",
                              publish=True, idempotency_key="chg-1", action_limit="2 Mbps")
    assert d.get("idempotency_conflict") is True and calls["n"] == 1


def test_apply_idempotency_dry_run_is_not_cached(monkeypatch, idemdb):
    # publish=false never commits, so an idempotency_key on a dry-run must not short-circuit later calls.
    _fake_server(monkeypatch)
    calls = {"n": 0}

    def _execute(srv, sec, req, layer, package=None, ticket_id="", publish=False):
        calls["n"] += 1
        return {"ok": True, "published": False, "call": calls["n"]}

    monkeypatch.setattr(aa, "execute", _execute)
    a = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443",
                              publish=False, idempotency_key="dry-1")
    b = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443",
                              publish=False, idempotency_key="dry-1")
    assert calls["n"] == 2 and "idempotent_replay" not in a and "idempotent_replay" not in b


def test_remove_access_publish_gate_and_delegates(monkeypatch):
    # publish gated by mcp_allow_publish (same as apply); dry-run delegates to aa.remove_execute
    monkeypatch.setattr(app_settings, "get", lambda k: False if k == "mcp_allow_publish" else None)
    blocked = mcp_tools.remove_access(1, "10.1.2.250", "Any", "Network", application="Facebook", publish=True)
    assert blocked["ok"] is False and blocked["published"] is False and "disabled" in blocked["error"]
    _fake_server(monkeypatch)
    seen = {}
    monkeypatch.setattr(aa, "remove_execute",
                        lambda srv, sec, req, layer, package=None, ticket_id="", publish=False:
                        seen.update(publish=publish) or {"ok": True, "outcome": "deny", "applied": True})
    out = mcp_tools.remove_access(1, "10.1.2.250", "Any", "Network", application="Facebook")
    assert out["outcome"] == "deny" and seen["publish"] is False


def test_remove_access_carries_autopilot_signal(monkeypatch):
    # M6: the headline one-turn revoke-and-publish needs the autopilot flag on the REMOVE result too (the
    # agent routes straight to remove_access).
    _fake_server(monkeypatch)
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "aa_autopilot" else None)
    monkeypatch.setattr(aa, "remove_execute",
                        lambda *a, **k: {"ok": True, "outcome": "deny", "applied": True, "published": False})
    out = mcp_tools.remove_access(1, "10.1.2.250", "Any", "Network", application="Facebook")
    assert out.get("autopilot") is True


def test_autopilot_signal_from_global_toggle(monkeypatch):
    # Autopilot is now a global lab-demo toggle (aa_autopilot), not a per-scope profile: on -> True for any
    # server/layer; off -> False.
    store = {}
    monkeypatch.setattr(app_settings, "get", lambda k: store.get(k))
    srv = types.SimpleNamespace(id=1, name="HQ")
    store["aa_autopilot"] = True
    assert mcp_tools._autopilot(srv, "DMZ") is True and mcp_tools._autopilot(None, None) is True
    store["aa_autopilot"] = False
    assert mcp_tools._autopilot(srv, "DMZ") is False


# --- list_changes / revert_change (rollback) ------------------------------------------------------
@pytest.fixture()
def cdb(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    monkeypatch.setattr(mcp_tools, "SessionLocal", Session)
    return Session


def _seed_change(Session, reverted=False):
    with Session() as s:
        if s.get(ManagementServer, 1) is None:        # revert_change resolves the server strictly by id
            s.add(ManagementServer(id=1, name="HQ", host="hq.example", username="admin", owner_id=1))
            s.commit()
        row = change_log.record(s, server=types.SimpleNamespace(id=1, name="HQ"), layer="Network",
                                request={"source": "10.1.2.250", "destination": "Any", "application": "Facebook"},
                                result={"ok": True, "published": True, "applied": True, "outcome": "create",
                                        "inverse": [{"op": "delete-access-rule", "uid": "u9", "layer": "Network"}]})
        if reverted:
            change_log.mark_reverted(s, row, actor="user:x")
        return row.id


def test_list_changes_returns_recorded(cdb):
    cid = _seed_change(cdb)
    out = mcp_tools.list_changes()
    assert out["ok"] and any(c["id"] == cid and c["outcome"] == "create" and not c["reverted"]
                             for c in out["changes"])


def test_revert_change_publish_gated(monkeypatch):
    monkeypatch.setattr(app_settings, "get", lambda k: False if k == "mcp_allow_publish" else None)
    out = mcp_tools.revert_change(1, publish=True)
    assert out["ok"] is False and "disabled" in out["error"]    # gate returns before touching the DB


def test_revert_change_marks_reverted_then_refuses_again(monkeypatch, cdb):
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "mcp_allow_publish" else None)
    monkeypatch.setattr(mgmt_creds, "get_secret", lambda db, ms: "secret")
    monkeypatch.setattr(gaia_client, "ensure_pinned", lambda db, ms: None)
    seen = {}
    monkeypatch.setattr(aa, "revert_execute", lambda srv, sec, ops, publish=False, disable_added_rules=False:
                        seen.update(ops=ops, publish=publish, disable=disable_added_rules) or {"ok": True, "reverted": publish})
    cid = _seed_change(cdb)
    out = mcp_tools.revert_change(cid, publish=True)
    assert out["ok"] and out["reverted"] is True and out["change_id"] == cid
    assert seen["ops"] == [{"op": "delete-access-rule", "uid": "u9", "layer": "Network"}] and seen["disable"] is False
    again = mcp_tools.revert_change(cid, publish=True)           # idempotent guard
    assert again["ok"] is False and "already" in again["error"]


def test_revert_change_disable_mode_passthrough(monkeypatch, cdb):
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "mcp_allow_publish" else None)
    monkeypatch.setattr(mgmt_creds, "get_secret", lambda db, ms: "secret")
    monkeypatch.setattr(gaia_client, "ensure_pinned", lambda db, ms: None)
    seen = {}
    monkeypatch.setattr(aa, "revert_execute", lambda srv, sec, ops, publish=False, disable_added_rules=False:
                        seen.update(disable=disable_added_rules) or
                        {"ok": True, "reverted": publish, "mode": "disable" if disable_added_rules else "delete"})
    out = mcp_tools.revert_change(_seed_change(cdb), publish=True, disable_instead_of_delete=True)
    assert out["ok"] and seen["disable"] is True and out["mode"] == "disable"


def test_revert_change_unknown_id(cdb):
    out = mcp_tools.revert_change(999, publish=False)
    assert out["ok"] is False and "no recorded change" in out["error"]


def test_revert_change_deleted_server_does_not_misroute(monkeypatch, cdb):
    # H4: the original server was deleted (stale server_id=5), and a DIFFERENT surviving server's host contains
    # that digit ("10.0.0.5"). revert_change must resolve STRICTLY by id, return "no longer exists", and NEVER
    # fuzzy-match onto the wrong live SMS or call revert_execute.
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "mcp_allow_publish" else None)
    monkeypatch.setattr(mgmt_creds, "get_secret", lambda db, ms: "secret")
    monkeypatch.setattr(gaia_client, "ensure_pinned", lambda db, ms: None)
    called = {"revert": False}
    monkeypatch.setattr(aa, "revert_execute",
                        lambda *a, **k: called.update(revert=True) or {"ok": True, "reverted": True})
    with cdb() as s:
        s.add(ManagementServer(id=1, name="DR", host="10.0.0.5", username="admin", owner_id=1))  # host has '5'
        s.commit()
        row = change_log.record(s, server=types.SimpleNamespace(id=5, name="OldSMS"), layer="Network",
                                request={"source": "x", "destination": "Any"},
                                result={"ok": True, "published": True, "applied": True, "outcome": "create",
                                        "inverse": [{"op": "delete-access-rule", "uid": "u1", "layer": "Network"}]})
        cid = row.id
    out = mcp_tools.revert_change(cid, publish=True)
    assert out["ok"] is False and "no longer exists" in out["error"]
    assert called["revert"] is False


def test_apply_dry_run_always_allowed(monkeypatch):
    monkeypatch.setattr(app_settings, "get", lambda k: False)   # publish disabled...
    _fake_server(monkeypatch)
    seen = {}
    monkeypatch.setattr(aa, "execute", lambda srv, sec, req, layer, package=None, ticket_id="", publish=False: seen.update(publish=publish) or {"ok": True})
    out = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443", publish=False)  # ...dry-run ok
    assert out["ok"] is True and seen["publish"] is False


# --- a server can be referenced by id OR name/host; an unmatched ref lists the options ----------------
def test_resolve_server_by_id_name_host_and_helpful_error():
    import types
    from app.services import mcp_tools
    srv = types.SimpleNamespace(id=7, name="HQ-Management", host="10.1.3.40", domain="")
    # A SECOND server so an unresolved ref is genuinely ambiguous (no single-server fallback) and the
    # helpful error fires. With one server, an unrecognised non-numeric ref resolves to it instead.
    srv2 = types.SimpleNamespace(id=8, name="Branch", host="10.9.9.9", domain="")

    class _DB:
        def get(self, _model, sid):
            return {7: srv, 8: srv2}.get(sid)
        def query(self, _model):
            class _Q:
                def all(_self):
                    return [srv, srv2]
            return _Q()

    db = _DB()
    assert mcp_tools._resolve_server(db, 7) is srv            # numeric id
    assert mcp_tools._resolve_server(db, "7") is srv          # digit string
    assert mcp_tools._resolve_server(db, "hq-management") is srv   # name, case-insensitive
    assert mcp_tools._resolve_server(db, "10.1.3.40") is srv  # host
    assert mcp_tools._resolve_server(db, "HQ") is srv         # unique partial match on name
    try:
        mcp_tools._resolve_server(db, "nope")                 # no match + 2 servers -> ambiguous -> error
        assert False, "expected ValueError"
    except ValueError as exc:
        msg = str(exc)
        assert "id 7 = HQ-Management" in msg and "list_management_servers" in msg   # error lists the options


# --- an unexpected (non-MgmtError) failure comes back STRUCTURED, never an opaque MCP "Internal error" ---
def test_decide_access_wraps_unexpected_engine_error(monkeypatch):
    _fake_server(monkeypatch)
    monkeypatch.setattr(aa, "preview", lambda *a, **k: (_ for _ in ()).throw(ConnectionError("SMS unreachable")))
    out = mcp_tools.decide_access(1, "10.1.2.222", "1.2.3.4", "Network", port="53", protocol="udp")
    assert out["ok"] is False and "SMS unreachable" in out["error"]   # the real reason, not a raise


def test_apply_access_wraps_unexpected_engine_error(monkeypatch):
    monkeypatch.setattr(app_settings, "get", lambda k: False)
    _fake_server(monkeypatch)
    monkeypatch.setattr(aa, "execute", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    out = mcp_tools.apply_access(1, "10.1.2.222", "1.2.3.4", "Network", port="53", protocol="udp")
    assert out["ok"] is False and out["applied"] is False and "boom" in out["error"]


def test_engine_preview_execute_wrap_non_mgmt_errors(monkeypatch):
    # preview/execute must catch ANY exception (unreachable SMS, TLS reset, MgmtSession=None from a degraded
    # import) and return {"ok": False, "error": <reason>} so no caller ever gets an opaque "Internal error".
    monkeypatch.setattr(aa, "read_session", lambda *a, **k: (_ for _ in ()).throw(ConnectionError("refused")))
    prev = aa.preview(object(), "s", object(), "Network")
    assert prev["ok"] is False and "refused" in prev["error"]
    monkeypatch.setattr(aa, "MgmtSession", None)             # the degraded-import / connect-failure case
    ex = aa.execute(object(), "s", object(), "Network")
    assert ex["ok"] is False and "apply failed" in ex["error"]


# --- coverage_lookup (uses the bundled artifacts) -------------------------------------------------
def test_coverage_lookup_object_and_list():
    detail = mcp_tools.coverage_lookup("management", "host")
    assert detail.get("terraform") == "checkpoint_management_host" and detail.get("fields")
    miss = mcp_tools.coverage_lookup("management", "totally-not-an-object")
    assert "error" in miss and isinstance(miss.get("objects"), list)
    listing = mcp_tools.coverage_lookup("management")
    assert "host" in listing["objects"]


# --- the pure-ASGI bearer guard -------------------------------------------------------------------
def _drive(app, headers):
    """Run one ASGI http request through `app`, returning (status, body)."""
    scope = {"type": "http", "headers": headers}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    asyncio.run(app(scope, receive, send))
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


def test_bearer_guard_rejects_without_token():
    inner_called = {"hit": False}

    async def inner(scope, receive, send):
        inner_called["hit"] = True
    guard = mcp_server._BearerGuard(inner, lambda p: p == "s3cret", lambda: True)
    status, body = _drive(guard, [(b"authorization", b"Bearer wrong")])
    assert status == 401 and b"Unauthorized" in body and inner_called["hit"] is False
    status2, _ = _drive(guard, [])                  # no header at all
    assert status2 == 401


def test_bearer_guard_distinguishes_missing_vs_invalid_bearer():
    # The 401 body must say WHICH problem it is, so a client log points at the fix:
    #  - no header at all -> a proxy/client dropped it (the n8n "empty bearer" symptom)
    #  - a bearer arrived but the key is bad/expired/wrong-scope
    guard = mcp_server._BearerGuard(_ok_inner(), lambda p: p == "s3cret", lambda: True)
    s_missing, b_missing = _drive(guard, [])                                  # header absent
    assert s_missing == 401 and b"no Authorization header" in b_missing
    s_scheme, b_scheme = _drive(guard, [(b"authorization", b"Token abc")])     # wrong scheme
    assert s_scheme == 401 and b"Bearer scheme" in b_scheme
    s_bad, b_bad = _drive(guard, [(b"authorization", b"Bearer nope")])         # bad key
    assert s_bad == 401 and b"not a valid active mcp-scope" in b_bad
    # a trailing newline on the header value must not break an otherwise-valid key
    s_ok, _ = _drive(guard, [(b"authorization", b"Bearer s3cret\n")])
    assert s_ok == 200


def test_bearer_guard_allows_with_token():
    passed = {"hit": False}

    async def inner(scope, receive, send):
        passed["hit"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    guard = mcp_server._BearerGuard(inner, lambda p: p == "s3cret", lambda: True)
    status, body = _drive(guard, [(b"authorization", b"Bearer s3cret")])
    assert status == 200 and body == b"ok" and passed["hit"] is True


def test_bearer_guard_503_when_not_enabled():
    inner_called = {"hit": False}

    async def inner(scope, receive, send):
        inner_called["hit"] = True
    guard = mcp_server._BearerGuard(inner, lambda p: True, lambda: False)   # mounted but nothing configured
    status, body = _drive(guard, [(b"authorization", b"Bearer anything")])
    assert status == 503 and b"disabled" in body and inner_called["hit"] is False


def test_bearer_guard_reflects_rotation_per_request():
    # the same mounted guard picks up a rotated/cleared credential with no remount
    valid = {"v": "first"}
    guard = mcp_server._BearerGuard(_ok_inner(), lambda p: bool(valid["v"]) and p == valid["v"],
                                    lambda: bool(valid["v"]))
    assert _drive(guard, [(b"authorization", b"Bearer first")])[0] == 200
    valid["v"] = "second"                                      # rotated
    assert _drive(guard, [(b"authorization", b"Bearer first")])[0] == 401
    assert _drive(guard, [(b"authorization", b"Bearer second")])[0] == 200
    valid["v"] = ""                                            # cleared -> disabled
    assert _drive(guard, [(b"authorization", b"Bearer second")])[0] == 503


def _ok_inner():
    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    return inner


# --- auth is API-keys-only: /mcp is enabled by an active mcp-scope key, authorized by verifying it -----
def test_mcp_enabled_only_when_an_active_mcp_key_exists(monkeypatch):
    from app.services import api_keys
    monkeypatch.setattr(api_keys, "any_active", lambda scope="mcp": False)
    assert mcp_server.mcp_enabled() is False and mcp_server.token_configured() is False
    monkeypatch.setattr(api_keys, "any_active", lambda scope="mcp": scope == "mcp")
    assert mcp_server.mcp_enabled() is True and mcp_server.token_configured() is True


def test_authorize_mcp_verifies_an_mcp_scope_key(monkeypatch):
    from app.services import api_keys
    seen = {}
    def _verify(presented, scope="mcp"):
        seen["scope"] = scope
        return presented == "good-key"
    monkeypatch.setattr(api_keys, "verify", _verify)
    assert mcp_server.authorize_mcp("good-key") is True and seen["scope"] == "mcp"
    assert mcp_server.authorize_mcp("bad") is False
    assert mcp_server.authorize_mcp("") is False        # empty bearer never authorizes


def test_bearer_guard_rejects_websocket_scope():
    forwarded = {"hit": False}

    async def inner(scope, receive, send):
        forwarded["hit"] = True
    guard = mcp_server._BearerGuard(inner, lambda p: True, lambda: True)
    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "websocket.connect"}
    asyncio.run(guard({"type": "websocket"}, receive, send))
    assert forwarded["hit"] is False                            # never reaches the inner app unauth'd
    assert any(m.get("type") == "websocket.close" for m in sent)


# --- build_mcp_app: mounts whenever the SDK is present (auth decided per request) ----------------
def test_build_mcp_app_mounts_when_sdk_present():
    built = mcp_server.build_mcp_app(verify_fn=lambda p: True, enabled_fn=lambda: True)
    if mcp_server.have_mcp():
        assert built is not None                     # mounted regardless of token; guard gates per request
    else:
        assert built is None                         # SDK absent -> not mounted
    assert set(mcp_server._TOOLS) <= set(dir(mcp_tools))   # every advertised tool exists


def test_mcp_transport_disables_localhost_host_allowlist():
    # FastMCP auto-enables a DNS-rebinding Host allowlist (127.0.0.1:* / localhost:*) for its default
    # localhost host, which 421s every request that arrives through a reverse proxy as Host: <domain>.
    # _new_server must turn that off so the mounted /mcp works behind any proxy (auth is _BearerGuard).
    if not mcp_server.have_mcp():
        import pytest
        pytest.skip("mcp SDK not installed")
    srv = mcp_server._new_server()
    sec = srv.settings.transport_security
    assert sec is not None and sec.enable_dns_rebinding_protection is False


def test_tool_catalog_lists_all_tools_with_summaries():
    cat = mcp_server.tool_catalog()
    names = {c["name"] for c in cat}
    assert names == set(mcp_server._TOOLS)                       # catalog == registered tools
    assert all(c["summary"] for c in cat)                        # every tool has a one-line summary
    assert "summarize_layer" in names and "analyze_policy" in names   # the CP-style analyze tools


def test_tool_catalog_groups_badges_and_blocks():
    # The /mcp-guide catalog view renders groups + read/write badges + structured blocks from this shape.
    cat = mcp_server.tool_catalog()
    assert sum(1 for c in cat if c["group"] == "management") == 21
    assert sum(1 for c in cat if c["group"] == "dynamic") == 8
    writes = {c["name"] for c in cat if c["writes"]}
    assert writes == {"apply_access", "remove_access", "amend_access_rule", "revert_change",
                      "import_dynamic_layer", "add_dynamic_rule", "remove_dynamic_rule",
                      "push_dynamic_layer"}                       # exactly the RBAC-guarded write tools
    assert all(c["brief"] and len(c["brief"]) <= 220 for c in cat)  # collapsed-row teaser: short, present
    assert all(c["blocks"] for c in cat)                          # every docstring parses into blocks
    rc = next(c for c in cat if c["name"] == "revert_change")
    assert any(b["kind"] == "ul" and len(b["items"]) >= 4 for b in rc["blocks"])  # the lifecycle list


def test_doc_blocks_splits_paragraphs_and_bullets():
    doc = """First paragraph line one
    wrapped line two.

    Intro to the list:
      • item one starts here
        and wraps onto this line
      • item two

    Final paragraph."""
    blocks = mcp_server._doc_blocks(doc)
    assert blocks[0] == {"kind": "p", "text": "First paragraph line one wrapped line two."}
    assert blocks[1] == {"kind": "p", "text": "Intro to the list:"}
    assert blocks[2] == {"kind": "ul",
                         "items": ["item one starts here and wraps onto this line", "item two"]}
    assert blocks[3] == {"kind": "p", "text": "Final paragraph."}


# --- generate-and-autofill: the MCP page mints an mcp-scope key and returns its plaintext once ----------
def test_mcp_guide_generate_key_route(monkeypatch):
    import types
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.db import get_db
    from app.routers import ui
    from app.services import api_keys

    monkeypatch.setattr(api_keys, "generate",
                        lambda name, scope, created_by="": (types.SimpleNamespace(name=name, scope=scope),
                                                            "SECRET-" + name))
    app = FastAPI(); app.include_router(ui.router); app.dependency_overrides[get_db] = lambda: None

    monkeypatch.setattr(ui, "get_user_or_none", lambda req, db: None)
    assert TestClient(app).post("/mcp-guide/key").status_code == 401            # auth required

    monkeypatch.setattr(ui, "get_user_or_none", lambda req, db: types.SimpleNamespace(username="admin"))
    r = TestClient(app).post("/mcp-guide/key")
    body = r.json()
    assert r.status_code == 200 and body["scope"] == "mcp" and body["key"].startswith("SECRET-")


# --- /mcp must be reachable WITHOUT a 307 -> /mcp/ redirect (which can drop the Authorization header) ---
def test_mcp_canonical_path_rewrites_bare_mcp():
    from app.main import _MCPCanonicalPath
    seen = {}
    async def inner(scope, receive, send):
        seen["path"] = scope.get("path")
    mw = _MCPCanonicalPath(inner)
    asyncio.run(mw({"type": "http", "path": "/mcp"}, None, None))
    assert seen["path"] == "/mcp/"            # bare /mcp rewritten in-place -> no client redirect
    asyncio.run(mw({"type": "http", "path": "/mcp/"}, None, None))
    assert seen["path"] == "/mcp/"            # already-slashed left as-is
    asyncio.run(mw({"type": "http", "path": "/settings"}, None, None))
    assert seen["path"] == "/settings"        # unrelated paths untouched


# --- Dynamic Layers (Rail B) tools ---------------------------------------------------------------
@pytest.fixture()
def dldb(monkeypatch):
    from app.models import DynamicLayer, Gateway, User
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    monkeypatch.setattr(mcp_tools, "SessionLocal", Session)
    db = Session()
    u = User(username="admin", password_hash="x"); db.add(u); db.commit()
    db.add(DynamicLayer(token="t1", name="DMZ-Layer", layer_name="dynamic_layer", owner_id=u.id,
                        content={"operation": "replace", "objects": {},
                                 "rulebase": [{"name": "cleanup", "action": "Drop",
                                               "source": "any", "destination": "any", "service": "any"}]}))
    db.add(Gateway(token="g1", name="GW1", host="10.1.1.111", port=443, username="admin", owner_id=u.id))
    db.commit(); db.close()
    return Session


def test_list_gateways_and_layers(dldb):
    gws = mcp_tools.list_gateways()["gateways"]
    assert any(g["name"] == "GW1" and g["host"] == "10.1.1.111" for g in gws)
    layers = mcp_tools.list_dynamic_layers()["layers"]
    assert any(L["name"] == "DMZ-Layer" and L["rules"] == 1 for L in layers)


def test_get_dynamic_layer_by_name_and_unknown(dldb):
    out = mcp_tools.get_dynamic_layer("DMZ-Layer")
    assert out["ok"] and out["layer_name"] == "dynamic_layer" and out["rules"][0]["name"] == "cleanup"
    miss = mcp_tools.get_dynamic_layer("nope")
    assert miss["ok"] is False and "DMZ-Layer" in miss["error"]   # error lists what's available


def test_add_dynamic_rule_creates_inline_host(dldb):
    out = mcp_tools.add_dynamic_rule("DMZ-Layer", "10.1.2.50", "10.1.2.60", service="ssh",
                                     action="Accept", name="web-ssh", position="top")
    assert out["ok"] and out["rules"] == 2
    layer = mcp_tools.get_dynamic_layer("DMZ-Layer")
    assert layer["rules"][0]["name"] == "web-ssh"                 # inserted on top
    assert layer["rules"][0]["source"] == ["h-10-1-2-50"]
    assert "hosts" in layer["object_types"]


def test_add_dynamic_rule_rejects_bad_action(dldb):
    out = mcp_tools.add_dynamic_rule("DMZ-Layer", "any", "any", action="Nuke")
    assert out["ok"] is False and "action" in out["error"]


def test_remove_dynamic_rule_guards_last_and_removes(dldb):
    last = mcp_tools.remove_dynamic_rule("DMZ-Layer", "cleanup")
    assert last["ok"] is False and "at least one" in last["error"]
    mcp_tools.add_dynamic_rule("DMZ-Layer", "10.1.2.50", "any", service="https", name="extra")
    out = mcp_tools.remove_dynamic_rule("DMZ-Layer", "extra")
    assert out["ok"] and out["rules"] == 1


def test_push_real_gateway_blocked_when_toggle_off(dldb, monkeypatch):
    monkeypatch.setattr(app_settings, "get", lambda k: False if k == "mcp_allow_layer_push" else None)
    out = mcp_tools.push_dynamic_layer("DMZ-Layer", gateway="GW1", dry_run=False)
    assert out["ok"] is False and out["pushed"] is False and "disabled" in out["error"]


def test_push_mock_runs_and_returns_summary(dldb, monkeypatch):
    from app.services import apply_runner
    monkeypatch.setattr(app_settings, "get", lambda k: None)
    monkeypatch.setattr(apply_runner, "start_apply", lambda **kw: "pid-1")
    monkeypatch.setattr(apply_runner, "get_progress",
                        lambda pid: {"status": "succeeded", "summary": {"rules": 1}, "task_id": "T1"})
    out = mcp_tools.push_dynamic_layer("DMZ-Layer", gateway="mock", dry_run=False)
    assert out["ok"] and out["target"] == "mock" and out["task_id"] == "T1"
    assert out["pushed"] is False           # the built-in demo target is never a real push


def test_push_idempotency_key_replays_real_push(dldb, monkeypatch):
    # A real-gateway push retried with the same key must replay the first result, not push to the GW twice.
    from app.services import apply_runner, gateway_creds, gaia_client, idempotency
    monkeypatch.setattr(idempotency, "SessionLocal", dldb)
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "mcp_allow_layer_push" else None)
    monkeypatch.setattr(gateway_creds, "get_password", lambda db, gw: "pw")
    monkeypatch.setattr(gaia_client, "ensure_pinned", lambda db, gw: None)
    calls = {"n": 0}
    monkeypatch.setattr(apply_runner, "start_apply",
                        lambda **kw: calls.update(n=calls["n"] + 1) or f"pid-{calls['n']}")
    monkeypatch.setattr(apply_runner, "get_progress",
                        lambda pid: {"status": "succeeded", "summary": {"rules": 1}, "task_id": "T1"})
    first = mcp_tools.push_dynamic_layer("DMZ-Layer", gateway="GW1", dry_run=False, idempotency_key="push-7")
    assert first["pushed"] is True and calls["n"] == 1 and "idempotent_replay" not in first
    second = mcp_tools.push_dynamic_layer("DMZ-Layer", gateway="GW1", dry_run=False, idempotency_key="push-7")
    assert second["idempotent_replay"] is True and second["task_id"] == "T1"
    assert calls["n"] == 1                   # the gateway was NOT pushed to a second time


def test_fetch_dynamic_layer_reads_live(dldb, monkeypatch):
    from app.services import apply_runner, gateway_creds, gaia_client
    monkeypatch.setattr(gateway_creds, "get_password", lambda db, gw: "pw")
    monkeypatch.setattr(gaia_client, "ensure_pinned", lambda db, gw: None)
    monkeypatch.setattr(apply_runner, "fetch_dynamic_content", lambda **kw: {"ok": True, "trace": [],
        "error": None, "layers": [{"name": "dynamic_layer", "objects": {"hosts": [{"name": "client"}]},
            "rulebase": [{"name": "allow_web", "action": "Accept", "source": ["client"],
                          "destination": ["lab_net"], "service": ["https"]}], "referenced": ["https"]}]})
    out = mcp_tools.fetch_dynamic_layer("GW1")
    assert out["ok"] and out["gateway"] == "GW1"
    assert out["layers"][0]["name"] == "dynamic_layer"
    assert out["layers"][0]["rules"][0]["name"] == "allow_web"   # reads the LIVE rulebase, not the portal copy
    assert "hosts" in out["layers"][0]["object_types"]


def test_fetch_dynamic_layer_unknown_gateway(dldb):
    out = mcp_tools.fetch_dynamic_layer("nope")
    assert out["ok"] is False and "GW1" in out["error"]   # error lists the available gateways


def test_import_dynamic_layer_creates_portal_copy_of_live(dldb, monkeypatch):
    from app.services import apply_runner, gateway_creds, gaia_client
    monkeypatch.setattr(gateway_creds, "get_password", lambda db, gw: "pw")
    monkeypatch.setattr(gaia_client, "ensure_pinned", lambda db, gw: None)
    monkeypatch.setattr(apply_runner, "fetch_dynamic_content", lambda **kw: {"ok": True, "trace": [], "error": None,
        "layers": [{"name": "dynamic_layer", "objects": {"hosts": [{"name": "client", "ip-address": "10.0.0.5"}]},
            "rulebase": [{"name": "live_rule", "action": "Accept", "source": ["client"],
                          "destination": "any", "service": "any"}], "referenced": []}]})
    out = mcp_tools.import_dynamic_layer("GW1")
    assert out["ok"] and out["created"] is True and out["rules"] == 1
    # the portal now has a layer mirroring the live gateway — so a later add+push won't wipe live rules
    got = mcp_tools.get_dynamic_layer(str(out["layer_id"]))
    assert got["ok"] and got["rules"][0]["name"] == "live_rule"


def _server_db(*names):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    for n in names:
        db.add(ManagementServer(name=n, host=n.lower() + ".lab", port=443, username="admin", owner_id=1))
    db.commit()
    return db


def test_resolve_server_single_falls_back_for_placeholder():
    # The agent invents "localhost" when the user names no server; with exactly one configured there's no
    # ambiguity, so resolve to it instead of erroring (the "who said localhost?" fix).
    db = _server_db("SMS")
    assert mcp_tools._resolve_server(db, "localhost").name == "SMS"
    assert mcp_tools._resolve_server(db, "").name == "SMS"
    assert mcp_tools._resolve_server(db, 1).name == "SMS"          # exact id still works
    db.close()


def test_resolve_server_stale_numeric_id_still_errors():
    # A NON-existent numeric id must NOT silently retarget the single server (stale-id misroute guard).
    db = _server_db("SMS")
    with pytest.raises(ValueError):
        mcp_tools._resolve_server(db, 5)
    db.close()


def test_resolve_server_multiple_servers_still_asks():
    # With more than one server a placeholder is genuinely ambiguous -> error that lists the choices.
    db = _server_db("SMS", "SMS2")
    with pytest.raises(ValueError):
        mcp_tools._resolve_server(db, "localhost")
    db.close()


def test_apply_access_carries_usercheck_fields_into_the_request():
    # The MCP apply_access / decide_access params must flow through _build -> build_request -> the exact
    # web_api user-check + action-settings payload (regression: "are the new fields confirmed over MCP?").
    from app.services import mcp_tools, access_automation as aa
    req = mcp_tools._build("Finance_Users", "Any", None, "443", "tcp", "Facebook",
                           source_kind="access-role", destination_kind="internet", action="Inform",
                           user_check="Company Policy", user_check_frequency="once a day",
                           user_check_confirm="per application/site", action_limit="Upload_10Mbps",
                           time_objects=["Work-Hours"])
    assert req.src_kind == "access-role" and req.src_value == "Finance_Users"
    assert aa._user_check_payload("Inform", req) == {
        "interaction": "Company Policy", "frequency": "once a day", "confirm": "per application/site"}
    assert aa._action_settings_payload("Inform", req) == {"limit": "Upload_10Mbps"}
    # custom-frequency over MCP
    r2 = mcp_tools._build("10.1.1.0/24", "Any", None, "443", "tcp", None, action="Ask",
                          user_check="Ask", user_check_frequency="custom frequency...",
                          user_check_custom_every=6, user_check_custom_unit="hours")
    assert aa._user_check_payload("Ask", r2)["custom-frequency"] == {"every": 6, "unit": "hours"}


# --- revert_change lifecycle (parity with the portal change panel: one shared state machine) --------
def _lifecycle_env(monkeypatch, result=None):
    """Gate open + creds stubbed + revert_execute stubbed (records ops; returns ``result`` or success)."""
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "mcp_allow_publish" else None)
    monkeypatch.setattr(mgmt_creds, "get_secret", lambda db, ms: "secret")
    monkeypatch.setattr(gaia_client, "ensure_pinned", lambda db, ms: None)
    seen = {}
    monkeypatch.setattr(aa, "revert_execute",
                        lambda srv, sec, ops, publish=False, disable_added_rules=False:
                        seen.update(ops=ops, publish=publish, disable=disable_added_rules)
                        or (result or {"ok": True, "reverted": publish}))
    return seen


def test_revert_disable_undo_lands_in_the_actionable_disabled_state(monkeypatch, cdb):
    # An added rule rolled back via DISABLE must stay actionable (NOT terminal) — exactly like the panel —
    # so it can later be finalized (delete_rule) or turned back on (reenable). Regression: the MCP path used
    # to stamp it terminal "reverted", stranding the rule half-rolled-back with no agent-side finalize.
    seen = _lifecycle_env(monkeypatch)
    cid = _seed_change(cdb)
    out = mcp_tools.revert_change(cid, publish=True, disable_instead_of_delete=True)
    assert out["ok"] and seen["disable"] is True
    assert out["state"] == "disabled"
    with cdb() as s:
        row = s.get(AppliedChange, cid)
        assert row.resolution == "disabled" and row.reverted_at is None
    lst = mcp_tools.list_changes()
    assert any(c["id"] == cid and c["state"] == "disabled" for c in lst["changes"])


def test_revert_finalize_deletes_the_disabled_rule(monkeypatch, cdb):
    seen = _lifecycle_env(monkeypatch)
    cid = _seed_change(cdb)
    mcp_tools.revert_change(cid, publish=True, disable_instead_of_delete=True)   # active -> disabled
    out = mcp_tools.revert_change(cid, publish=True, delete_rule=True)           # disabled -> deleted
    assert out["ok"] and out["state"] == "resolved"
    assert seen["ops"] == [{"op": "delete-access-rule", "uid": "u9", "layer": "Network"}]
    with cdb() as s:
        row = s.get(AppliedChange, cid)
        assert row.resolution == "deleted" and row.reverted_at is not None


def test_revert_reenable_restores_an_added_rule_to_active(monkeypatch, cdb):
    seen = _lifecycle_env(monkeypatch)
    cid = _seed_change(cdb)
    mcp_tools.revert_change(cid, publish=True, disable_instead_of_delete=True)   # active -> disabled
    out = mcp_tools.revert_change(cid, publish=True, reenable=True)              # disabled -> active again
    assert out["ok"] and out["state"] == "active"
    assert seen["ops"] == [{"op": "set-access-rule", "uid": "u9", "layer": "Network", "enabled": True}]
    out2 = mcp_tools.revert_change(cid, publish=True)                            # rollable again
    assert out2["ok"] and out2["state"] == "resolved"


def test_revert_lifecycle_guards_teach_the_right_next_call(monkeypatch, cdb):
    _lifecycle_env(monkeypatch)
    cid = _seed_change(cdb)
    out = mcp_tools.revert_change(cid, publish=True, delete_rule=True)   # finalize an ACTIVE change
    assert out["ok"] is False and "disabled" in out["error"].lower()
    mcp_tools.revert_change(cid, publish=True, disable_instead_of_delete=True)
    out = mcp_tools.revert_change(cid, publish=True)                     # plain undo on a DISABLED entry
    assert out["ok"] is False and "delete_rule" in out["error"] and "reenable" in out["error"]
    out = mcp_tools.revert_change(cid, publish=True, delete_rule=True, reenable=True)
    assert out["ok"] is False and "ONE action" in out["error"]


def test_revert_claim_is_released_when_the_sms_fails(monkeypatch, cdb):
    # Claim-first + restore-on-failure: an SMS failure must leave the entry ACTIVE (retryable) with the
    # error stamped — never falsely resolved.
    _lifecycle_env(monkeypatch, result={"ok": False, "error": "lock conflict"})
    cid = _seed_change(cdb)
    out = mcp_tools.revert_change(cid, publish=True)
    assert out["ok"] is False and out["state"] == "active"
    with cdb() as s:
        row = s.get(AppliedChange, cid)
        assert row.reverted_at is None and (row.resolution or "") == ""
        assert "lock conflict" in (row.revert_error or "")
    again = mcp_tools.revert_change(cid, publish=True)                   # still retryable... but SMS still down
    assert again["ok"] is False and again["state"] == "active"
