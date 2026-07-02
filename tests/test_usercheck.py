"""Correlate a UserCheck phrase to a real Check Point UserCheck interaction object. The engine queries
show-objects by NAME and keeps anything whose type starts with 'user-check' (a block message is
type 'user-check-drop', per a live R82 rule; Ask/Inform have their own user-check-* types)."""
import types

from app.services import usercheck as uc


class FakeSession:
    """show-objects returns name-substring matches of ANY type (no type filter) — usercheck._query keeps
    only the user-check* ones client-side, exactly like the real call."""
    def __init__(self, objs):
        self.objs = objs
        self.server = types.SimpleNamespace(host="h", port=443, domain="")

    def call(self, cmd, payload=None, **k):
        if cmd != "show-objects":
            return {}
        flt = (payload or {}).get("filter", "").lower()
        return {"objects": [o for o in self.objs if flt in o.get("name", "").lower()]}


_OBJS = [
    {"name": "Blocked Message - Access Control", "uid": "u1", "type": "user-check-drop"},
    {"name": "Company Policy", "uid": "u2", "type": "user-check-ask"},
    {"name": "Access Notification", "uid": "u3", "type": "user-check-inform"},
    {"name": "win_server", "uid": "h1", "type": "host"},   # NOT a UserCheck object — must be filtered out
]


def test_resolve_exact_usercheck_object():
    r = uc.resolve(FakeSession(_OBJS), "Company Policy")
    assert r["match"] == "Company Policy" and r["match_kind"] == "ask" and r["confidence"] == "exact"


def test_resolve_block_message_from_the_real_rule_shape():
    r = uc.resolve(FakeSession(_OBJS), "Blocked Message - Access Control")
    assert r["match"] == "Blocked Message - Access Control" and r["match_kind"] == "drop"


def test_resolve_keeps_only_user_check_types():
    # a name that matches a non-UserCheck object (a host) yields no UserCheck candidate
    r = uc.resolve(FakeSession(_OBJS), "win_server")
    assert r["match"] is None and not r["candidates"] and r["note"]


def test_search_type_ahead_returns_usercheck_candidates():
    cands = uc.search(FakeSession(_OBJS), "message")
    assert any(c["name"] == "Blocked Message - Access Control" for c in cands)
    assert all("host" != c.get("kind") for c in cands)   # host filtered out


def test_mcp_correlate_user_check_delegates(monkeypatch):
    from app.services import mcp_tools
    monkeypatch.setattr(mcp_tools, "_server_secret",
                        lambda db, sid: (types.SimpleNamespace(id=sid, host="h"), "secret"))

    class _RS:
        def __enter__(self): return FakeSession(_OBJS)
        def __exit__(self, *a): return False
    monkeypatch.setattr("app.services.mgmt_api.read_session", lambda ms, secret: _RS())
    assert mcp_tools.correlate_user_check(1, "Company Policy")["match"] == "Company Policy"
    monkeypatch.setattr(mcp_tools, "_server_secret",
                        lambda db, sid: (_ for _ in ()).throw(ValueError("no such server")))
    assert "error" in mcp_tools.correlate_user_check(9, "Company Policy")
