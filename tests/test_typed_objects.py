"""Cached server-side search/recommendations for the typed (non-IP) source/destination objects —
mirrors the applications/services model (one filtered show-objects, cached, ranked locally)."""
import types

from app.services import access_automation as aa
from app.services import typed_objects as to


class FakeSession:
    """Simulates a read session: show-objects filters by type + a name substring (like the server's
    indexed filter), and counts calls so the cache can be observed."""
    def __init__(self, objs):
        self.objs = objs
        self.calls = 0
        self.server = types.SimpleNamespace(host="h", port=443, domain="")

    def call(self, cmd, payload=None, **k):
        if cmd != "show-objects":
            return {}
        self.calls += 1
        p = payload or {}
        typ, flt = p.get("type"), (p.get("filter") or "").lower()
        objs = [o for o in self.objs
                if o.get("type") == typ and flt in (o.get("name", "").lower())]
        return {"objects": objs}


def _roles_and_domains():
    return FakeSession([
        {"name": "Finance_Users", "uid": "r1", "type": "access-role"},
        {"name": "HR_Users", "uid": "r2", "type": "access-role"},
        {"name": ".example.com", "uid": "d1", "type": "dns-domain", "is-sub-domain": True},
        {"name": ".exact.com", "uid": "d2", "type": "dns-domain", "is-sub-domain": False},
        {"name": "Office365 Services", "uid": "u1", "type": "updatable-object"},
    ])


def test_search_returns_typed_candidates_filtered_by_kind():
    s = _roles_and_domains()
    roles = to.search(s, "access-role", "users")
    assert {c["name"] for c in roles} == {"Finance_Users", "HR_Users"}
    assert all(c["kind"] == "access-role" for c in roles)
    # a different kind on the same term doesn't bleed across object types
    assert to.search(s, "updatable-object", "office") == [
        {"name": "Office365 Services", "uid": "u1", "kind": "updatable-object", "category": "updatable-object"}]


def test_search_empty_for_short_term_or_unsupported_kind():
    s = _roles_and_domains()
    assert to.search(s, "access-role", "a") == []        # < 2 chars
    assert to.search(s, "bogus-kind", "users") == []      # not a typed kind
    assert to.search(s, "ip", "10.0.0.1") == []           # ip is not a typed-object search


def test_search_caches_per_server_kind_term():
    s = _roles_and_domains()
    to.search(s, "access-role", "users")
    n = s.calls
    to.search(s, "access-role", "users")                  # identical -> served from cache
    assert s.calls == n
    to.search(s, "access-role", "finance")                # different term -> a fresh query
    assert s.calls == n + 1


def test_domain_candidate_name_reflects_is_sub_domain():
    s = _roles_and_domains()
    res = {c["name"]: c for c in to.search(s, "domain", "exa")}
    # a sub-domain object -> the request-form value keeps the leading dot; an exact object drops it
    assert res[".example.com"]["category"] == "domain + sub-domains"
    assert "exact.com" in res and res["exact.com"]["category"] == "exact domain"
    assert ".exact.com" not in res                          # exact object never offered with a leading dot


def test_suggest_ranks_closest_first():
    s = FakeSession([
        {"name": "HR-Users", "uid": "r1", "type": "access-role"},
        {"name": "HR-Admins", "uid": "r2", "type": "access-role"},
    ])
    sug = to.suggest(s, "access-role", "HR_Users")
    assert sug and sug[0]["name"] == "HR-Users"            # normalized-exact beats the weaker match


def test_supported_kinds_match_engine_typed_kinds():
    # adding/removing a typed kind in the engine must be reflected here (keeps the form in lock-step)
    assert set(to._KIND_TYPE) == set(aa.TYPED_KINDS)
    assert all(to.supported_kind(k) for k in aa.TYPED_KINDS)
    assert not to.supported_kind("ip")


def test_typed_object_preview_recommends_for_missing_reuse_only():
    # a missing access-role (reuse-only) -> preview carries 'did you mean' candidates from suggest()
    s = FakeSession([{"name": "Finance_Users", "uid": "r1", "type": "access-role"}])
    prev = aa.typed_object_preview(s, "access-role", "Finance Users")
    assert prev["exists"] is False and prev["creatable"] is False
    assert any(c["name"] == "Finance_Users" for c in prev.get("candidates", []))
    # a creatable domain that's missing just gets created -> no candidates noise
    prev_dom = aa.typed_object_preview(s, "domain", "newsite.com")
    assert prev_dom["creatable"] is True and "candidates" not in prev_dom


def test_resolve_auto_matches_a_unique_exact_access_role():
    s = _roles_and_domains()
    r = to.resolve(s, "access-role", "Finance_Users")
    assert r["match"] == "Finance_Users" and r["confidence"] == "exact" and r["match_kind"] == "access-role"


def test_resolve_no_auto_match_when_not_a_unique_exact():
    # "Finance" matches Finance_Users as a substring but is NOT a unique exact -> no silent pick
    s = FakeSession([{"name": "Finance_Users", "uid": "r1", "type": "access-role"},
                     {"name": "Finance_Admins", "uid": "r2", "type": "access-role"}])
    r = to.resolve(s, "access-role", "Finance")
    assert r["match"] is None and r["note"]


def test_resolve_zone_and_no_match_note():
    s = FakeSession([{"name": "DMZ", "uid": "z1", "type": "security-zone"}])
    assert to.resolve(s, "security-zone", "DMZ")["match"] == "DMZ"
    miss = to.resolve(s, "security-zone", "Nonexistent")
    assert miss["match"] is None and miss["note"]


def test_resolve_query_type_matches_the_apply_side_lookup():
    # DRIFT GUARD: correlate must query the SAME object type the apply path (lookup_typed_object) resolves,
    # else a discovered name could fail to apply. _KIND_TYPE value == _TYPED_OBJ[kind]["type"].
    for kind, cp_type in to._KIND_TYPE.items():
        assert cp_type == aa._TYPED_OBJ[kind]["type"], kind


def test_mcp_correlate_access_role_and_zone_delegate(monkeypatch):
    from app.services import mcp_tools
    monkeypatch.setattr(mcp_tools, "_server_secret",
                        lambda db, sid: (types.SimpleNamespace(id=sid, host="h"), "secret"))

    class _RS:
        def __enter__(self): return FakeSession([
            {"name": "Finance_Users", "uid": "r1", "type": "access-role"},
            {"name": "DMZ", "uid": "z1", "type": "security-zone"}])
        def __exit__(self, *a): return False
    monkeypatch.setattr("app.services.mgmt_api.read_session", lambda ms, secret: _RS())
    assert mcp_tools.correlate_access_role(1, "Finance_Users")["match"] == "Finance_Users"
    assert mcp_tools.correlate_zone(1, "DMZ")["match"] == "DMZ"
    monkeypatch.setattr(mcp_tools, "_server_secret",
                        lambda db, sid: (_ for _ in ()).throw(ValueError("no such server")))
    assert "error" in mcp_tools.correlate_access_role(9, "Finance_Users")
