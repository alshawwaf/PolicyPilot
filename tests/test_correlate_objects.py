"""Correlate a time / data-type (content) / limit NAME to the real Check Point object — auto-use only a
confident unique match over a COMPLETE page; ambiguous/truncated -> candidates; the queried classes match
the apply-side validator (access_automation._resolve_named_objects) so a match always applies cleanly."""
import types

from app.services import correlate_objects as co


def _obj(name, typ, uid=None):
    return {"name": name, "uid": uid or name, "type": typ}


class _Sess:
    """show-objects returns `objs` (PRE-filter, honoring the limit — my module filters by type); show-limits
    pages `limits`. `total` simulates a server-side count beyond the returned page (truncation)."""
    def __init__(self, objs=None, limits=None, total=None):
        self._objs = objs or []
        self._limits = limits
        self._total = total
        self.server = types.SimpleNamespace(host="h", port=443, domain="")

    def call(self, cmd, payload=None):
        if cmd == "show-objects":
            lim = (payload or {}).get("limit", 50)
            r = {"objects": self._objs[:lim]}
            if self._total is not None:
                r["total"] = self._total
            return r
        if cmd == "show-limits":
            off, lim = (payload or {}).get("offset", 0), (payload or {}).get("limit", 200)
            items = (self._limits or [])[off:off + lim]
            return {"objects": items, "total": len(self._limits or [])}
        return {"objects": []}


def test_discovery_classes_match_the_apply_side_validator():
    # A name the correlators auto-match MUST validate + apply cleanly — so the queried object classes have to
    # stay identical to what access_automation._resolve_named_objects accepts. Guard against silent drift.
    from app.services import access_automation as aa
    assert set(co._TIME_TYPES) == set(aa._TIME_TYPES)
    assert set(co._CONTENT_TYPES) == set(aa._CONTENT_DT_TYPES)
    assert aa._LIST_CMDS_LIMIT == ("show-limits",)      # limit resolver enumerates the same command


def test_resolve_time_exact_match():
    co._cache.clear()
    s = _Sess(objs=[_obj("Work-Hours", "time"), _obj("Off-Hours", "time")])
    r = co.resolve_time(s, "Work-Hours")
    assert r["match"] == "Work-Hours" and r["confidence"] == "exact"


def test_resolve_time_ignores_non_time_types():
    # a host that happens to match the filter term must NOT be offered as a time object (wrong-class guard)
    s = _Sess(objs=[_obj("Work-Hours", "host")])
    r = co.resolve_time(s, "Work-Hours")
    assert r["match"] is None and r["candidates"] == []


def test_resolve_content_exact_and_ambiguous():
    s = _Sess(objs=[_obj("SQL Queries", "data-type-patterns"), _obj("SQL Injection", "data-type-patterns")])
    assert co.resolve_content(s, "SQL Queries")["match"] == "SQL Queries"
    amb = _Sess(objs=[_obj("SQL Queries", "data-type-patterns"), _obj("SQL-Queries", "data-type-keywords")])
    r = co.resolve_content(amb, "sqlqueries")           # both normalize alike -> ambiguous, no auto-match
    assert r["match"] is None and len(r["candidates"]) >= 2 and r["note"]


def test_resolve_time_truncated_never_auto_matches():
    # a full page (len == limit) with a larger server total -> truncated -> never auto-match, even a lone
    # exact (a duplicate could hide past the cutoff = a wrong object = a wrong rule).
    objs = [_obj(f"T{i}", "time") for i in range(co._RESOLVE_LIMIT)]
    s = _Sess(objs=objs, total=co._RESOLVE_LIMIT + 1)
    r = co.resolve_time(s, "T0")
    assert r["match"] is None and "refine" in r["note"].lower()


def test_resolve_limit_via_show_limits():
    r = co.resolve_limit(_Sess(limits=[_obj("Upload_10Mbps", "limit"), _obj("Download_50Mbps", "limit")]),
                         "Upload_10Mbps")
    assert r["match"] == "Upload_10Mbps" and r["match_kind"] == "limit"


def test_resolve_limit_ambiguous_returns_candidates():
    r = co.resolve_limit(_Sess(limits=[_obj("Upload_10", "limit"), _obj("Upload-10", "limit")]), "upload10")
    assert r["match"] is None and len(r["candidates"]) >= 2


def test_resolve_limit_command_unavailable_is_a_clean_note_not_a_guess():
    class _NoLimits:
        server = types.SimpleNamespace(host="h", port=443, domain="")
        def call(self, cmd, payload=None):
            raise RuntimeError("show-limits not available on this version")
    r = co.resolve_limit(_NoLimits(), "Upload_10Mbps")
    assert r["match"] is None and "show-limits" in r["note"]


def test_mcp_correlate_tools_delegate_after_resolving_server(monkeypatch):
    # the MCP tool resolves the server, then delegates to correlate_objects — mirror of correlate_service.
    from app.services import mcp_tools, correlate_objects
    monkeypatch.setattr(mcp_tools, "_server_secret",
                        lambda db, sid: (types.SimpleNamespace(id=sid, host="h"), "secret"))

    class _RS:
        def __enter__(self): return _Sess(objs=[_obj("Work-Hours", "time")],
                                          limits=[_obj("Upload_10Mbps", "limit")])
        def __exit__(self, *a): return False
    monkeypatch.setattr("app.services.mgmt_api.read_session", lambda ms, secret: _RS())
    assert mcp_tools.correlate_time(1, "Work-Hours")["match"] == "Work-Hours"
    assert mcp_tools.correlate_limit(1, "Upload_10Mbps")["match"] == "Upload_10Mbps"
    # a bad server_id surfaces the resolver error, never a crash
    monkeypatch.setattr(mcp_tools, "_server_secret",
                        lambda db, sid: (_ for _ in ()).throw(ValueError("no such server")))
    assert "error" in mcp_tools.correlate_content(999, "SQL Queries")


class _CmdSess:
    """Responds to the dedicated list commands (show-gateways-and-servers / show-vpn-communities-*) that the
    gateway/VPN resolvers enumerate through access_automation._known_object_names."""
    def __init__(self, by_cmd):
        self._c = by_cmd
        self.server = types.SimpleNamespace(host="h", port=443, domain="")

    def call(self, cmd, payload=None):
        items = self._c.get(cmd, [])
        return {"objects": items, "total": len(items)}


def test_resolve_gateway_unique_exact_and_ambiguous():
    s = _CmdSess({"show-gateways-and-servers": [_obj("GW1", "simple-gateway"), _obj("GW2", "simple-gateway")]})
    assert co.resolve_gateway(s, "GW1")["match"] == "GW1"
    amb = _CmdSess({"show-gateways-and-servers": [_obj("Perimeter-A", "simple-gateway"),
                                                  _obj("Perimeter-B", "simple-gateway")]})
    r = co.resolve_gateway(amb, "Perimeter")
    assert r["match"] is None and len(r["candidates"]) == 2 and r["note"]


def test_resolve_vpn_matches_enumerated_and_the_all_gwtogw_literal():
    s = _CmdSess({"show-vpn-communities-star": [_obj("Site2Site", "vpn-community-star")]})
    assert co.resolve_vpn(s, "Site2Site")["match"] == "Site2Site"
    # the built-in All_GwToGw is matchable even though it isn't returned by the community list commands
    assert co.resolve_vpn(s, "All_GwToGw")["match"] == "All_GwToGw"


def test_search_server_dispatches_gateway_and_vpn(monkeypatch):
    # the form's field-search endpoint routes kind=gateway/vpn through search_server
    s = _CmdSess({"show-gateways-and-servers": [_obj("GW1", "simple-gateway")]})

    class _RS:
        def __enter__(self): return s
        def __exit__(self, *a): return False
    monkeypatch.setattr("app.services.mgmt_api.read_session", lambda ms, secret: _RS())
    cands = co.search_server(object(), "secret", "GW", "gateway")
    assert any(c["name"] == "GW1" for c in cands)


def test_search_server_browses_time_and_content_on_empty_term(monkeypatch):
    # focus (empty term) -> the first page of that object kind (type-filtered), so the menu shows options
    # BEFORE anything is typed. A non-matching type (host) is still excluded.
    s = _Sess(objs=[_obj("Work-Hours", "time"), _obj("Off-Hours", "time"),
                    _obj("SQL Queries", "data-type-patterns"), _obj("win_server", "host")])

    class _RS:
        def __enter__(self): return s
        def __exit__(self, *a): return False
    monkeypatch.setattr("app.services.mgmt_api.read_session", lambda ms, secret: _RS())
    assert {c["name"] for c in co.search_server(object(), "sec", "", "time")} == {"Work-Hours", "Off-Hours"}
    assert [c["name"] for c in co.search_server(object(), "sec", "", "content")] == ["SQL Queries"]


def test_search_server_browses_limit_gateway_vpn_on_empty_term(monkeypatch):
    s = _CmdSess({"show-limits": [_obj("Upload_10Mbps", "limit"), _obj("Download_50Mbps", "limit")],
                  "show-gateways-and-servers": [_obj("perimeter-gw", "simple-gateway"),
                                                _obj("dmz-cluster", "simple-cluster")],
                  "show-vpn-communities-star": [_obj("Site2Site", "vpn-community-star")]})

    class _RS:
        def __enter__(self): return s
        def __exit__(self, *a): return False
    monkeypatch.setattr("app.services.mgmt_api.read_session", lambda ms, secret: _RS())
    assert {c["name"] for c in co.search_server(object(), "sec", "", "limit")} == {"Upload_10Mbps", "Download_50Mbps"}
    assert {c["name"] for c in co.search_server(object(), "sec", "", "gateway")} == {"perimeter-gw", "dmz-cluster"}
    # VPN browse includes the built-in All_GwToGw literal alongside the enumerated communities
    assert {c["name"] for c in co.search_server(object(), "sec", "", "vpn")} == {"Site2Site", "All_GwToGw"}
