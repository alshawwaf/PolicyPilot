"""Needs-reinstall detection (services.changed_policies) + the MCP tool.

Pure evaluate_package logic over plain dicts (no SMS), the scan aggregation over a fake session, and the
packages_needing_install MCP wrapper's error handling.
"""
import types

from app.services import changed_policies as cp


def _date(days_ago):
    import datetime as dt
    when = dt.datetime(2026, 7, 10, 12, 0, 0) - dt.timedelta(days=days_ago)
    return {"posix": int(when.timestamp() * 1000)}


def _pkg(name, modify_days_ago, uid="p1"):
    return {"name": name, "uid": uid, "meta-info": {"last-modify-time": _date(modify_days_ago)}}


def _gw(name, policy_name, *, installed=True, install_days_ago=1):
    return {"name": name, "uid": "g-" + name,
            "policy": {"access-policy-name": policy_name,
                       "access-policy-installed": installed,
                       "access-policy-installation-date": _date(install_days_ago)}}


def test_up_to_date_when_installed_after_last_change():
    # Package changed 5 days ago, installed 1 day ago (after) → up to date.
    pkg = _pkg("Standard", modify_days_ago=5)
    out = cp.evaluate_package(pkg, [_gw("gw1", "Standard", install_days_ago=1)])
    assert out["needs_install"] is False and out["reason"] == "up to date"


def test_stale_when_changed_after_install():
    # Changed 1 day ago, last installed 10 days ago → needs reinstall.
    pkg = _pkg("Standard", modify_days_ago=1)
    out = cp.evaluate_package(pkg, [_gw("gw1", "Standard", install_days_ago=10)])
    assert out["needs_install"] is True and "changed since" in out["reason"]
    assert out["targets"][0]["stale"] is True


def test_never_installed_target():
    pkg = _pkg("Standard", modify_days_ago=5)
    out = cp.evaluate_package(pkg, [_gw("gw1", "Standard", installed=False)])
    assert out["needs_install"] is True and "not yet installed" in out["reason"]


def test_unassigned_package_is_not_flagged():
    pkg = _pkg("Unused", modify_days_ago=1)
    out = cp.evaluate_package(pkg, [_gw("gw1", "Standard", install_days_ago=10)])
    assert out["needs_install"] is False and out["reason"] == "not assigned to any gateway"
    assert out["targets"] == []


def test_multi_target_one_stale_flags_package():
    pkg = _pkg("Standard", modify_days_ago=3)
    gws = [_gw("fresh", "Standard", install_days_ago=1), _gw("old", "Standard", install_days_ago=30)]
    out = cp.evaluate_package(pkg, gws)
    assert out["needs_install"] is True
    assert [t["stale"] for t in out["targets"]] == [False, True]


# --- scan aggregation over a fake session ----------------------------------------------------

class _FakeSession:
    def __init__(self, packages, gateways):
        self._packages = packages
        self._gateways = gateways
        self.trace = []

    def call_paged(self, command, key="objects", **k):
        if command == "show-packages":
            return self._packages
        if command == "show-gateways-and-servers":
            return self._gateways
        return []


def test_scan_orders_stale_first_and_summarizes():
    packages = [_pkg("Clean", modify_days_ago=9, uid="c"), _pkg("Stale", modify_days_ago=1, uid="s")]
    gws = [_gw("gw-clean", "Clean", install_days_ago=2), _gw("gw-stale", "Stale", install_days_ago=8)]
    out = cp._scan(_FakeSession(packages, gws))
    assert out["summary"]["needs_install"] == 1 and out["summary"]["names"] == ["Stale"]
    assert out["packages"][0]["name"] == "Stale"           # stale sorted first
    assert out["packages"][0]["needs_install"] and not out["packages"][1]["needs_install"]


# --- MCP tool wrapper -------------------------------------------------------------------------

def test_mcp_tool_unknown_server_is_clean_error(monkeypatch):
    from app.services import mcp_tools
    resp = mcp_tools.packages_needing_install("no-such-server-xyz")
    assert "error" in resp and resp.get("ok") is not True


def test_mcp_tool_registered():
    from app import mcp_server
    assert "packages_needing_install" in mcp_server._TOOLS
    names = {c["name"] for c in mcp_server.tool_catalog()}
    assert "packages_needing_install" in names
