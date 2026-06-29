"""Post-deploy conformance self-check — prove the agent surface is correctly wired and SAFE without
touching a live SMS / gateway or mutating any policy.

The first thing to run after a deploy: ``python -m app.conformance`` (prints a checklist, exits non-zero on
failure) or ``GET /dbapi/v1/conformance`` (api-scope key). Every check is read-only / in-process — it never
logs in to a management server, never pushes to a gateway, and never writes policy. It answers "is this
deployment wired correctly and safe by default?", complementing /version (build + tool count) and /readyz
(DB readiness).

Required checks must pass for ``ok``; informational checks (MCP SDK present, gate states) are reported but
never fail the run — an admin may legitimately have a gate enabled, and /mcp is dormant-by-design until the
SDK is installed."""
from __future__ import annotations

from . import app_settings, authz, mcp_tools

# State-changing tools that must carry the read-only RBAC guard (functools.wraps leaves __wrapped__).
_WRITE_TOOLS = ("apply_access", "remove_access", "amend_access_rule", "revert_change",
                "add_dynamic_rule", "remove_dynamic_rule", "import_dynamic_layer", "push_dynamic_layer")


def _check(name: str, ok: bool, detail: str = "", required: bool = True) -> dict:
    return {"name": name, "ok": bool(ok), "required": required, "detail": detail}


def run() -> dict:
    """Run every check once. Returns ``{"ok", "tools", "checks": [...]}``; ``ok`` is the AND of the required
    checks only."""
    from .. import mcp_server
    checks = []

    # 1) Every tool is registered with a one-line summary, and the count matches the declared surface.
    cat = mcp_server.tool_catalog()
    names = {c["name"] for c in cat}
    missing = [n for n in mcp_server._TOOLS if n not in names]
    no_summary = [c["name"] for c in cat if not c["summary"]]
    tools_ok = not missing and not no_summary and len(cat) == len(mcp_server._TOOLS)
    detail = f"{len(cat)} tools"
    if missing:
        detail += f"; missing {missing}"
    if no_summary:
        detail += f"; no summary {no_summary}"
    checks.append(_check("tools_registered", tools_ok, detail))

    # 2) Every write tool carries the read-only RBAC guard.
    unguarded = [n for n in _WRITE_TOOLS if not hasattr(getattr(mcp_tools, n, None), "__wrapped__")]
    checks.append(_check("write_tools_rbac_guarded", not unguarded,
                         "all 8 write tools wrapped" if not unguarded else f"unguarded: {unguarded}"))

    # 3) A read-only capability actually refuses a write — exercised in-process, refused before any DB/SMS.
    tok = authz.set_can_write(False)
    try:
        r = mcp_tools.apply_access(0, "10.0.0.1", "Any", "Network", port="443")
    finally:
        authz.reset_can_write(tok)
    refused = isinstance(r, dict) and not r.get("ok") and "read-only" in (r.get("error") or "")
    checks.append(_check("readonly_capability_enforced", refused,
                         "read-only key refused a write" if refused else f"unexpected: {r}"))

    # 4) The DB is reachable (a trivial read).
    try:
        mcp_tools.list_management_servers()
        db_ok, db_detail = True, "db read ok"
    except Exception as exc:  # noqa: BLE001
        db_ok, db_detail = False, f"{type(exc).__name__}: {exc}"
    checks.append(_check("db_reachable", db_ok, db_detail))

    # 5) Publish/push gates — informational (default-closed is safest, but an admin may enable a rail).
    try:
        pub = bool(app_settings.get("mcp_allow_publish"))
        push = bool(app_settings.get("mcp_allow_layer_push"))
        gate_detail = f"mcp_allow_publish={pub}, mcp_allow_layer_push={push}"
        gate_ok = True
    except Exception as exc:  # noqa: BLE001
        gate_detail, gate_ok = f"could not read gates: {exc}", False
    checks.append(_check("publish_gates_readable", gate_ok, gate_detail, required=False))

    # 6) MCP SDK presence — informational (/mcp is dormant-by-design until the SDK ships via Artifactory).
    have = mcp_server.have_mcp()
    checks.append(_check("mcp_sdk_present", have,
                         "mcp SDK importable" if have else "mcp SDK not installed — /mcp dormant (REST still works)",
                         required=False))

    ok = all(c["ok"] for c in checks if c["required"])
    return {"ok": ok, "tools": len(cat), "checks": checks}


def main() -> int:
    """CLI: print the checklist; exit 0 if all required checks pass, else 1."""
    from ..db import init_db
    init_db()
    report = run()
    print(f"PolicyPilot conformance — {report['tools']} tools — "
          f"{'PASS' if report['ok'] else 'FAIL'}\n")
    for c in report["checks"]:
        mark = "ok " if c["ok"] else ("ERR" if c["required"] else "—  ")
        tag = "" if c["required"] else " (info)"
        print(f"  [{mark}] {c['name']}{tag}: {c['detail']}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
