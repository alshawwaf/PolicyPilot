"""Which policy packages need to be (re)installed — the "needs reinstall" signal.

A read-only check inspired by Check Point's open-source ChangedPolicies tool: after you publish, the SMS
database is ahead of what's actually enforcing on the gateways until you *install policy*. This answers
"which packages are published-but-not-installed (or changed since their last install)?" so the portal can
badge a stale package and an agent can ask for the list.

Rather than diffing revisions with ``show-changes`` + ``where-used`` (fragile across versions, and it only
covers one session), we compare each package's **last-modify-time** against the **install date** on the
gateways currently running it — the same install-freshness logic PolicyCleanUp uses (``is_installation_
updated``). It directly answers "needs reinstall" and needs only two documented reads:
``show-packages`` and ``show-gateways-and-servers``.
"""
from __future__ import annotations

import datetime as dt
from typing import Optional

from . import mgmt_api


def _posix_dt(date_object) -> Optional[dt.datetime]:
    """A Check Point date reply ({'posix': <ms>}) → naive datetime, or None."""
    if not isinstance(date_object, dict):
        return None
    posix = date_object.get("posix")
    if posix in (None, ""):
        return None
    try:
        return dt.datetime.fromtimestamp(int(posix) / 1000)
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def _iso(date_object) -> str:
    d = _posix_dt(date_object)
    return d.strftime("%Y-%m-%d %H:%M:%S") if d else ""


def _targets_running(package_name: str, gateways: list[dict]) -> list[dict]:
    """The gateways whose installed access policy is ``package_name`` (assigned to run this package)."""
    out = []
    for gw in gateways:
        pol = gw.get("policy") or {}
        if pol.get("access-policy-name") == package_name:
            out.append(gw)
    return out


def evaluate_package(package: dict, gateways: list[dict]) -> dict:
    """Decide whether ONE package needs (re)install, by comparing its last-modify-time to the install date
    on each gateway running it. Pure — unit-testable with plain dicts. Returns a display-ready record."""
    name = package.get("name") or ""
    modify = _posix_dt((package.get("meta-info") or {}).get("last-modify-time"))
    targets_out = []
    stale = False
    uninstalled = False
    running = _targets_running(name, gateways)
    for gw in running:
        pol = gw.get("policy") or {}
        installed = bool(pol.get("access-policy-installed"))
        inst = _posix_dt(pol.get("access-policy-installation-date"))
        gw_stale = False
        if not installed or inst is None:
            uninstalled = True
            gw_stale = True
        elif modify is not None and modify > inst:
            stale = True
            gw_stale = True
        targets_out.append({"gateway": gw.get("name") or gw.get("uid") or "?",
                            "installed": installed,
                            "installed_at": _iso(pol.get("access-policy-installation-date")),
                            "stale": gw_stale})
    needs = stale or uninstalled
    if not running:
        reason = "not assigned to any gateway"
    elif uninstalled and stale:
        reason = "changed since last install; some targets never installed"
    elif uninstalled:
        reason = "assigned but not yet installed on some target(s)"
    elif stale:
        reason = "policy changed since the last install"
    else:
        reason = "up to date"
    return {"name": name, "uid": package.get("uid"),
            "last_modified": _iso((package.get("meta-info") or {}).get("last-modify-time")),
            "targets": targets_out, "needs_install": needs, "reason": reason}


def _scan(session) -> dict:
    packages = session.call_paged("show-packages", key="packages")
    gateways = session.call_paged("show-gateways-and-servers", key="objects")
    results = [evaluate_package(p, gateways) for p in packages]
    results.sort(key=lambda r: (not r["needs_install"], r["name"].lower()))   # stale first, then by name
    need = [r for r in results if r["needs_install"]]
    return {"packages": results,
            "summary": {"total": len(results), "needs_install": len(need),
                        "names": [r["name"] for r in need]}}


def install_status(server, secret: str) -> dict:
    """Full report: every package on ``server`` with its (re)install status. Read-only, pooled session."""
    with mgmt_api.read_session(server, secret) as s:
        out = _scan(s)
        out["trace"] = s.trace
    return out
