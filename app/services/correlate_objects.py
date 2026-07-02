"""Correlate a requested TIME object, DATA-TYPE (content), or LIMIT name to the real Check Point object —
so an agent can turn natural language ("work hours", "SQL Queries", "10 Mbps upload") into the exact object
name the apply path requires. Same discover-then-decide flow as ``services`` / ``applications``.

CRITICAL: each resolver queries the SAME object classes the apply-side validator accepts —
``access_automation._resolve_named_objects`` uses ``_TIME_TYPES`` for time, ``_CONTENT_DT_TYPES`` for
content, and ``show-limits`` for limits — so a name this module auto-matches will always validate + apply
cleanly (no "resolved here, rejected there" gap). Auto-match is CONSERVATIVE: only a confident, UNIQUE
exact / normalized-exact hit over a COMPLETE (non-truncated) result set; anything ambiguous or truncated
returns candidates for a human/agent to pick — never a wrong object (a wrong time/content/limit = a wrong
rule).
"""
from __future__ import annotations

import time as _time

from .applications import _score, _server_key   # shared, pure matchers (identical ranking to service/app)

_TTL = 60.0
_RESOLVE_LIMIT = 200      # deep page so a duplicate can't hide past the cutoff (truncation guard)

# time + data-type objects live in the generic object index (show-objects), like services/apps. Kept in sync
# with access_automation._TIME_TYPES / _CONTENT_DT_TYPES (the apply-side allow_types).
_TIME_TYPES = ("time", "time-group")
_CONTENT_TYPES = ("data-type-patterns", "data-type-keywords", "data-type-file-attributes",
                  "data-type-group", "data-type-compound-group", "data-type-traditional-group",
                  "data-type-weighted-keywords", "data-type-file-group")
_cache: dict = {}


def _query_typed(session, term: str, limit: int, allow_types: tuple) -> tuple:
    """(objects of ``allow_types`` matching ``term``, truncated?) from ONE show-objects call. ``truncated``
    is derived from the SERVER's PRE-filter response (it applies ``limit`` before our type filter), so a page
    full of other-typed objects still counts as truncated — otherwise we could auto-match a name that is
    actually ambiguous past the cutoff (a wrong object = a wrong rule)."""
    try:
        r = session.call("show-objects", {"filter": term, "limit": limit, "details-level": "standard"})
        raw = r.get("objects") or []
        total = r.get("total")
        truncated = len(raw) >= limit or (total is not None and total > len(raw))
        objs = [o for o in raw if (o.get("type") or "") in allow_types]
        return objs, truncated
    except Exception:  # noqa: BLE001 — best-effort; a failure just yields no candidates
        return [], False


def _candidates(objects: list[dict]) -> list[dict]:
    seen: set = set()
    out: list[dict] = []
    for o in objects:
        name = o.get("name")
        if not name:
            continue
        key = o.get("uid") or (name, o.get("type") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "uid": o.get("uid"), "kind": o.get("type") or ""})
    return out


def _finish(out: dict, scored: list, truncated: bool, label: str) -> dict:
    """Shared auto-match + candidate/note logic (identical rule to services.resolve)."""
    if not scored:
        out["note"] = f"No Check Point {label} matches “{out['term']}”."
        return out
    exacts = [c for (lvl, _), c in scored if lvl == "exact"]
    norms = [c for (lvl, _), c in scored if lvl == "normalized"]
    win = (exacts[0] if (not truncated and len(exacts) == 1)
           else norms[0] if (not truncated and not exacts and len(norms) == 1) else None)
    if win is not None:
        out["match"], out["match_kind"] = win["name"], win.get("kind", "")
        out["confidence"] = "exact" if exacts else "normalized"
    out["candidates"] = [{"name": c["name"], "kind": c.get("kind", ""), "score": round(sc, 2)}
                         for (lvl, sc), c in scored if sc >= 0.4][:8]
    if not out["match"]:
        out["note"] = (f"Too many matches for “{out['term']}” — refine the name." if truncated
                       else (f"“{out['term']}” is ambiguous — choose the exact Check Point {label}."
                             if out["candidates"] else f"No close match for “{out['term']}”."))
    return out


def _resolve_typed(session, term: str, allow_types: tuple, label: str) -> dict:
    term = (term or "").strip()
    out = {"term": term, "match": None, "match_kind": "", "confidence": "", "candidates": [], "note": ""}
    if not term:
        return out
    raw, truncated = _query_typed(session, term, _RESOLVE_LIMIT, allow_types)
    scored = sorted(((_score(term, c["name"]), c) for c in _candidates(raw)),
                    key=lambda x: x[0][1], reverse=True)
    return _finish(out, scored, truncated, label)


def resolve_time(session, term: str) -> dict:
    """Map ``term`` (e.g. "work hours") to a Check Point time / time-group object, or return candidates."""
    return _resolve_typed(session, term, _TIME_TYPES, "time object")


def resolve_content(session, term: str) -> dict:
    """Map ``term`` (e.g. "SQL Queries") to a Check Point data-type (content) object, or return candidates."""
    return _resolve_typed(session, term, _CONTENT_TYPES, "data type")


# --- Limit objects: NOT in the generic show-objects index -> enumerated via show-limits (its own command,
# mirroring access_automation._LIST_CMDS_LIMIT). A COMPLETE enumeration means a unique exact hit is safe to
# auto-match without a truncation caveat; a failure to enumerate degrades to a clear note (never a guess).
def _list_limits(session) -> list | None:
    names: list[str] = []
    offset = 0
    any_ok = False
    try:
        while True:
            r = session.call("show-limits", {"limit": 200, "offset": offset, "details-level": "standard"})
            any_ok = True
            objs = r.get("objects") or []
            for o in objs:
                nm = o.get("name")
                if nm:
                    names.append(nm)
            total = r.get("total")
            offset += len(objs)
            if not objs or len(objs) < 200 or (total is not None and offset >= total):
                break
        return names
    except Exception:  # noqa: BLE001
        return names if any_ok else None       # partial page after progress is better than nothing; a
        #                                         first-call failure (command absent) -> None (unknown)


def resolve_limit(session, term: str) -> dict:
    """Map ``term`` (e.g. "10 Mbps upload") to a Check Point Limit (QoS/bandwidth-RATE) object, or return
    candidates. NOTE: a Limit is a RATE (Mbps/Gbps), not a volume/quota — there is no "10 GB total" object in
    the Access Policy, so a volume request must map to an existing rate object or be declined."""
    term = (term or "").strip()
    out = {"term": term, "match": None, "match_kind": "limit", "confidence": "", "candidates": [], "note": ""}
    if not term:
        return out
    names = _list_limits(session)
    if names is None:
        out["note"] = "Couldn't enumerate limit objects on this server (show-limits unavailable)."
        return out
    scored = sorted(((_score(term, n), {"name": n, "kind": "limit"}) for n in set(names)),
                    key=lambda x: x[0][1], reverse=True)
    # A complete enumeration -> no truncation caveat; a unique exact/normalized hit auto-matches.
    return _finish(out, scored, False, "limit object")


# --- Install-on (gateways/targets) + VPN communities: NOT in the generic show-objects index -> enumerated
# via their dedicated list commands, the SAME ones access_automation._resolve_named_objects validates
# against (imported so the command set can't drift). A complete enumeration -> a unique exact hit auto-matches.
def _resolve_enumerated(session, term: str, commands: tuple, label: str, kind: str, extra=()) -> dict:
    term = (term or "").strip()
    out = {"term": term, "match": None, "match_kind": kind, "confidence": "", "candidates": [], "note": ""}
    if not term:
        return out
    from .access_automation import _known_object_names
    names = _known_object_names(session, commands)
    if names is None:
        out["note"] = f"Couldn't enumerate {label}s on this server ({', '.join(commands)} unavailable)."
        return out
    allnames = set(names) | set(extra)
    scored = sorted(((_score(term, n), {"name": n, "kind": kind}) for n in allnames),
                    key=lambda x: x[0][1], reverse=True)
    return _finish(out, scored, False, label)


def resolve_gateway(session, term: str) -> dict:
    """Map ``term`` (e.g. "the perimeter gateway") to a Check Point gateway/server object for the Install-On
    column, or return candidates. Enumerated via show-gateways-and-servers (the apply-side list command)."""
    from .access_automation import _LIST_CMDS_INSTALL_ON
    return _resolve_enumerated(session, term, _LIST_CMDS_INSTALL_ON, "gateway/target", "gateway")


def resolve_vpn(session, term: str) -> dict:
    """Map ``term`` (e.g. "the site-to-site community") to a Check Point VPN community for the VPN column, or
    return candidates. Enumerated via the show-vpn-communities-* commands; includes the built-in All_GwToGw."""
    from .access_automation import _LIST_CMDS_VPN
    return _resolve_enumerated(session, term, _LIST_CMDS_VPN, "VPN community", "vpn", extra=("All_GwToGw",))


# --- UI type-ahead helpers (parallel to services.search_server / applications) ------------------------
def _browse_typed(session, allow_types: tuple, limit: int = 40) -> list[dict]:
    """The first page of objects of ``allow_types`` (empty filter = all) — for the menu shown on FOCUS,
    before anything is typed. Best-effort; an empty list just means the menu prompts you to type."""
    objs, _ = _query_typed(session, "", limit, allow_types)
    return _candidates(objs)


def _browse_names(names, kind: str, limit: int = 40) -> list[dict]:
    """First ``limit`` enumerated names (limit/gateway/vpn) as candidate rows for the focus menu."""
    return [{"name": n, "kind": kind} for n in sorted(set(names or []), key=str.lower)[:limit]]


def _search_typed(session, term: str, allow_types: tuple, limit: int = 40) -> list[dict]:
    term = (term or "").strip()
    if not term:
        return _browse_typed(session, allow_types, limit)
    key = (_server_key(session), term.lower(), tuple(allow_types), limit)
    now = _time.monotonic()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    objs, _ = _query_typed(session, term, limit, allow_types)
    cands = _candidates(objs)
    _cache[key] = (now + _TTL, cands)
    return cands


def search_server(server, secret: str, term: str, kind: str) -> list[dict]:
    """Candidate objects of ``kind`` (time | content | limit | gateway | vpn) for a UI type-ahead. An empty
    ``term`` BROWSES (the first page of that object kind, shown when the field is focused before typing); a
    non-empty term filters. Best-effort — a failure/absent index just yields []."""
    from .mgmt_api import read_session
    term = (term or "").strip()
    browse = not term
    with read_session(server, secret) as s:
        if kind == "time":
            return _search_typed(s, term, _TIME_TYPES)          # _search_typed browses on empty term
        if kind == "content":
            return _search_typed(s, term, _CONTENT_TYPES)
        if kind == "limit":
            if browse:
                return _browse_names(_list_limits(s), "limit")
            r = resolve_limit(s, term)
            return [{"name": c["name"], "kind": "limit"} for c in r.get("candidates", [])]
        if kind in ("gateway", "install_on", "install-on"):
            if browse:
                from .access_automation import _known_object_names, _LIST_CMDS_INSTALL_ON
                return _browse_names(_known_object_names(s, _LIST_CMDS_INSTALL_ON), "gateway")
            r = resolve_gateway(s, term)
            return [{"name": c["name"], "kind": "gateway"} for c in r.get("candidates", [])]
        if kind == "vpn":
            if browse:
                from .access_automation import _known_object_names, _LIST_CMDS_VPN
                names = list(_known_object_names(s, _LIST_CMDS_VPN) or []) + ["All_GwToGw"]
                return _browse_names(names, "vpn")
            r = resolve_vpn(s, term)
            return [{"name": c["name"], "kind": "vpn"} for c in r.get("candidates", [])]
        return []
