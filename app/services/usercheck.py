"""Correlate a UserCheck phrase ("the blocked message", "company policy") to a real Check Point UserCheck
interaction object — so an Ask/Inform prompt or a Drop/Reject block-message page references the exact object
the access rule's ``user-check.interaction`` needs, never a wrong / erroring name.

Same safety + caching model as ``services`` / ``applications`` (and it reuses their pure matchers). CP's
UserCheck interaction objects carry a ``user-check-*`` type (verified on a live R82 SMS: a block message is
type ``user-check-drop``; Ask/Inform/certificate/… have their own ``user-check-*`` types). Rather than guess
the full subtype list, we query ``show-objects`` by NAME and keep anything whose type starts with
``user-check`` — robust to any subtype. Auto-matches ONLY a confident, UNIQUE exact/normalized hit over a
COMPLETE page; anything ambiguous or truncated returns candidates. Best-effort: if the server doesn't index
these objects, it returns no candidates and the apply path validates the name at publish (atomic)."""
from __future__ import annotations

import time

from .applications import _score, _server_key   # shared, pure matchers

_TTL = 60.0
_cache: dict = {}
_RESOLVE_LIMIT = 200


def _query(session, term: str, limit: int) -> tuple:
    """(UserCheck-interaction objects matching ``term``, truncated?) from one show-objects call. ``truncated``
    is derived from the SERVER's PRE-filter page size, so a page full of non-UserCheck objects still counts as
    truncated — never auto-match a name that could be ambiguous past the cutoff (a wrong message object)."""
    try:
        r = session.call("show-objects", {"filter": term, "limit": limit, "details-level": "standard"})
        raw = r.get("objects") or []
        total = r.get("total")
        truncated = len(raw) >= limit or (total is not None and total > len(raw))
        objs = [o for o in raw if (o.get("type") or "").startswith("user-check")]
        return objs, truncated
    except Exception:  # noqa: BLE001 — best-effort; a failure just yields no candidates
        return [], False


def _kind(o: dict) -> str:
    # "user-check-drop" -> "drop", "user-check-ask" -> "ask", bare "user-check" -> "user-check".
    t = (o.get("type") or "user-check")
    return t[len("user-check-"):] if t.startswith("user-check-") else t


def _candidates(objects: list) -> list:
    seen: set = set()
    out: list = []
    for o in objects:
        name = o.get("name")
        if not name:
            continue
        key = o.get("uid") or (name, o.get("type") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "uid": o.get("uid"), "kind": _kind(o)})
    return out


def search(session, term: str, limit: int = 40) -> list:
    """Candidate UserCheck objects matching ``term`` (for the form type-ahead). Cached ~60s per (server, term)."""
    term = (term or "").strip()
    if len(term) < 2:
        return []
    key = (_server_key(session), term.lower(), limit)
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    objs, _ = _query(session, term, limit)
    cands = _candidates(objs)
    _cache[key] = (now + _TTL, cands)
    return cands


def resolve(session, term: str) -> dict:
    """Map ``term`` to a Check Point UserCheck interaction object. Returns {term, match, match_kind,
    confidence, candidates, note}. ``match`` is set ONLY for a confident, UNIQUE exact/normalized hit over a
    complete page (a wrong message object is a wrong rule)."""
    term = (term or "").strip()
    out = {"term": term, "match": None, "match_kind": "", "confidence": "", "candidates": [], "note": ""}
    if not term:
        return out
    raw, truncated = _query(session, term, _RESOLVE_LIMIT)
    scored = sorted(((_score(term, c["name"]), c) for c in _candidates(raw)),
                    key=lambda x: x[0][1], reverse=True)
    if not scored:
        out["note"] = (f"No Check Point UserCheck object matches “{term}” (or this server doesn't index them "
                       f"— pass the exact name; it's validated when the rule is published).")
        return out
    exacts = [c for (lvl, _), c in scored if lvl == "exact"]
    norms = [c for (lvl, _), c in scored if lvl == "normalized"]
    win = (exacts[0] if (not truncated and len(exacts) == 1)
           else norms[0] if (not truncated and not exacts and len(norms) == 1) else None)
    if win is not None:
        out["match"], out["match_kind"] = win["name"], win["kind"]
        out["confidence"] = "exact" if exacts else "normalized"
    out["candidates"] = [{"name": c["name"], "kind": c["kind"], "score": round(sc, 2)}
                         for (lvl, sc), c in scored if sc >= 0.4][:8]
    if not out["match"]:
        out["note"] = (f"Too many matches for “{term}” — refine the name." if truncated
                       else (f"“{term}” is ambiguous — choose the exact UserCheck object."
                             if out["candidates"] else f"No close match for “{term}”."))
    return out


def search_server(server, secret: str, term: str) -> list:
    from .mgmt_api import read_session
    with read_session(server, secret) as s:
        return search(s, term)
