"""Cached server-side search for the TYPED (non-IP) source/destination objects the access-automation
engine understands — dns-domain, access-role, dynamic-object, updatable-object, security-zone — so the
request form can type-ahead and RECOMMEND the real Check Point object instead of a free-typed name.

Same model as ``applications`` / ``services`` (and it reuses their pure matchers): one ``show-objects``
call filtered to the picked kind's object type (CP indexes the filter — no catalogue dump), cached ~60s
per (server, kind, term); candidates ranked locally. This only SUGGESTS — a wrong object is a wrong
access, so the apply path still resolves the exact object by name/value (see access_automation
.resolve_typed_object); this module never decides anything.

For a dns-domain the candidate's ``name`` is the REQUEST-FORM value that reproduces the object — a
leading dot iff ``is-sub-domain`` is set ("the domain + its sub-domains") — so picking a suggestion fills
the field with a value the engine + apply interpret identically to the underlying object."""
from __future__ import annotations

import re
import time

from .applications import _score, _server_key   # shared, pure matchers

_TTL = 60.0
_cache: dict = {}
_SUGGEST_LIMIT = 200      # deeper page for the "did you mean" ranker than for the live type-ahead

# request kind -> the Check Point object type to search. The keys are exactly access_automation
# .TYPED_KINDS (kept local so this module doesn't import the engine); a guard test ties them together.
_KIND_TYPE = {
    "domain": "dns-domain",
    "access-role": "access-role",
    "dynamic-object": "dynamic-object",
    "updatable-object": "updatable-object",
    "security-zone": "security-zone",
}


def supported_kind(kind: str) -> bool:
    return (kind or "").lower() in _KIND_TYPE


def _query(session, kind: str, term: str, limit: int) -> list:
    """Raw objects of ``kind`` whose name/description matches ``term`` (one indexed show-objects call)."""
    try:
        r = session.call("show-objects", {"filter": term, "type": _KIND_TYPE[kind],
                                          "limit": limit, "details-level": "full"})
        return r.get("objects") or []
    except Exception:  # noqa: BLE001 — search is best-effort; a failure just yields no candidates
        return []


def _candidates(objects: list, kind: str) -> list:
    """Dedup raw results to candidate dicts. Dedup on uid, falling back to (raw name, type) for the rare
    uid-less object so distinct names stay separate (mirrors applications._candidates)."""
    seen: set = set()
    out: list = []
    for o in objects:
        raw = o.get("name")
        if not raw:
            continue
        key = o.get("uid") or (raw, o.get("type") or "")
        if key in seen:
            continue
        seen.add(key)
        if kind == "domain":
            base = raw.lstrip(".")
            sub = bool(o.get("is-sub-domain"))
            out.append({"name": ("." + base) if sub else base, "uid": o.get("uid"), "kind": "domain",
                        "category": "domain + sub-domains" if sub else "exact domain"})
        else:
            out.append({"name": raw, "uid": o.get("uid"), "kind": kind, "category": kind})
    return out


def search(session, kind: str, term: str, limit: int = 40) -> list:
    """Candidate objects of ``kind`` matching ``term`` (for the form type-ahead / recommendations).
    Cached ~60s per (server, kind, term). Empty for an unsupported kind or a <2-char term."""
    kind = (kind or "").lower()
    term = (term or "").strip()
    if not supported_kind(kind) or len(term) < 2:
        return []
    key = (_server_key(session), kind, term.lower(), limit)
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    cands = _candidates(_query(session, kind, term, limit), kind)
    _cache[key] = (now + _TTL, cands)
    return cands


def _loose_filter(term: str) -> str:
    """A relaxed server filter for the near-miss ranker: the longest alphanumeric token of the value
    (so 'HR_Users' / 'HR Users' still surfaces 'HR-Users'), falling back to the whole term."""
    toks = [t for t in re.split(r"[^A-Za-z0-9]+", term) if len(t) >= 2]
    return max(toks, key=len) if toks else term


def suggest(session, kind: str, term: str) -> list:
    """Ranked 'did you mean' candidates for a typed value that didn't match an existing object — closest
    first, for the missing-object recommendation. Queries with a RELAXED filter (so a near-miss like an
    underscore-vs-hyphen difference still surfaces) over a deep page, then ranks locally. Not cached
    (called once on a miss, not per keystroke)."""
    kind = (kind or "").lower()
    term = (term or "").strip()
    if not supported_kind(kind) or not term:
        return []
    raw = _query(session, kind, _loose_filter(term), _SUGGEST_LIMIT)
    scored = sorted(((_score(term, c["name"]), c) for c in _candidates(raw, kind)),
                    key=lambda x: x[0][1], reverse=True)
    return [{"name": c["name"], "kind": c["kind"], "category": c.get("category", ""), "score": round(sc, 2)}
            for (lvl, sc), c in scored if sc >= 0.4][:8]


def search_server(server, secret: str, kind: str, term: str) -> list:
    from .mgmt_api import read_session
    with read_session(server, secret) as s:
        return search(s, kind, term)
