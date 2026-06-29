"""Correlate a human application name (from a ticket / the form) to a real Check Point application —
so "abcnews" maps to the actual App-&-URL-Filtering object **ABC News**, or surfaces candidates when
it's genuinely ambiguous, but NEVER a wrong guess.

Why not pull the whole catalogue: Check Point ships thousands of predefined application-sites, so we
don't dump them all. Instead we let the SMS do the heavy lifting — ``show-objects`` with a ``filter`` is
indexed server-side over the object name/description — to gather a small candidate set, then rank it
locally. Results are cached briefly per (server, term) so type-ahead doesn't hammer the API.

Safety: only a HIGH-CONFIDENCE match is auto-used — an exact (case-insensitive) name, or an exact match
after normalising case/spacing/punctuation ("abcnews" == "ABC News"), and only when it's unique.
Anything else returns ranked candidates for a human to choose; an ambiguous application is never applied
on its own (mirrors the decision engine's REVIEW-on-uncertainty rule — a wrong app = wrong access)."""
from __future__ import annotations

import difflib
import re
import time

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_TTL = 60.0                      # seconds to cache a (server, term) candidate set (type-ahead friendly)
_cache: dict = {}                # key -> (expires_monotonic, candidates)


def _norm(s: str) -> str:
    """Fold case + drop spaces/punctuation: 'ABC News!' -> 'abcnews', so spelling style stops mattering."""
    return _NON_ALNUM.sub("", (s or "").lower())


def _server_key(session) -> tuple:
    sv = getattr(session, "server", None)
    return (getattr(sv, "host", ""), getattr(sv, "port", ""), getattr(sv, "domain", "") or "")


def _query(session, term: str, obj_type: str, limit: int) -> list[dict]:
    try:
        r = session.call("show-objects", {"filter": term, "type": obj_type,
                                          "limit": limit, "details-level": "full"})
        return r.get("objects", []) or []
    except Exception:  # noqa: BLE001 — search is best-effort; a failure just yields no candidates
        return []


def _candidates(objects: list[dict]) -> list[dict]:
    """Normalise raw show-objects results to candidate dicts, deduped. The dedup key is the object uid;
    for the (rare) uid-less object it falls back to (raw name, type) — NOT the normalized name — so two
    distinct names that merely normalize alike (e.g. 'ABC News' vs 'abc-news') stay SEPARATE and remain
    visible as an ambiguity (collapsing them would fake a unique match)."""
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
        out.append({
            "name": name, "uid": o.get("uid"),
            "kind": "category" if "categor" in (o.get("type") or "") else "application",
            "category": o.get("primary-category") or "",
        })
    return out


def search(session, term: str, limit: int = 40) -> list[dict]:
    """Candidate applications/categories matching ``term`` (server-side filter, deduped) — for the UI
    type-ahead. Cached ~60s per (server, term)."""
    term = (term or "").strip()
    if len(term) < 2:
        return []
    key = (_server_key(session), term.lower(), limit)
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    cands = _candidates(_query(session, term, "application-site", limit) +
                        _query(session, term, "application-site-category", max(8, limit // 4)))
    _cache[key] = (now + _TTL, cands)
    return cands


def _score(term: str, name: str) -> tuple[str, float]:
    t, n = term.lower(), name.lower()
    if t == n:
        return ("exact", 1.0)
    nt, nn = _norm(term), _norm(name)
    if nt and nt == nn:
        return ("normalized", 0.97)
    if nt and nn.startswith(nt):
        base = 0.85
    elif nt and nt in nn:
        base = 0.70
    else:
        base = 0.0
    return ("fuzzy", max(base, difflib.SequenceMatcher(None, nt, nn).ratio()))


_RESOLVE_LIMIT = 200      # the safety-critical query pulls a deep page so a duplicate can't hide past it


def resolve(session, term: str) -> dict:
    """Map ``term`` to a Check Point application. Returns {term, match, confidence, candidates, note}.
    ``match`` is set ONLY for a confident, UNIQUE exact / normalized-exact hit proven over a COMPLETE
    result page; otherwise it's None and ``candidates`` holds the ranked alternatives for a human to
    pick. A truncated (== limit) result is never auto-matched — if there could be a hidden twin, we
    refuse to guess and route to a human (a wrong app = wrong access)."""
    term = (term or "").strip()
    out = {"term": term, "match": None, "match_kind": "", "confidence": "", "candidates": [], "note": ""}
    if not term:
        return out
    apps = _query(session, term, "application-site", _RESOLVE_LIMIT)
    cats = _query(session, term, "application-site-category", 40)
    truncated = len(apps) >= _RESOLVE_LIMIT or len(cats) >= 40   # page may be cut -> not provably complete
    scored = sorted(((_score(term, c["name"]), c) for c in _candidates(apps + cats)),
                    key=lambda x: x[0][1], reverse=True)
    if not scored:
        out["note"] = f"No Check Point application matches “{term}”."
        return out

    exacts = [c for (lvl, _), c in scored if lvl == "exact"]
    norms = [c for (lvl, _), c in scored if lvl == "normalized"]
    if not truncated and len(exacts) == 1:
        out["match"], out["confidence"], out["match_kind"] = exacts[0]["name"], "exact", exacts[0]["kind"]
    elif not truncated and not exacts and len(norms) == 1:
        out["match"], out["confidence"], out["match_kind"] = norms[0]["name"], "normalized", norms[0]["kind"]

    out["candidates"] = [{"name": c["name"], "kind": c["kind"], "category": c["category"],
                          "score": round(sc, 2)}
                         for (lvl, sc), c in scored if sc >= 0.4][:8]
    if not out["match"]:
        out["note"] = (f"Too many matches for “{term}” — refine the name." if truncated
                       else (f"“{term}” is ambiguous — choose the exact Check Point application."
                             if out["candidates"] else f"No close match for “{term}”."))
    return out


def search_server(server, secret: str, term: str) -> list[dict]:
    """Open a pooled read session and search (for the type-ahead endpoint)."""
    from .mgmt_api import read_session
    with read_session(server, secret) as s:
        return search(s, term)
