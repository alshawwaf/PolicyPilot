"""Correlate a requested service / protocol name to a real Check Point service object — icmp, GRE, AH,
ESP, sctp, dce-rpc, gtp, a tcp/udp service by name, … — so "icmp" maps to the actual predefined object
(e.g. "echo-request") or surfaces candidates, never a wrong / erroring reference.

Same safety + caching model as ``applications`` (and it reuses its matchers): one server-side search
(``show-objects`` filter, kept to ``service-*`` types — CP indexes the filter, no catalogue dump),
cached briefly; a local ranker that auto-uses ONLY a confident, UNIQUE exact / normalized-exact match
proven over a complete page. Anything ambiguous or truncated returns candidates for a human to pick."""
from __future__ import annotations

import time

from .applications import _norm, _score, _server_key   # shared, pure matchers

_TTL = 60.0
_cache: dict = {}
_RESOLVE_LIMIT = 200      # deep page so a duplicate can't hide past it (truncation guard, like apps)


# A picked Service type -> the Check Point object type(s) to keep. ICMP spans both families; the rest map
# 1:1. An unknown/empty kind keeps every service-* type (the original behaviour).
_KIND_TYPES: dict = {
    "icmp": ("service-icmp", "service-icmp6"), "sctp": ("service-sctp",),
    "rpc": ("service-rpc",), "dce-rpc": ("service-dce-rpc",), "gtp": ("service-gtp",),
    "compound-tcp": ("service-compound-tcp",), "citrix-tcp": ("service-citrix-tcp",),
    "other": ("service-other",), "group": ("service-group",),
    "tcp": ("service-tcp",), "udp": ("service-udp",),
}


def _query(session, term: str, limit: int, kind: str = "") -> tuple:
    """(service objects matching ``term``, truncated?) from one show-objects call. ``kind`` restricts to a
    Service type client-side. CRUCIALLY ``truncated`` is derived from the SERVER's PRE-filter response
    (the server applies ``limit`` before our type/kind filter), so a page that's full of non-service
    objects still counts as truncated — otherwise resolve() could auto-match a name that's actually
    ambiguous past the cutoff (wrong service = wrong access)."""
    keep = _KIND_TYPES.get((kind or "").lower())
    try:
        r = session.call("show-objects", {"filter": term, "limit": limit, "details-level": "standard"})
        raw = r.get("objects") or []
        total = r.get("total")
        truncated = len(raw) >= limit or (total is not None and total > len(raw))
        objs = [o for o in raw if (o.get("type") or "").startswith("service-")]
        if keep:
            objs = [o for o in objs if o.get("type") in keep]
        return objs, truncated
    except Exception:  # noqa: BLE001 — best-effort; a failure just yields no candidates
        return [], False


def _candidates(objects: list[dict]) -> list[dict]:
    # Dedup on uid, falling back to (raw name, type) for uid-less objects so distinct names that merely
    # normalize alike stay separate (and visibly ambiguous) — same rule as applications._candidates.
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
        out.append({"name": name, "uid": o.get("uid"),
                    "kind": (o.get("type") or "service").replace("service-", "")})
    return out


def search(session, term: str, limit: int = 40, kind: str = "") -> list[dict]:
    """Candidate services matching ``term`` (for the UI type-ahead), optionally restricted to a picked
    Service ``kind``. Cached ~60s per (server, term, kind)."""
    term = (term or "").strip()
    if len(term) < 2:
        return []
    key = (_server_key(session), term.lower(), limit, (kind or "").lower())
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    objs, _ = _query(session, term, limit, kind)
    cands = _candidates(objs)
    _cache[key] = (now + _TTL, cands)
    return cands


def resolve(session, term: str) -> dict:
    """Map ``term`` to a Check Point service. Returns {term, match, confidence, candidates, note}.
    ``match`` is set ONLY for a confident, UNIQUE exact / normalized-exact hit over a complete page; a
    truncated result is never auto-matched (a wrong service = wrong access)."""
    term = (term or "").strip()
    out = {"term": term, "match": None, "match_kind": "", "confidence": "", "candidates": [], "note": ""}
    if not term:
        return out
    raw, truncated = _query(session, term, _RESOLVE_LIMIT)
    scored = sorted(((_score(term, c["name"]), c) for c in _candidates(raw)),
                    key=lambda x: x[0][1], reverse=True)
    if not scored:
        out["note"] = f"No Check Point service matches “{term}”."
        return out
    exacts = [c for (lvl, _), c in scored if lvl == "exact"]
    norms = [c for (lvl, _), c in scored if lvl == "normalized"]
    win = exacts[0] if (not truncated and len(exacts) == 1) else \
        (norms[0] if (not truncated and not exacts and len(norms) == 1) else None)
    if win is not None:                 # carry the matched object's protocol family (icmp/icmp6/…) so
        out["match"], out["match_kind"] = win["name"], win["kind"]   # the engine can't alias families
        out["confidence"] = "exact" if exacts else "normalized"
    out["candidates"] = [{"name": c["name"], "kind": c["kind"], "score": round(sc, 2)}
                         for (lvl, sc), c in scored if sc >= 0.4][:8]
    if not out["match"]:
        out["note"] = (f"Too many matches for “{term}” — refine the name." if truncated
                       else (f"“{term}” is ambiguous — choose the exact Check Point service."
                             if out["candidates"] else f"No close match for “{term}”."))
    return out


def search_server(server, secret: str, term: str, kind: str = "") -> list[dict]:
    from .mgmt_api import read_session
    with read_session(server, secret) as s:
        return search(s, term, kind=kind)
