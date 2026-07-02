"""Idempotency for agent / REST writes.

An LLM agent (or n8n with retry-on-fail, or a flaky network) can re-send the same write. Without protection
that means a double publish / double push. A caller passes an ``idempotency_key`` (any stable string per
logical change); the FIRST committed result is stored, and a repeat with the same key REPLAYS that result
instead of committing again. Stored in the ``idempotency_records`` table with a TTL, so it survives a worker
restart. Best-effort throughout — a storage hiccup never blocks or breaks the actual operation.
"""
from __future__ import annotations

import datetime as dt
import json

from ..db import SessionLocal
from ..models import IdempotencyRecord, utcnow

_TTL = dt.timedelta(hours=24)


def _as_aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def replay(key: str, fingerprint: str | None = None):
    """The stored result for ``key`` if it was recorded within the TTL (with ``idempotent_replay: true``),
    else None. Never raises.

    When ``fingerprint`` is provided and the stored record was committed for a DIFFERENT request (a
    fingerprint mismatch), return a CONFLICT marker dict (``idempotency_conflict: true``) instead of the
    cached result — so the caller fails loud rather than falsely reporting the first change as applied.
    (A record with no stored fingerprint — pre-migration — replays as before, never conflicts.)"""
    if not key:
        return None
    try:
        db = SessionLocal()
        try:
            row = db.get(IdempotencyRecord, key)
            if row is None or not row.result:
                return None
            if (utcnow() - _as_aware(row.created_at)) > _TTL:
                return None
            if fingerprint and (getattr(row, "fingerprint", "") or "") and row.fingerprint != fingerprint:
                return {"ok": False, "applied": False, "published": False, "idempotency_conflict": True,
                        "error": "idempotency_key was already used for a DIFFERENT request — refusing to "
                                 "replay (that would report the earlier change's result for this one). Use a "
                                 "new idempotency_key for a new change."}
            res = json.loads(row.result)
            return {**res, "idempotent_replay": True} if isinstance(res, dict) else res
        finally:
            db.close()
    except Exception:  # noqa: BLE001 — idempotency must never break the caller
        return None


def remember(key: str, result, fingerprint: str | None = None) -> None:
    """Store ``result`` (and the request ``fingerprint``) under ``key`` for replay within the TTL. Call only
    for a result that actually committed. Best-effort; never raises."""
    if not key or not isinstance(result, dict):
        return
    try:
        db = SessionLocal()
        try:
            payload = json.dumps(result)
            row = db.get(IdempotencyRecord, key)
            if row is None:
                db.add(IdempotencyRecord(key=key, result=payload,
                                         fingerprint=fingerprint or "", created_at=utcnow()))
            else:
                row.result, row.created_at = payload, utcnow()
                if fingerprint is not None:
                    row.fingerprint = fingerprint
            db.commit()
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        pass


def prune(db) -> int:
    """Delete records past the TTL with a single set-based DELETE. Returns the count removed. Caller owns the
    session + commit. ``created_at < cutoff`` is safe — all writes use the same tz-aware ``utcnow()`` (the
    same pattern as retention._trim_by_age), so the stored values sort consistently against the cutoff."""
    from sqlalchemy import delete
    cutoff = utcnow() - _TTL
    res = db.execute(delete(IdempotencyRecord).where(IdempotencyRecord.created_at < cutoff))
    return res.rowcount or 0
