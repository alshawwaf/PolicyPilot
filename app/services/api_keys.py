"""Named, revocable API keys for the machine endpoints (MCP /mcp + the ticketing webhook).

Keys are stored HASHED (SHA-256) — the plaintext is returned once at creation and never recoverable —
so a DB leak exposes no usable credential (strictly better than a reversible at-rest secret). A key is
high-entropy random (256 bits), so a plain SHA-256 is sufficient; no salt/KDF is needed. Verification
hashes the presented bearer and constant-time-compares it against the active key hashes for the scope,
behind a short in-process cache so the auth hot path doesn't hit the DB per request. ``last_used_at`` is
updated fire-and-forget and throttled, so it never slows or blocks a request."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from datetime import timezone

from ..db import SessionLocal
from ..models import ApiKey, utcnow


def as_utc(d):
    """Coerce a (possibly naive, from SQLite) datetime to tz-aware UTC, so comparisons never raise."""
    if d is None:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)

SCOPES = ("mcp", "webhook", "api")     # api = the general REST API (/api/v1) for any HTTP client
_PREFIX = "dcsim"                      # token looks like dcsim_<scope>_<random> — scope is visible, not secret

# Cache of active keys per scope: scope -> (monotonic_at, [(id, key_hash)]). Short TTL so a create/revoke
# lands fast (we also bust explicitly). Keeps verify() off the DB on the request path. The cache is
# per-process: with the single-worker deployment, create/revoke take effect immediately (we bust the
# local cache); if ever scaled to multiple workers, a revoke could lag up to _CACHE_TTL on other workers.
_CACHE_TTL = 5.0
_cache: dict = {}
_last_used_write: dict = {}            # id -> monotonic of last last_used write (throttle)
_LAST_USED_THROTTLE = 60.0


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _normalize_scope(scope: str) -> str:
    return scope if scope in SCOPES else "mcp"


def generate(name: str, scope: str = "mcp", created_by: str = "", expires_at=None) -> tuple[ApiKey, str]:
    """Create a key and return (record, PLAINTEXT). The plaintext is the only time the secret exists in
    the clear — show it once to the admin, then it's unrecoverable (only the hash is stored). Retries once
    on the astronomically-unlikely key_hash UNIQUE collision (256-bit token) so it self-heals, never 500s.
    ``expires_at`` (tz-aware, optional) makes the key stop authenticating after that time."""
    from sqlalchemy.exc import IntegrityError
    scope = _normalize_scope(scope)
    name = (name or "key").strip()[:120]
    created_by = (created_by or "")[:120]
    for _ in range(3):
        secret = f"{_PREFIX}_{scope}_{secrets.token_urlsafe(32)}"
        row = ApiKey(name=name, scope=scope, key_hash=_hash(secret), hint=secret[-4:],
                     created_by=created_by, expires_at=expires_at)
        db = SessionLocal()
        try:
            db.add(row)
            db.commit()
            db.refresh(row)
        except IntegrityError:
            db.rollback()
            continue                       # collision → draw a fresh secret and retry
        finally:
            db.close()
        _bust()
        return row, secret
    raise RuntimeError("could not generate a unique API key")


def list_keys(scope: str | None = None) -> list[ApiKey]:
    """Active keys (no secret material beyond the display hint), newest first; optionally one scope."""
    db = SessionLocal()
    try:
        q = db.query(ApiKey)
        if scope:
            q = q.filter(ApiKey.scope == scope)
        return list(q.order_by(ApiKey.created_at.desc()).all())
    finally:
        db.close()


def revoke(key_id: int) -> bool:
    """Delete (revoke) a key. Returns True if a row was removed; busts the verify cache so it stops
    authenticating immediately (in this process)."""
    db = SessionLocal()
    try:
        row = db.get(ApiKey, key_id)
        if row is None:
            return False
        db.delete(row)
        db.commit()
    finally:
        db.close()
    _bust()
    _last_used_write.pop(key_id, None)
    return True


def set_expiry(key_id: int, expires_at) -> bool:
    """Change a key's expiry (a tz-aware datetime, or None for 'never'). Returns True if a row was updated;
    busts the verify cache so the new expiry takes effect immediately — a now-past date stops the key
    authenticating, and extending or clearing it lets a previously-expired key authenticate again."""
    db = SessionLocal()
    try:
        row = db.get(ApiKey, key_id)
        if row is None:
            return False
        row.expires_at = expires_at
        db.commit()
    finally:
        db.close()
    _bust()
    return True


def _active(scope: str) -> list[tuple[int, str, object]]:
    """[(id, key_hash, expires_at)] for a scope, cached ~5s. The single chokepoint for verify()/
    any_active(), so it normalizes the scope (an unknown scope can't silently cache an empty list under a
    typo'd key). Expiry is checked per call (not cache-bound) by _live()."""
    scope = _normalize_scope(scope)
    now = time.monotonic()
    hit = _cache.get(scope)
    if hit is not None and (now - hit[0]) <= _CACHE_TTL:
        return hit[1]
    try:
        db = SessionLocal()
        try:
            rows = [(r.id, r.key_hash, r.expires_at)
                    for r in db.query(ApiKey).filter(ApiKey.scope == scope).all()]
        finally:
            db.close()
    except Exception:  # noqa: BLE001 — a DB hiccup must fail closed (no keys), never crash the auth path
        return []
    _cache[scope] = (now, rows)
    return rows


def _live(scope: str) -> list[tuple[int, str]]:
    """[(id, key_hash)] for keys that are NOT expired — expiry checked against 'now' each call so a key
    expiring mid-cache-window stops authenticating immediately, without waiting for the cache TTL."""
    now = utcnow()
    return [(kid, kh) for (kid, kh, exp) in _active(scope) if as_utc(exp) is None or as_utc(exp) > now]


def verify(presented: str, scope: str = "mcp") -> bool:
    """True if ``presented`` matches a live (non-expired) key for ``scope`` (constant-time). Marks used."""
    if not presented:
        return False
    h = _hash(presented)
    matched_id = None
    for kid, kh in _live(scope):
        if hmac.compare_digest(h, kh):     # constant-time per comparison
            matched_id = kid
            break
    if matched_id is None:
        return False
    _touch(matched_id)
    return True


def any_active(scope: str = "mcp") -> bool:
    """True if at least one live (non-expired) key exists for the scope (endpoint counts as configured)."""
    return bool(_live(scope))


def _touch(key_id: int) -> None:
    """Record last-used, fire-and-forget + throttled (at most once / 60s per key) so the request path is
    never blocked by a write."""
    now = time.monotonic()
    last = _last_used_write.get(key_id, -1e9)
    if (now - last) < _LAST_USED_THROTTLE:
        return
    _last_used_write[key_id] = now

    def _write():
        db = SessionLocal()
        try:
            row = db.get(ApiKey, key_id)
            if row is not None:
                row.last_used_at = utcnow()
                db.commit()
        except Exception:  # noqa: BLE001 — telemetry write must never crash anything
            db.rollback()
        finally:
            db.close()

    threading.Thread(target=_write, daemon=True).start()


def _bust() -> None:
    _cache.clear()
