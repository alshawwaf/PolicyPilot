"""Brute-force protection for the login form. Throttle by CLIENT IP (never by username — locking on a
username would let anyone DoS the admin out of their own portal). After THRESHOLD failures within a
sliding WINDOW, the IP is locked for an escalating cooldown; a successful login clears it."""
from __future__ import annotations

import datetime as dt

from fastapi import Request
from sqlalchemy.orm import Session

from ..models import LoginThrottle

THRESHOLD = 5            # failures before the first lockout
WINDOW = 900             # seconds; failures older than this start a fresh count
BASE_LOCK = 60           # seconds for the first lockout
MAX_LOCK = 900           # cap (15 min)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _aware(t: dt.datetime | None) -> dt.datetime | None:
    """SQLite returns naive datetimes; treat them as UTC so arithmetic with _now() is valid."""
    if t is None or t.tzinfo is not None:
        return t
    return t.replace(tzinfo=dt.timezone.utc)


def _lock_seconds(fails: int) -> int:
    """Pure lockout policy: 0 below the threshold, then 60s doubling per extra failure, capped."""
    if fails < THRESHOLD:
        return 0
    over = min(fails - THRESHOLD, 8)
    return min(MAX_LOCK, BASE_LOCK * (2 ** over))


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if fwd:
        return fwd[:64]
    return (request.client.host if request.client else "") or "?"


def locked_for(db: Session, ip: str) -> int:
    """Seconds remaining on this IP's lockout, or 0 if not locked."""
    row = db.get(LoginThrottle, ip)
    if row is None or row.locked_until is None:
        return 0
    return max(0, int((_aware(row.locked_until) - _now()).total_seconds()))


def record_failure(db: Session, ip: str) -> None:
    now = _now()
    row = db.get(LoginThrottle, ip)
    if row is None:
        row = LoginThrottle(key=ip, fails=0, first_fail=now)
        db.add(row)
    elif row.first_fail and (now - _aware(row.first_fail)).total_seconds() > WINDOW and locked_for(db, ip) == 0:
        row.fails = 0           # the failure window elapsed and we're not mid-lockout -> fresh count
        row.first_fail = now
    row.fails += 1
    lock = _lock_seconds(row.fails)
    row.locked_until = (now + dt.timedelta(seconds=lock)) if lock else row.locked_until
    db.commit()


def record_success(db: Session, ip: str) -> None:
    row = db.get(LoginThrottle, ip)
    if row is not None:
        db.delete(row)
        db.commit()
