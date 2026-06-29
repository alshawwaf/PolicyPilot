"""Storage guardrail — bound the two high-volume tables so a long-running demo can never fill the disk
or slow the database.

The Activity log grows with every served request and the SIEM receiver grows with every Log Exporter
line, so leaving either running unattended (a Data Center importing on a schedule, or a gateway
streaming logs for days) is exactly the kind of "production crash / data loss" risk we must prevent.
A small background pass — started in ``main.lifespan`` and run every few minutes — enforces the
admin-configurable caps from the **Settings** page: keep the newest N records, and/or delete anything
older than N days. Every delete is a cheap, indexed range/age delete that runs only when over cap.

Defensive by design: a failure is logged and the loop keeps going. Housekeeping must never crash the
app, and trimming the oldest demo traffic is expected, not a fault.
"""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import ActivityLog, AppState, SiemLog, User, utcnow
from . import app_settings, notifications

log = logging.getLogger("dcsim.retention")

_LAST_NOTIFY_KEY = "retention_last_notify"   # AppState: ISO timestamp of the last trim notification
_NOTIFY_THROTTLE = dt.timedelta(hours=1)     # at most one "records trimmed" notification per hour


def _trim_by_count(db: Session, model, cap: int) -> int:
    """Delete all but the newest ``cap`` rows (by primary key). Indexed range delete; fires only when
    over cap, so it's cheap even on a hot table. ``cap <= 0`` means unlimited (no trim)."""
    if cap <= 0:
        return 0
    n = db.scalar(select(func.count()).select_from(model)) or 0
    if n <= cap:
        return 0
    max_id = db.scalar(select(func.max(model.id))) or 0
    res = db.execute(delete(model).where(model.id <= max_id - cap))
    db.commit()
    return res.rowcount or 0


def _trim_by_age(db: Session, model, days: int) -> int:
    """Delete rows older than ``days`` (on the table's indexed ``at`` column). ``days <= 0`` = off."""
    if days <= 0:
        return 0
    cutoff = utcnow() - dt.timedelta(days=days)
    res = db.execute(delete(model).where(model.at < cutoff))
    db.commit()
    return res.rowcount or 0


def sweep(db: Session) -> dict:
    """Enforce every configured cap once. Returns ``{"activity": n, "siem": m}`` (rows deleted)."""
    vals = app_settings.all_values()
    deleted = {"activity": 0, "siem": 0}
    deleted["activity"] += _trim_by_count(db, ActivityLog, int(vals.get("activity_max_records", 0)))
    deleted["activity"] += _trim_by_age(db, ActivityLog, int(vals.get("activity_max_age_days", 0)))
    deleted["siem"] += _trim_by_count(db, SiemLog, int(vals.get("siem_max_records", 0)))
    return deleted


def _maybe_notify(db: Session, deleted: dict) -> None:
    """Post one throttled notification (to every user) summarizing a trim, if notifications are on."""
    total = sum(deleted.values())
    if total <= 0 or not app_settings.get("retention_notify"):
        return
    now = utcnow()
    row = db.get(AppState, _LAST_NOTIFY_KEY)
    if row is not None and row.value:
        try:
            last = dt.datetime.fromisoformat(row.value)
            if last.tzinfo is None:
                last = last.replace(tzinfo=dt.timezone.utc)
            if now - last < _NOTIFY_THROTTLE:
                return
        except ValueError:
            pass
    parts = []
    if deleted.get("activity"):
        parts.append(f"{deleted['activity']:,} activity-log")
    if deleted.get("siem"):
        parts.append(f"{deleted['siem']:,} SIEM")
    text = ("Storage housekeeping: trimmed " + " and ".join(parts) +
            " record(s) to stay within the configured retention cap.")
    for uid in db.scalars(select(User.id)).all():
        notifications.add(db, uid, text, kind="info")
    iso = now.isoformat()
    if row is None:
        db.add(AppState(key=_LAST_NOTIFY_KEY, value=iso))
    else:
        row.value = iso
    db.commit()


def run_once() -> dict:
    """One housekeeping pass with its own session; swallows + logs errors (called from a daemon loop)."""
    db = SessionLocal()
    try:
        deleted = sweep(db)
        _maybe_notify(db, deleted)
        return deleted
    except Exception:  # noqa: BLE001 — housekeeping must never crash the caller
        log.exception("retention sweep failed")
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return {}
    finally:
        db.close()
