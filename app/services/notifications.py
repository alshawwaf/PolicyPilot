"""Per-user notification history for the header bell. Every flash message is also recorded here so
the admin can review and delete past notifications. Capped per user so it never grows unbounded."""
from __future__ import annotations

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from ..models import Notification

_MAX_PER_USER = 50


def add(db: Session, owner_id: int, text: str, kind: str = "success") -> None:
    if not owner_id or not (text or "").strip():
        return
    db.add(Notification(owner_id=owner_id, text=text[:800], kind=kind or "success"))
    db.commit()
    _prune(db, owner_id)


def _prune(db: Session, owner_id: int) -> None:
    stale = db.scalars(
        select(Notification.id).where(Notification.owner_id == owner_id)
        .order_by(Notification.created_at.desc()).offset(_MAX_PER_USER)).all()
    if stale:
        db.execute(delete(Notification).where(Notification.id.in_(stale)))
        db.commit()


def recent(db: Session, owner_id: int, limit: int = _MAX_PER_USER) -> list[Notification]:
    return list(db.scalars(
        select(Notification).where(Notification.owner_id == owner_id)
        .order_by(Notification.created_at.desc(), Notification.id.desc()).limit(limit)).all())


def unread_count(db: Session, owner_id: int) -> int:
    return db.scalar(select(func.count()).select_from(Notification)
                     .where(Notification.owner_id == owner_id, Notification.read.is_(False))) or 0


def mark_all_read(db: Session, owner_id: int) -> None:
    db.execute(update(Notification).where(Notification.owner_id == owner_id,
                                          Notification.read.is_(False)).values(read=True))
    db.commit()


def delete_one(db: Session, owner_id: int, nid: int) -> bool:
    n = db.get(Notification, nid)
    if n is None or n.owner_id != owner_id:
        return False
    db.delete(n)
    db.commit()
    return True


def clear(db: Session, owner_id: int) -> int:
    res = db.execute(delete(Notification).where(Notification.owner_id == owner_id))
    db.commit()
    return res.rowcount or 0
