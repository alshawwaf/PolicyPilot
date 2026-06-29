"""Per-user notification history (header bell) — add / list / unread / mark-read / delete / clear."""
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import models
from app.db import Base
from app.services import notifications as notif


def _db():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def test_notifications_lifecycle():
    with _db() as db:
        u = models.User(username="t", password_hash="x")
        db.add(u)
        db.commit()
        notif.add(db, u.id, "Settings saved", "success")
        notif.add(db, u.id, "Publish failed", "error")
        notif.add(db, u.id, "   ", "info")                # blank -> ignored

        assert notif.unread_count(db, u.id) == 2
        items = notif.recent(db, u.id)
        assert [i.text for i in items] == ["Publish failed", "Settings saved"]   # newest first
        assert items[0].kind == "error"

        notif.mark_all_read(db, u.id)
        assert notif.unread_count(db, u.id) == 0

        assert notif.delete_one(db, u.id, items[0].id) is True
        assert notif.delete_one(db, 999, items[1].id) is False   # not the owner -> refused
        assert len(notif.recent(db, u.id)) == 1

        assert notif.clear(db, u.id) == 1
        assert notif.recent(db, u.id) == []


def test_ago_handles_naive_datetime():
    # SQLite returns naive datetimes; _ago must not crash subtracting from a tz-aware now
    import datetime as dt

    from app.routers.notifications import _ago
    naive = dt.datetime.utcnow() - dt.timedelta(minutes=5)
    assert _ago(naive) == "5m ago"
    assert _ago(None) == ""


def test_notifications_capped_per_user():
    with _db() as db:
        u = models.User(username="t", password_hash="x")
        db.add(u)
        db.commit()
        for i in range(notif._MAX_PER_USER + 15):
            notif.add(db, u.id, f"event {i}", "info")
        assert len(notif.recent(db, u.id, limit=999)) == notif._MAX_PER_USER   # pruned to the cap
