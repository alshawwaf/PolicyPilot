"""Storage guardrail — the retention sweep trims the Activity log + SIEM tables to the configured caps,
and posts a (throttled) notification when it does."""
import datetime as dt

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app import models
from app.db import Base
from app.models import ActivityLog, AppState, Notification, SiemLog, User


def _db():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def _settings(monkeypatch, **vals):
    """Pin app_settings.all_values()/get() to the given map so the sweep is deterministic in tests."""
    from app.services import app_settings, retention
    full = app_settings.defaults()
    full.update(vals)
    monkeypatch.setattr(app_settings, "all_values", lambda fresh=False: dict(full))
    monkeypatch.setattr(app_settings, "get", lambda k: full.get(k))
    return retention


def test_trim_by_count_keeps_newest(monkeypatch):
    with _db() as db:
        for i in range(50):
            db.add(ActivityLog(kind="ui", path=f"/p{i}"))
        db.commit()
        retention = _settings(monkeypatch, activity_max_records=10, siem_max_records=0,
                              activity_max_age_days=0, retention_notify=False)
        deleted = retention.sweep(db)
        assert deleted["activity"] == 40
        assert db.scalar(select(func.count()).select_from(ActivityLog)) == 10
        # the survivors are the newest 10 (highest ids)
        kept = db.scalars(select(ActivityLog.path)).all()
        assert "/p49" in kept and "/p40" in kept and "/p39" not in kept


def test_unlimited_when_zero(monkeypatch):
    with _db() as db:
        for i in range(20):
            db.add(SiemLog(raw=f"line {i}"))
        db.commit()
        retention = _settings(monkeypatch, siem_max_records=0, activity_max_records=0,
                              activity_max_age_days=0, retention_notify=False)
        deleted = retention.sweep(db)
        assert deleted["siem"] == 0
        assert db.scalar(select(func.count()).select_from(SiemLog)) == 20


def test_trim_by_age(monkeypatch):
    with _db() as db:
        old = models.utcnow() - dt.timedelta(days=40)
        recent = models.utcnow() - dt.timedelta(days=1)
        db.add(ActivityLog(kind="ui", path="/old", at=old))
        db.add(ActivityLog(kind="ui", path="/recent", at=recent))
        db.commit()
        retention = _settings(monkeypatch, activity_max_records=0, activity_max_age_days=30,
                              siem_max_records=0, retention_notify=False)
        deleted = retention.sweep(db)
        assert deleted["activity"] == 1
        assert db.scalars(select(ActivityLog.path)).all() == ["/recent"]


def test_notify_is_throttled(monkeypatch):
    with _db() as db:
        db.add(User(username="admin", password_hash="x"))
        for i in range(30):
            db.add(ActivityLog(kind="ui", path=f"/p{i}"))
        db.commit()
        retention = _settings(monkeypatch, activity_max_records=5, siem_max_records=0,
                              activity_max_age_days=0, retention_notify=True)
        # first sweep trims -> one notification
        retention.sweep(db)
        retention._maybe_notify(db, {"activity": 25, "siem": 0})
        assert db.scalar(select(func.count()).select_from(Notification)) == 1
        assert db.get(AppState, retention._LAST_NOTIFY_KEY) is not None
        # an immediate second trim does NOT notify again (throttled to 1/hour)
        retention._maybe_notify(db, {"activity": 3, "siem": 0})
        assert db.scalar(select(func.count()).select_from(Notification)) == 1


def test_notify_disabled(monkeypatch):
    with _db() as db:
        db.add(User(username="admin", password_hash="x"))
        db.commit()
        retention = _settings(monkeypatch, retention_notify=False)
        retention._maybe_notify(db, {"activity": 99, "siem": 0})
        assert db.scalar(select(func.count()).select_from(Notification)) == 0
