"""The idempotency store: remember a committed result, replay it within the TTL (marked), prune when expired."""
import datetime as dt

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — registers tables on Base.metadata
from app.db import Base
from app.models import IdempotencyRecord
from app.services import idempotency


@pytest.fixture()
def Session(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    monkeypatch.setattr(idempotency, "SessionLocal", S)
    return S


def test_replay_none_when_absent_or_empty_key(Session):
    assert idempotency.replay("missing") is None
    assert idempotency.replay("") is None


def test_remember_then_replay_adds_marker(Session):
    idempotency.remember("k1", {"ok": True, "rule": "r1"})
    assert idempotency.replay("k1") == {"ok": True, "rule": "r1", "idempotent_replay": True}


def test_remember_ignores_non_dict_and_empty_key(Session):
    idempotency.remember("k2", "not-a-dict")
    idempotency.remember("", {"ok": True})
    assert idempotency.replay("k2") is None


def test_remember_overwrites_same_key(Session):
    idempotency.remember("k3", {"v": 1})
    idempotency.remember("k3", {"v": 2})
    assert idempotency.replay("k3")["v"] == 2


def test_expired_record_does_not_replay_and_prunes(Session):
    idempotency.remember("old", {"ok": True})
    db = Session()
    db.get(IdempotencyRecord, "old").created_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=48)
    db.commit()
    assert idempotency.replay("old") is None                  # past the 24h TTL
    removed = idempotency.prune(db)
    db.commit()
    assert removed == 1 and db.get(IdempotencyRecord, "old") is None
    db.close()


def test_prune_keeps_fresh_records(Session):
    idempotency.remember("fresh", {"ok": True})
    db = Session()
    assert idempotency.prune(db) == 0 and db.get(IdempotencyRecord, "fresh") is not None
    db.close()
