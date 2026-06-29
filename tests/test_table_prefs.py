"""Per-user table column preferences — defaults, validation/locked, persistence, reset."""
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import models
from app.db import Base
from app.services import table_prefs as tp


def _db():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def _user(db):
    u = models.User(username="t", password_hash="x")
    db.add(u)
    db.commit()
    return u


def test_defaults_validate_persist_reset():
    with _db() as db:
        u = _user(db)
        # default visible = the spec's default+locked, in spec order (Created is off by default)
        assert tp.visible_columns(db, u.id, "gateways") == ["name", "address", "username", "tls", "layers"]

        # save: enable Created, drop the rest, include a bogus id -> bogus dropped, locked Name forced,
        # result stays in spec order
        tp.save_columns(db, u.id, "gateways", ["address", "created", "bogus"])
        assert tp.visible_columns(db, u.id, "gateways") == ["name", "address", "created"]

        # hiding every optional column leaves only the locked identifier (a valid minimal view)
        tp.save_columns(db, u.id, "gateways", [])
        assert tp.visible_columns(db, u.id, "gateways") == ["name"]

        # reset -> back to defaults
        tp.reset(db, u.id, "gateways")
        assert tp.visible_columns(db, u.id, "gateways") == ["name", "address", "username", "tls", "layers"]


def test_unknown_table_is_inert():
    with _db() as db:
        u = _user(db)
        assert tp.spec("nope") == []
        assert tp.visible_columns(db, u.id, "nope") == []


def test_prefs_are_per_user():
    with _db() as db:
        a, b = _user(db), models.User(username="b", password_hash="x")
        db.add(b)
        db.commit()
        tp.save_columns(db, a.id, "gateways", ["created"])
        assert "created" in tp.visible_columns(db, a.id, "gateways")
        assert "created" not in tp.visible_columns(db, b.id, "gateways")   # b is unaffected
