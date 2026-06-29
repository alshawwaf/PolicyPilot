"""Login hardening: IP-based brute-force throttle + password-strength rule + change-password hashing."""
import datetime as dt

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import models
from app.db import Base
from app.security import hash_password, password_strength_error, verify_password
from app.services import login_guard as lg


def _db():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def test_lock_seconds_policy():
    assert lg._lock_seconds(lg.THRESHOLD - 1) == 0           # below threshold: no lock
    assert lg._lock_seconds(lg.THRESHOLD) == lg.BASE_LOCK    # first lock = base
    assert lg._lock_seconds(lg.THRESHOLD + 1) == lg.BASE_LOCK * 2
    assert lg._lock_seconds(lg.THRESHOLD + 50) == lg.MAX_LOCK  # capped


def test_login_throttle_locks_after_threshold_then_clears():
    with _db() as db:
        ip = "203.0.113.9"
        assert lg.locked_for(db, ip) == 0
        for _ in range(lg.THRESHOLD - 1):
            lg.record_failure(db, ip)
        assert lg.locked_for(db, ip) == 0                    # not yet
        lg.record_failure(db, ip)                            # THRESHOLD-th failure
        assert lg.locked_for(db, ip) > 0                     # now locked
        lg.record_success(db, ip)                            # a good login clears it
        assert lg.locked_for(db, ip) == 0


def test_login_throttle_is_per_ip():
    with _db() as db:
        for _ in range(lg.THRESHOLD + 1):
            lg.record_failure(db, "10.0.0.1")
        assert lg.locked_for(db, "10.0.0.1") > 0
        assert lg.locked_for(db, "10.0.0.2") == 0            # a different IP is unaffected


def test_expired_lock_reads_as_unlocked():
    with _db() as db:
        ip = "198.51.100.5"
        for _ in range(lg.THRESHOLD):
            lg.record_failure(db, ip)
        row = db.get(models.LoginThrottle, ip)
        row.locked_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)  # already past
        db.commit()
        assert lg.locked_for(db, ip) == 0


def test_password_strength_rule():
    assert password_strength_error("short1") is not None         # too short
    assert password_strength_error("checkpoint") is not None     # common
    assert password_strength_error("alllettershere") is not None  # no digits
    assert password_strength_error("12345678901") is not None     # all digits
    assert password_strength_error("Sup3r-Secret-Pass") is None   # strong enough


def test_change_password_roundtrip_hash():
    h = hash_password("Sup3r-Secret-Pass")
    assert verify_password("Sup3r-Secret-Pass", h) and not verify_password("wrong", h)


def test_user_display_name():
    u = models.User(username="admin", first_name="", last_name="")
    assert u.display_name == "admin"                      # falls back to username
    u.first_name, u.last_name = "Khalid", "Alshawwaf"
    assert u.display_name == "Khalid Alshawwaf"
