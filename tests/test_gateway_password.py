"""Encrypted-at-rest storage for the optional saved gateway password (AES-256-GCM).

Skipped where `cryptography` is not installed (e.g. a minimal local env); runs in the
deployed image / CI where the library is present.
"""
import pytest

pytest.importorskip("cryptography")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import models  # noqa: E402,F401  (register tables on the metadata)
from app.config import get_settings  # noqa: E402
from app.db import Base  # noqa: E402
from app.models import Gateway, GatewaySecret  # noqa: E402
from app.services import gateway_creds  # noqa: E402


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("DCSIM_ENCRYPTION_KEY", "unit-test-key-do-not-use-in-prod-0001")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False)()


def _gw(db):
    gw = Gateway(token="tok-pw", name="GW", host="10.0.0.1", port=443, username="admin", owner_id=1)
    db.add(gw)
    db.commit()
    return gw


def test_available_when_key_is_set():
    assert gateway_creds.available() is True


def test_round_trip_without_leaking_plaintext():
    token = gateway_creds.encrypt("Cpwins!1")
    assert "Cpwins!1" not in token and token.startswith("v1.")
    assert gateway_creds.decrypt(token) == "Cpwins!1"


def test_random_nonce_makes_each_token_unique():
    a, b = gateway_creds.encrypt("same"), gateway_creds.encrypt("same")
    assert a != b  # fresh 96-bit nonce per encryption
    assert gateway_creds.decrypt(a) == gateway_creds.decrypt(b) == "same"


def test_decrypt_rejects_bad_tokens():
    assert gateway_creds.decrypt("") is None
    assert gateway_creds.decrypt("garbage-no-prefix") is None
    assert gateway_creds.decrypt("v1.not-valid-base64-@@@") is None
    assert gateway_creds.decrypt("v1.QUJD") is None  # decodes but too short to be valid


def test_store_get_and_clear_on_a_gateway():
    db = _session()
    gw = _gw(db)
    assert gateway_creds.has_password(db, gw) is False
    assert gateway_creds.get_password(db, gw) is None

    gateway_creds.store_password(db, gw, "s3cret")
    db.commit()
    assert gateway_creds.has_password(db, gw) is True
    assert gateway_creds.get_password(db, gw) == "s3cret"

    gateway_creds.store_password(db, gw, "rotated")  # upsert, not a second row
    db.commit()
    assert db.query(GatewaySecret).filter_by(gateway_id=gw.id).count() == 1
    assert gateway_creds.get_password(db, gw) == "rotated"

    gateway_creds.clear_password(db, gw)
    db.commit()
    assert gateway_creds.has_password(db, gw) is False
    assert gateway_creds.get_password(db, gw) is None


def test_rotating_the_key_invalidates_stored_secrets(monkeypatch):
    token = gateway_creds.encrypt("topsecret")
    monkeypatch.setenv("DCSIM_ENCRYPTION_KEY", "a-totally-different-key-99999")
    get_settings.cache_clear()
    assert gateway_creds.decrypt(token) is None  # AES-GCM tag fails under the wrong key
