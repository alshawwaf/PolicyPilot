"""Named, revocable API keys for the machine endpoints — hashed at rest, show-once, constant-time verify,
and the MCP/webhook guards accepting them alongside the legacy shared token."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — registers tables on Base.metadata
from app.db import Base
from app.models import ApiKey
from app.services import api_keys


@pytest.fixture()
def kdb(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    monkeypatch.setattr(api_keys, "SessionLocal", sessionmaker(bind=eng))
    monkeypatch.setattr(api_keys, "_touch", lambda *a, **k: None)   # last-used is fire-and-forget telemetry
    api_keys._cache.clear()
    api_keys._last_used_write.clear()
    yield api_keys
    api_keys._cache.clear()
    api_keys._last_used_write.clear()


def test_generate_returns_plaintext_and_stores_only_hash(kdb):
    row, secret = kdb.generate("n8n-prod", "mcp", created_by="admin")
    assert secret.startswith("dcsim_mcp_") and len(secret) > 30
    assert row.name == "n8n-prod" and row.scope == "mcp" and row.hint == secret[-4:]
    with kdb.SessionLocal() as db:
        stored = db.get(ApiKey, row.id)
    assert secret not in stored.key_hash                 # plaintext never persisted
    assert stored.key_hash and len(stored.key_hash) == 64   # sha256 hex


def test_verify_matches_only_correct_key_and_scope(kdb):
    _, secret = kdb.generate("k1", "mcp")
    assert kdb.verify(secret, "mcp") is True
    assert kdb.verify(secret + "x", "mcp") is False      # wrong key
    assert kdb.verify(secret, "webhook") is False        # right key, wrong scope
    assert kdb.verify("", "mcp") is False


def test_revoke_disables_immediately(kdb):
    row, secret = kdb.generate("k2", "mcp")
    assert kdb.verify(secret, "mcp") is True
    assert kdb.revoke(row.id) is True
    assert kdb.verify(secret, "mcp") is False            # cache busted on revoke -> immediate
    assert kdb.any_active("mcp") is False
    assert kdb.revoke(row.id) is False                   # already gone


def test_any_active_and_list(kdb):
    assert kdb.any_active("mcp") is False
    kdb.generate("a", "mcp")
    kdb.generate("b", "webhook")
    assert kdb.any_active("mcp") is True and kdb.any_active("webhook") is True
    assert {k.name for k in kdb.list_keys()} == {"a", "b"}
    assert {k.name for k in kdb.list_keys("webhook")} == {"b"}


def test_multiple_mcp_keys_each_validate(kdb):
    _, s1 = kdb.generate("laptop", "mcp")
    _, s2 = kdb.generate("ci", "mcp")
    assert kdb.verify(s1, "mcp") and kdb.verify(s2, "mcp")
    # revoke one; the other still works
    row = next(k for k in kdb.list_keys("mcp") if k.name == "laptop")
    kdb.revoke(row.id)
    assert kdb.verify(s1, "mcp") is False and kdb.verify(s2, "mcp") is True


def test_expires_at_has_additive_migration():
    # create_all won't add a column to the already-shipped api_keys table — the additive migration must
    # carry expires_at so existing (preview + deployed) DBs get it on boot, not just fresh ones.
    from app import db
    assert "expires_at" in db._ADDED_COLUMNS.get("api_keys", {})


def test_expired_key_does_not_authenticate(kdb):
    import datetime as dt
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
    _, expired = kdb.generate("old", "mcp", expires_at=past)
    _, valid = kdb.generate("fresh", "mcp", expires_at=future)
    assert kdb.verify(expired, "mcp") is False        # past expiry -> rejected
    assert kdb.verify(valid, "mcp") is True            # future expiry -> ok
    # any_active counts only live keys: with ONLY the expired one, the scope is not "configured"
    kdb.revoke(next(k.id for k in kdb.list_keys("mcp") if k.name == "fresh"))
    assert kdb.any_active("mcp") is False


def test_expiry_naive_datetime_is_handled(kdb):
    import datetime as dt
    naive_past = dt.datetime.utcnow() - dt.timedelta(days=1)   # naive (as SQLite may return)
    _, k = kdb.generate("naive", "mcp", expires_at=naive_past)
    assert kdb.verify(k, "mcp") is False               # as_utc() coercion -> no TypeError, correctly expired


def test_set_expiry_changes_authentication_immediately(kdb):
    import datetime as dt
    _, secret = kdb.generate("k", "mcp")                       # no expiry -> authenticates
    assert kdb.verify(secret, "mcp") is True
    kid = next(k.id for k in kdb.list_keys("mcp"))
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    assert kdb.set_expiry(kid, past) is True
    assert kdb.verify(secret, "mcp") is False                  # now expired -> rejected (cache busted)
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)
    assert kdb.set_expiry(kid, future) is True
    assert kdb.verify(secret, "mcp") is True                   # extended -> authenticates again
    assert kdb.set_expiry(kid, None) is True and kdb.verify(secret, "mcp") is True   # 'never'
    assert kdb.set_expiry(10_000_000, future) is False         # no such key


def test_webhook_auth_header_is_redacted_in_activity_log():
    # a webhook key/token rides in X-DCSim-Token; it must never be logged in the clear
    from app.services import activity
    out = activity.redact_headers({"X-DCSim-Token": "dcsim_webhook_supersecret", "accept": "application/json"})
    assert out["X-DCSim-Token"] == "(masked)" and out["accept"] == "application/json"


def test_active_fails_closed_on_db_error(monkeypatch):
    # no DB wired -> _active swallows the error and returns no keys (never crashes the auth path)
    monkeypatch.setattr(api_keys, "_cache", {})
    monkeypatch.setattr(api_keys, "SessionLocal", lambda: (_ for _ in ()).throw(RuntimeError("no db")))
    assert api_keys.verify("anything", "mcp") is False
    assert api_keys.any_active("mcp") is False


# --- the MCP guard accepts an API key OR the legacy token ----------------------------------------
def test_authorize_mcp_accepts_an_active_mcp_key(kdb):
    # API keys are the SINGLE auth mechanism for /mcp (no shared bearer token).
    from app import mcp_server
    assert mcp_server.mcp_enabled() is False                  # no key yet -> endpoint disabled
    _, secret = kdb.generate("agent", "mcp")
    assert mcp_server.mcp_enabled() is True                   # an active mcp key enables it
    assert mcp_server.authorize_mcp(secret) is True           # the key authorizes
    assert mcp_server.authorize_mcp("nope") is False
    assert mcp_server.authorize_mcp("") is False
