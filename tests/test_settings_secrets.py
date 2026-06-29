"""Portal-configurable integration secrets: encrypted-at-rest storage in app_settings, the env-fallback
resolvers, and the consumers (MCP token, webhook token/scope, ServiceNow write-back) reading them — so an
admin can set/rotate every integration from the portal with no redeploy."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — registers tables on Base.metadata
from app.config import get_settings
from app.db import Base
from app.models import AppState
from app.services import app_settings, crypto


@pytest.fixture()
def sdb(monkeypatch):
    """An isolated in-memory AppState store + a configured encryption key, wired into app_settings."""
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    monkeypatch.setattr(app_settings, "SessionLocal", sessionmaker(bind=eng))
    app_settings._cache["at"] = -1e9
    app_settings._secret_cache.clear()
    monkeypatch.setenv("DCSIM_SESSION_SECRET", "unit-test-secret-please-ignore")
    get_settings.cache_clear()
    yield app_settings
    app_settings._secret_cache.clear()
    get_settings.cache_clear()


def _crypto_or_skip():
    if not crypto.available():
        pytest.skip("cryptography library unavailable")


# --- encrypted secret round-trip -----------------------------------------------------------------
def test_secret_set_get_clear_roundtrip(sdb):
    _crypto_or_skip()
    assert sdb.get_secret("webhook_token") == ""            # unset
    sdb.set_secret("webhook_token", "s3cr3t-token")
    assert sdb.get_secret("webhook_token") == "s3cr3t-token"
    sdb.clear_secret("webhook_token")
    assert sdb.get_secret("webhook_token") == ""


def test_secret_stored_ciphertext_not_plaintext(sdb):
    _crypto_or_skip()
    sdb.set_secret("webhook_token", "plain-value-123")
    with sdb.SessionLocal() as db:
        row = db.get(AppState, "set:webhook_token")
    assert row is not None
    assert "plain-value-123" not in row.value          # encrypted at rest
    assert row.value.startswith("v1.")                 # crypto.py token format


def test_secret_blank_is_keep_not_clear(sdb):
    _crypto_or_skip()
    sdb.set_secret("mcp_token", "keepme")
    sdb.set_secret("mcp_token", "")                    # blank submit -> no-op (don't wipe)
    assert sdb.get_secret("mcp_token") == "keepme"


def test_secret_never_in_all_values_or_defaults(sdb):
    _crypto_or_skip()
    sdb.set_secret("webhook_token", "leaky")
    assert "webhook_token" not in sdb.all_values(fresh=True)   # would otherwise be echoed into the form
    assert "webhook_token" not in sdb.defaults()
    for k in ("webhook_token", "servicenow_password"):
        assert k not in sdb.all_values()


def test_secret_status_reflects_presence(sdb):
    _crypto_or_skip()
    status = sdb.secret_status()
    assert status == {"webhook_token": False, "servicenow_password": False}
    sdb.set_secret("servicenow_password", "pw")
    assert sdb.secret_status()["servicenow_password"] is True


def test_set_secret_refuses_when_crypto_unavailable(sdb, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("encryption unavailable")
    monkeypatch.setattr(app_settings.crypto, "encrypt", _boom)
    with pytest.raises(RuntimeError):
        sdb.set_secret("webhook_token", "should-not-store")
    with sdb.SessionLocal() as db:
        assert db.get(AppState, "set:webhook_token") is None    # nothing persisted in cleartext


# --- env-fallback resolvers ----------------------------------------------------------------------
def test_get_or_env_precedence(sdb, monkeypatch):
    assert sdb.get_or_env("webhook_server_ids", "9,9") == "9,9"   # unset -> env value
    sdb.save({"webhook_server_ids": "1,3"})
    assert sdb.get_or_env("webhook_server_ids", "9,9") == "1,3"   # setting wins
    assert sdb.get_or_env("webhook_server_ids", "") == "1,3"


def test_get_secret_or_env_precedence(sdb):
    _crypto_or_skip()
    assert sdb.get_secret_or_env("webhook_token", "env-tok") == "env-tok"   # unset -> env
    sdb.set_secret("webhook_token", "db-tok")
    assert sdb.get_secret_or_env("webhook_token", "env-tok") == "db-tok"    # setting wins
    assert sdb.get_secret_or_env("webhook_token", "") == "db-tok"


# --- consumers: webhook scope (fail-closed preserved) --------------------------------------------
def test_webhook_allowlist_from_setting_and_failclosed(sdb):
    from app.routers import access_automation as aa
    assert aa._allowed_server_ids() == set()             # nothing set -> documented allow-all
    sdb.save({"webhook_server_ids": "1,3"})
    assert aa._allowed_server_ids() == {1, 3}
    sdb.save({"webhook_server_ids": "1,prod-2"})         # a typo must FAIL CLOSED, never allow-all
    with pytest.raises(ValueError):
        aa._allowed_server_ids()


# --- consumers: ServiceNow write-back resolves from settings -------------------------------------
def test_servicenow_cfg_resolves_from_settings(sdb):
    _crypto_or_skip()
    from app.services import ticketing
    assert ticketing.servicenow_configured() is False
    sdb.save({"servicenow_instance": "https://dev1.service-now.com", "servicenow_user": "svc"})
    sdb.set_secret("servicenow_password", "snow-pw")
    inst, user, pw, table = ticketing._servicenow_cfg()
    assert (inst, user, pw, table) == ("https://dev1.service-now.com", "svc", "snow-pw", "incident")
    assert ticketing.servicenow_configured() is True
    sdb.save({"servicenow_table": "change_request"})
    assert ticketing._servicenow_cfg()[3] == "change_request"


# --- base_url resolver (Setting over env) --------------------------------------------------------
def test_base_url_resolves_setting_then_env(sdb):
    assert sdb.base_url() == "http://localhost:8000"     # nothing set -> env/default
    sdb.save({"base_url": "https://dcsim.example.com"})
    assert sdb.base_url() == "https://dcsim.example.com"  # Setting wins, no redeploy


# --- TLS verification is never disablable (org policy) -------------------------------------------
def test_cp_docs_tls_verification_locked_on(monkeypatch):
    monkeypatch.setenv("VERIFY_SSL", "false")            # an env off-switch must NOT take effect
    import importlib

    from app.services.cp_docs import config as cpc
    importlib.reload(cpc)
    assert cpc.VERIFY_SSL is True
    importlib.reload(cpc)                                # leave the module in a clean state


# --- activity redaction covers the secret keys ---------------------------------------------------
def test_activity_redacts_secret_setting_keys():
    from app.services import activity
    redacted = activity.redact_body({"mcp_token": "abc", "webhook_token": "def",
                                     "servicenow_password": "ghi", "servicenow_user": "ok-to-log"})
    assert redacted["mcp_token"] == "***" and redacted["webhook_token"] == "***"
    assert redacted["servicenow_password"] == "***"
    assert redacted["servicenow_user"] == "ok-to-log"     # non-secret config is still visible
