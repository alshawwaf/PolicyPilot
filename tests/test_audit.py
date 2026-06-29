"""Governance audit: emit() notifies every user in-app (when enabled) and POSTs the configured webhook
(metadata only), and is a no-op when disabled/unset. Best-effort — never raises."""
import types

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — registers tables
from app.db import Base
from app.models import Notification, User
from app.services import app_settings, audit


@pytest.fixture()
def db(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    monkeypatch.setattr(audit, "SessionLocal", S)
    s = S()
    s.add_all([User(username="a", password_hash="x"), User(username="b", password_hash="x")])
    s.commit(); s.close()
    return S


def _settings(monkeypatch, *, notify, url=""):
    monkeypatch.setattr(app_settings, "get", lambda k: notify if k == "audit_notify" else None)
    monkeypatch.setattr(app_settings, "get_secret_or_env",
                        lambda k, d="": url if k == "audit_webhook_url" else d)


def test_emit_notifies_every_user_when_enabled(db, monkeypatch):
    _settings(monkeypatch, notify=True)
    audit.emit("mcp · apply (create) on HQ / Network", actor="mcp")
    s = db()
    rows = s.scalars(select(Notification)).all()
    assert len(rows) == 2 and all(r.text.startswith("Audit · mcp · apply") for r in rows)
    s.close()


def test_emit_skips_inapp_when_disabled(db, monkeypatch):
    _settings(monkeypatch, notify=False)
    audit.emit("x")
    s = db(); assert s.scalars(select(Notification)).all() == []; s.close()


def test_emit_blank_summary_is_noop(db, monkeypatch):
    _settings(monkeypatch, notify=True)
    audit.emit("   ")
    s = db(); assert s.scalars(select(Notification)).all() == []; s.close()


def test_emit_posts_webhook_when_url_set(db, monkeypatch):
    _settings(monkeypatch, notify=False, url="https://hooks.example/abc")   # isolate the webhook path
    monkeypatch.setattr(audit.threading, "Thread",
                        lambda target=None, daemon=None: types.SimpleNamespace(start=target))
    sent = {}

    class _Client:
        def __init__(self, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None):
            sent.update(url=url, json=json)

    import httpx
    monkeypatch.setattr(httpx, "Client", _Client)
    audit.emit("agent · pushed dynamic layer “DMZ” to gateway GW1", actor="agent")
    assert sent["url"] == "https://hooks.example/abc"
    assert sent["json"]["actor"] == "agent" and "DMZ" in sent["json"]["text"]
    assert sent["json"]["source"] == "PolicyPilot"


def test_emit_no_webhook_thread_when_url_blank(db, monkeypatch):
    _settings(monkeypatch, notify=False, url="")
    spawned = {"n": 0}
    monkeypatch.setattr(audit.threading, "Thread",
                        lambda **k: spawned.update(n=spawned["n"] + 1) or types.SimpleNamespace(start=lambda: None))
    audit.emit("x")
    assert spawned["n"] == 0      # no outbound thread when no URL is configured


def test_change_log_record_emits_audit_on_committed_change(monkeypatch):
    # The Rail A chokepoint must raise a governance event (metadata: actor, action, outcome, server/layer).
    from app.services import change_log
    seen = {}
    monkeypatch.setattr(audit, "emit", lambda s, **k: seen.update(summary=s, actor=k.get("actor")))
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    server = types.SimpleNamespace(id=1, name="HQ")
    result = {"ok": True, "published": True, "applied": True, "outcome": "create", "inverse": []}
    change_log.record(s, server=server, result=result, request={"source": "10.0.0.5"},
                      layer="Network", ticket_id="INC42", actor="mcp")
    s.close()
    assert "mcp" in seen["summary"] and "create" in seen["summary"] and "HQ" in seen["summary"]
    assert "INC42" in seen["summary"] and seen["actor"] == "mcp"


def test_change_log_record_no_audit_for_dry_run(monkeypatch):
    # A non-committed result (dry-run / no-op) records nothing and raises no audit event.
    from app.services import change_log
    seen = {"n": 0}
    monkeypatch.setattr(audit, "emit", lambda s, **k: seen.update(n=seen["n"] + 1))
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    change_log.record(s, server=types.SimpleNamespace(id=1, name="HQ"),
                      result={"ok": True, "published": False, "applied": False, "outcome": "no_op"},
                      request={}, layer="Network", actor="mcp")
    s.close()
    assert seen["n"] == 0
