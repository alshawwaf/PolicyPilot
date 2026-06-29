"""Policy Manager landing — the first-class "fourth face": lists the user's management servers, each linking
into the existing live policy viewer/editor. Renders server cards + an empty state; gated by auth."""
import types

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — registers tables
from app.db import Base
from app.models import ManagementServer, User
from app.routers import policy_manager as pm
from app.routers.ui import templates


def _render(**ctx):
    ctx.setdefault("request", None)
    ctx.setdefault("flash", None)
    return templates.env.get_template("policy_manager.html").render(**ctx)


def test_renders_server_cards_with_open_link():
    ms = types.SimpleNamespace(id=3, name="HQ-SMS", host="10.0.0.1", port=443, domain="")
    html = _render(rows=[{"ms": ms, "has_secret": True}])
    assert "Policy Manager" in html
    assert "HQ-SMS" in html and "/management/3" in html and "Open live policy" in html


def test_renders_add_credential_when_no_secret():
    ms = types.SimpleNamespace(id=4, name="NoCred", host="h", port=443, domain="d1")
    html = _render(rows=[{"ms": ms, "has_secret": False}])
    assert "no credential" in html and "/management/4/edit" in html
    assert "Open live policy" not in html        # can't browse a server without a saved credential


def test_empty_state_when_no_servers():
    html = _render(rows=[])
    assert "No management servers yet" in html and "/management/new" in html


def test_route_redirects_when_logged_out(monkeypatch):
    monkeypatch.setattr(pm, "get_user_or_none", lambda req, db: None)
    resp = pm.policy_manager(request=None, db=None)
    assert resp.status_code == 303 and resp.headers["location"] == "/login"


def test_route_lists_only_owned_servers(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    u = User(username="a", password_hash="x")
    other = User(username="b", password_hash="x")
    db.add_all([u, other]); db.commit()
    db.add(ManagementServer(name="Mine", host="h1", port=443, username="admin", owner_id=u.id))
    db.add(ManagementServer(name="Theirs", host="h2", port=443, username="admin", owner_id=other.id))
    db.commit()
    monkeypatch.setattr(pm, "get_user_or_none", lambda req, d: db.get(User, u.id))
    monkeypatch.setattr(pm, "_pop_flash", lambda req: None)   # no SessionMiddleware in this minimal test
    monkeypatch.setattr(pm.mgmt_creds, "has_secret", lambda d, m: True)
    captured = {}
    monkeypatch.setattr(pm.templates, "TemplateResponse",
                        lambda req, tpl, ctx: captured.update(tpl=tpl, ctx=ctx) or "OK")
    out = pm.policy_manager(request=None, db=db)
    assert out == "OK" and captured["tpl"] == "policy_manager.html"
    names = [r["ms"].name for r in captured["ctx"]["rows"]]
    assert names == ["Mine"]                     # never lists another user's servers
    db.close()
