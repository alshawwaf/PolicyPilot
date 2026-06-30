"""IaC Exporter landing — lists the user's management servers, each linking into the existing per-server
export pages (policy layer → Terraform/Ansible/mgmt_cli; Gaia OS config → Terraform/Ansible/clish). Renders
server cards + an empty state; gated by auth and scoped to the owner."""
import types

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — registers tables
from app.db import Base
from app.models import ManagementServer, User
from app.routers import iac_exporter as ie
from app.routers.ui import templates


def _render(**ctx):
    ctx.setdefault("request", None)
    ctx.setdefault("flash", None)
    return templates.env.get_template("iac_exporter.html").render(**ctx)


def test_renders_both_export_links_when_credential_saved():
    ms = types.SimpleNamespace(id=3, name="HQ-SMS", host="10.0.0.1", port=443, domain="")
    html = _render(rows=[{"ms": ms, "has_secret": True}])
    assert "IaC Exporter" in html and "HQ-SMS" in html
    assert "/management/3/export" in html          # policy-layer export
    assert "/management/3/gaia-export" in html      # Gaia OS config export


def test_no_credential_still_offers_gaia_and_add_credential():
    ms = types.SimpleNamespace(id=4, name="NoCred", host="h", port=443, domain="d1")
    html = _render(rows=[{"ms": ms, "has_secret": False}])
    # Gaia export accepts a runtime password, so it's offered even without a saved secret…
    assert "/management/4/gaia-export" in html
    # …but the policy export needs a saved credential, so it's not linked; nudge to add one instead.
    assert "/management/4/export" not in html
    assert "/management/4/edit" in html


def test_empty_state_when_no_servers():
    html = _render(rows=[])
    assert "No management servers yet" in html and "/management/new" in html


def test_route_redirects_when_logged_out(monkeypatch):
    monkeypatch.setattr(ie, "get_user_or_none", lambda req, db: None)
    resp = ie.iac_exporter(request=None, db=None)
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
    monkeypatch.setattr(ie, "get_user_or_none", lambda req, d: db.get(User, u.id))
    monkeypatch.setattr(ie, "_pop_flash", lambda req: None)   # no SessionMiddleware in this minimal test
    monkeypatch.setattr(ie.mgmt_creds, "has_secret", lambda d, m: True)
    captured = {}
    monkeypatch.setattr(ie.templates, "TemplateResponse",
                        lambda req, tpl, ctx: captured.update(tpl=tpl, ctx=ctx) or "OK")
    out = ie.iac_exporter(request=None, db=db)
    assert out == "OK" and captured["tpl"] == "iac_exporter.html"
    names = [r["ms"].name for r in captured["ctx"]["rows"]]
    assert names == ["Mine"]                     # never lists another user's servers
    db.close()
