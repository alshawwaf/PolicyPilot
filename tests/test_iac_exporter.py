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


def test_renders_server_in_rail_and_wires_both_export_endpoints():
    # Two-pane design: the server is a selectable rail button carrying data-* the JS reads; the export
    # endpoints are called from the inline script (no per-row links), so assert both the row + the wiring.
    ms = types.SimpleNamespace(id=3, name="HQ-SMS", host="10.0.0.1", port=443, domain="")
    html = _render(rows=[{"ms": ms, "has_secret": True}])
    assert "IaC Exporter" in html and "HQ-SMS" in html
    assert 'data-id="3"' in html and 'data-secret="1"' in html and "credential saved" in html
    assert "/export?name=" in html        # policy-layer export endpoint, called inline
    assert "/gaia-export/run" in html      # Gaia OS config export endpoint, called inline


def test_no_credential_server_marked_and_gaia_password_available():
    ms = types.SimpleNamespace(id=4, name="NoCred", host="h", port=443, domain="d1")
    html = _render(rows=[{"ms": ms, "has_secret": False}])
    assert 'data-id="4"' in html and 'data-secret="0"' in html and "no credential" in html
    # Gaia export accepts a runtime password (the field is always present)…
    assert 'id="iax-gaia-pw"' in html
    # …while the policy side shows the "needs a saved credential" note instead of pulling.
    assert "no saved credential" in html


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
