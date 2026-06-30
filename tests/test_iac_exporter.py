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
    ctx.setdefault("gateways", [])
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


def test_no_password_field__exporter_reuses_saved_credentials():
    ms = types.SimpleNamespace(id=4, name="NoCred", host="h", port=443, domain="d1")
    html = _render(rows=[{"ms": ms, "has_secret": False, "has_gaia": False}])
    assert 'data-id="4"' in html and 'data-secret="0"' in html and 'data-gaia="0"' in html
    # No password field — Gaia export reuses saved credentials (gateway password / the SMS's Gaia creds).
    assert 'id="iax-gaia-pw"' not in html
    # The "no Gaia credentials saved" note is in the panel for the JS to surface when none are on file.
    assert 'id="iax-gaia-nocred"' in html


def test_management_form_has_distinct_gaia_section():
    ms = types.SimpleNamespace(id=1, name="SMS", host="h", port=443, domain="", username="api",
                               gaia_username="admin", cert_pem="", auto_trust=True)
    html = templates.env.get_template("_management_form.html").render(
        ms=ms, error=None, action="/x", has_secret=True, has_gaia_secret=True, crypto_ok=True)
    assert "SmartConsole / Management API" in html          # the API creds are clearly labelled now
    assert "Gaia OS credentials" in html                    # the separate, optional Gaia section
    assert 'name="gaia_username"' in html and 'name="gaia_password"' in html
    assert 'name="clear_gaia_password"' in html             # clear control shown when a Gaia secret is saved


def test_server_gaia_creds_flag_in_rail():
    ms = types.SimpleNamespace(id=2, name="SMS2", host="h", port=443, domain="")
    assert 'data-gaia="1"' in _render(rows=[{"ms": ms, "has_secret": True, "has_gaia": True}])
    assert 'data-gaia="0"' in _render(rows=[{"ms": ms, "has_secret": True, "has_gaia": False}])


def test_empty_state_when_no_servers_or_gateways():
    html = _render(rows=[], gateways=[])
    assert "Nothing to export yet" in html and "/management/new" in html and "/gateways/new" in html


def test_gateway_appears_as_gaia_only_export_target():
    gw = types.SimpleNamespace(id=7, name="GW", host="g.example", port=443)
    html = _render(rows=[], gateways=[{"gw": gw, "has_secret": True}])
    assert 'data-kind="gateway"' in html and 'data-id="7"' in html and "GW" in html
    # the gateway Gaia export endpoint is wired in the inline script (kind-aware base path + /gaia-export/run)
    assert "'/gateways/'" in html and "/gaia-export/run" in html


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
