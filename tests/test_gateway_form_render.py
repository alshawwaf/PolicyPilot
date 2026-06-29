"""The gateway form/detail templates render in both crypto states — encryption available
(password field offered) and unavailable (field disabled, falls back to per-apply)."""
from app.routers.ui import templates


class _GW:
    id, name, host, port = 7, "GW", "10.0.0.1", 443
    username, cert_pem = "admin", ""
    auto_trust = True


def _render(name, **ctx):
    ctx.setdefault("request", None)
    return templates.env.get_template(name).render(**ctx)


def test_form_enabled_offers_password_field():
    html = _render("gateway_form.html", gw=None, error=None, action="/gateways/new",
                   crypto_ok=True, has_password=False)
    assert 'name="password"' in html and "AES-256" in html
    assert "Encryption unavailable" not in html


def test_form_enabled_edit_offers_clear_when_saved():
    html = _render("gateway_form.html", gw=_GW(), error=None, action="/gateways/7/edit",
                   crypto_ok=True, has_password=True)
    assert 'name="clear_password"' in html and "Clear the saved password" in html


def test_form_offers_auto_trust_on_by_default_for_new():
    html = _render("gateway_form.html", gw=None, error=None, action="/gateways/new",
                   crypto_ok=True, has_password=False)
    assert 'name="auto_trust"' in html
    assert 'name="auto_trust" value="1" checked' in html  # default on for new gateways
    assert "pin it for you on save" in html                # eager pin: trust handled behind the scenes


def test_form_auto_trust_reflects_disabled_state_on_edit():
    gw = _GW()
    gw.auto_trust = False
    html = _render("gateway_form.html", gw=gw, error=None, action="/gateways/7/edit",
                   crypto_ok=True, has_password=False)
    assert 'name="auto_trust"' in html
    assert 'name="auto_trust" value="1" checked' not in html  # unticked, so not auto-trusting


def test_form_degraded_disables_field():
    html = _render("gateway_form.html", gw=None, error=None, action="/gateways/new",
                   crypto_ok=False, has_password=False)
    assert "Encryption unavailable" in html
    # the disabled input has no name, so nothing is ever submitted/stored
    assert 'name="password"' not in html


class _Layer:
    id, name, layer_name, description = 1, "L", "dynamic_layer", ""
    content = {}


def test_layer_apply_form_drops_the_password_field():
    html = _render(
        "dynamic_detail.html", layer=_Layer(), payload_json="{}", tasks=[], task_total=0,
        latest=None, layer_gateway_id=1, mock_url="http://x/gaia_api/v1.9",
        gateways=[{"id": 1, "name": "GW", "host": "h", "port": 443,
                   "username": "admin", "cert_pem": "", "has_password": True}],
    )
    assert "gw_pass" not in html  # the password input and its JS are gone
    assert "all come from the selected" in html  # consolidated onto the gateway profile
    assert "/layers/1/edit" in html  # Edit affordance to change rules and re-push


def test_detail_shows_password_status():
    saved = _render("gateway_detail.html", gw=_GW(), snapshot=None, has_password=True, flash=None)
    assert "saved (encrypted)" in saved and "leave blank, or type to override" in saved
    plain = _render("gateway_detail.html", gw=_GW(), snapshot=None, has_password=False, flash=None)
    assert "entered per apply" in plain
