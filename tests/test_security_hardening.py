"""Security-audit fixes: trusted-proxy client-IP resolution (login-throttle anti-bypass), the webhook
callback_url SSRF guard, the table-prefs open-redirect guard, and the clearer layer-not-found message."""
import asyncio
import types

import pytest

import app.config as config
from app.services import access_automation as aa
from app.services import login_guard, ticketing


def _req(xff=None, peer="203.0.113.9"):
    headers = {"x-forwarded-for": xff} if xff is not None else {}
    return types.SimpleNamespace(headers=headers, client=types.SimpleNamespace(host=peer))


def _hops(monkeypatch, n):
    monkeypatch.setattr(config, "get_settings", lambda: types.SimpleNamespace(trusted_proxy_hops=n))


# --- client_ip / login-throttle anti-bypass -------------------------------------------------------
def test_client_ip_ignores_xff_without_trusted_proxy(monkeypatch):
    _hops(monkeypatch, 0)
    # A spoofed X-Forwarded-For must NOT change the throttle key — the direct peer is used.
    assert login_guard.client_ip(_req(xff="1.1.1.1, 2.2.2.2", peer="203.0.113.9")) == "203.0.113.9"
    assert login_guard.client_ip(_req(xff=None, peer="203.0.113.9")) == "203.0.113.9"


def test_client_ip_takes_appended_hop_behind_trusted_proxy(monkeypatch):
    _hops(monkeypatch, 1)
    # Behind one proxy that APPENDS the peer, the real client is the rightmost entry — a spoofed leftmost
    # value is ignored, so an attacker can't rotate it to dodge the lockout.
    assert login_guard.client_ip(_req(xff="9.9.9.9, 198.51.100.7", peer="10.0.0.2")) == "198.51.100.7"
    # Malformed (fewer entries than hops) falls back to the direct peer.
    assert login_guard.client_ip(_req(xff="", peer="10.0.0.2")) == "10.0.0.2"


# --- webhook callback_url SSRF guard --------------------------------------------------------------
def test_callback_url_ssrf_guard_blocks_dangerous_targets():
    blocked = [
        "http://169.254.169.254/latest/meta-data/",   # cloud metadata (link-local)
        "http://127.0.0.1:8000/",                       # loopback
        "http://[::1]/",                                # loopback v6
        "ftp://example.com/x",                          # non-http scheme
        "/no/host",                                     # no host
    ]
    for url in blocked:
        ok, reason = ticketing._outbound_url_ok(url, allow_private=False)
        assert ok is False, f"{url} should be blocked"
    # private is blocked by default, allowed only on opt-in
    assert ticketing._outbound_url_ok("http://10.1.2.3/cb", allow_private=False)[0] is False
    assert ticketing._outbound_url_ok("http://10.1.2.3/cb", allow_private=True)[0] is True
    # a public literal is allowed (IP literal -> no real DNS needed)
    assert ticketing._outbound_url_ok("https://93.184.216.34/cb", allow_private=False)[0] is True


def test_post_callback_refuses_blocked_url_without_posting(monkeypatch):
    from app.services import app_settings
    monkeypatch.setattr(app_settings, "get", lambda k: False)   # private callbacks not allowed
    # the SSRF check must fire BEFORE any HTTP client is built
    monkeypatch.setattr(ticketing.httpx, "Client",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not POST a blocked URL")))
    t = types.SimpleNamespace(ticket_id="T1", callback_url="http://169.254.169.254/", callback_token=None)
    out = ticketing._post_callback(t, {"outcome": "create"})
    assert out["ok"] is False and out.get("blocked") is True


# --- table-prefs open-redirect guard --------------------------------------------------------------
@pytest.mark.parametrize("nxt,expected", [
    ("//evil.com/x", "/"),            # protocol-relative -> rejected
    ("https://evil.com", "/"),        # scheme-bearing -> rejected
    ("http://x", "/"),                # scheme-bearing -> rejected
    ("/settings#grp", "/settings#grp"),   # same-origin path -> kept
])
def test_table_prefs_next_open_redirect_guard(monkeypatch, nxt, expected):
    from app.routers import settings as settings_router

    class _Form(dict):
        def getlist(self, k):
            return []

    async def _form():
        return _Form(next=nxt)

    req = types.SimpleNamespace(form=_form)
    monkeypatch.setattr(settings_router, "get_user_or_none", lambda r, d: types.SimpleNamespace(id=1))
    monkeypatch.setattr(settings_router.table_prefs, "spec", lambda t: None)   # skip the save branch
    resp = asyncio.run(settings_router.save_table_columns("servers", req, db=None))
    assert resp.headers["location"] == expected


# --- layer-name resolution ("Network Layer" -> "Network") -----------------------------------------
def test_resolve_layer_name_normalizes_and_lists():
    session = types.SimpleNamespace(list_access_layers=lambda: [{"name": "Network"}, {"name": "DMZ"}])
    assert aa.resolve_layer_name(session, "Network") == ("Network", "")          # exact
    assert aa.resolve_layer_name(session, "network")[0] == "Network"             # case-insensitive exact
    canon, note = aa.resolve_layer_name(session, "Network Layer")                # the reported bug (capital L)
    assert canon == "Network" and "Network" in note
    assert aa.resolve_layer_name(session, "network layer")[0] == "Network"       # lowercase too
    with pytest.raises(aa.MgmtError) as e:
        aa.resolve_layer_name(session, "Bogus Layer")
    assert "Available access layers" in str(e.value) and "Network" in str(e.value)


def test_resolve_layer_name_passthrough_when_unlistable():
    # If layers can't be listed, fall back to the requested name (the later load surfaces the real error).
    session = types.SimpleNamespace(list_access_layers=lambda: (_ for _ in ()).throw(RuntimeError("no api")))
    assert aa.resolve_layer_name(session, "Whatever") == ("Whatever", "")


# --- clearer layer-not-found message --------------------------------------------------------------
def test_load_layer_missing_lists_available_layers(monkeypatch):
    def _boom(session, name, package, max_rules=50000):
        raise aa.MgmtError("Requested object [Network Layer] not found")
    monkeypatch.setattr(aa, "_pull_items", _boom)
    session = types.SimpleNamespace(list_access_layers=lambda: [{"name": "Network"}, {"name": "DMZ"}])
    with pytest.raises(aa.MgmtError) as e:
        aa.load_layer(session, "Network Layer")
    msg = str(e.value)
    assert "Network Layer" in msg and "not found" in msg
    assert "Available access layers" in msg and "Network" in msg and "DMZ" in msg
