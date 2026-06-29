"""Activity middleware: routing/exclusions + form-and-JSON body redaction (security)."""
import json

from app.middleware import _excluded, _kind, _parse_request


def test_kind_classification():
    assert _kind("/dbapi/v1/servers") == "api"
    assert _kind("/mcp/") == "api"
    assert _kind("/access-automation/webhook") == "api"
    assert _kind("/layers/1") == "ui"
    assert _kind("/access-automation") == "ui"


def test_exclusions():
    assert _excluded("/activity/rows")          # log viewer — avoid feedback loop
    assert _excluded("/healthz")
    assert _excluded("/layers/1/apply-status/xyz")
    assert _excluded("/api-explorer/proxy")     # relays the user's own server creds — never persist
    assert not _excluded("/dbapi/v1/servers")
    assert not _excluded("/login")


def test_form_body_redaction():
    body = b"username=admin&password=topsecret&gw_pass=gwsecret&basic_pass=bp&gw_host=10.0.0.1"
    out = _parse_request(body, "application/x-www-form-urlencoded")
    assert out["username"] == "admin"
    assert out["gw_host"] == "10.0.0.1"
    assert out["password"] == "***"
    assert out["gw_pass"] == "***"
    assert out["basic_pass"] == "***"


def test_json_body_redaction():
    raw = json.dumps({"user": "a", "password": "p", "auth_header_value": "v", "name": "ok"}).encode()
    out = _parse_request(raw, "application/json")
    assert out["password"] == "***"
    assert out["auth_header_value"] == "***"
    assert out["user"] == "a"
    assert out["name"] == "ok"
