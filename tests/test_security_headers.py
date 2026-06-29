"""Defensive HTTP response headers (anti-clickjacking / nosniff / referrer / HSTS)."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware import SecurityHeadersMiddleware


def _app(https: bool) -> TestClient:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, https=https)

    @app.get("/x")
    def _x():
        return {"ok": True}

    return TestClient(app)


def test_security_headers_present_and_hsts_on_https():
    r = _app(https=True).get("/x")
    assert r.status_code == 200
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "same-origin"
    assert "max-age=31536000" in r.headers["strict-transport-security"]


def test_no_hsts_when_not_https():
    r = _app(https=False).get("/x")
    assert "strict-transport-security" not in r.headers       # HSTS only when served over TLS
    assert r.headers["x-frame-options"] == "DENY"             # the rest still apply
