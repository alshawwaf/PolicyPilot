"""The PolicyPilot API docs app (/api-docs): a themed Swagger UI over the portal's OWN REST API. The spec
is FastAPI's live OpenAPI, filtered to the public /dbapi/v1 surface (the `api` tag) with a Bearer security
scheme injected. These assert the filter never leaks non-API routes and that auth is enforced."""
import pytest
from fastapi.testclient import TestClient

import app.main
from app.routers import api_docs


@pytest.fixture(scope="module")
def client():
    # No context-manager form here: these tests don't query the DB (they read app.openapi() and monkeypatch
    # auth), and entering the shared app's lifespan a second time would re-run the one-shot MCP session
    # manager (StreamableHTTPSessionManager.run() can only be called once per instance).
    return TestClient(app.main.app)


def test_spec_and_page_require_auth(client):
    assert client.get("/api-docs/openapi.json").status_code == 401          # data endpoint → 401
    assert client.get("/api-docs", follow_redirects=False).status_code == 303  # page → /login


def test_spec_is_filtered_to_the_public_rest_api(client, monkeypatch):
    monkeypatch.setattr(api_docs, "get_user_or_none", lambda req, db: object())
    j = client.get("/api-docs/openapi.json").json()
    paths = list(j["paths"])
    assert paths, "spec exposed no paths"
    assert all(p.startswith("/dbapi/v1") for p in paths), f"leaked non-API routes: {paths}"
    # the UI routes themselves (include_in_schema=False) and other UI endpoints must never appear
    assert not any(p.startswith("/api-docs") or p == "/access-automation" for p in paths)
    assert j["info"]["title"] == "PolicyPilot API"


def test_spec_injects_bearer_security_on_every_op(client, monkeypatch):
    monkeypatch.setattr(api_docs, "get_user_or_none", lambda req, db: object())
    j = client.get("/api-docs/openapi.json").json()
    scheme = j["components"]["securitySchemes"]["ApiKeyAuth"]
    assert scheme["type"] == "http" and scheme["scheme"] == "bearer"
    for path, item in j["paths"].items():
        for method, op in item.items():
            assert op.get("security") == [{"ApiKeyAuth": []}], f"{method} {path} missing bearer security"
    # request-body schemas resolve (components copied wholesale, so $refs aren't dangling)
    assert "ApplyBody" in j["components"]["schemas"]


def test_export_sets_download_header(client, monkeypatch):
    monkeypatch.setattr(api_docs, "get_user_or_none", lambda req, db: object())
    r = client.get("/api-docs/openapi.json?download=1")
    assert r.status_code == 200 and "attachment" in r.headers.get("content-disposition", "")


def test_page_renders_swagger_when_authed(client, monkeypatch):
    monkeypatch.setattr(api_docs, "get_user_or_none", lambda req, db: object())
    html = client.get("/api-docs").text
    assert 'id="swagger-ui"' in html and 'id="apd-authorize"' in html
    assert "/api-docs/openapi.json" in html       # the page loads the filtered spec
