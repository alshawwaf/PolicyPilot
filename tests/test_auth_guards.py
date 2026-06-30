"""Portal auth is enforced per-route (each handler re-checks the session). This asserts that an
unauthenticated request to a representative endpoint in every LIVE router redirects to /login, so a future
route that forgets the guard fails CI instead of silently exposing data."""
import pytest
from fastapi.testclient import TestClient

import app.main


@pytest.fixture(scope="module")
def client():
    with TestClient(app.main.app) as c:    # context-manager form runs lifespan (init_db) so the DB is ready
        yield c


# One representative protected HTML page per live router — these redirect anonymous callers to /login.
@pytest.mark.parametrize("path", [
    "/management", "/gateways", "/layers", "/activity", "/access-automation", "/settings", "/api-docs",
])
def test_anonymous_html_page_redirects_to_login(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login", f"{path} did not guard"


# JSON/data endpoints deny anonymous callers too — they answer 401/403/404 (never 200), not an HTML redirect.
@pytest.mark.parametrize("path", ["/notifications", "/exports", "/management/1/rulebase?name=Network",
                                  "/api-docs/openapi.json"])
def test_anonymous_data_endpoint_denied(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code != 200, f"{path} served an anonymous caller"
    assert r.status_code in (303, 401, 403, 404), (path, r.status_code)


def test_anonymous_post_is_denied(client):
    # A state-changing POST must not run for an anonymous caller (deny, not execute).
    r = client.post("/management/1/test", data={}, follow_redirects=False)
    assert r.status_code != 200, r.status_code
