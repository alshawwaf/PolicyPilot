"""Destination-reputation enrichment (services.reputation) — client behaviour + decision hook.

No live rep.checkpoint.com: the httpx layer and settings are stubbed. Covers the destination picker
(public IP / domain only, skip private/ranges/typed), the severity→posture mapping, token caching + 403
refresh, fail-open, and that access_automation._enrich_reputation attaches only for allow-shaped requests.
"""
import types

import pytest

from app.services import reputation


def _req(**kw):
    base = {"dst_kind": "ip", "dst_cidrs": ["8.8.8.8/32"], "dst_value": "", "action": "Accept"}
    base.update(kw)
    return types.SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    # Clean module caches + a default "enabled with a key" setting for each test.
    reputation._token.update(value="", at=-1e9)
    reputation._results.clear()
    monkeypatch.setattr(reputation, "enabled", lambda: True)
    monkeypatch.setattr(reputation, "_api_key", lambda: "test-key")
    yield


# --- destination picker ----------------------------------------------------------------------

def test_picks_public_ip_host():
    assert reputation._destination(_req(dst_cidrs=["8.8.4.4/32"])) == ("ip", "8.8.4.4")


def test_skips_private_ip():
    assert reputation._destination(_req(dst_cidrs=["10.1.1.5/32"])) is None


def test_skips_cidr_range():
    assert reputation._destination(_req(dst_cidrs=["8.8.0.0/16"])) is None


def test_skips_multiple_destinations():
    assert reputation._destination(_req(dst_cidrs=["8.8.8.8/32", "1.1.1.1/32"])) is None


def test_picks_domain():
    assert reputation._destination(_req(dst_kind="domain", dst_value="evil.example")) == ("url", "evil.example")


def test_skips_typed_nonnetwork():
    assert reputation._destination(_req(dst_kind="access-role", dst_value="Finance")) is None


# --- classification mapping ------------------------------------------------------------------

def test_classify_high_on_malware_critical():
    v = reputation._classify({"classification": "Malware", "severity": "Critical", "confidence": "High"})
    assert v["risk"] == "high" and v["classification"] == "Malware"


def test_classify_medium():
    v = reputation._classify({"classification": "Adware", "severity": "Medium", "confidence": "Medium"})
    assert v["risk"] == "medium"


def test_classify_benign_never_high():
    # Even if severity somehow says High, a Benign classification is not a risk.
    v = reputation._classify({"classification": "Benign", "severity": "High", "confidence": "Low"})
    assert v["risk"] == "low"


# --- lookup (stubbed HTTP) -------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status, *, text="", json_body=None):
        self.status_code = status
        self.text = text
        self._json = json_body

    def json(self):
        return self._json


class _FakeClient:
    """Records calls; serves a scripted auth token then reputation JSON."""

    def __init__(self, *, query_status=200, reputation_obj=None, token="exp=1~acl=/*~hmac=x"):
        self.query_status = query_status
        self.reputation_obj = reputation_obj if reputation_obj is not None else {
            "classification": "Malware", "severity": "High", "confidence": "High"}
        self.token = token
        self.posts = 0
        self.auth_calls = 0

    def __enter__(self): return self
    def __exit__(self, *a): return False

    def get(self, path, headers=None):
        self.auth_calls += 1
        return _FakeResp(200, text=self.token)

    def post(self, url, headers=None, json=None):
        self.posts += 1
        if self.query_status != 200:
            return _FakeResp(self.query_status, json_body={})
        return _FakeResp(200, json_body={"resource": "x", "reputation": self.reputation_obj})


def test_lookup_returns_verdict_with_advisory(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(reputation, "_client", lambda: fake)
    v = reputation.lookup(_req(dst_cidrs=["9.9.9.9/32"]))
    assert v["risk"] == "high" and v["resource"] == "9.9.9.9"
    assert "high-risk" in v["advisory"] and v["classification"] == "Malware"


def test_lookup_disabled_returns_none(monkeypatch):
    monkeypatch.setattr(reputation, "enabled", lambda: False)
    monkeypatch.setattr(reputation, "_client", lambda: pytest.fail("must not call the service when disabled"))
    assert reputation.lookup(_req()) is None


def test_lookup_no_key_returns_none(monkeypatch):
    monkeypatch.setattr(reputation, "_api_key", lambda: "")
    monkeypatch.setattr(reputation, "_client", lambda: pytest.fail("must not call the service without a key"))
    assert reputation.lookup(_req()) is None


def test_lookup_caches_result(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(reputation, "_client", lambda: fake)
    reputation.lookup(_req(dst_cidrs=["1.1.1.1/32"]))
    reputation.lookup(_req(dst_cidrs=["1.1.1.1/32"]))
    assert fake.posts == 1                                  # second call served from cache


def test_lookup_fail_open_on_error(monkeypatch):
    def boom():
        raise RuntimeError("network down")
    monkeypatch.setattr(reputation, "_client", boom)
    assert reputation.lookup(_req()) is None                # never raises


def test_lookup_refreshes_token_on_403(monkeypatch):
    # First query 403s (expired token) → refresh + retry succeeds.
    class _Refresher(_FakeClient):
        def post(self, url, headers=None, json=None):
            self.posts += 1
            if self.posts == 1:
                return _FakeResp(403, json_body={})
            return _FakeResp(200, json_body={"reputation": self.reputation_obj})
    fake = _Refresher()
    monkeypatch.setattr(reputation, "_client", lambda: fake)
    v = reputation.lookup(_req(dst_cidrs=["1.0.0.1/32"]))
    assert v is not None and fake.auth_calls == 2 and fake.posts == 2


# --- decision hook ---------------------------------------------------------------------------

def test_enrich_attaches_for_allow(monkeypatch):
    from app.services import access_automation as aa
    monkeypatch.setattr(reputation, "lookup", lambda req: {"risk": "high", "advisory": "bad"})
    result = {"ok": True, "outcome": "create"}
    aa._enrich_reputation(_req(action="Accept"), result)
    assert result["reputation"]["risk"] == "high"


def test_enrich_skips_for_block(monkeypatch):
    from app.services import access_automation as aa
    monkeypatch.setattr(reputation, "lookup", lambda req: pytest.fail("no reputation for a Drop"))
    result = {"ok": True, "outcome": "create"}
    aa._enrich_reputation(_req(action="Drop"), result)
    assert "reputation" not in result
