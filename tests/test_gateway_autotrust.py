"""Trust-on-first-use auto-pin: gaia_client.ensure_pinned fetches and pins the gateway's presented
certificate on first connect when the profile opts in — and is a safe no-op otherwise. TLS
verification is never disabled; this only decides which certificate the later apply/fetch trusts."""
from app.services import gaia_client


class _GW:
    def __init__(self, auto_trust=True, cert_pem="", host="10.0.0.1", port=443):
        self.auto_trust, self.cert_pem, self.host, self.port = auto_trust, cert_pem, host, port


class _DB:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1


def test_pins_when_auto_trust_on_and_no_cert(monkeypatch):
    seen = {}

    def fake(host, port):
        seen["host"], seen["port"] = host, port
        return {"pem": "-----BEGIN CERTIFICATE-----\nPEM\n-----END CERTIFICATE-----", "fingerprint": "AA:BB"}

    monkeypatch.setattr(gaia_client, "fetch_gateway_cert", fake)
    gw, db = _GW(), _DB()
    assert gaia_client.ensure_pinned(db, gw) is True
    assert "BEGIN CERTIFICATE" in gw.cert_pem  # the presented cert is now pinned to the profile
    assert db.commits == 1
    assert seen == {"host": "10.0.0.1", "port": 443}  # fetched from the gateway's own address


def test_noop_when_cert_already_pinned(monkeypatch):
    calls = {"n": 0}

    def fake(host, port):
        calls["n"] += 1
        return {"pem": "NEW", "fingerprint": "x"}

    monkeypatch.setattr(gaia_client, "fetch_gateway_cert", fake)
    gw, db = _GW(cert_pem="-----BEGIN CERTIFICATE-----\nEXISTING\n-----END CERTIFICATE-----"), _DB()
    assert gaia_client.ensure_pinned(db, gw) is False
    assert "EXISTING" in gw.cert_pem  # a manually pinned cert is never overwritten
    assert calls["n"] == 0 and db.commits == 0  # and we don't even reach out to the gateway


def test_noop_when_auto_trust_off(monkeypatch):
    monkeypatch.setattr(gaia_client, "fetch_gateway_cert", lambda h, p: {"pem": "NEW"})
    gw, db = _GW(auto_trust=False), _DB()
    assert gaia_client.ensure_pinned(db, gw) is False
    assert gw.cert_pem == "" and db.commits == 0


def test_best_effort_when_gateway_unreachable(monkeypatch):
    def boom(host, port):
        raise OSError("connection refused")

    monkeypatch.setattr(gaia_client, "fetch_gateway_cert", boom)
    gw, db = _GW(), _DB()
    # Unreachable now → leave the cert empty and let the next connect retry; never raises.
    assert gaia_client.ensure_pinned(db, gw) is False
    assert gw.cert_pem == "" and db.commits == 0


def test_pin_now_pins_eagerly_and_returns_fingerprint(monkeypatch):
    # eager pin at save time: auto-trust on + no cert → fetch + pin now, report the fingerprint
    monkeypatch.setattr(gaia_client, "fetch_gateway_cert",
                        lambda h, p: {"pem": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----"})
    monkeypatch.setattr(gaia_client, "cert_fingerprint", lambda pem: "AA:BB:CC")
    gw, db = _GW(), _DB()
    assert gaia_client.pin_now(db, gw) == (True, "AA:BB:CC")
    assert "BEGIN CERTIFICATE" in gw.cert_pem and db.commits == 1


def test_pin_now_graceful_when_unreachable(monkeypatch):
    monkeypatch.setattr(gaia_client, "fetch_gateway_cert",
                        lambda h, p: (_ for _ in ()).throw(OSError("refused")))
    gw, db = _GW(), _DB()
    # never raises; signals "not pinned" so the caller can fall back to lazy first-connect pinning
    assert gaia_client.pin_now(db, gw) == (False, "")
    assert gw.cert_pem == "" and db.commits == 0
