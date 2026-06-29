"""Per-key rate limiter: unlimited at 0, blocks past the cap within a window, resets after the window,
isolates identities, and fails open."""
import pytest

from app.services import app_settings, rate_limit


@pytest.fixture(autouse=True)
def _clean():
    rate_limit.reset()
    yield
    rate_limit.reset()


def _limit(monkeypatch, n):
    monkeypatch.setattr(app_settings, "get", lambda k: n if k == "agent_rate_limit_per_min" else None)


def test_unlimited_when_zero(monkeypatch):
    _limit(monkeypatch, 0)
    assert all(rate_limit.allow("x") for _ in range(100))


def test_blocks_past_cap_in_window(monkeypatch):
    _limit(monkeypatch, 3)
    assert [rate_limit.allow("a") for _ in range(5)] == [True, True, True, False, False]
    assert rate_limit.allow("b") is True       # a different identity has its own budget


def test_window_resets(monkeypatch):
    clock = {"t": 1000.0}
    _limit(monkeypatch, 2)
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: clock["t"])
    assert [rate_limit.allow("a") for _ in range(3)] == [True, True, False]
    clock["t"] += 61                            # next window
    assert rate_limit.allow("a") is True


def test_fails_open_on_setting_error(monkeypatch):
    def _boom(k):
        raise RuntimeError("settings down")
    monkeypatch.setattr(app_settings, "get", _boom)
    assert rate_limit.allow("a") is True        # a limiter fault must never block the request
