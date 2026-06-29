"""Shared pytest fixtures."""
import contextlib

import pytest


@pytest.fixture(autouse=True)
def _aa_write_session_delegates(monkeypatch):
    """The access-automation write paths (execute / remove_execute / amend_execute / revert_execute) now go
    through ``mgmt_api.write_session`` — a pooled, reused read-write session that amortises the SMS login
    across applies. The existing engine tests monkeypatch ``aa.MgmtSession`` with a fake and call those write
    paths; make ``aa.write_session`` a thin context-manager delegate to that (patched) MgmtSession so the
    engine logic is exercised without the real pool / network. The pool itself is tested directly against
    ``mgmt_api.write_session`` (which this fixture leaves untouched)."""
    try:
        from app.services import access_automation as aa
    except Exception:  # pragma: no cover - import-safe
        return

    @contextlib.contextmanager
    def _ws(server, secret):
        with aa.MgmtSession(server, secret) as s:
            yield s

    monkeypatch.setattr(aa, "write_session", _ws, raising=False)
