"""The post-deploy conformance self-check: required checks pass on a healthy in-process surface, and the
report degrades cleanly when something is wrong. No live SMS/gateway, no mutations. The DB is stubbed via
SessionLocal (so the real tool functions — with their docstrings, which tool_catalog reads — stay intact)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — registers tables
from app.db import Base
from app.services import conformance, mcp_tools


@pytest.fixture()
def memdb(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    monkeypatch.setattr(mcp_tools, "SessionLocal", sessionmaker(bind=eng))


def test_run_passes_on_healthy_surface(memdb):
    rep = conformance.run()
    assert rep["ok"] is True and rep["tools"] == 27
    by = {c["name"]: c for c in rep["checks"]}
    for required in ("tools_registered", "write_tools_rbac_guarded",
                     "readonly_capability_enforced", "db_reachable"):
        assert by[required]["ok"] is True and by[required]["required"] is True
    assert by["publish_gates_readable"]["required"] is False     # gate states reported, never fail the run


def test_db_unreachable_fails_required_check(monkeypatch):
    def _boom():
        raise RuntimeError("db down")
    monkeypatch.setattr(mcp_tools, "SessionLocal", _boom)
    rep = conformance.run()
    by = {c["name"]: c for c in rep["checks"]}
    assert by["db_reachable"]["ok"] is False and rep["ok"] is False   # a required failure sinks the run


def test_sdk_absence_is_informational_only(memdb, monkeypatch):
    from app import mcp_server
    monkeypatch.setattr(mcp_server, "have_mcp", lambda: False)
    rep = conformance.run()
    by = {c["name"]: c for c in rep["checks"]}
    assert by["mcp_sdk_present"]["ok"] is False and by["mcp_sdk_present"]["required"] is False
    assert rep["ok"] is True       # /mcp dormant must NOT fail conformance — REST still works


def test_readonly_check_uses_the_real_guard(memdb):
    by = {c["name"]: c for c in conformance.run()["checks"]}
    assert by["readonly_capability_enforced"]["ok"] is True   # exercises the actual _write_tool decorator
