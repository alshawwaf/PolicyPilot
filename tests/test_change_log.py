"""Audit + rollback store: records ONLY published changes that carry an inverse, surfaces them newest-first
(globally and per-server), and tracks revert state."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — registers tables on Base.metadata
from app.db import Base
from app.services import change_log


class _Srv:
    id = 7
    name = "HQ-Management"


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()


REQ = {"source": "10.1.2.250", "destination": "Any", "application": "Facebook",
       "source_kind": "ip", "destination_kind": "ip"}
_INV = [{"op": "delete-access-rule", "uid": "u9", "layer": "Network"}]


def test_record_skips_dry_runs_and_noops(db):
    # dry-run (not published) -> nothing committed -> nothing to roll back
    assert change_log.record(db, server=_Srv(), request=REQ, layer="L",
                             result={"ok": True, "published": False, "applied": True, "outcome": "create",
                                     "inverse": _INV}) is None
    # a no-op / review (published flag set but nothing applied) -> not recorded
    assert change_log.record(db, server=_Srv(), request=REQ, layer="L",
                             result={"ok": True, "published": True, "applied": False, "outcome": "no_op"}) is None
    assert change_log.recent(db) == []


def test_record_audits_a_committed_change_with_no_inverse_as_non_revertable(db):
    # L5: a COMMITTED change whose SMS returned no uid (no inverse) is still AUDITED — flagged non-revertable
    # (empty inverse) rather than vanishing from the log entirely.
    row = change_log.record(db, server=_Srv(), request=REQ, layer="L",
                            result={"ok": True, "published": True, "applied": True, "outcome": "create"})
    assert row is not None and row.inverse_json == []
    assert len(change_log.recent(db)) == 1


def test_record_persists_published_change_with_inverse(db):
    row = change_log.record(db, server=_Srv(), request=REQ, layer="Network", ticket_id="INC42",
                            actor="user:khalid",
                            result={"ok": True, "published": True, "applied": True, "outcome": "create",
                                    "inverse": _INV, "source_object": "h-x", "destination_object": "Any"})
    assert row is not None and row.outcome == "create" and row.action == "apply"
    assert row.server_id == 7 and row.server_name == "HQ-Management" and row.ticket_id == "INC42"
    assert row.created_by == "user:khalid" and row.inverse_json[0]["uid"] == "u9"
    assert "Facebook" in row.summary and row.objects_json == ["h-x", "Any"]
    assert change_log.recent_for_server(db, 7) and not change_log.recent_for_server(db, 99)


def test_record_stamps_remove_action_and_revoke_summary(db):
    row = change_log.record(db, server=_Srv(), request=REQ, layer="L",
                            result={"ok": True, "published": True, "applied": True, "action": "remove",
                                    "outcome": "deny",
                                    "inverse": [{"op": "delete-access-rule", "uid": "d1", "layer": "L"}]})
    assert row.action == "remove" and row.outcome == "deny" and row.summary.startswith("revoke")


def test_mark_reverted_then_clears_any_prior_error(db):
    row = change_log.record(db, server=_Srv(), request=REQ, layer="L",
                            result={"ok": True, "published": True, "applied": True, "outcome": "disable",
                                    "inverse": [{"op": "set-access-rule", "uid": "rx", "layer": "L", "enabled": True}]})
    change_log.mark_revert_failed(db, row, "locked by another admin")
    assert row.revert_error == "locked by another admin" and row.reverted_at is None
    change_log.mark_reverted(db, row, actor="user:khalid")
    assert row.reverted_at is not None and row.reverted_by == "user:khalid" and row.revert_error == ""


def _seed(db, outcome="create"):
    return change_log.record(db, server=_Srv(), request=REQ, layer="L",
                             result={"ok": True, "published": True, "applied": True, "outcome": outcome,
                                     "inverse": [{"op": "delete-access-rule", "uid": "u", "layer": "L"}]})


def test_mark_reverted_resolution_distinguishes_deleted_from_rolledback(db):
    a, b = _seed(db, "disable"), _seed(db, "disable")
    change_log.mark_reverted(db, a, actor="user:x")                       # default = reverted
    change_log.mark_reverted(db, b, actor="user:x", resolution="deleted")
    assert a.resolution == "reverted" and b.resolution == "deleted"
    assert a.reverted_at is not None and b.reverted_at is not None


def test_delete_entry_removes_one(db):
    row = _seed(db)
    change_log.delete_entry(db, row)
    assert change_log.recent(db) == []


def test_clear_resolved_keeps_open_and_failed(db):
    open_row = _seed(db)                                                  # untouched -> stays
    done = _seed(db); change_log.mark_reverted(db, done, actor="user:x")  # resolved -> cleared
    failed = _seed(db); change_log.mark_revert_failed(db, failed, "boom")  # failed but not resolved -> stays
    removed = change_log.clear_resolved(db, 7)
    assert removed == 1
    ids = {r.id for r in change_log.recent(db)}
    assert open_row.id in ids and failed.id in ids and done.id not in ids


def test_snapshot_request_reads_ip_and_typed_endpoints():
    class _Req:
        src_kind, src_cidrs, src_value = "ip", ["10.1.2.250/32"], ""
        dst_kind, dst_value, dst_cidrs = "domain", "facebook.com", []
        protocol, ports, service, application = "tcp", "", None, None
    snap = change_log.snapshot_request(_Req())
    assert snap["source"] == "10.1.2.250/32" and snap["destination"] == "facebook.com"
    assert snap["destination_kind"] == "domain"
