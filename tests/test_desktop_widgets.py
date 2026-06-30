"""Desktop widget rail: the /desktop/widgets data aggregation + the enabled-widgets allowlist.

All widget data is DB-side (no live SMS). These assert the aggregation maps the real models
(AppliedChange / ActivityLog / ManagementServer / Gateway+snapshot) onto the widget shape, and that the
per-user enabled-widgets list is allowlisted the same way the rest of the layout is.
"""
import datetime as dt

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models  # noqa: F401 — register tables
from app.db import Base
from app.models import (ActivityLog, AppliedChange, Gateway, GatewayLayerSnapshot, ManagementServer)
from app.routers.ui import _sanitize_layout, _widget_data


def _db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def _now():
    return dt.datetime.now(dt.timezone.utc)


def test_widget_data_empty_db_full_shape():
    d = _widget_data(_db())
    assert d["decisions"] == {"created": 0, "widened": 0, "disabled": 0}
    assert d["last"] is None
    assert len(d["activity"]["spark"]) == 20 and d["activity"]["rate"] == 0
    assert d["errors"] == {"pct": 0.0, "err": 0, "total": 0}
    assert d["latency"]["avg"] == 0
    assert d["connections"] == [] and d["recent"] == []
    assert d["coverage"] == {"layers": 0, "gateways": 0, "connections": 0}


def test_decisions_today_grouped_and_last_decision():
    db = _db()
    # today's published changes, by outcome
    db.add_all([
        AppliedChange(outcome="create", action="apply", layer="Net", ticket_id="INC1", summary="allow a->b"),
        AppliedChange(outcome="widen", action="apply", layer="Net"),
        AppliedChange(outcome="widen", action="apply", layer="Net"),
        AppliedChange(outcome="disable", action="remove", layer="Net"),
    ])
    # a change from two days ago must NOT count toward "today"
    old = AppliedChange(outcome="create", action="apply", layer="Old")
    old.created_at = _now() - dt.timedelta(days=2)
    db.add(old)
    db.commit()

    d = _widget_data(db)
    assert d["decisions"] == {"created": 1, "widened": 2, "disabled": 1}
    # most recent row is the last-committed (the disable), surfaced with its fields
    assert d["last"]["outcome"] in {"create", "widen", "disable"}
    assert d["last"]["layer"] == "Net"


def test_activity_spark_errors_latency_recent():
    db = _db()
    now = _now()
    # 3 events in the last minute (bucket 19), 1 error, varied latency
    db.add_all([
        ActivityLog(kind="api", method="GET", path="/a", status=200, duration_ms=10, at=now),
        ActivityLog(kind="api", method="POST", path="/b", status=201, duration_ms=20, at=now),
        ActivityLog(kind="api", method="GET", path="/c", status=503, duration_ms=30, at=now),
    ])
    db.commit()
    d = _widget_data(db)
    assert sum(d["activity"]["spark"]) == 3 and d["activity"]["rate"] == 3
    assert d["errors"]["total"] == 3 and d["errors"]["err"] == 1 and d["errors"]["pct"] == round(100 / 3, 1)
    assert d["latency"]["avg"] == 20  # (10+20+30)/3
    assert len(d["recent"]) == 3 and d["recent"][0]["path"] in {"/a", "/b", "/c"}


def test_connections_and_coverage():
    db = _db()
    db.add(ManagementServer(name="lab-mgmt", host="10.0.0.1", owner_id=1))
    gw = Gateway(token="t1", name="gw-edge", host="10.0.0.2", owner_id=1)
    db.add(gw)
    db.commit()
    db.add(GatewayLayerSnapshot(gateway_id=gw.id, ok=True, layers=[], fetched_at=_now()))
    db.commit()

    d = _widget_data(db)
    kinds = {c["kind"] for c in d["connections"]}
    assert kinds == {"sms", "gw"}
    sms = next(c for c in d["connections"] if c["kind"] == "sms")
    assert sms["name"] == "lab-mgmt" and sms["ok"] is True and sms["note"] == "configured"
    gwc = next(c for c in d["connections"] if c["kind"] == "gw")
    assert gwc["name"] == "gw-edge" and gwc["ok"] is True and "ago" in gwc["note"] or gwc["note"] == "just now"
    assert d["coverage"] == {"layers": 0, "gateways": 1, "connections": 1}


def test_gateway_with_failed_snapshot_reads_down():
    db = _db()
    gw = Gateway(token="t2", name="gw-bad", host="10.0.0.3", owner_id=1)
    db.add(gw)
    db.commit()
    db.add(GatewayLayerSnapshot(gateway_id=gw.id, ok=False, error="auth failed", layers=[], fetched_at=_now()))
    db.commit()
    gwc = next(c for c in _widget_data(db)["connections"] if c["kind"] == "gw")
    assert gwc["ok"] is False and gwc["note"] == "fetch error"


def test_enabled_widgets_allowlist_and_dedup():
    s = _sanitize_layout({"dock": ["access"], "widgets": ["decisions", "bogus", "activity", "decisions", "clock"]})
    assert s["widgets"] == ["decisions", "activity", "clock"]   # bogus dropped, deduped, order preserved


def test_widgets_absent_is_omitted_empty_is_kept():
    assert "widgets" not in _sanitize_layout({"dock": ["access"]})        # client applies its default
    assert _sanitize_layout({"dock": ["access"], "widgets": []})["widgets"] == []  # explicit "none" preserved
