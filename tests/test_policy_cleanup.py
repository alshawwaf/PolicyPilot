"""Policy Cleanup — the PolicyCleanUp port.

Covers the pure classification logic (hit-count thresholds + per-rule custom-field overrides), op building
(disable stamps field-3 + appends the marker; delete), a scan over a fake web_api session, and the router
(auth gate, owned-server filtering, template render). No live SMS — the session is faked like test_mgmt.
"""
import datetime as dt
import types

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — registers tables
from app.db import Base
from app.models import ManagementServer, User
from app.routers import policy_cleanup as pcr
from app.routers.ui import templates
from app.services import policy_cleanup as pc

NOW = dt.datetime(2026, 7, 9, 12, 0, 0)


def _date(days_ago):
    """A Check Point date object (posix ms) `days_ago` days before NOW."""
    when = NOW - dt.timedelta(days=days_ago)
    return {"posix": int(when.timestamp() * 1000)}


# Translate a few convenience kwargs to the hyphenated CP keys so tests can pass them directly
# (e.g. modify_days_ago=300, custom_fields={...}) instead of post-patching the dict.
def _rule(*, modify_days_ago=400, custom_fields=None, number=1, **kw):
    base = {"type": "access-rule", "uid": "u1", "rule-number": number, "name": "r", "enabled": True,
            "hits": {}, "meta-info": {"last-modify-time": _date(modify_days_ago)},
            "custom-fields": custom_fields or {}, "comments": ""}
    base.update(kw)
    return base


# --- classification --------------------------------------------------------------------------

def test_enabled_unused_rule_is_disable_candidate():
    r = _rule(hits={"value": 0, "last-date": _date(200)}, modify_days_ago=300)
    verdict, reason = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "disable" and "180 days" in reason


def test_never_hit_falls_back_to_modify_time():
    # No last-date in hits -> use last-modify-time (400 days ago) -> older than 180 -> disable, "never hit".
    r = _rule(hits={"value": 0}, modify_days_ago=400)
    verdict, reason = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "disable" and "never hit" in reason


def test_recently_hit_rule_is_kept():
    r = _rule(hits={"value": 5, "last-date": _date(10)})
    verdict, _ = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "keep"


def test_recently_modified_rule_is_kept_even_if_old_hit():
    # Last hit 300d ago but modified 5d ago -> "active as of" the modification -> keep.
    r = _rule(hits={"value": 1, "last-date": _date(300)}, modify_days_ago=5)
    verdict, _ = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "keep"


def test_disable_override_pins_rule_off():
    # field-1 == "-1" -> never touch this rule.
    r = _rule(hits={"value": 0}, custom_fields={"field-1": "-1"})
    verdict, _ = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "keep"


def test_disable_override_shortens_threshold():
    # field-1 == "30" -> disable after 30 days; modified 40d ago -> disable.
    r = _rule(hits={"value": 0}, modify_days_ago=40, custom_fields={"field-1": "30"})
    verdict, reason = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "disable" and "30 days" in reason


def test_non_numeric_override_is_skipped_with_reason():
    r = _rule(hits={"value": 0}, custom_fields={"field-1": "soon"})
    verdict, reason = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "skip" and "non-numeric" in reason


def test_malformed_negative_override_does_not_crash():
    # "--1" (typo for -1) must be skipped cleanly, not raise ValueError out of int() and 500 the whole plan.
    r = _rule(hits={"value": 0}, custom_fields={"field-1": "--1"})
    verdict, reason = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "skip" and "non-numeric" in reason


def test_disabled_by_tool_long_ago_is_delete_candidate():
    r = _rule(enabled=False,
              custom_fields={"field-3": (NOW - dt.timedelta(days=90)).strftime(pc.DATETIME_FORMAT)})
    verdict, reason = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "delete" and "older than 60 days" in reason


def test_disabled_recently_is_kept():
    r = _rule(enabled=False,
              custom_fields={"field-3": (NOW - dt.timedelta(days=10)).strftime(pc.DATETIME_FORMAT)})
    verdict, _ = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "keep"


def test_disabled_but_not_by_tool_is_kept():
    # Disabled by a human (no field-3 stamp) -> the tool never deletes it.
    r = _rule(enabled=False)
    verdict, reason = pc.classify_rule(r, disable_after=180, delete_after=60, now=NOW)
    assert verdict == "keep" and "not by this tool" in reason


# --- op building -----------------------------------------------------------------------------

def test_build_ops_disable_stamps_field3_and_marks_comment():
    ops = pc.build_ops([{"uid": "u9", "layer": "L", "number": 3, "name": "old", "comments": "orig"}],
                       [], now=NOW)
    assert len(ops) == 1
    op = ops[0]
    assert op["command"] == "set-access-rule"
    assert op["payload"]["enabled"] is False
    assert op["payload"]["custom-fields"][pc.FIELD_DISABLED_TIME] == NOW.strftime(pc.DATETIME_FORMAT)
    assert op["payload"]["comments"].startswith("orig") and pc.DISABLE_MARKER.strip() in op["payload"]["comments"]


def test_build_ops_disable_preserves_existing_overrides():
    # A disable op must carry field-1/field-2 forward (set-access-rule REPLACES custom-fields), else a
    # "never delete" pin (field-2="-1") would be wiped and the rule could later be deleted.
    ops = pc.build_ops(
        [{"uid": "u9", "layer": "L", "number": 3, "name": "old", "comments": "",
          "custom_fields": {"field-1": "90", "field-2": "-1"}}], [], now=NOW)
    cf = ops[0]["payload"]["custom-fields"]
    assert cf["field-1"] == "90" and cf["field-2"] == "-1"
    assert cf[pc.FIELD_DISABLED_TIME] == NOW.strftime(pc.DATETIME_FORMAT)


def test_build_ops_delete_and_order():
    ops = pc.build_ops(
        [{"uid": "d1", "layer": "L", "number": 1, "name": "a", "comments": ""}],
        [{"uid": "x1", "layer": "L", "number": 2, "name": "b"}], now=NOW)
    assert [o["command"] for o in ops] == ["set-access-rule", "delete-access-rule"]
    assert ops[1]["payload"] == {"uid": "x1", "layer": "L"}


def test_build_ops_skips_rows_missing_uid_or_layer():
    ops = pc.build_ops([{"uid": "", "layer": "L"}, {"uid": "u", "layer": ""}], [], now=NOW)
    assert ops == []


# --- scan over a fake session ----------------------------------------------------------------

class _FakeSession:
    """Minimal stand-in for an open MgmtSession: one page of a rulebase with hits + an object dict."""

    def __init__(self, rules, objdict):
        self._rules = rules
        self._objdict = objdict
        self.trace = []

    def call(self, command, payload=None, **k):
        if command == "show-access-rulebase":
            if (payload or {}).get("offset", 0) == 0:
                return {"rulebase": self._rules,
                        "objects-dictionary": [{"uid": u, **o} for u, o in self._objdict.items()],
                        "total": len(self._rules), "to": len(self._rules)}
            return {"rulebase": [], "total": len(self._rules), "to": len(self._rules)}
        return {}

    def list_access_layers(self):
        return [{"name": "Network", "uid": "L1"}]


def test_scan_layer_buckets_rules():
    objdict = {"o-web": {"name": "web", "type": "host"}, "o-any": {"name": "Any"}}
    rules = [
        _rule(uid="keep", hits={"value": 3, "last-date": _date(5)}),
        _rule(uid="disable", number=2, hits={"value": 0}, modify_days_ago=400, source=["o-web"]),
        _rule(uid="delete", number=3, enabled=False,
              custom_fields={"field-3": (NOW - dt.timedelta(days=90)).strftime(pc.DATETIME_FORMAT)}),
    ]
    sess = _FakeSession(rules, objdict)
    out = pc.scan_layer(sess, "Network", disable_after=180, delete_after=60, now=NOW)
    assert out["counts"] == {"disable": 1, "delete": 1, "skipped": 0, "scanned": 3}
    assert out["disable"][0]["uid"] == "disable" and out["disable"][0]["source"] == ["web"]
    assert out["delete"][0]["uid"] == "delete"
    assert out["delete"][0]["disabled_at"]        # the field-3 date is surfaced for the UI column


def test_scan_layer_reports_error_on_pull_failure():
    class _Boom:
        trace = []

        def call(self, *a, **k):
            raise pc.mgmt_api.MgmtError("boom")

    out = pc.scan_layer(_Boom(), "Network", disable_after=180, delete_after=60, now=NOW)
    assert out["error"] == "boom" and out["disable"] == []


def test_scan_aggregates_totals(monkeypatch):
    objdict = {}
    rules = [_rule(uid="disable", hits={"value": 0}, modify_days_ago=400)]
    sess = _FakeSession(rules, objdict)

    import contextlib

    @contextlib.contextmanager
    def _fake_read_session(server, secret):
        yield sess

    monkeypatch.setattr(pc.mgmt_api, "read_session", _fake_read_session)
    server = types.SimpleNamespace(id=1, host="h", port=443, domain="", username="u", cert_pem="")
    plan = pc.scan(server, "secret", now=NOW)
    assert plan["totals"]["disable"] == 1 and plan["totals"]["scanned"] == 1
    assert plan["thresholds"] == {"disable_after": 180, "delete_after": 60}


def _stub_reclassify(fresh_disable, fresh_delete, skipped=None):
    """Bypass the live re-fetch: apply_plan's re-classification returns these fresh rows verbatim."""
    return lambda *a, **k: (fresh_disable, fresh_delete, skipped or [])


def _fresh_row(uid, *, layer="L", number=1, name="r", comments="", custom_fields=None, reason="stale"):
    return {"uid": uid, "layer": layer, "number": number, "name": name, "comments": comments,
            "custom_fields": custom_fields or {}, "verdict": "disable", "reason": reason}


def test_apply_plan_empty_is_error(monkeypatch):
    # Rows that all filter out (no uid/layer) must NOT be reported as a validated dry-run — apply_changes
    # is never called and the result is a clear error, not a false "ok".
    called = {"apply": False}

    def _boom(*a, **k):
        called["apply"] = True
        raise AssertionError("should not call apply_changes with no ops")

    monkeypatch.setattr(pc.mgmt_api, "apply_changes", _boom)
    server = types.SimpleNamespace(id=1)
    out = pc.apply_plan(server, "s", disable=[{"uid": "", "layer": ""}], delete=[], publish=True, now=NOW)
    assert out["ok"] is False and out["applied"] is False and out["error"] and not called["apply"]


def test_apply_plan_all_skipped_by_recheck_applies_nothing(monkeypatch):
    skips = [{"uid": "a", "layer": "L", "number": 1, "name": "r", "requested": "disable",
              "reason": "verdict changed since the plan — now “keep” (recently active)"}]
    monkeypatch.setattr(pc, "_reclassify", _stub_reclassify([], [], skips))
    monkeypatch.setattr(pc.mgmt_api, "apply_changes",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not apply")))
    server = types.SimpleNamespace(id=1)
    out = pc.apply_plan(server, "s", disable=[{"uid": "a", "layer": "L"}], delete=[], publish=True, now=NOW)
    assert out["ok"] and out["applied"] is False and out["skipped"] == skips and out["note"]


def test_apply_plan_emits_audit_on_publish(monkeypatch):
    monkeypatch.setattr(pc, "_reclassify",
                        _stub_reclassify([_fresh_row("a")], [_fresh_row("b", number=2)]))
    monkeypatch.setattr(pc, "_record_batch", lambda *a, **k: 2)
    monkeypatch.setattr(pc.mgmt_api, "apply_changes",
                        lambda *a, **k: {"ok": True, "published": True, "results": [], "trace": []})
    events = []
    from app.services import audit
    monkeypatch.setattr(audit, "emit", lambda summary, **kw: events.append((summary, kw)))
    server = types.SimpleNamespace(id=1, name="HQ", host="h")
    out = pc.apply_plan(server, "s", disable=[{"uid": "a", "layer": "L"}], delete=[{"uid": "b", "layer": "L"}],
                        publish=True, now=NOW, actor="user:alice")
    assert out["applied"] and out["disabled"] == 1 and out["deleted"] == 1 and out["recorded"] == 2
    assert len(events) == 1
    summary, kw = events[0]
    assert "policy-cleanup" in summary and "disabled 1" in summary and "deleted 1" in summary
    assert "HQ" in summary and kw["actor"] == "user:alice"


def test_apply_plan_no_audit_or_record_on_dry_run(monkeypatch):
    monkeypatch.setattr(pc, "_reclassify", _stub_reclassify([_fresh_row("a")], []))
    monkeypatch.setattr(pc, "_record_batch",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no recording on dry-run")))
    monkeypatch.setattr(pc.mgmt_api, "apply_changes",
                        lambda *a, **k: {"ok": True, "published": False, "results": [{"ok": True}], "trace": []})
    events = []
    from app.services import audit
    monkeypatch.setattr(audit, "emit", lambda *a, **k: events.append(a))
    server = types.SimpleNamespace(id=1, name="HQ", host="h")
    out = pc.apply_plan(server, "s", disable=[{"uid": "a", "layer": "L"}], delete=[], publish=False, now=NOW)
    assert out["applied"] and out["published"] is False and out["recorded"] == 0 and events == []


def test_apply_plan_calls_apply_changes_with_fresh_rows(monkeypatch):
    # Ops must be built from the RE-FETCHED rows (live comments/custom-fields), not the client's plan rows.
    captured = {}

    def _fake_apply(server, secret, ops, *, publish):
        captured["ops"] = ops
        captured["publish"] = publish
        return {"ok": True, "published": publish, "results": [{"ok": True} for _ in ops], "trace": []}

    monkeypatch.setattr(pc, "_reclassify", _stub_reclassify(
        [_fresh_row("a", comments="LIVE comment", custom_fields={"field-2": "-1"})],
        [_fresh_row("b", number=2)]))
    monkeypatch.setattr(pc.mgmt_api, "apply_changes", _fake_apply)
    server = types.SimpleNamespace(id=1)
    out = pc.apply_plan(server, "s",
                        disable=[{"uid": "a", "layer": "L", "comments": "STALE plan comment"}],
                        delete=[{"uid": "b", "layer": "L"}], publish=False, now=NOW)
    assert captured["publish"] is False
    assert [o["command"] for o in captured["ops"]] == ["set-access-rule", "delete-access-rule"]
    dis = captured["ops"][0]["payload"]
    assert dis["comments"].startswith("LIVE comment")          # fresh, not the stale client snapshot
    assert dis["custom-fields"]["field-2"] == "-1"             # live pin carried forward
    assert out["disabled"] == 1 and out["deleted"] == 1


# --- live re-classification (_reclassify) ------------------------------------------------------

def _patch_pull(monkeypatch, rules_by_layer, objdicts=None):
    import contextlib

    @contextlib.contextmanager
    def _fake_read_session(server, secret):
        yield object()

    def _fake_raw_pull(session, layer, package, max_rules, *, hits=False):
        assert hits is True                            # the re-check must request hit counts
        return {"items": rules_by_layer.get(layer, []),
                "objdict": (objdicts or {}).get(layer, {}), "total": len(rules_by_layer.get(layer, []))}

    monkeypatch.setattr(pc.mgmt_api, "read_session", _fake_read_session)
    monkeypatch.setattr(pc.mgmt_api, "_raw_pull", _fake_raw_pull)


def test_reclassify_skips_rule_that_became_active(monkeypatch):
    # Planned as disable, but it took hits since -> skipped with the changed verdict, not disabled.
    _patch_pull(monkeypatch, {"L": [_rule(uid="a", hits={"value": 9, "last-date": _date(1)})]})
    fresh_dis, fresh_del, skipped = pc._reclassify(
        object(), "s", [({"uid": "a", "layer": "L"}, "disable")],
        disable_after=180, delete_after=60, now=NOW, max_rules=50000)
    assert fresh_dis == [] and fresh_del == []
    assert len(skipped) == 1 and "verdict changed" in skipped[0]["reason"]


def test_reclassify_skips_vanished_rule(monkeypatch):
    _patch_pull(monkeypatch, {"L": []})
    fresh_dis, _, skipped = pc._reclassify(
        object(), "s", [({"uid": "gone", "layer": "L"}, "disable")],
        disable_after=180, delete_after=60, now=NOW, max_rules=50000)
    assert fresh_dis == [] and skipped[0]["reason"] == "rule no longer exists in this layer"


def test_reclassify_confirms_and_rebuilds_from_live_state(monkeypatch):
    rule = _rule(uid="a", hits={"value": 0}, modify_days_ago=400, comments="live c",
                 custom_fields={"field-2": "-1"})
    _patch_pull(monkeypatch, {"L": [rule]})
    fresh_dis, _, skipped = pc._reclassify(
        object(), "s", [({"uid": "a", "layer": "L", "comments": "stale"}, "disable")],
        disable_after=180, delete_after=60, now=NOW, max_rules=50000)
    assert skipped == [] and len(fresh_dis) == 1
    assert fresh_dis[0]["comments"] == "live c" and fresh_dis[0]["custom_fields"] == {"field-2": "-1"}


# --- inverse + recording ------------------------------------------------------------------------

def test_disable_inverse_shape():
    inv = pc._disable_inverse(_fresh_row("u1", comments="orig", custom_fields={"field-1": "90"}))
    assert inv["op"] == "set-access-rule" and inv["enabled"] is True
    assert inv["uid"] == "u1" and inv["layer"] == "L"
    # field-3 explicitly blanked so the tool's stamp clears even under merge semantics
    assert inv["set"] == {"comments": "orig", "custom-fields": {"field-1": "90", "field-3": ""}}


def test_disable_inverse_preserves_pre_existing_stamp():
    # If the rule already carried a field-3 value BEFORE this cleanup touched it, restore that exact value.
    inv = pc._disable_inverse(_fresh_row("u1", custom_fields={"field-3": "2025-01-01 00:00:00"}))
    assert inv["set"]["custom-fields"]["field-3"] == "2025-01-01 00:00:00"


def test_record_batch_rows(monkeypatch):
    import app.db as appdb
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    monkeypatch.setattr(appdb, "SessionLocal", sessionmaker(bind=eng))
    events = []
    from app.services import audit
    monkeypatch.setattr(audit, "emit", lambda *a, **k: events.append(a))

    server = types.SimpleNamespace(id=7, name="HQ")
    dis = _fresh_row("d1", name="old", reason="never hit; older than 180 days")
    dele = _fresh_row("x1", number=2, name="dead", reason="disabled by the tool")
    n = pc._record_batch(server, fresh_disable=[dis], fresh_delete=[dele],
                         inverses={"d1": pc._disable_inverse(dis)}, actor="user:alice", now=NOW)
    assert n == 2 and events == []                     # per-row audit suppressed (batch event is separate)

    from app.models import AppliedChange
    with sessionmaker(bind=eng)() as db:
        rows = {r.outcome: r for r in db.query(AppliedChange).all()}
    d = rows["disable"]
    assert d.action == "cleanup" and d.inverse_json and d.inverse_json[0]["enabled"] is True
    assert d.resolution == "" and d.reverted_at is None            # state "disabled" -> re-enable/delete offered
    assert d.ticket_id.startswith("cleanup-") and "old" in d.summary
    x = rows["delete"]
    assert x.inverse_json == [] and x.resolution == "deleted" and x.reverted_at is not None
    assert x.request_json["name"] == "dead"                        # full snapshot kept for the audit trail
    assert x.ticket_id == d.ticket_id                              # same batch id


def test_record_committed_emits_audit_by_default(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    events = []
    from app.services import audit, change_log
    monkeypatch.setattr(audit, "emit", lambda summary, **k: events.append(summary))
    with sessionmaker(bind=eng)() as db:
        row = change_log.record_committed(db, server=types.SimpleNamespace(id=1, name="HQ"), layer="Net",
                                          action="apply", outcome="create", summary="allow a -> b")
    assert row.id and len(events) == 1 and "HQ" in events[0]


# --- revert integration: the recorded inverse replays through the shared executor ----------------

def test_apply_inverse_op_restores_enabled_and_metadata():
    from app.services.access_automation import _apply_inverse_op

    class _Sess:
        def __init__(self):
            self.calls = []

        def call(self, command, payload):
            self.calls.append((command, payload))
            return {}

    s = _Sess()
    inv = pc._disable_inverse(_fresh_row("u1", comments="orig", custom_fields={"field-1": "90"}))
    _apply_inverse_op(s, inv)
    cmd, payload = s.calls[0]
    assert cmd == "set-access-rule" and payload["enabled"] is True
    assert payload["comments"] == "orig"
    assert payload["custom-fields"] == {"field-1": "90", "field-3": ""}   # stamp explicitly blanked
    assert payload["uid"] == "u1" and payload["layer"] == "L"


def test_apply_inverse_op_drops_non_whitelisted_set_fields():
    from app.services.access_automation import _apply_inverse_op

    class _Sess:
        def __init__(self):
            self.calls = []

        def call(self, command, payload):
            self.calls.append((command, payload))
            return {}

    s = _Sess()
    _apply_inverse_op(s, {"op": "set-access-rule", "uid": "u", "layer": "L", "enabled": True,
                          "set": {"comments": "ok", "source": ["evil"], "action": "Accept"}})
    _, payload = s.calls[0]
    assert payload["comments"] == "ok"
    assert "source" not in payload and "action" not in payload   # match columns never replayed


def test_reenable_replays_recorded_full_inverse(monkeypatch):
    # A cleanup-disable row in state "disabled": the panel's Re-enable must replay the FULL recorded
    # inverse (comments + custom-fields restore), not a bare enabled=true op.
    import app.routers.access_automation as aar
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    u = User(username="a", password_hash="x", is_admin=True)
    db.add(u); db.commit()
    ms = ManagementServer(name="HQ", host="h", port=443, username="admin", owner_id=u.id)
    db.add(ms); db.commit()
    from app.models import AppliedChange
    inv = pc._disable_inverse(_fresh_row("u9", comments="orig", custom_fields={"field-1": "5"}))
    row = AppliedChange(server_id=ms.id, server_name="HQ", layer="L", action="cleanup",
                        outcome="disable", summary="cleanup: disable", inverse_json=[inv])
    db.add(row); db.commit(); db.refresh(row)

    monkeypatch.setattr(aar, "get_user_or_none", lambda req, d: db.get(User, u.id))
    monkeypatch.setattr(aar, "_secret_or_error", lambda d, m: ("secret", None))
    captured = {}

    def _fake_revert(server, secret, ops, *, publish, disable_added_rules):
        captured["ops"] = ops
        return {"ok": True, "reverted": publish, "validated": not publish, "ops": [], "trace": []}

    monkeypatch.setattr(aar.aa, "revert_execute", _fake_revert)
    body = aar.RevertBody(publish=False, reenable=True)
    resp = aar.aa_revert(sid=ms.id, cid=row.id, body=body, request=None, db=db)
    assert resp.status_code == 200
    assert captured["ops"] == [inv]                    # full inverse, not a minimal enabled-only op
    db.close()


# --- router ----------------------------------------------------------------------------------

def _render(**ctx):
    ctx.setdefault("request", None)
    ctx.setdefault("flash", None)
    return templates.env.get_template("policy_cleanup.html").render(**ctx)


def test_landing_renders_server_cards():
    ms = types.SimpleNamespace(id=3, name="HQ-SMS", host="10.0.0.1", port=443, domain="")
    html = _render(server=None, rows=[{"ms": ms, "has_secret": True}])
    assert "Policy Cleanup" in html
    assert "HQ-SMS" in html and "/policy-cleanup/3" in html and "Scan this server" in html


def test_landing_empty_state():
    html = _render(server=None, rows=[])
    assert "No management servers yet" in html and "/management/new" in html


def test_workspace_renders_controls_when_credential_present():
    ms = types.SimpleNamespace(id=7, name="Lab", host="h", port=443, domain="")
    html = _render(server=ms, rows=None, has_secret=True,
                   defaults={"disable_after": 180, "delete_after": 60})
    assert 'data-sid="7"' in html and "Run plan" in html and 'id="pc-layer"' in html


def test_workspace_prompts_for_credential_when_missing():
    ms = types.SimpleNamespace(id=8, name="NoCred", host="h", port=443, domain="")
    html = _render(server=ms, rows=None, has_secret=False,
                   defaults={"disable_after": 180, "delete_after": 60})
    assert "No saved credential" in html and "/management/8/edit" in html and "Run plan" not in html


def test_route_redirects_when_logged_out(monkeypatch):
    monkeypatch.setattr(pcr, "get_user_or_none", lambda req, db: None)
    resp = pcr.policy_cleanup_home(request=None, db=None)
    assert resp.status_code == 303 and resp.headers["location"] == "/login"


def test_plan_route_requires_auth(monkeypatch):
    monkeypatch.setattr(pcr, "get_user_or_none", lambda req, db: None)
    resp = pcr.policy_cleanup_plan(sid=1, request=None, req=pcr.PlanReq(), db=None)
    assert resp.status_code == 401


def test_home_lists_only_owned_servers(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    u = User(username="a", password_hash="x")
    other = User(username="b", password_hash="x")
    db.add_all([u, other]); db.commit()
    db.add(ManagementServer(name="Mine", host="h1", port=443, username="admin", owner_id=u.id))
    db.add(ManagementServer(name="Theirs", host="h2", port=443, username="admin", owner_id=other.id))
    db.commit()
    monkeypatch.setattr(pcr, "get_user_or_none", lambda req, d: db.get(User, u.id))
    monkeypatch.setattr(pcr, "_pop_flash", lambda req: None)
    monkeypatch.setattr(pcr.mgmt_creds, "has_secret", lambda d, m: True)
    captured = {}
    monkeypatch.setattr(pcr.templates, "TemplateResponse",
                        lambda req, tpl, ctx: captured.update(tpl=tpl, ctx=ctx) or "OK")
    out = pcr.policy_cleanup_home(request=None, db=db)
    assert out == "OK" and captured["tpl"] == "policy_cleanup.html"
    assert [r["ms"].name for r in captured["ctx"]["rows"]] == ["Mine"]
    db.close()


def test_apply_route_passes_actor_and_returns_ok(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    u = User(username="alice", password_hash="x", is_admin=True)
    db.add(u); db.commit()
    ms = ManagementServer(name="HQ", host="h", port=443, username="admin", owner_id=u.id)
    db.add(ms); db.commit()

    monkeypatch.setattr(pcr, "get_user_or_none", lambda req, d: db.get(User, u.id))
    monkeypatch.setattr(pcr, "_secret_or_error", lambda d, m: ("secret", None))
    captured = {}

    def _fake_apply(server, secret, *, disable, delete, publish, actor, **kw):
        captured.update(actor=actor, publish=publish, thresholds=(kw.get("disable_after"), kw.get("delete_after")))
        return {"ok": True, "published": publish, "disabled": 2, "deleted": 1, "applied": True}

    monkeypatch.setattr(pcr.policy_cleanup, "apply_plan", _fake_apply)
    req = pcr.ApplyReq(disable=[{"uid": "a", "layer": "L"}], delete=[], publish=True)
    resp = pcr.policy_cleanup_apply(sid=ms.id, request=None, req=req, db=db)
    assert resp.status_code == 200 and captured["actor"] == "user:alice" and captured["publish"] is True
    db.close()


def test_apply_route_returns_400_on_sms_failure(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    u = User(username="alice", password_hash="x", is_admin=True)
    db.add(u); db.commit()
    ms = ManagementServer(name="HQ", host="h", port=443, username="admin", owner_id=u.id)
    db.add(ms); db.commit()

    monkeypatch.setattr(pcr, "get_user_or_none", lambda req, d: db.get(User, u.id))
    monkeypatch.setattr(pcr, "_secret_or_error", lambda d, m: ("secret", None))
    monkeypatch.setattr(pcr.policy_cleanup, "apply_plan",
                        lambda *a, **k: {"ok": False, "error": "Locked for editing by admin",
                                         "lock_conflict": True, "published": False})
    req = pcr.ApplyReq(disable=[{"uid": "a", "layer": "L"}], delete=[], publish=True)
    resp = pcr.policy_cleanup_apply(sid=ms.id, request=None, req=req, db=db)
    assert resp.status_code == 400     # an SMS-side failure surfaces as a 4xx, not a 200
    db.close()


def test_apply_route_403_without_apply_permission(monkeypatch):
    # A standard user with no APPLY capability must be refused before any SMS work happens (RBAC).
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    u = User(username="nobody", password_hash="x")     # standard user, no perm flags
    db.add(u); db.commit()
    ms = ManagementServer(name="HQ", host="h", port=443, username="admin", owner_id=u.id)
    db.add(ms); db.commit()
    monkeypatch.setattr(pcr, "get_user_or_none", lambda req, d: db.get(User, u.id))
    monkeypatch.setattr(pcr.policy_cleanup, "apply_plan",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not reach apply")))
    req = pcr.ApplyReq(disable=[{"uid": "a", "layer": "L"}], delete=[], publish=False)
    resp = pcr.policy_cleanup_apply(sid=ms.id, request=None, req=req, db=db)
    assert resp.status_code == 403
    db.close()


def test_plan_route_rejects_nonpositive_threshold():
    import pydantic
    try:
        pcr.PlanReq(disable_after=0)
    except pydantic.ValidationError:
        pass
    else:
        raise AssertionError("disable_after=0 should be rejected")
