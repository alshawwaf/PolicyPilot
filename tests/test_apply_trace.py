"""The apply trace captures each Gaia step's request/response and redacts secrets."""
import ssl

from app.services import apply_runner

PAYLOAD = {
    "dry-run": False,
    "objects": {"hosts": [{"name": "h", "ip-address": "1.1.1.1"}]},
    "referenced-objects": {"access-layers": ["dl"]},
    "access-layers-content": [{"name": "dl", "operation": "replace", "rulebase": [
        {"name": "r", "action": "Accept", "source": "any", "destination": "any", "service": "any"}
    ]}],
}


def test_mock_trace_steps_and_redaction(monkeypatch):
    monkeypatch.setattr(apply_runner.time, "sleep", lambda *_a, **_k: None)
    pid = "t1"
    apply_runner._PROGRESS[pid] = {"stage": "queued", "status": "running", "done_stages": []}
    result, status, code, task_id = apply_runner._run_mock(pid, PAYLOAD, False)

    steps = [s["step"] for s in result["trace"]]
    assert steps == ["login", "set-dynamic-content", "show-task", "logout"]
    assert status == "succeeded"

    login = result["trace"][0]
    assert login["request"]["body"]["password"] == "***"          # password never recorded
    assert login["response"]["sid"] == apply_runner._MASK          # session token masked

    push = result["trace"][1]
    assert push["request"]["headers"]["X-chkp-sid"] == apply_runner._MASK
    assert push["request"]["body"]["objects"]["hosts"][0]["name"] == "h"  # real payload captured
    assert push["response"]["task-id"]                            # task-id returned

    show = result["trace"][2]
    assert show["response"]["tasks"][0]["status"] == "succeeded"


def test_mock_trace_present_for_failed_validation(monkeypatch):
    monkeypatch.setattr(apply_runner.time, "sleep", lambda *_a, **_k: None)
    bad = {**PAYLOAD, "access-layers-content": [{"name": "dl", "operation": "replace",
           "rulebase": [{"name": "noaction"}]}]}  # missing action -> validation error
    apply_runner._PROGRESS["t2"] = {"stage": "queued", "status": "running", "done_stages": []}
    result, status, code, _ = apply_runner._run_mock("t2", bad, False)
    assert status == "failed"
    assert len(result["trace"]) == 4  # still captures the full session


def test_pinned_context_is_pinning_not_skip_verify(monkeypatch):
    # Don't require a real PEM on disk — assert the security posture of the pinned context.
    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", lambda self, **kw: None)
    ctx = apply_runner._pinned_ssl_context("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
    assert ctx.verify_mode == ssl.CERT_REQUIRED            # verification stays ON (never CERT_NONE)
    assert ctx.check_hostname is False                     # hostname match superseded by the pin
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2   # TLS 1.2+ enforced (org policy)
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN  # pinned leaf honored as trust anchor


def test_layer_view_normalizes_show_dynamic_layer():
    d = {"name": "dc_Network_layer", "objects": {"hosts": [{"name": "client"}]},
         "rulebase": [{"name": "test1", "action": "accept"}],
         "last-dynamic-content-change": {"administrator": "admin"}}
    v = apply_runner._layer_view(d, queried_name="Network")
    assert v["name"] == "Network" and v["display_name"] == "dc_Network_layer"
    assert v["rulebase"][0]["name"] == "test1"
    assert v["last_change"]["administrator"] == "admin"
    assert v["referenced"] == []  # rule references nothing external here
    # when the queried name equals the response name, no separate display_name
    v2 = apply_runner._layer_view({"name": "L", "objects": {}, "rulebase": []}, queried_name="L")
    assert v2["name"] == "L" and v2["display_name"] == ""


def test_fetch_mock_reflects_authored_layers(monkeypatch):
    monkeypatch.setattr(apply_runner, "write_activity", lambda **_k: None)  # no DB side effect

    class _Layer:
        def __init__(self, layer_name, name, content):
            self.layer_name, self.name, self.content = layer_name, name, content

    class _Scalars:
        def __init__(self, rows): self._rows = rows
        def all(self): return self._rows

    class _DB:
        def scalars(self, *_a, **_k):
            return _Scalars([_Layer("dynamic_layer", "Demo",
                {"objects": {"hosts": [{"name": "h"}]}, "rulebase": [{"name": "r1"}]})])

    data = apply_runner.fetch_dynamic_content(target="mock", db=_DB(), owner_id=1)
    assert data["ok"] and data["error"] is None
    assert data["layers"][0]["name"] == "dynamic_layer" and data["layers"][0]["display_name"] == "Demo"
    steps = [s["step"] for s in data["trace"]]
    assert steps[0] == "login" and steps[-1] == "logout"
    assert "show-dynamic-layers" in steps and "show-dynamic-layer" in steps


def test_summary_from_payload_counts_rules_and_objects():
    payload = {
        "objects": {"hosts": [{"name": "h1"}, {"name": "h2"}], "networks": [{"name": "n1"}]},
        "access-layers-content": [{"name": "dl", "rulebase": [{"name": "r1"}, {"name": "r2"}]}],
    }
    cs = apply_runner._summary_from_payload(payload)
    assert sorted(cs["objects"]["create"]) == ["h1", "h2", "n1"]
    assert cs["layers"][0]["rules"]["create"] == ["r1", "r2"]
    s = apply_runner._summary({"change_summary": cs})  # the modal's "Created N rule(s), M object(s)"
    assert s["objects"] == 3 and s["rules"] == 2


class _Resp:
    def __init__(self, code, body=None, raises=False):
        self.status_code = code
        self._body, self._raises = body, raises
    def json(self):
        if self._raises:
            raise ValueError("not json")
        return self._body


class _FakeClient:
    """Scripts httpx.Client.post by URL substring so we can exercise _run_gateway end-to-end."""
    def __init__(self, script):
        self.script = script
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def post(self, url, json=None, headers=None):
        for key, resp in self.script.items():
            if key in url:
                return resp
        raise AssertionError("unexpected URL: " + url)


def _gw_script(show_task):
    return {"/login": _Resp(200, {"sid": "S"}),
            "/set-dynamic-content": _Resp(200, {"task-id": "abc"}),
            "/show-task": _Resp(200, show_task),
            "/logout": _Resp(200, {"message": "bye"})}


def _gw_progress(pid):
    apply_runner._PROGRESS[pid] = {"stage": "queued", "status": "running",
                                   "done_stages": [], "failed_stage": None}


def test_run_gateway_failed_when_task_reports_validation_errors(monkeypatch):
    # The gateway returns the task as "partially succeeded" but with validation errors (e.g. an
    # application used on a layer without the App & URL Filtering blade) — that is NOT a success.
    monkeypatch.setattr(apply_runner.time, "sleep", lambda *a, **k: None)
    errs = [{"layer": "dl", "rule": "block_facebook", "object": "Facebook",
             "message": "Service and Applications column cannot contain applications or categories ..."}]
    show = {"tasks": [{"task-id": "abc", "status": "partially succeeded", "status-code": 200,
            "task-details": [{"change-summary": {}, "validation-errors": errs, "validation-warnings": []}]}]}
    monkeypatch.setattr(apply_runner.httpx, "Client", lambda **kw: _FakeClient(_gw_script(show)))
    _gw_progress("gwf")
    result, status, code, task_id = apply_runner._run_gateway(
        "gwf", PAYLOAD, False, host="h", port=443, user="u", password="p", cert_pem=None)
    assert status == "failed" and task_id == "abc"          # not painted green
    assert "applications or categories" in result["validation_errors"][0]["message"]


def test_run_gateway_succeeds_on_clean_task(monkeypatch):
    monkeypatch.setattr(apply_runner.time, "sleep", lambda *a, **k: None)
    show = {"tasks": [{"task-id": "abc", "status": "succeeded", "status-code": 200,
            "task-details": [{"change-summary": {"layers": [{"name": "dl", "rules": {"create": ["r"]}}],
                              "objects": {"create": ["h"]}}, "validation-errors": [],
                              "validation-warnings": []}]}]}
    monkeypatch.setattr(apply_runner.httpx, "Client", lambda **kw: _FakeClient(_gw_script(show)))
    _gw_progress("gws")
    result, status, code, task_id = apply_runner._run_gateway(
        "gws", PAYLOAD, False, host="h", port=443, user="u", password="p", cert_pem=None)
    assert status == "succeeded" and not result["validation_errors"]
    assert result["change_summary"]["objects"]["create"] == ["h"]


def test_login_error_clean_for_401():
    msg = apply_runner._login_error(_Resp(401, {"message": "Authentication required"}))
    assert "401" in msg and "rejected the username/password" in msg
    assert "does not store the password" in msg and "Authentication required" in msg


def test_login_error_generic_for_500_without_json():
    msg = apply_runner._login_error(_Resp(500, raises=True))
    assert "500" in msg and "Client error" not in msg  # not httpx's raw string


def _progress(stage, done):
    return {"stage": stage, "status": "running", "done_stages": list(done), "failed_stage": None,
            "task_id": None, "summary": None, "error": None, "trace": []}


def test_finish_transport_failure_marks_only_the_failing_step():
    # A step failed (e.g. TLS/connect): that step is the failure; only steps BEFORE it are done.
    apply_runner._PROGRESS["g1"] = _progress("logging_out", ["connecting", "logging_in", "pushing"])
    result = {"failed_stage": "pushing", "validation_errors": [{"message": "boom"}], "trace": []}
    apply_runner._finish("g1", status="failed", result=result, task_id="t")
    p = apply_runner._PROGRESS["g1"]
    assert p["failed_stage"] == "pushing"
    assert p["done_stages"] == ["connecting", "logging_in"]   # not pushing/polling/logging_out/done
    assert p["error"] == "boom"


def test_finish_session_complete_marks_every_step_done():
    done = ["connecting", "logging_in", "pushing", "polling", "logging_out"]
    apply_runner._PROGRESS["g2"] = _progress("logging_out", done)
    apply_runner._finish("g2", status="succeeded", result={"trace": []}, task_id="t")
    p = apply_runner._PROGRESS["g2"]
    assert p["stage"] == "done" and p["failed_stage"] is None
    assert all(k in p["done_stages"] for k in done)


def test_finish_validation_failure_keeps_steps_green():
    # Session completed but the task reported validation errors -> steps stay done, error surfaced.
    done = ["connecting", "logging_in", "pushing", "polling", "logging_out"]
    apply_runner._PROGRESS["g3"] = _progress("logging_out", done)
    result = {"trace": [], "validation_errors": [{"message": "rule invalid"}]}  # no failed_stage
    apply_runner._finish("g3", status="failed", result=result, task_id="t")
    p = apply_runner._PROGRESS["g3"]
    assert p["failed_stage"] is None and "pushing" in p["done_stages"]
    assert p["error"] == "rule invalid"
