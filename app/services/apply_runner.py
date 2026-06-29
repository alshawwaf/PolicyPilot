"""Background apply runner with live progress AND a full request/response trace.

Runs the Gaia API session (login -> set-dynamic-content -> poll show-task -> logout) in a
daemon thread, reporting the current stage via an in-memory progress map the UI polls. Each
HTTP step is captured into a trace (method, URL, request, response, status, ms) so the SE can
inspect the actual data. TLS verification is never disabled. Secrets are redacted: the gateway
password is never recorded, and the session token (X-chkp-sid) is masked.
"""
import ssl
import threading
import time
import uuid

import httpx
from sqlalchemy import select

from ..db import SessionLocal
from ..models import DynamicLayer, GatewayLayerSnapshot, LayerTask
from ..schemas.dynamic_layer import (
    build_set_dynamic_content,
    evaluate_dynamic_content,
    referenced_object_names,
)
from . import app_settings
from .activity import write_activity

GAIA_VERSION = "v1.9"
_MASK = "(session token masked)"

STAGES = [
    ("connecting", "Connecting"),
    ("logging_in", "Logging in"),
    ("pushing", "Pushing policy"),
    ("polling", "Waiting for task"),
    ("logging_out", "Logging out"),
    ("done", "Done"),
]

_PROGRESS: dict[str, dict] = {}


def get_progress(pid: str) -> dict | None:
    return _PROGRESS.get(pid)


def _summary(result: dict) -> dict:
    cs = result.get("change_summary", {}) or {}
    return {
        "rules": sum(len((lyr.get("rules", {}) or {}).get("create", [])) for lyr in cs.get("layers", [])),
        "objects": len((cs.get("objects", {}) or {}).get("create", [])),
        "warnings": len(result.get("validation_warnings", [])),
        "errors": len(result.get("validation_errors", [])),
    }


def _summary_from_payload(payload: dict) -> dict:
    """Build a change-summary from the pushed payload — used when the gateway accepted the content
    (task-id returned) but show-task didn't return its own summary."""
    objs = []
    for items in (payload.get("objects") or {}).values():
        for o in (items or []):
            if isinstance(o, dict) and o.get("name"):
                objs.append(o["name"])
    layers = []
    for lyr in (payload.get("access-layers-content") or []):
        rnames = [r.get("name") for r in (lyr.get("rulebase") or []) if isinstance(r, dict) and r.get("name")]
        layers.append({"name": lyr.get("name", ""), "rules": {"create": rnames, "delete": [], "modify": []}})
    return {"layers": layers, "objects": {"create": sorted(set(objs)), "delete": [], "modify": []}}


def _trace_entry(step, method, url, *, headers=None, body=None, resp=None, err=None, ms=None) -> dict:
    entry = {"step": step, "method": method, "url": url,
             "request": {"headers": headers or {}, "body": body},
             "status": (resp.status_code if resp is not None else None), "ms": ms}
    if err is not None:
        entry["response"] = {"error": str(err)}
    elif resp is not None:
        try:
            entry["response"] = resp.json()
        except Exception:
            entry["response"] = (resp.text or "")[:4000]
    else:
        entry["response"] = None
    return entry


def _task_details(result: dict) -> dict:
    return {
        "change-summary": result.get("change_summary", {}),
        "validation-warnings": result.get("validation_warnings", []),
        "validation-errors": result.get("validation_errors", []),
        "dry-run": result.get("dry_run", False),
    }


def _advance(pid: str, stage: str) -> None:
    p = _PROGRESS[pid]
    if p["stage"] not in ("queued", stage) and p["stage"] not in p["done_stages"]:
        p["done_stages"].append(p["stage"])
    p["stage"] = stage


def _finish(pid: str, *, status: str, result: dict, task_id: str) -> None:
    p = _PROGRESS[pid]
    fstage = result.get("failed_stage")
    if fstage:
        # A transport/session step failed: mark that step (red), keep the steps before it done,
        # and leave the rest pending — so the modal shows exactly where it broke.
        order = [k for k, _ in STAGES]
        if fstage not in order:
            fstage = "connecting"
        p["done_stages"] = order[: order.index(fstage)]
        p["failed_stage"] = fstage
        p["stage"] = fstage
    else:
        # The Gaia session completed end-to-end (the task itself may still report a validation
        # failure, surfaced in the result box below) — so every step is done.
        for key, _ in STAGES:
            if key != "done" and key not in p["done_stages"]:
                p["done_stages"].append(key)
        p["stage"] = "done"
    p.update(status=status, task_id=task_id, summary=_summary(result), trace=result.get("trace", []))
    if result.get("validation_errors"):
        p["error"] = result["validation_errors"][0].get("message", "")


def start_apply(*, layer_id: int, target: str, dry_run: bool, gateway_host: str | None = None,
                gateway_port: int = 443, user: str | None = None, password: str | None = None,
                cert_pem: str | None = None) -> str:
    pid = uuid.uuid4().hex
    _PROGRESS[pid] = {"stage": "queued", "status": "running", "target": target, "failed_stage": None,
                      "done_stages": [], "task_id": None, "summary": None, "error": None, "trace": []}
    threading.Thread(
        target=_run, args=(pid,),
        kwargs=dict(layer_id=layer_id, target=target, dry_run=dry_run, gateway_host=gateway_host,
                    gateway_port=gateway_port, user=user, password=password, cert_pem=cert_pem),
        daemon=True,
    ).start()
    return pid


def _run_mock(pid, payload, dry_run):
    """In-process mock: step the stages and synthesize a realistic request/response trace."""
    base = app_settings.base_url().rstrip("/") + f"/gaia_api/{GAIA_VERSION}"
    trace = []
    _advance(pid, "connecting"); time.sleep(0.3)
    _advance(pid, "logging_in"); time.sleep(0.3)
    trace.append(_trace_entry("login", "POST", f"{base}/login",
        headers={"Content-Type": "application/json"},
        body={"user": "<mock>", "password": "***"}, resp=None, ms=4))
    trace[-1]["status"] = 200
    trace[-1]["response"] = {"sid": _MASK, "session-timeout": 600}
    _advance(pid, "pushing"); time.sleep(0.35)
    result = evaluate_dynamic_content(payload)
    result["dry_run"] = dry_run
    task_id = uuid.uuid4().hex
    trace.append({"step": "set-dynamic-content", "method": "POST", "url": f"{base}/set-dynamic-content",
        "request": {"headers": {"Content-Type": "application/json", "X-chkp-sid": _MASK}, "body": payload},
        "status": 200, "ms": 6, "response": {"task-id": task_id}})
    _advance(pid, "polling"); time.sleep(0.3)
    show = {"tasks": [{"task-id": task_id, "task-name": "/set-dynamic-content",
            "status": result["status"], "status-code": result["status_code"],
            "progress-percentage": 100, "task-details": [_task_details(result)]}]}
    trace.append({"step": "show-task", "method": "POST", "url": f"{base}/show-task",
        "request": {"headers": {"X-chkp-sid": _MASK}, "body": {"task-id": task_id}},
        "status": 200, "ms": 5, "response": show})
    _advance(pid, "logging_out"); time.sleep(0.25)
    trace.append({"step": "logout", "method": "POST", "url": f"{base}/logout",
        "request": {"headers": {"X-chkp-sid": _MASK}, "body": None},
        "status": 200, "ms": 3, "response": {"message": "Session ended."}})
    result["trace"] = trace
    return result, result["status"], result["status_code"], task_id


def _pinned_ssl_context(cert_pem: str) -> ssl.SSLContext:
    """Build an SSL context that trusts ONLY the pinned certificate.

    TLS verification stays ON (CERT_REQUIRED, TLS 1.2+) — this is certificate *pinning*, not a
    skip-verify toggle. Hostname matching is turned off because a self-signed gateway is commonly
    reached via a DNS name its certificate was never issued for (e.g. a cloud-lab hostname);
    pinning the exact, operator-reviewed certificate is a stronger identity check than the
    hostname match. The peer must still present a certificate that validates against the pin.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Honor the pinned certificate as a trust anchor on its own — so it works whether the gateway
    # presents a self-signed cert or a leaf issued by an internal CA (we only fetched the leaf).
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=cert_pem)
    return ctx


def _login_error(resp) -> str:
    """A clean message for a failed gateway login (instead of httpx's raw 'Client error 401 …')."""
    msg = ""
    try:
        body = resp.json() or {}
        msg = body.get("message") or body.get("errors") or body.get("error") or ""
    except Exception:
        msg = ""
    if resp.status_code in (401, 403):
        return (f"Gateway login failed ({resp.status_code} Unauthorized): the gateway rejected the "
                f"username/password" + (f" — {msg}" if msg else "") + ". Note: a saved gateway does "
                "not store the password, so you must enter it for each apply/fetch.")
    return f"Gateway login failed (HTTP {resp.status_code})." + (f" {msg}" if msg else "")


def _run_gateway(pid, payload, dry_run, *, host, port, user, password, cert_pem):
    pinned = bool(cert_pem and cert_pem.strip())
    verify = _pinned_ssl_context(cert_pem) if pinned else True
    base = f"https://{host}:{port}/gaia_api/{GAIA_VERSION}"
    trace = []
    result = {"change_summary": {}, "validation_warnings": [], "validation_errors": [], "dry_run": dry_run}
    status, status_code, task_id = "failed", 0, ""
    failed_stage = None
    try:
        with httpx.Client(verify=verify, timeout=30.0) as client:
            _advance(pid, "connecting")
            try:
                t = time.perf_counter()
                login = client.post(f"{base}/login", json={"user": user, "password": password})
            except Exception:
                failed_stage = "connecting"   # couldn't establish the session (TLS / timeout / unreachable)
                raise
            trace.append(_trace_entry("login", "POST", f"{base}/login",
                headers={"Content-Type": "application/json"},
                body={"user": user, "password": "***"}, resp=login,
                ms=round((time.perf_counter() - t) * 1000)))
            if login.status_code >= 400:   # reached the gateway, but it rejected the login
                failed_stage = "logging_in"
                result["validation_errors"] = [{"layer": "", "rule": "", "object": "",
                                                 "message": _login_error(login)}]
                result["trace"] = trace
                result["failed_stage"] = failed_stage
                return result, status, status_code, task_id
            sid = login.json().get("sid")
            _advance(pid, "logging_in")
            headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
            shown_headers = {"X-chkp-sid": _MASK, "Content-Type": "application/json"}
            try:
                _advance(pid, "pushing")
                t = time.perf_counter()
                resp = client.post(f"{base}/set-dynamic-content", json=payload, headers=headers)
                trace.append(_trace_entry("set-dynamic-content", "POST", f"{base}/set-dynamic-content",
                    headers=shown_headers, body=payload, resp=resp, ms=round((time.perf_counter() - t) * 1000)))
                status_code = resp.status_code
                try:
                    body = resp.json() or {}
                except Exception:
                    body = {}
                task_id = body.get("task-id") or body.get("task_id") or ""
                _advance(pid, "polling")
                if task_id:
                    # A task-id means the gateway ACCEPTED the content. Poll show-task for the
                    # detailed result (best-effort); every poll is traced for visibility.
                    details, terminal = {}, None
                    for i in range(20):
                        t = time.perf_counter()
                        tr = client.post(f"{base}/show-task", json={"task-id": task_id}, headers=headers)
                        try:
                            tasks = (tr.json() or {}).get("tasks", []) or []
                        except Exception:
                            tasks = []
                        st = str(tasks[0].get("status") if tasks else "").strip().lower()
                        is_terminal = st in ("succeeded", "failed", "partially succeeded")
                        if i == 0 or is_terminal:   # always show the first poll, plus the terminal one
                            trace.append(_trace_entry("show-task", "POST", f"{base}/show-task",
                                headers=shown_headers, body={"task-id": task_id}, resp=tr,
                                ms=round((time.perf_counter() - t) * 1000)))
                        if is_terminal:
                            t0 = tasks[0]
                            details = (t0.get("task-details") or [{}])[0]
                            terminal = st
                            status_code = t0.get("status-code", status_code)
                            break
                        time.sleep(0.4)
                    verrs = details.get("validation-errors") or []
                    if terminal == "failed" or verrs:
                        # Task failed, OR it completed ("succeeded"/"partially succeeded") but the
                        # gateway rejected content (e.g. an application used on a layer without the
                        # Application & URL Filtering blade). Either way the policy was NOT fully
                        # applied — report failed and surface the gateway's own message, don't
                        # paint it green.
                        status = "failed"
                        result = {"change_summary": details.get("change-summary", {}),
                                  "validation_warnings": details.get("validation-warnings", []),
                                  "validation_errors": (verrs or
                                      [{"layer": "", "rule": "", "object": "",
                                        "message": "Gateway reported the set-dynamic-content task as failed."}]),
                                  "dry_run": dry_run}
                    elif terminal:  # succeeded with no validation errors
                        status = "succeeded"
                        result = {"change_summary": details.get("change-summary") or _summary_from_payload(payload),
                                  "validation_warnings": details.get("validation-warnings", []),
                                  "validation_errors": [], "dry_run": dry_run}
                    else:
                        # Accepted (task-id returned) but show-task never confirmed a terminal state in
                        # the poll window — report accepted, summarizing from the pushed payload.
                        status = "succeeded"
                        result = {"change_summary": _summary_from_payload(payload),
                                  "validation_warnings": [{"layer": "", "rule": "", "object": "",
                                      "message": f"Content accepted (task-id {task_id}); detailed task status "
                                                 "was not confirmed via show-task within the poll window."}],
                                  "validation_errors": [], "dry_run": dry_run}
                else:
                    # Per Check Point's docs a valid push returns a task-id; its absence means the
                    # gateway rejected the request — surface its actual message, don't fail blankly.
                    if failed_stage is None:
                        failed_stage = "pushing"
                    gw_msg = (body.get("message") or body.get("errors") or body.get("error")
                              or f"HTTP {status_code} with no task-id in the response")
                    result = {"change_summary": {}, "validation_warnings": [],
                              "validation_errors": [{"layer": "", "rule": "", "object": "",
                                  "message": f"Gateway did not accept set-dynamic-content: {gw_msg}"}],
                              "dry_run": dry_run}
            except Exception:
                if failed_stage is None:
                    failed_stage = _PROGRESS[pid]["stage"]   # "pushing" or "polling"
                raise
            finally:
                _advance(pid, "logging_out")
                try:
                    t = time.perf_counter()
                    lo = client.post(f"{base}/logout", headers=headers)
                    trace.append(_trace_entry("logout", "POST", f"{base}/logout",
                        headers=shown_headers, body=None, resp=lo, ms=round((time.perf_counter() - t) * 1000)))
                except Exception:
                    pass
    except httpx.ConnectError as exc:
        if failed_stage is None:
            failed_stage = "connecting"
        trace.append(_trace_entry("connect", "POST", f"{base}/login", err=exc))
        msg = (f"Could not reach the gateway, or it presented a certificate that doesn't match the "
               f"pinned one — re-pin it on the gateway's profile (Gateways → edit → Fetch & trust): {exc}"
               ) if pinned else (
              f"Could not reach the gateway, or TLS verification failed (self-signed?) — pin the "
              f"gateway's certificate on its profile (Gateways → edit → Fetch & trust certificate): {exc}")
        result["validation_errors"] = [{"layer": "", "rule": "", "object": "", "message": msg}]
    except Exception as exc:
        if failed_stage is None:
            failed_stage = _PROGRESS[pid].get("stage") or "connecting"
        trace.append(_trace_entry("error", "POST", base, err=exc))
        result["validation_errors"] = [{"layer": "", "rule": "", "object": "", "message": f"Gateway request failed: {exc}"}]
    result["trace"] = trace
    result["failed_stage"] = failed_stage
    return result, status, status_code, task_id


# --- Read side: fetch what dynamic layers / content a gateway currently has ----------------
# Real Gaia API (R82): show-dynamic-layers -> [{name, last-dynamic-content-change}];
#                      show-dynamic-layer {name} -> {name, objects, rulebase, last-dynamic-content-change}.
def _layer_view(d: dict, queried_name: str = "") -> dict:
    """Normalize a show-dynamic-layer response into the shape the UI renders."""
    inner = d.get("name") or ""
    objects = d.get("objects") or {}
    rulebase = d.get("rulebase") or []
    return {
        "name": queried_name or inner or "(unnamed)",
        "display_name": inner if (inner and queried_name and inner != queried_name) else "",
        "objects": objects,
        "rulebase": rulebase,
        # Objects the rules reference but don't define here — resolved on the gateway.
        "referenced": referenced_object_names(objects, rulebase, d.get("referenced-objects")),
        "last_change": d.get("last-dynamic-content-change") or {},
    }


def _fetch_mock(db, owner_id: int) -> dict:
    """The built-in mock gateway reflects the dynamic layers authored in the portal."""
    base = app_settings.base_url().rstrip("/") + f"/gaia_api/{GAIA_VERSION}"
    rows = db.scalars(
        select(DynamicLayer).where(DynamicLayer.owner_id == owner_id).order_by(DynamicLayer.name)
    ).all()
    layers = []
    for r in rows:
        c = r.content or {}
        objs, rb = c.get("objects", {}) or {}, c.get("rulebase", []) or []
        layers.append({"name": r.layer_name, "display_name": r.name, "objects": objs, "rulebase": rb,
                       "referenced": referenced_object_names(objs, rb, c.get("referenced_objects")),
                       "last_change": {}})
    trace = [
        {"step": "login", "method": "POST", "url": f"{base}/login",
         "request": {"headers": {"Content-Type": "application/json"},
                     "body": {"user": "<mock>", "password": "***"}},
         "status": 200, "ms": 3, "response": {"sid": _MASK, "session-timeout": 600}},
        {"step": "show-dynamic-layers", "method": "POST", "url": f"{base}/show-dynamic-layers",
         "request": {"headers": {"X-chkp-sid": _MASK, "Content-Type": "application/json"}, "body": {}},
         "status": 200, "ms": 4, "response": {"layers": [{"name": lr["name"]} for lr in layers]}},
    ]
    for lr in layers:
        trace.append({"step": "show-dynamic-layer", "method": "POST", "url": f"{base}/show-dynamic-layer",
            "request": {"headers": {"X-chkp-sid": _MASK, "Content-Type": "application/json"},
                        "body": {"name": lr["name"]}},
            "status": 200, "ms": 4,
            "response": {"name": lr["name"], "objects": lr["objects"], "rulebase": lr["rulebase"]}})
    trace.append({"step": "logout", "method": "POST", "url": f"{base}/logout",
        "request": {"headers": {"X-chkp-sid": _MASK}, "body": None},
        "status": 200, "ms": 2, "response": {"message": "Session ended."}})
    return {"ok": True, "layers": layers, "trace": trace, "error": None}


def _fetch_gateway_content(*, host, port, user, password, cert_pem) -> dict:
    pinned = bool(cert_pem and cert_pem.strip())
    verify = _pinned_ssl_context(cert_pem) if pinned else True
    base = f"https://{host}:{port}/gaia_api/{GAIA_VERSION}"
    trace, layers, error = [], [], None
    try:
        with httpx.Client(verify=verify, timeout=30.0) as client:
            t = time.perf_counter()
            login = client.post(f"{base}/login", json={"user": user, "password": password})
            trace.append(_trace_entry("login", "POST", f"{base}/login",
                headers={"Content-Type": "application/json"},
                body={"user": user, "password": "***"}, resp=login,
                ms=round((time.perf_counter() - t) * 1000)))
            if login.status_code >= 400:
                return {"ok": False, "layers": layers, "trace": trace, "error": _login_error(login)}
            sid = login.json().get("sid")
            headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
            shown = {"X-chkp-sid": _MASK, "Content-Type": "application/json"}
            try:
                # 1) list the dynamic layers the gateway has
                t = time.perf_counter()
                lr = client.post(f"{base}/show-dynamic-layers", json={}, headers=headers)
                trace.append(_trace_entry("show-dynamic-layers", "POST", f"{base}/show-dynamic-layers",
                    headers=shown, body={}, resp=lr, ms=round((time.perf_counter() - t) * 1000)))
                try:
                    ldata = lr.json() or {}
                except Exception:
                    ldata = {}
                names = [x.get("name") for x in (ldata.get("layers") or [])
                         if isinstance(x, dict) and x.get("name")]
                if lr.status_code >= 400 and not names:
                    msg = ldata.get("message") or ldata.get("errors") or f"HTTP {lr.status_code}"
                    error = f"show-dynamic-layers failed: {msg}"
                # 2) pull each layer's objects + rulebase
                for name in names:
                    t = time.perf_counter()
                    dr = client.post(f"{base}/show-dynamic-layer", json={"name": name}, headers=headers)
                    trace.append(_trace_entry("show-dynamic-layer", "POST", f"{base}/show-dynamic-layer",
                        headers=shown, body={"name": name}, resp=dr,
                        ms=round((time.perf_counter() - t) * 1000)))
                    try:
                        d = dr.json() or {}
                    except Exception:
                        d = {}
                    layers.append(_layer_view(d, queried_name=name))
            finally:
                try:
                    t = time.perf_counter()
                    lo = client.post(f"{base}/logout", headers=headers)
                    trace.append(_trace_entry("logout", "POST", f"{base}/logout",
                        headers=shown, body=None, resp=lo,
                        ms=round((time.perf_counter() - t) * 1000)))
                except Exception:
                    pass
    except httpx.ConnectError as exc:
        trace.append(_trace_entry("connect", "POST", f"{base}/login", err=exc))
        error = (f"Could not reach the gateway, or it presented a certificate that doesn't match the "
                 f"pinned one — re-pin it on the gateway's profile (Gateways → edit → Fetch & trust): {exc}"
                 ) if pinned else (
                 f"Could not reach the gateway, or TLS verification failed (self-signed?) — pin the "
                 f"gateway's certificate on its profile (Gateways → edit → Fetch & trust certificate): {exc}")
    except Exception as exc:
        trace.append(_trace_entry("error", "POST", base, err=exc))
        error = f"Gateway request failed: {exc}"
    return {"ok": error is None, "layers": layers, "trace": trace, "error": error}


def _save_snapshot(db, gateway_id: int, data: dict) -> None:
    """Persist the fetched layers so a gateway's 'layers' view survives the fetch modal closing."""
    snap = db.scalar(select(GatewayLayerSnapshot).where(GatewayLayerSnapshot.gateway_id == gateway_id))
    if snap is None:
        snap = GatewayLayerSnapshot(gateway_id=gateway_id)
        db.add(snap)
    snap.layers = data.get("layers", []) or []
    snap.ok = bool(data.get("ok"))
    snap.error = data.get("error") or ""
    db.commit()


def fetch_dynamic_content(*, target, db, owner_id, host=None, port=443,
                          user=None, password=None, cert_pem=None, gateway_id=None) -> dict:
    """Read the dynamic layers / content currently on a gateway (real or the built-in mock)."""
    if target == "mock":
        data = _fetch_mock(db, owner_id)
        src = "mock"
    else:
        data = _fetch_gateway_content(host=host, port=port, user=user,
                                      password=password, cert_pem=cert_pem)
        src = host or "gateway"
        if gateway_id:
            _save_snapshot(db, gateway_id, data)
    total_ms = sum((s.get("ms") or 0) for s in data.get("trace", []))
    n = len(data.get("layers") or [])
    write_activity(kind="gateway_read", direction="outbound", method="POST",
                   path=f"show-dynamic-content [{target}]", source_ip=src,
                   status=(200 if data.get("ok") else 0), duration_ms=total_ms,
                   summary=f"Fetch dynamic layers from {src}: {n} layer(s)"
                           + ("" if data.get("ok") else " (failed)"),
                   detail={"trace": data.get("trace", [])})
    return data


def _run(pid, *, layer_id, target, dry_run, gateway_host, gateway_port, user, password, cert_pem):
    db = SessionLocal()
    try:
        layer = db.get(DynamicLayer, layer_id)
        if layer is None:
            _PROGRESS[pid].update(stage="done", status="failed", error="Layer not found.")
            return
        payload = build_set_dynamic_content(layer, dry_run=dry_run)
        if target == "mock":
            result, status, status_code, task_id = _run_mock(pid, payload, dry_run)
        else:
            result, status, status_code, task_id = _run_gateway(
                pid, payload, dry_run, host=gateway_host, port=gateway_port,
                user=user, password=password, cert_pem=cert_pem)
        task = LayerTask(task_id=task_id or uuid.uuid4().hex, layer_id=layer_id, target=target,
                         gateway_host=gateway_host, dry_run=dry_run, status=status,
                         status_code=status_code, result=result)
        db.add(task)
        db.commit()
        db.refresh(task)
        total_ms = sum((s.get("ms") or 0) for s in result.get("trace", []))
        write_activity(kind="layer_apply", direction="outbound", method="POST",
                       path=f"set-dynamic-content [{target}]", source_ip=(gateway_host or "mock"),
                       status=status_code or (200 if status == "succeeded" else 0),
                       duration_ms=total_ms, summary=f"Apply “{layer.name}” → {target}: {status}",
                       detail={"trace": result.get("trace", [])})
        _finish(pid, status=status, result=result, task_id=task.task_id)
    except Exception as exc:
        p = _PROGRESS[pid]
        fstage = p.get("stage") if p.get("stage") not in (None, "queued", "done") else "connecting"
        p.update(status="failed", failed_stage=fstage, error=str(exc))
    finally:
        db.close()
