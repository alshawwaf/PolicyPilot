"""Mock of the gateway-side Gaia API so the full set-dynamic-content flow demos without a
real R82 gateway. SEs can also point their own scripts at the portal as a fake gateway.

Endpoints mirror the real API (versioned and version-less):
  POST /gaia_api/[<version>/]login              {"user","password"}        -> {"sid"}
  POST /gaia_api/[<version>/]set-dynamic-content (X-chkp-sid)               -> {"task-id"}
  POST /gaia_api/[<version>/]show-task           {"task-id"} (X-chkp-sid)   -> {"tasks":[...]}
  POST /gaia_api/[<version>/]logout              (X-chkp-sid)               -> {"message"}

The mock accepts any non-empty credentials (it represents a demo gateway).
"""
import time
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import LayerTask
from ..schemas.dynamic_layer import evaluate_dynamic_content

router = APIRouter(tags=["gaia-mock"])


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""

_SID_TTL = 600  # seconds — matches a gateway's 10-minute session
_SESSIONS: dict[str, float] = {}  # sid -> expiry epoch
_TASKS: dict[str, dict] = {}      # task-id -> evaluate() result
_LAYERS: dict[str, dict] = {}     # layer name -> stored content (for show-dynamic-layer[s])


def _new_sid() -> str:
    return uuid.uuid4().hex


def _require_sid(sid: str | None) -> None:
    expiry = _SESSIONS.get(sid or "")
    if not expiry or expiry < time.time():
        raise HTTPException(status_code=401, detail="Missing or expired X-chkp-sid session.")


def _task_details(result: dict) -> dict:
    return {
        "change-summary": result.get("change_summary", {}),
        "validation-warnings": result.get("validation_warnings", []),
        "validation-errors": result.get("validation_errors", []),
        "dry-run": result.get("dry_run", False),
        "comments": result.get("comments", ""),
        "tags": result.get("tags", []),
    }


def _login(body: dict) -> dict:
    if not (body or {}).get("user") or not (body or {}).get("password"):
        raise HTTPException(status_code=400, detail="Missing user or password.")
    sid = _new_sid()
    _SESSIONS[sid] = time.time() + _SID_TTL
    return {"sid": sid, "uid": uuid.uuid4().hex, "session-timeout": _SID_TTL}


def _set_dynamic_content(request: Request, body: dict, db: Session, sid: str | None) -> dict:
    _require_sid(sid)
    result = evaluate_dynamic_content(body or {})
    # Remember the applied content per layer so show-dynamic-layer(s) can return it (skip dry-runs).
    if not (body or {}).get("dry-run"):
        for lyr in (body or {}).get("access-layers-content", []) or []:
            nm = lyr.get("name")
            if not nm:
                continue
            _LAYERS[nm] = {
                "name": nm,
                "objects": (body or {}).get("objects", {}) or {},
                "rulebase": lyr.get("rulebase", []) or [],
                "last-dynamic-content-change": {
                    "administrator": "mock",
                    "change-comments": (body or {}).get("comments", ""),
                    "change-tags": (body or {}).get("tags", []),
                },
            }
    task_id = str(uuid.uuid4())
    _TASKS[task_id] = result
    db.add(LayerTask(
        task_id=task_id, layer_id=None, target="mock",
        dry_run=result.get("dry_run", False), status=result["status"],
        status_code=result["status_code"], result=result,
        source_ip=client_ip(request), user_agent=(request.headers.get("user-agent") or "")[:255],
    ))
    db.commit()
    return {"task-id": task_id}


def _show_task(body: dict, sid: str | None) -> dict:
    _require_sid(sid)
    result = _TASKS.get((body or {}).get("task-id"))
    if result is None:
        raise HTTPException(status_code=404, detail="Task not found.")
    return {"tasks": [{
        "task-id": (body or {}).get("task-id"),
        "task-name": "/set-dynamic-content",
        "status": result["status"],
        "status-code": result["status_code"],
        "progress-percentage": 100,
        "task-details": [_task_details(result)],
    }]}


def _show_dynamic_layers(sid: str | None) -> dict:
    _require_sid(sid)
    return {"layers": [{"name": v["name"],
                        "last-dynamic-content-change": v.get("last-dynamic-content-change", {})}
                       for v in _LAYERS.values()]}


def _show_dynamic_layer(body: dict, sid: str | None) -> dict:
    _require_sid(sid)
    name = (body or {}).get("name")
    v = _LAYERS.get(name)
    if v is None:
        raise HTTPException(status_code=404, detail=f"Dynamic layer '{name}' not found.")
    return v


def _logout(sid: str | None) -> dict:
    _SESSIONS.pop(sid or "", None)
    return {"message": "Session ended."}


# --- Routes: registered both versioned (/gaia_api/v1.9/...) and version-less ---------------
@router.post("/gaia_api/{version}/login")
@router.post("/gaia_api/login")
def gaia_login(body: dict, version: str = "v1.9"):
    return _login(body)


@router.post("/gaia_api/{version}/set-dynamic-content")
@router.post("/gaia_api/set-dynamic-content")
def gaia_set_dynamic_content(
    request: Request, body: dict, db: Session = Depends(get_db),
    x_chkp_sid: str | None = Header(default=None), version: str = "v1.9",
):
    return _set_dynamic_content(request, body, db, x_chkp_sid)


@router.post("/gaia_api/{version}/show-task")
@router.post("/gaia_api/show-task")
def gaia_show_task(body: dict, x_chkp_sid: str | None = Header(default=None), version: str = "v1.9"):
    return _show_task(body, x_chkp_sid)


@router.post("/gaia_api/{version}/show-dynamic-layers")
@router.post("/gaia_api/show-dynamic-layers")
def gaia_show_dynamic_layers(x_chkp_sid: str | None = Header(default=None), version: str = "v1.9"):
    return _show_dynamic_layers(x_chkp_sid)


@router.post("/gaia_api/{version}/show-dynamic-layer")
@router.post("/gaia_api/show-dynamic-layer")
def gaia_show_dynamic_layer(body: dict, x_chkp_sid: str | None = Header(default=None), version: str = "v1.9"):
    return _show_dynamic_layer(body, x_chkp_sid)


@router.post("/gaia_api/{version}/logout")
@router.post("/gaia_api/logout")
def gaia_logout(x_chkp_sid: str | None = Header(default=None), version: str = "v1.9"):
    return _logout(x_chkp_sid)
