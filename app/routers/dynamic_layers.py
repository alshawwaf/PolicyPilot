"""Dynamic Layers UI: author objects + rulebase -> preview the set-dynamic-content payload ->
apply to the built-in mock or a real R82 gateway -> review the task result & history."""
import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import DynamicLayer, Gateway, LayerTask, User
from ..schemas.dynamic_layer import (
    OBJECT_SPECS,
    OBJECT_TYPES,
    REFERENCE_TYPES,
    RULE_ACTIONS,
    TRACK_TYPES,
    build_set_dynamic_content,
    referenced_object_names,
    validate_layer_content,
)
from ..security import get_user_or_none, new_feed_token
from ..services import app_settings, gateway_creds, table_prefs
from ..services.apply_runner import STAGES, fetch_dynamic_content, get_progress, start_apply
from ..services.gaia_client import ensure_pinned, fetch_gateway_cert
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)

# Pre-filled sample so the builder opens with a working example (the docs' "Simple Objects" shape).
DEFAULT_LAYER_CONTENT = {
    "operation": "replace",
    "objects": {
        "hosts": [{"name": "client", "ip-address": "10.0.0.5"}],
        "networks": [{"name": "lab_net", "subnet4": "10.0.0.0", "mask-length4": 24}],
    },
    # Predefined services that already exist on the gateway, referenced by name. The rules below
    # use them — that's what "referenced-objects" is for. Services work on a plain Firewall layer;
    # we deliberately avoid applications/categories here, as those would require the layer to have
    # the "Application & URL Filtering" blade enabled (Layer Editor → General).
    "referenced_objects": {
        "services-tcp": ["ssh", "https"],
    },
    "rulebase": [
        {"name": "allow_web", "action": "Accept", "track": {"type": "Log"},
         "source": ["client"], "destination": ["lab_net"], "service": ["https", "ssh"]},
        {"name": "cleanup_rule", "action": "Drop", "track": {"type": "Log"},
         "source": "any", "destination": "any", "service": "any"},
    ],
}

_BUILDER_CTX = {
    "specs": OBJECT_SPECS, "object_types": OBJECT_TYPES, "ref_types": REFERENCE_TYPES,
    "actions": RULE_ACTIONS, "tracks": TRACK_TYPES,
}


def _user(request: Request, db: Session) -> User | None:
    return get_user_or_none(request, db)


def _owned(db: Session, layer_id: int, user: User) -> DynamicLayer:
    layer = db.get(DynamicLayer, layer_id)
    if layer is None or layer.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Dynamic Layer not found")
    return layer


def _gateway(db: Session, gateway_id: str, user: User) -> Gateway | None:
    """Resolve a selected saved gateway owned by the user (connection details live on the profile)."""
    try:
        gw = db.get(Gateway, int(gateway_id)) if gateway_id else None
    except (ValueError, TypeError):
        gw = None
    return gw if gw and gw.owner_id == user.id else None


def _gateway_error(gw: Gateway | None, password: str) -> str | None:
    if gw is None:
        return ("Select a saved gateway (or tick “Use mock gateway”). "
                "Define gateways on the Gateways page.")
    if not gw.username:
        return f"Gateway “{gw.name}” has no username — set it on the gateway profile (Gateways → edit)."
    if not password:
        return (f"Gateway “{gw.name}” has no saved password — set one on the gateway profile "
                "(Gateways → edit) before applying.")
    return None


def _builder_ctx(*, action, is_edit, cancel_url, default_content, form, gateways,
                 selected_gateway_id, error=None):
    """Context for the shared layer builder template (used by both 'new' and 'edit')."""
    ctx = dict(_BUILDER_CTX)
    ctx.update({"action": action, "is_edit": is_edit, "cancel_url": cancel_url,
                "error": error, "default_content": default_content, "form": form,
                "gateways": gateways, "selected_gateway_id": selected_gateway_id})
    return ctx


def _parse_layer_content(*, objects_json, rules_json, referenced_json, comments, tags, gateway_id):
    """Parse + validate the builder's submitted JSON into a DynamicLayer.content dict.
    Raises on bad JSON / validation error so the caller can re-render with the message."""
    content = {
        "operation": "replace", "comments": comments,
        "tags": [t.strip() for t in tags.split(",") if t.strip()],
        "objects": json.loads(objects_json or "{}"),
        "rulebase": json.loads(rules_json or "[]"),
        "referenced_objects": json.loads(referenced_json or "{}"),
    }
    if gateway_id:
        try:
            content["gateway_id"] = int(gateway_id)
        except ValueError:
            pass
    validate_layer_content(content)
    return content


@router.get("/layers", response_class=HTMLResponse)
def layers_list(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layers = db.scalars(
        select(DynamicLayer).where(DynamicLayer.owner_id == user.id).order_by(DynamicLayer.created_at.desc())
    ).all()
    gws = {g.id: g for g in db.scalars(select(Gateway).where(Gateway.owner_id == user.id)).all()}
    rows = []
    gw_counts: dict[str, int] = {}
    for layer in layers:
        objs = sum(len(v or []) for v in (layer.content.get("objects") or {}).values())
        gid = (layer.content or {}).get("gateway_id")
        gw = gws.get(gid)
        key = str(gid) if gw else "none"
        gw_counts[key] = gw_counts.get(key, 0) + 1
        rows.append({
            "layer": layer, "objects": objs,
            "rules": len(layer.content.get("rulebase") or []),
            "last": layer.tasks[0] if layer.tasks else None,
            "gateway": gw.name if gw else None, "gw_key": key,
        })
    gw_filters = [{"key": str(g.id), "name": g.name, "count": gw_counts.get(str(g.id), 0)} for g in gws.values()]
    if gw_counts.get("none"):
        gw_filters.append({"key": "none", "name": "No gateway", "count": gw_counts["none"]})
    return templates.TemplateResponse(request, "dynamic_list.html",
        {"rows": rows, "gw_filters": gw_filters, "flash": _pop_flash(request),
         "cols": table_prefs.spec("layers"),
         "vis": table_prefs.visible_columns(db, user.id, "layers")})


def _gateways_of(db: Session, user: User):
    return db.scalars(select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.name)).all()


@router.get("/layers/new", response_class=HTMLResponse)
def layers_new(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ctx = _builder_ctx(
        action="/layers/new", is_edit=False, cancel_url="/layers",
        default_content=DEFAULT_LAYER_CONTENT, gateways=_gateways_of(db, user), selected_gateway_id="",
        form={"name": "Self-managed-demo", "layer_name": "dynamic_layer",
              "description": "", "comments": "", "tags": ""})
    return templates.TemplateResponse(request, "dynamic_new.html", ctx)


@router.post("/layers/new")
def layers_create(
    request: Request,
    name: str = Form(...),
    layer_name: str = Form("dynamic_layer"),
    description: str = Form(""),
    comments: str = Form(""),
    tags: str = Form(""),
    gateway_id: str = Form(""),
    objects_json: str = Form("{}"),
    rules_json: str = Form("[]"),
    referenced_json: str = Form("{}"),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        content = _parse_layer_content(objects_json=objects_json, rules_json=rules_json,
                                       referenced_json=referenced_json, comments=comments,
                                       tags=tags, gateway_id=gateway_id)
    except Exception as exc:
        ctx = _builder_ctx(
            action="/layers/new", is_edit=False, cancel_url="/layers", error=str(exc),
            gateways=_gateways_of(db, user), selected_gateway_id=gateway_id,
            default_content={"objects": _safe_json(objects_json, {}),
                             "rulebase": _safe_json(rules_json, []),
                             "referenced_objects": _safe_json(referenced_json, {})},
            form={"name": name, "layer_name": layer_name, "description": description,
                  "comments": comments, "tags": tags})
        return templates.TemplateResponse(request, "dynamic_new.html", ctx, status_code=400)
    layer = DynamicLayer(token=new_feed_token(), name=name, layer_name=layer_name or "dynamic_layer",
                         description=description, content=content, owner_id=user.id)
    db.add(layer)
    db.commit()
    db.refresh(layer)
    _flash(request, f"Dynamic Layer “{name}” saved.")
    return RedirectResponse(f"/layers/{layer.id}", status_code=303)


@router.post("/layers/{layer_id}/quick-edit")
async def layers_quick_edit(layer_id: int, request: Request, db: Session = Depends(get_db)):
    """Inline rename from the layer detail page (JSON {field:'name', value}). Rules/objects are
    structured, so they stay on the full Edit page — only the name is editable in place."""
    user = _user(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    layer = _owned(db, layer_id, user)
    try:
        data = await request.json()
    except Exception:
        data = {}
    if (data.get("field") or "") != "name":
        return JSONResponse({"error": "Only the name can be edited inline."}, status_code=400)
    value = (data.get("value") or "").strip()
    if not value:
        return JSONResponse({"error": "Name can’t be empty."}, status_code=400)
    layer.name = value
    db.commit()
    return JSONResponse({"ok": True, "value": layer.name})


@router.get("/layers/{layer_id}/edit", response_class=HTMLResponse)
def layers_edit(layer_id: int, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layer = _owned(db, layer_id, user)
    c = layer.content or {}
    ctx = _builder_ctx(
        action=f"/layers/{layer_id}/edit", is_edit=True, cancel_url=f"/layers/{layer_id}",
        gateways=_gateways_of(db, user), selected_gateway_id=str(c.get("gateway_id") or ""),
        default_content={"objects": c.get("objects") or {}, "rulebase": c.get("rulebase") or [],
                         "referenced_objects": c.get("referenced_objects") or {}},
        form={"name": layer.name, "layer_name": layer.layer_name, "description": layer.description or "",
              "comments": c.get("comments") or "", "tags": ", ".join(c.get("tags") or [])})
    return templates.TemplateResponse(request, "dynamic_new.html", ctx)


@router.post("/layers/{layer_id}/edit")
def layers_update(
    layer_id: int,
    request: Request,
    name: str = Form(...),
    layer_name: str = Form("dynamic_layer"),
    description: str = Form(""),
    comments: str = Form(""),
    tags: str = Form(""),
    gateway_id: str = Form(""),
    objects_json: str = Form("{}"),
    rules_json: str = Form("[]"),
    referenced_json: str = Form("{}"),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layer = _owned(db, layer_id, user)
    try:
        content = _parse_layer_content(objects_json=objects_json, rules_json=rules_json,
                                       referenced_json=referenced_json, comments=comments,
                                       tags=tags, gateway_id=gateway_id)
    except Exception as exc:
        ctx = _builder_ctx(
            action=f"/layers/{layer_id}/edit", is_edit=True, cancel_url=f"/layers/{layer_id}",
            error=str(exc), gateways=_gateways_of(db, user), selected_gateway_id=gateway_id,
            default_content={"objects": _safe_json(objects_json, {}),
                             "rulebase": _safe_json(rules_json, []),
                             "referenced_objects": _safe_json(referenced_json, {})},
            form={"name": name, "layer_name": layer_name, "description": description,
                  "comments": comments, "tags": tags})
        return templates.TemplateResponse(request, "dynamic_new.html", ctx, status_code=400)
    layer.name = name
    layer.layer_name = layer_name or "dynamic_layer"
    layer.description = description
    layer.content = content  # fresh dict → SQLAlchemy persists the JSON change
    db.commit()
    _flash(request, f"Dynamic Layer “{name}” updated — review and Apply to re-push.")
    return RedirectResponse(f"/layers/{layer_id}", status_code=303)


def _safe_json(text: str, default):
    try:
        return json.loads(text or "")
    except Exception:
        return default


def _task_view(task) -> dict:
    result = task.result or {}
    cs = result.get("change_summary", {}) or {}
    layers = cs.get("layers", []) or []
    rules_created = sum(len((lyr.get("rules", {}) or {}).get("create", []) or []) for lyr in layers)
    objects_created = (cs.get("objects", {}) or {}).get("create", []) or []
    return {
        "t": task,
        "layers": layers,
        "rules_created": rules_created,
        "objects_created": objects_created,
        "warnings": result.get("validation_warnings", []) or [],
        "errors": result.get("validation_errors", []) or [],
        "trace": result.get("trace", []) or [],
    }


@router.get("/layers/{layer_id}", response_class=HTMLResponse)
def layer_detail(layer_id: int, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layer = _owned(db, layer_id, user)
    payload_json = json.dumps(build_set_dynamic_content(layer), indent=2)
    base = app_settings.base_url().rstrip("/")
    # Only the latest apply is shown inline (merged into the Rulebase card); the full history
    # lives on its own page (/layers/{id}/history), where records can be pruned.
    task_total = db.scalar(
        select(func.count()).select_from(LayerTask).where(LayerTask.layer_id == layer.id)
    ) or 0
    latest_task = db.scalar(
        select(LayerTask).where(LayerTask.layer_id == layer.id).order_by(LayerTask.at.desc()).limit(1)
    )
    gws = db.scalars(select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.name)).all()
    gateways = [{"id": g.id, "name": g.name, "host": g.host, "port": g.port,
                 "username": g.username, "cert_pem": g.cert_pem,
                 "has_password": gateway_creds.has_password(db, g)} for g in gws]
    c = layer.content or {}
    referenced = referenced_object_names(c.get("objects"), c.get("rulebase"), c.get("referenced_objects"))
    return templates.TemplateResponse(request, "dynamic_detail.html", {
        "layer": layer, "payload_json": payload_json, "task_total": task_total,
        "latest": _task_view(latest_task) if latest_task else None, "referenced": referenced,
        "gateways": gateways, "layer_gateway_id": (layer.content or {}).get("gateway_id"),
        "mock_url": f"{base}/gaia_api/v1.9", "flash": _pop_flash(request),
    })


@router.post("/layers/{layer_id}/apply-start")
def apply_start(
    layer_id: int,
    request: Request,
    use_mock: str = Form(""),
    dry_run: str = Form(""),
    gateway_id: str = Form(""),
    gw_pass: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    layer = _owned(db, layer_id, user)
    dry = bool(dry_run)
    if use_mock:
        pid = start_apply(layer_id=layer.id, target="mock", dry_run=dry)
    else:
        gw = _gateway(db, gateway_id, user)
        if gw:
            ensure_pinned(db, gw)  # trust-on-first-use: pin the cert before applying if auto-trust is on
        # Typed password wins; otherwise fall back to the one saved (encrypted) on the gateway.
        pw = gw_pass or (gateway_creds.get_password(db, gw) if gw else None)
        err = _gateway_error(gw, pw)
        if err:
            return JSONResponse({"error": err}, status_code=400)
        pid = start_apply(layer_id=layer.id, target="gateway", dry_run=dry, gateway_host=gw.host,
                          gateway_port=gw.port, user=gw.username, password=pw,
                          cert_pem=gw.cert_pem or None)
    return JSONResponse({"progress_id": pid})


@router.get("/layers/{layer_id}/apply-status/{pid}")
def apply_status(layer_id: int, pid: str, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    p = get_progress(pid)
    if p is None:
        return JSONResponse({"error": "unknown progress id"}, status_code=404)
    return JSONResponse({
        "stage": p["stage"], "status": p["status"], "done_stages": p["done_stages"],
        "failed_stage": p.get("failed_stage"),
        "summary": p.get("summary"), "error": p.get("error"), "task_id": p.get("task_id"),
        "trace": p.get("trace", []),
        "stages": [{"key": k, "label": label} for k, label in STAGES],
    })


@router.post("/layers/{layer_id}/fetch-content")
def fetch_content(
    layer_id: int, request: Request,
    use_mock: str = Form(""), gateway_id: str = Form(""), gw_pass: str = Form(""),
    db: Session = Depends(get_db),
):
    """Read the dynamic layers / content a gateway (real or mock) currently has."""
    user = _user(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    _owned(db, layer_id, user)
    if use_mock:
        data = fetch_dynamic_content(target="mock", db=db, owner_id=user.id)
    else:
        gw = _gateway(db, gateway_id, user)
        if gw:
            ensure_pinned(db, gw)  # trust-on-first-use: pin the cert before fetching if auto-trust is on
        pw = gw_pass or (gateway_creds.get_password(db, gw) if gw else None)
        err = _gateway_error(gw, pw)
        if err:
            return JSONResponse({"error": err}, status_code=400)
        data = fetch_dynamic_content(target="gateway", db=db, owner_id=user.id, host=gw.host,
                                     port=gw.port, user=gw.username, password=pw,
                                     cert_pem=gw.cert_pem or None, gateway_id=gw.id)
    return JSONResponse(data)


@router.post("/layers/{layer_id}/fetch-cert")
def fetch_cert(layer_id: int, request: Request, gw_host: str = Form(""),
               gw_port: str = Form("443"), db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    _owned(db, layer_id, user)
    if not gw_host:
        return JSONResponse({"error": "Enter the gateway address first."}, status_code=400)
    try:
        port = int(gw_port or 443)
    except ValueError:
        port = 443
    try:
        return JSONResponse(fetch_gateway_cert(gw_host, port))
    except Exception as exc:
        return JSONResponse({"error": f"Could not fetch certificate from {gw_host}:{port} — {exc}"}, status_code=400)


@router.get("/layers/{layer_id}/history", response_class=HTMLResponse)
def layers_history(layer_id: int, request: Request, db: Session = Depends(get_db)):
    """Full apply history for one layer (every recorded set-dynamic-content), with multi-delete."""
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layer = _owned(db, layer_id, user)
    rows = db.scalars(
        select(LayerTask).where(LayerTask.layer_id == layer.id).order_by(LayerTask.at.desc())
    ).all()
    return templates.TemplateResponse(request, "dynamic_history.html",
        {"layer": layer, "tasks": [_task_view(t) for t in rows], "flash": _pop_flash(request)})


@router.post("/layers/{layer_id}/history/delete")
def layers_history_delete(layer_id: int, request: Request,
                          task_ids: list[int] = Form(default=[]),
                          db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layer = _owned(db, layer_id, user)
    n = 0
    if task_ids:
        # Scoped to this layer's records, so a forged id can't reach another layer's history.
        res = db.execute(delete(LayerTask).where(LayerTask.layer_id == layer.id,
                                                 LayerTask.id.in_(task_ids)))
        db.commit()
        n = res.rowcount or 0
    _flash(request, f"Deleted {n} apply record(s)." if n else "No records selected.",
           "success" if n else "error")
    return RedirectResponse(f"/layers/{layer_id}/history", status_code=303)


@router.post("/layers/{layer_id}/delete")
def layer_delete(layer_id: int, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layer = _owned(db, layer_id, user)
    name = layer.name
    db.delete(layer)
    db.commit()
    _flash(request, f"Dynamic Layer “{name}” deleted.")
    return RedirectResponse("/layers", status_code=303)


@router.get("/layers/{layer_id}/payload")
def layer_payload(layer_id: int, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return Response("", status_code=401)
    layer = _owned(db, layer_id, user)
    return Response(json.dumps(build_set_dynamic_content(layer), indent=2), media_type="application/json")
