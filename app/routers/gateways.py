"""Saved gateway connection profiles (name, host, port, username, pinned cert). The password is
optional — stored AES-256-GCM encrypted or entered per apply. Self-signed gateways are trusted by
pinning the cert (auto trust-on-first-use, or manual). Each Dynamic Layer can target a gateway."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import DynamicLayer, Gateway, GatewayLayerSnapshot, User
from ..security import get_user_or_none, new_feed_token
from ..services import gateway_creds, gaia_export, permissions, table_prefs
from ..services.apply_runner import fetch_dynamic_content
from ..services.gaia_client import cert_fingerprint, ensure_pinned, fetch_gateway_cert, pin_now
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)


def _perm_or_403(user, perm):
    if not permissions.can(user, perm):
        return JSONResponse(
            {"error": f"You don't have permission to {permissions.label(perm).lower()}."}, status_code=403)
    return None


def _owned(db: Session, gid: int, user: User) -> Gateway:
    gw = db.get(Gateway, gid)
    if gw is None or gw.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Gateway not found")
    return gw


def _port(value: str) -> int:
    try:
        return int(value or 443)
    except ValueError:
        return 443


def _autotrust_note(db: Session, gw) -> str:
    """When auto-trust is on and nothing is pinned yet, pin the cert NOW (behind the scenes) and report
    the fingerprint — so the user never has to uncheck the box and fetch manually. Falls back gracefully
    if the gateway isn't reachable at save time (the lazy first-connect pin still covers it)."""
    if not (getattr(gw, "auto_trust", False) and not (gw.cert_pem or "").strip()):
        return ""
    pinned, fp = pin_now(db, gw)
    if pinned:
        return f" Its certificate was trusted automatically (SHA-256 {fp})."
    return " It’ll be pinned automatically on first connect (the gateway wasn’t reachable just now)."


@router.get("/gateways", response_class=HTMLResponse)
def gateways_list(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gws = db.scalars(
        select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.created_at.desc())
    ).all()
    layers = db.scalars(select(DynamicLayer).where(DynamicLayer.owner_id == user.id)).all()
    counts: dict[int, int] = {}
    for layer in layers:
        gid = (layer.content or {}).get("gateway_id")
        if gid:
            counts[gid] = counts.get(gid, 0) + 1
    snaps = {s.gateway_id: s for s in db.scalars(
        select(GatewayLayerSnapshot).where(
            GatewayLayerSnapshot.gateway_id.in_([g.id for g in gws] or [0]))).all()} if gws else {}
    rows = []
    for g in gws:
        snap = snaps.get(g.id)
        fp = ""
        if g.cert_pem:
            try:
                fp = cert_fingerprint(g.cert_pem)
            except Exception:  # noqa: BLE001 — display-only, never block the list
                fp = ""
        rows.append({"gw": g, "layers": counts.get(g.id, 0),
                     "has_pw": gateway_creds.has_password(db, g), "snap": snap, "cert_fp": fp})
    health = {
        "total": len(gws),
        "reachable": sum(1 for r in rows if r["snap"] and r["snap"].ok),
        "errored": sum(1 for r in rows if r["snap"] and not r["snap"].ok),
        "never": sum(1 for r in rows if not r["snap"]),
        "trusted": sum(1 for g in gws if g.cert_pem),
        "with_pw": sum(1 for r in rows if r["has_pw"]),
        "fetched_layers": sum(len(r["snap"].layers or []) for r in rows if r["snap"]),
    }
    return templates.TemplateResponse(request, "gateway_list.html", {
        "rows": rows, "flash": _pop_flash(request), "health": health,
        "cols": table_prefs.spec("gateways"),
        "vis": table_prefs.visible_columns(db, user.id, "gateways"),
    })


def _form_tpl(request: Request) -> str:
    """The full page normally; just the form fragment when loaded into the modal (X-Fragment header)."""
    return "_gateway_form.html" if request.headers.get("x-fragment") else "gateway_form.html"


@router.get("/gateways/new", response_class=HTMLResponse)
def gateways_new(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, _form_tpl(request),
                                      {"gw": None, "error": None, "action": "/gateways/new",
                                       "has_password": False, "crypto_ok": gateway_creds.available()})


@router.post("/gateways/new")
def gateways_create(request: Request, name: str = Form(...), host: str = Form(...),
                    port: str = Form("443"), username: str = Form(""), cert_pem: str = Form(""),
                    password: str = Form(""), auto_trust: str = Form(""),
                    db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = Gateway(token=new_feed_token(), name=name, host=host, port=_port(port),
                 username=username, cert_pem=cert_pem, auto_trust=bool(auto_trust), owner_id=user.id)
    db.add(gw)
    db.commit()
    stored = False
    if password and gateway_creds.available():
        gateway_creds.store_password(db, gw, password)
        db.commit()
        stored = True
    if password and not stored:
        _flash(request, f"Gateway “{name}” saved, but the password was not stored — "
                        "encryption is unavailable in this environment.", "error")
    else:
        _flash(request, f"Gateway “{name}” saved." + _autotrust_note(db, gw))
    return RedirectResponse("/gateways", status_code=303)


@router.post("/gateways/fetch-cert")
def gateways_fetch_cert(request: Request, host: str = Form(""), port: str = Form("443"),
                        db: Session = Depends(get_db)):
    """Fetch the gateway's certificate so it can be reviewed and pinned with the saved profile."""
    if get_user_or_none(request, db) is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if not host:
        return JSONResponse({"error": "Enter the gateway address first."}, status_code=400)
    try:
        return JSONResponse(fetch_gateway_cert(host, _port(port)))
    except Exception as exc:
        return JSONResponse({"error": f"Could not fetch certificate from {host}:{_port(port)} — {exc}"},
                            status_code=400)


@router.post("/gateways/{gid}/cert")
def gateways_set_cert(gid: int, request: Request, cert_pem: str = Form(""),
                      db: Session = Depends(get_db)):
    """Persist a (re)fetched certificate onto a saved gateway so apply/fetch reuse it."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    gw = _owned(db, gid, user)
    gw.cert_pem = cert_pem
    db.commit()
    return JSONResponse({"ok": True, "name": gw.name})


@router.get("/gateways/{gid}", response_class=HTMLResponse)
def gateways_detail(gid: int, request: Request, db: Session = Depends(get_db)):
    """Persistent 'what's on this gateway' view — the last-fetched dynamic layers + a refresh."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    snap = db.scalar(select(GatewayLayerSnapshot).where(GatewayLayerSnapshot.gateway_id == gw.id))
    return templates.TemplateResponse(request, "gateway_detail.html",
                                      {"gw": gw, "snapshot": snap,
                                       "has_password": gateway_creds.has_password(db, gw),
                                       "flash": _pop_flash(request)})


@router.post("/gateways/{gid}/fetch")
def gateways_fetch(gid: int, request: Request, password: str = Form(""),
                   db: Session = Depends(get_db)):
    ajax = request.headers.get("x-pp-ajax") == "1"   # in-window flow: return JSON instead of redirecting
    user = get_user_or_none(request, db)
    if user is None:
        if ajax:
            return JSONResponse({"error": "Session expired — reload the page."}, status_code=401)
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    ensure_pinned(db, gw)  # trust-on-first-use: pin the gateway's cert before this fetch if needed
    pw = password or gateway_creds.get_password(db, gw)
    err = None
    count = 0
    if not gw.username:
        err = f"Gateway “{gw.name}” has no username — set it on this gateway first."
    elif not pw:
        err = "Enter the gateway password to fetch (no saved password on this gateway)."
    else:
        data = fetch_dynamic_content(target="gateway", db=db, owner_id=user.id, host=gw.host,
                                     port=gw.port, user=gw.username, password=pw,
                                     cert_pem=gw.cert_pem or None, gateway_id=gw.id)
        if data.get("ok"):
            count = len(data.get("layers") or [])
        else:
            err = data.get("error") or "Fetch failed."
    if ajax:
        if err:
            return JSONResponse({"error": err}, status_code=400)
        return JSONResponse({"ok": True, "count": count})
    if err:
        _flash(request, err, "error")
    else:
        _flash(request, f"Fetched {count} dynamic layer(s) from “{gw.name}”.")
    return RedirectResponse(f"/gateways/{gid}", status_code=303)


@router.post("/gateways/{gid}/import-layer")
def gateways_import_layer(gid: int, request: Request, layer: str = Form(...),
                          db: Session = Depends(get_db)):
    """Import a layer from this gateway's last fetch into a portal Dynamic Layer (create or overwrite by name),
    so it shows up under Dynamic Layers where it can be edited and pushed back. Writes the portal only."""
    ajax = request.headers.get("x-pp-ajax") == "1"   # in-window flow: return JSON + a link, don't navigate away
    user = get_user_or_none(request, db)
    if user is None:
        if ajax:
            return JSONResponse({"error": "Session expired — reload the page."}, status_code=401)
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    snap = db.scalar(select(GatewayLayerSnapshot).where(GatewayLayerSnapshot.gateway_id == gw.id))
    src = next((L for L in (snap.layers if snap and snap.layers else []) if (L.get("name") or "") == layer), None)
    if src is None:
        msg = f"Couldn't find layer “{layer}” in the last fetch — click Fetch now, then import."
        if ajax:
            return JSONResponse({"error": msg}, status_code=400)
        _flash(request, msg, "error")
        return RedirectResponse(f"/gateways/{gid}", status_code=303)
    content = {"operation": "replace", "objects": src.get("objects") or {}, "rulebase": src.get("rulebase") or []}
    # Carry the layer's full fidelity through the import so an import → edit → push round-trip isn't lossy:
    # the raw referenced-objects (definitions, not just names) and any layer-level comments/tags the fetch
    # captured. (Per-rule comments/tags already round-trip inside each rulebase entry.)
    ref = src.get("referenced_objects") or src.get("referenced-objects")
    if ref:
        content["referenced_objects"] = ref
    if src.get("comments"):
        content["comments"] = src.get("comments")
    if src.get("tags"):
        content["tags"] = src.get("tags")
    from ..schemas.dynamic_layer import validate_layer_content
    try:
        validate_layer_content(content)
    except ValueError as exc:
        msg = f"Can't import “{layer}”: {exc}"
        if ajax:
            return JSONResponse({"error": msg}, status_code=400)
        _flash(request, msg, "error")
        return RedirectResponse(f"/gateways/{gid}", status_code=303)
    existing = next((L for L in db.scalars(select(DynamicLayer).where(DynamicLayer.owner_id == user.id)).all()
                     if (L.name or "").lower() == layer.lower()), None)
    if existing is not None:
        existing.content = content
        existing.layer_name = layer
        verb = "Updated"
    else:
        db.add(DynamicLayer(token=new_feed_token(), name=layer, layer_name=layer,
                            owner_id=user.id, content=content))
        verb = "Imported"
    db.commit()
    if ajax:
        return JSONResponse({"ok": True, "verb": verb, "layer": layer})
    _flash(request, f"{verb} “{layer}” from “{gw.name}” — edit or push it from Dynamic Layers.")
    return RedirectResponse("/layers", status_code=303)


@router.get("/gateways/{gid}/gaia-export", response_class=HTMLResponse)
def gw_gaia_export_page(gid: int, request: Request, db: Session = Depends(get_db)):
    """Export this gateway's Gaia OS config (interfaces/routes/dns/ntp/…) to Terraform/Ansible/clish."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    return templates.TemplateResponse(request, "gaia_export.html",
                                      {"title": gw.name, "host": f"{gw.host}:{gw.port}",
                                       "run_url": f"/gateways/{gw.id}/gaia-export/run",
                                       "back_url": f"/gateways/{gw.id}", "back_label": "Gateway",
                                       "has_secret": gateway_creds.has_password(db, gw),
                                       "flash": _pop_flash(request)})


@router.post("/gateways/{gid}/gaia-export/run")
def gw_gaia_export_run(gid: int, request: Request, password: str = Form(""),
                       db: Session = Depends(get_db)):
    """JSON: pull the gateway's Gaia config and render the three IaC targets."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if (e := _perm_or_403(user, permissions.EXPORT)):
        return e
    gw = _owned(db, gid, user)
    if not gw.username:
        return JSONResponse({"error": "This gateway has no username — set one on Edit."}, status_code=400)
    ensure_pinned(db, gw)   # trust-on-first-use before the TLS handshake
    secret = password or gateway_creds.get_password(db, gw)
    if not secret:
        return JSONResponse({"error": "Enter the gateway password (none saved on this gateway)."},
                            status_code=400)
    return JSONResponse(gaia_export.pull_and_generate(gw.host, gw.port, gw.username, secret,
                                                      gw.cert_pem or None))


@router.get("/gateways/{gid}/edit", response_class=HTMLResponse)
def gateways_edit(gid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    return templates.TemplateResponse(request, _form_tpl(request),
                                      {"gw": gw, "error": None, "action": f"/gateways/{gid}/edit",
                                       "has_password": gateway_creds.has_password(db, gw),
                                       "crypto_ok": gateway_creds.available()})


@router.post("/gateways/{gid}/edit")
def gateways_update(gid: int, request: Request, name: str = Form(...), host: str = Form(...),
                    port: str = Form("443"), username: str = Form(""), cert_pem: str = Form(""),
                    password: str = Form(""), clear_password: str = Form(""),
                    auto_trust: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    gw.name, gw.host, gw.port, gw.username, gw.cert_pem = name, host, _port(port), username, cert_pem
    gw.auto_trust = bool(auto_trust)
    note = ""
    if clear_password:
        gateway_creds.clear_password(db, gw)
    elif password:  # blank = keep whatever is already stored
        if gateway_creds.available():
            gateway_creds.store_password(db, gw, password)
        else:
            note = " (the new password was not stored — encryption is unavailable in this environment)"
    db.commit()
    msg = f"Gateway “{name}” updated.{note}{_autotrust_note(db, gw)}"
    _flash(request, msg, "error" if note else "success")
    return RedirectResponse("/gateways", status_code=303)


@router.post("/gateways/{gid}/delete")
def gateways_delete(gid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    name = gw.name
    db.delete(gw)
    db.commit()
    _flash(request, f"Gateway “{name}” deleted.")
    return RedirectResponse("/gateways", status_code=303)
