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
from ..services import gateway_creds, gaia_export, table_prefs
from ..services.apply_runner import fetch_dynamic_content
from ..services.gaia_client import ensure_pinned, fetch_gateway_cert, pin_now
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)


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
    rows = [{"gw": g, "layers": counts.get(g.id, 0)} for g in gws]
    return templates.TemplateResponse(request, "gateway_list.html", {
        "rows": rows, "flash": _pop_flash(request),
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
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    ensure_pinned(db, gw)  # trust-on-first-use: pin the gateway's cert before this fetch if needed
    pw = password or gateway_creds.get_password(db, gw)
    if not gw.username:
        _flash(request, f"Gateway “{gw.name}” has no username — set it on this gateway first.", "error")
    elif not pw:
        _flash(request, "Enter the gateway password to fetch (no saved password on this gateway).", "error")
    else:
        data = fetch_dynamic_content(target="gateway", db=db, owner_id=user.id, host=gw.host,
                                     port=gw.port, user=gw.username, password=pw,
                                     cert_pem=gw.cert_pem or None, gateway_id=gw.id)
        if data.get("ok"):
            _flash(request, f"Fetched {len(data.get('layers') or [])} dynamic layer(s) from “{gw.name}”.")
        else:
            _flash(request, data.get("error") or "Fetch failed.", "error")
    return RedirectResponse(f"/gateways/{gid}", status_code=303)


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
