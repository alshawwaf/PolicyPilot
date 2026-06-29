"""Saved Check Point Management Server / MDS-domain profiles, driven over the `web_api`.

Phase 1: connection profiles (encrypted secret, pinned/auto-trust TLS) + Test Connection. The policy
viewer, IaC export, and CRUD build on this. Mirrors the Gateways router; the login password / API key
is stored AES-256-GCM (mgmt_creds) and TLS verification is never disabled.
"""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ManagementServer, User
from ..security import get_user_or_none
from ..services import gaia_export, mgmt_api, mgmt_creds, mgmt_export, table_prefs
from ..services.gaia_client import ensure_pinned, fetch_gateway_cert, pin_now
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)


class RuleEdit(BaseModel):
    """A single rule edit posted from the viewer. ``publish`` False = dry-run (discard)."""
    layer: str
    uid: str
    changes: dict = {}
    publish: bool = False


def _owned(db: Session, sid: int, user: User) -> ManagementServer:
    ms = db.get(ManagementServer, sid)
    if ms is None or ms.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Management server not found")
    return ms


def _port(value: str) -> int:
    try:
        return int(value or 443)
    except ValueError:
        return 443


@router.get("/management", response_class=HTMLResponse)
def mgmt_list(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()
    rows = [{"ms": m, "has_secret": mgmt_creds.has_secret(db, m)} for m in servers]
    return templates.TemplateResponse(request, "management_list.html",
                                      {"rows": rows, "flash": _pop_flash(request),
                                       "cols": table_prefs.spec("management"),
                                       "vis": table_prefs.visible_columns(db, user.id, "management")})


def _form_tpl(request: Request) -> str:
    """The full page normally; just the form fragment when loaded into the modal (X-Fragment header)."""
    return "_management_form.html" if request.headers.get("x-fragment") else "management_form.html"


@router.get("/management/new", response_class=HTMLResponse)
def mgmt_new(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, _form_tpl(request),
                                      {"ms": None, "error": None, "action": "/management/new",
                                       "has_secret": False, "crypto_ok": mgmt_creds.available()})


def _autotrust_note(db: Session, ms) -> str:
    """Pin the cert NOW (behind the scenes) when auto-trust is on and nothing is pinned yet, and report
    the fingerprint — so the user never has to uncheck the box and fetch manually. Graceful fallback to
    the lazy first-connect pin if the server isn't reachable at save time."""
    if not (getattr(ms, "auto_trust", False) and not (ms.cert_pem or "").strip()):
        return ""
    pinned, fp = pin_now(db, ms)
    if pinned:
        return f" Its certificate was trusted automatically (SHA-256 {fp})."
    return " It’ll be pinned automatically on first connect (the server wasn’t reachable just now)."


@router.post("/management/new")
def mgmt_create(request: Request, name: str = Form(...), host: str = Form(...), port: str = Form("443"),
                username: str = Form(""), domain: str = Form(""), cert_pem: str = Form(""),
                password: str = Form(""), auto_trust: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = ManagementServer(name=name, host=host, port=_port(port), username=username,
                          domain=domain.strip(), cert_pem=cert_pem, auto_trust=bool(auto_trust),
                          owner_id=user.id)
    db.add(ms)
    db.commit()
    db.refresh(ms)
    note = ""
    if password and mgmt_creds.available():
        mgmt_creds.store_secret(db, ms, password, kind="password")
    elif password:
        note = " (the secret was not stored — encryption is unavailable in this environment)"
    msg = f"Management server “{name}” saved.{note}{_autotrust_note(db, ms)}"
    _flash(request, msg, "error" if note else "success")
    return RedirectResponse("/management", status_code=303)


@router.post("/management/fetch-cert")
def mgmt_fetch_cert(request: Request, host: str = Form(""), port: str = Form("443"),
                    db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if not host:
        return JSONResponse({"error": "Enter the management address first."}, status_code=400)
    try:
        return JSONResponse(fetch_gateway_cert(host, _port(port)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"Could not fetch certificate from {host}:{_port(port)} — {exc}"},
                            status_code=400)


@router.post("/management/{sid}/test")
def mgmt_test(sid: int, request: Request, password: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    ensure_pinned(db, ms)   # trust-on-first-use: pin the presented cert before the TLS handshake
    secret = password or mgmt_creds.get_secret(db, ms)
    if not ms.username:
        return JSONResponse({"ok": False, "message": "This server has no username — set one first."})
    if not secret:
        return JSONResponse({"ok": False, "message": "No saved credential — enter the password, or "
                            "store one on the Edit page."})
    return JSONResponse(mgmt_api.test_connection(ms, secret))


def _secret_or_error(db: Session, ms: ManagementServer):
    """Resolve the stored secret for a live pull, or a JSONResponse error if it can't run."""
    if not ms.username:
        return None, JSONResponse({"error": "This server has no username — set one on Edit."}, status_code=400)
    secret = mgmt_creds.get_secret(db, ms)
    if not secret:
        return None, JSONResponse({"error": "No saved credential — store one on the Edit page to browse "
                                  "policy."}, status_code=400)
    ensure_pinned(db, ms)   # trust-on-first-use before the TLS handshake
    return secret, None


@router.get("/management/{sid}/layers")
def mgmt_layers(sid: int, request: Request, db: Session = Depends(get_db)):
    """JSON: the access layers on this server/domain (live)."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    try:
        return JSONResponse(mgmt_api.pull_layers(ms, secret))
    except mgmt_api.MgmtError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/management/{sid}/rulebase")
def mgmt_rulebase(sid: int, request: Request, name: str = "", db: Session = Depends(get_db)):
    """JSON: a layer's access rulebase, cells resolved to object names."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if not name:
        return JSONResponse({"error": "No layer specified."}, status_code=400)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    try:
        return JSONResponse(mgmt_api.pull_rulebase(ms, secret, name))
    except mgmt_api.MgmtError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/management/{sid}/export", response_class=HTMLResponse)
def mgmt_export_page(sid: int, request: Request, layer: str = "", db: Session = Depends(get_db)):
    """Export page: pick a layer, generate Terraform / Ansible / mgmt_cli, preview + download."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    return templates.TemplateResponse(request, "management_export.html",
                                      {"ms": ms, "layer": layer,
                                       "has_secret": mgmt_creds.has_secret(db, ms),
                                       "flash": _pop_flash(request)})


@router.post("/management/{sid}/export")
def mgmt_export_run(sid: int, request: Request, name: str = "", db: Session = Depends(get_db)):
    """JSON: pull a layer's rulebase + objects and render all three IaC targets."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if not name:
        return JSONResponse({"error": "No layer specified."}, status_code=400)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    try:
        bundle = mgmt_api.pull_for_export(ms, secret, name)
    except mgmt_api.MgmtError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(mgmt_export.generate(bundle, host=ms.host, domain=ms.domain or ""))


@router.post("/management/{sid}/apply")
def mgmt_apply(sid: int, request: Request, edit: RuleEdit, db: Session = Depends(get_db)):
    """Apply one rule edit. ``publish:false`` is a dry-run — the change is made then DISCARDED, so it
    validates the payload against the SMS with zero commit; ``publish:true`` commits it."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if not edit.layer or not edit.uid:
        return JSONResponse({"error": "Missing layer or rule id."}, status_code=400)
    if not edit.changes:
        return JSONResponse({"error": "No changes to apply."}, status_code=400)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    op = mgmt_api.build_set_rule_op(edit.layer, edit.uid, edit.changes)
    try:
        return JSONResponse(mgmt_api.apply_changes(ms, secret, [op], publish=edit.publish))
    except mgmt_api.MgmtError as exc:        # incl. a wrapped mid-session transport drop -> clean 400, not 500
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/management/{sid}/gaia-export", response_class=HTMLResponse)
def mgmt_gaia_export_page(sid: int, request: Request, db: Session = Depends(get_db)):
    """Export the SMS's Gaia OS config (the SMS is a Gaia appliance too) to Terraform/Ansible/clish."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    return templates.TemplateResponse(request, "gaia_export.html",
                                      {"title": ms.name, "host": f"{ms.host}:{ms.port}",
                                       "run_url": f"/management/{ms.id}/gaia-export/run",
                                       "back_url": f"/management/{ms.id}", "back_label": "Policy viewer",
                                       "has_secret": mgmt_creds.has_secret(db, ms),
                                       "flash": _pop_flash(request)})


@router.post("/management/{sid}/gaia-export/run")
def mgmt_gaia_export_run(sid: int, request: Request, password: str = Form(""),
                         db: Session = Depends(get_db)):
    """JSON: pull the SMS's Gaia config (via its gaia_api) and render the three IaC targets."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    if not ms.username:
        return JSONResponse({"error": "This server has no username — set one on Edit."}, status_code=400)
    ensure_pinned(db, ms)
    secret = password or mgmt_creds.get_secret(db, ms)
    if not secret:
        return JSONResponse({"error": "No saved credential — enter the OS password, or store one on Edit."},
                            status_code=400)
    return JSONResponse(gaia_export.pull_and_generate(ms.host, ms.port, ms.username, secret,
                                                      ms.cert_pem or None))


@router.get("/management/{sid}", response_class=HTMLResponse)
def mgmt_detail(sid: int, request: Request, db: Session = Depends(get_db)):
    """Policy viewer: pick a layer (loaded live) and render its rulebase + resolved objects."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    return templates.TemplateResponse(request, "management_detail.html",
                                      {"ms": ms, "has_secret": mgmt_creds.has_secret(db, ms),
                                       "flash": _pop_flash(request)})


@router.get("/management/{sid}/edit", response_class=HTMLResponse)
def mgmt_edit(sid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    return templates.TemplateResponse(request, _form_tpl(request),
                                      {"ms": ms, "error": None, "action": f"/management/{sid}/edit",
                                       "has_secret": mgmt_creds.has_secret(db, ms),
                                       "crypto_ok": mgmt_creds.available()})


@router.post("/management/{sid}/edit")
def mgmt_update(sid: int, request: Request, name: str = Form(...), host: str = Form(...),
                port: str = Form("443"), username: str = Form(""), domain: str = Form(""),
                cert_pem: str = Form(""), password: str = Form(""), clear_password: str = Form(""),
                auto_trust: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    ms.name, ms.host, ms.port, ms.username = name, host, _port(port), username
    ms.domain, ms.cert_pem, ms.auto_trust = domain.strip(), cert_pem, bool(auto_trust)
    note = ""
    if clear_password:
        mgmt_creds.clear_secret(db, ms)
    elif password:
        if mgmt_creds.available():
            mgmt_creds.store_secret(db, ms, password, kind="password")
        else:
            note = " (the new secret was not stored — encryption is unavailable here)"
    db.commit()
    _flash(request, f"Management server “{name}” updated.{note}{_autotrust_note(db, ms)}",
           "error" if note else "success")
    return RedirectResponse("/management", status_code=303)


@router.post("/management/{sid}/delete")
def mgmt_delete(sid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    name = ms.name
    db.delete(ms)
    db.commit()
    _flash(request, f"Management server “{name}” deleted.")
    return RedirectResponse("/management", status_code=303)
