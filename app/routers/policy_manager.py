"""Policy Manager — the human "fourth face" over the same engine: browse a live access-policy rulebase and
edit a rule (dry-run or publish), surfaced as a first-class destination.

This landing lists the saved management servers; opening one goes to its live policy viewer/editor (the
per-server page under /management/{id}, which pulls the rulebase over web_api and edits a rule via
set-access-rule). Read-only here — no new write paths; all live work runs through the existing,
owned-and-secret-guarded management endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ManagementServer
from ..security import get_user_or_none
from ..services import changed_policies, mgmt_creds
from ..services.gaia_client import ensure_pinned
from .ui import _pop_flash, templates

router = APIRouter(include_in_schema=False)


@router.get("/policy-manager", response_class=HTMLResponse)
def policy_manager(request: Request, db: Session = Depends(get_db)):
    """Landing: pick a management server to browse + edit its live access policy."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()
    rows = [{"ms": m, "has_secret": mgmt_creds.has_secret(db, m)} for m in servers]
    return templates.TemplateResponse(request, "policy_manager.html",
                                      {"rows": rows, "flash": _pop_flash(request)})


@router.get("/policy-manager/{sid}/install-status")
def policy_manager_install_status(sid: int, request: Request, db: Session = Depends(get_db)):
    """JSON: which packages on this server are published-but-not-installed / changed since last install.
    Lazy-loaded per server card so the landing paints instantly and only queries the SMS when shown."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = db.get(ManagementServer, sid)
    if ms is None or ms.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Management server not found")
    secret = mgmt_creds.get_secret(db, ms)
    if not ms.username or not secret:
        return JSONResponse({"error": "No saved credential."}, status_code=400)
    ensure_pinned(db, ms)   # trust-on-first-use before the TLS handshake
    try:
        return JSONResponse(changed_policies.install_status(ms, secret))
    except changed_policies.mgmt_api.MgmtError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
