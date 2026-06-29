"""Policy Manager — the human "fourth face" over the same engine: browse a live access-policy rulebase and
edit a rule (dry-run or publish), surfaced as a first-class destination.

This landing lists the saved management servers; opening one goes to its live policy viewer/editor (the
per-server page under /management/{id}, which pulls the rulebase over web_api and edits a rule via
set-access-rule). Read-only here — no new write paths; all live work runs through the existing,
owned-and-secret-guarded management endpoints.
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ManagementServer
from ..security import get_user_or_none
from ..services import mgmt_creds
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
