"""IaC Exporter — turn a live Management Server into Infrastructure-as-Code: export a policy LAYER
(rulebase + objects → Terraform / Ansible / mgmt_cli) or the SMS's GAIA OS config (hostname, DNS, NTP,
interfaces, routes, proxy → Terraform / Ansible / clish) — a backup-as-code of the appliance.

This landing lists the saved management servers; each one links into the existing per-server export pages
under /management/{id}/export and /management/{id}/gaia-export. Read-only here — no new write paths; every
pull runs through the existing, owned-and-secret-guarded management endpoints.
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


@router.get("/iac-export", response_class=HTMLResponse)
def iac_exporter(request: Request, db: Session = Depends(get_db)):
    """Landing: pick a management server to export its policy or Gaia OS config as IaC."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()
    rows = [{"ms": m, "has_secret": mgmt_creds.has_secret(db, m)} for m in servers]
    return templates.TemplateResponse(request, "iac_exporter.html",
                                      {"rows": rows, "flash": _pop_flash(request)})
