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
from ..models import Gateway, ManagementServer
from ..security import get_user_or_none
from ..services import gateway_creds, mgmt_creds
from .ui import _pop_flash, templates

router = APIRouter(include_in_schema=False)


@router.get("/iac-export", response_class=HTMLResponse)
def iac_exporter(request: Request, db: Session = Depends(get_db)):
    """Landing: pick a Management Server (policy + Gaia) or a Gateway (Gaia only) to export as IaC."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()
    gateways = db.scalars(
        select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.created_at.desc())
    ).all()
    # has_secret = the SmartConsole/Management-API secret (policy export); has_gaia = the SEPARATE Gaia
    # OS creds (username + password) for the SMS's own config export. A gateway's saved password IS its
    # Gaia login, so for gateways has_secret doubles as the Gaia-cred flag.
    rows = [{"ms": m, "has_secret": mgmt_creds.has_secret(db, m),
             "has_gaia": mgmt_creds.has_gaia_creds(db, m)} for m in servers]
    gw_rows = [{"gw": g, "has_secret": gateway_creds.has_password(db, g)} for g in gateways]
    return templates.TemplateResponse(request, "iac_exporter.html",
                                      {"rows": rows, "gateways": gw_rows, "flash": _pop_flash(request)})
