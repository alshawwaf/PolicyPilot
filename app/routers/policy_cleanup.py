"""Policy Cleanup — find rules that hit count says are dead weight, then disable / delete them.

A port of Check Point's open-source PolicyCleanUp tool (MIT) onto PolicyPilot's ``web_api`` client. The
landing lists the user's management servers; opening one runs a read-only **plan** over a chosen access
layer (or all layers) and shows the disable / delete / skipped candidates. Applying the reviewed plan is
either a **dry-run** (validate + discard) or a **publish** (commit) — the same publish/discard machinery,
audit trail, and pinned-TLS session pool as every other rail. Human-in-the-loop: nothing is committed
without an explicit confirm.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ManagementServer, User
from ..security import get_user_or_none
from ..services import mgmt_creds, permissions, policy_cleanup
from ..services.gaia_client import ensure_pinned
from .ui import _pop_flash, templates

router = APIRouter(include_in_schema=False)


class PlanReq(BaseModel):
    """A plan (scan) request. ``layers`` empty = scan every access layer. Thresholds are days and must be
    >= 1 — a zero/negative threshold would make every rule 'older than the threshold' and flag the whole
    policy, so it's rejected (422) rather than silently clamped."""
    layers: list[str] = []
    disable_after: int = Field(default=policy_cleanup.DEFAULT_DISABLE_AFTER, ge=1, le=100000)
    delete_after: int = Field(default=policy_cleanup.DEFAULT_DELETE_AFTER, ge=1, le=100000)


class ApplyReq(BaseModel):
    """Apply a REVIEWED plan. ``disable`` / ``delete`` are the candidate rows (need uid + layer) the user
    kept from the plan. ``publish`` False = dry-run (validate + discard). The thresholds are the SAME
    values the plan ran with — the apply re-fetches and re-classifies every rule against the live policy,
    skipping any whose verdict changed since the plan."""
    disable: list[dict] = []
    delete: list[dict] = []
    publish: bool = False
    disable_after: int = Field(default=policy_cleanup.DEFAULT_DISABLE_AFTER, ge=1, le=100000)
    delete_after: int = Field(default=policy_cleanup.DEFAULT_DELETE_AFTER, ge=1, le=100000)


def _perm_or_403(user: User, perm: str):
    if not permissions.can(user, perm):
        return JSONResponse(
            {"error": f"You don't have permission to {permissions.label(perm).lower()}."}, status_code=403)


def _owned(db: Session, sid: int, user: User) -> ManagementServer:
    ms = db.get(ManagementServer, sid)
    if ms is None or ms.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Management server not found")
    return ms


def _secret_or_error(db: Session, ms: ManagementServer):
    """Resolve the stored secret for a live pull, or a JSONResponse error if it can't run."""
    if not ms.username:
        return None, JSONResponse({"error": "This server has no username — set one on Edit."}, status_code=400)
    secret = mgmt_creds.get_secret(db, ms)
    if not secret:
        return None, JSONResponse({"error": "No saved credential — store one on the Edit page to scan "
                                  "policy."}, status_code=400)
    ensure_pinned(db, ms)   # trust-on-first-use before the TLS handshake
    return secret, None


@router.get("/policy-cleanup", response_class=HTMLResponse)
def policy_cleanup_home(request: Request, db: Session = Depends(get_db)):
    """Landing: pick a management server to scan for unused rules."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()
    rows = [{"ms": m, "has_secret": mgmt_creds.has_secret(db, m)} for m in servers]
    return templates.TemplateResponse(request, "policy_cleanup.html",
                                      {"rows": rows, "server": None, "flash": _pop_flash(request)})


@router.get("/policy-cleanup/{sid}", response_class=HTMLResponse)
def policy_cleanup_server(sid: int, request: Request, db: Session = Depends(get_db)):
    """Per-server workspace: choose a layer + thresholds, run a plan, review, apply."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    return templates.TemplateResponse(request, "policy_cleanup.html",
                                      {"rows": None, "server": ms,
                                       "has_secret": mgmt_creds.has_secret(db, ms),
                                       "defaults": {"disable_after": policy_cleanup.DEFAULT_DISABLE_AFTER,
                                                    "delete_after": policy_cleanup.DEFAULT_DELETE_AFTER},
                                       "flash": _pop_flash(request)})


@router.get("/policy-cleanup/{sid}/unused")
def policy_cleanup_unused(sid: int, request: Request, db: Session = Depends(get_db)):
    """JSON: the objects nothing references on this server (read-only), grouped by type."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    from ..services import unused_objects
    try:
        return JSONResponse(unused_objects.list_unused(ms, secret))
    except policy_cleanup.mgmt_api.MgmtError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/policy-cleanup/{sid}/plan")
def policy_cleanup_plan(sid: int, request: Request, req: PlanReq, db: Session = Depends(get_db)):
    """JSON: run a read-only cleanup plan (scan) over the chosen layer(s)."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    try:
        return JSONResponse(policy_cleanup.scan(ms, secret, layers=req.layers,
                                                disable_after=req.disable_after,
                                                delete_after=req.delete_after))
    except policy_cleanup.mgmt_api.MgmtError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/policy-cleanup/{sid}/apply")
def policy_cleanup_apply(sid: int, request: Request, req: ApplyReq, db: Session = Depends(get_db)):
    """JSON: apply a reviewed plan. ``publish:false`` is a dry-run (validate then discard); ``publish:true``
    commits + publishes and raises a governance audit event."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if (e := _perm_or_403(user, permissions.APPLY)):        # staging/dry-run capability (RBAC)
        return e
    if req.publish and (e := _perm_or_403(user, permissions.PUBLISH)):   # committing needs publish too
        return e
    if not req.disable and not req.delete:
        return JSONResponse({"error": "No rules selected to apply."}, status_code=400)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    try:
        # The live re-check, per-rule change-log recording, and the governance audit event all happen
        # inside apply_plan so every apply surface inherits them; the actor is stamped here.
        result = policy_cleanup.apply_plan(ms, secret, disable=req.disable, delete=req.delete,
                                           publish=req.publish, actor=f"user:{user.username}",
                                           disable_after=req.disable_after, delete_after=req.delete_after)
    except policy_cleanup.mgmt_api.MgmtError as exc:   # the re-fetch phase failed -> clean 400, nothing applied
        return JSONResponse({"error": str(exc)}, status_code=400)
    status = 200 if result.get("ok") else 400   # an SMS-side failure (incl. lock conflict) is a 4xx
    return JSONResponse(result, status_code=status)
