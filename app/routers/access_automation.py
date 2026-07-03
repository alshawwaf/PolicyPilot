"""Ticket-driven access automation: turn an access request into the minimal correct change on a
Check Point access layer (no-op / widen / create), over the ``web_api``.

Three surfaces, all reusing the saved Management Server profiles + encrypted secret:
  * the UI request form (preview, then dry-run validate or publish),
  * JSON preview / apply endpoints the form calls,
  * a token-authenticated ServiceNow webhook for end-to-end automation.

The decision engine + API call sequence live in ``services.access_automation``; payload parsing and
the optional write-back in ``services.ticketing``. Approvals are out of scope (your ITSM owns them).
"""
import hmac

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import AppliedChange, ManagementServer, User, utcnow
from ..security import get_user_or_none
from ..services import access_automation as aa
from ..services import api_keys, app_settings, applications, change_log, decision_tree, mgmt_api, mgmt_creds, permissions, services, table_prefs, ticketing, typed_objects
from ..services.gaia_client import ensure_pinned
from .ui import _pop_flash, templates

router = APIRouter(include_in_schema=False)


class AccessReqBody(BaseModel):
    layer: str
    source: str
    destination: str
    protocol: str = "tcp"
    port: str = ""
    application: str | None = None      # an application-site name (e.g. "Facebook") — overrides everything
    service: str | None = None          # a named non-port service (e.g. "icmp", "GRE") — overrides port
    source_kind: str = "ip"             # "ip" (default) or a typed kind: domain / access-role /
    destination_kind: str = "ip"        # dynamic-object / updatable-object / security-zone
    ticket_id: str = ""
    publish: bool = False
    package: str | None = None
    # full-column support — a UI/API caller can set any column (all optional; defaults reproduce today's request)
    action: str = "Accept"              # Accept / Drop / Reject / Ask / Inform / Apply Layer
    inline_layer: str | None = None     # required iff action == "Apply Layer"
    action_limit: str | None = None     # action-settings QoS/limit object name
    captive_portal: bool = False        # action-settings enable-identity-captive-portal
    # UserCheck (top-level user-check object) — Ask/Inform message + frequency + confirm; Drop/Reject block page
    user_check: str | None = None       # UserCheck interaction object name
    user_check_frequency: str | None = None   # once a day | once a week | once a month | custom frequency...
    user_check_confirm: str | None = None     # per rule | per category | per application/site | per data type
    user_check_custom_every: int = 0    # custom-frequency {every}
    user_check_custom_unit: str | None = None  # custom-frequency {unit}: hours|days|weeks|months
    content: list[str] | None = None    # Content Awareness data-type names
    content_direction: str = "any"      # any | up | down
    content_negate: bool = False
    time_objects: list[str] | None = None   # time / time-group names
    install_on: list[str] | None = None     # gateway/target names
    vpn: list[str] | None = None            # VPN community names ([] = Any)


def _owned(db: Session, sid: int, user: User) -> ManagementServer:
    ms = db.get(ManagementServer, sid)
    if ms is None or ms.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Management server not found")
    return ms


def _secret_or_error(db: Session, ms: ManagementServer):
    """Resolve the stored secret for a live call, or a JSONResponse error if it can't run."""
    if not ms.username:
        return None, JSONResponse({"error": "This server has no username — set one on Edit."},
                                  status_code=400)
    secret = mgmt_creds.get_secret(db, ms)
    if not secret:
        return None, JSONResponse({"error": "No saved credential — store one on the Edit page to run "
                                  "access automation."}, status_code=400)
    ensure_pinned(db, ms)   # trust-on-first-use before the TLS handshake
    return secret, None


# --- UI -------------------------------------------------------------------------------------
@router.get("/access-automation", response_class=HTMLResponse)
def aa_list(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()
    rows = [{"ms": m, "has_secret": mgmt_creds.has_secret(db, m)} for m in servers]
    return templates.TemplateResponse(request, "access_automation_list.html",
                                      {"rows": rows, "flash": _pop_flash(request),
                                       "cols": table_prefs.spec("access-servers"),
                                       "vis": table_prefs.visible_columns(db, user.id, "access-servers")})


@router.get("/access-automation/decision-tree/{fmt}")
def aa_decision_tree(fmt: str, request: Request, db: Session = Depends(get_db)):
    """Download the decision tree as a portable diagram: .drawio (diagrams.net / → Visio), .mmd
    (Mermaid), or .dot (Graphviz). Generated from the single source of truth in services.decision_tree
    so it always matches the engine. Registered BEFORE /{sid} so the literal path wins over the int id."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    spec = decision_tree.RENDERERS.get(fmt)
    if spec is None:
        return PlainTextResponse("Unknown format.", status_code=404)
    render, ctype, ext = spec
    return PlainTextResponse(render(), media_type=ctype, headers={
        "Content-Disposition": f'attachment; filename="policypilot-decision-tree.{ext}"'})


@router.get("/access-automation/{sid}", response_class=HTMLResponse)
def aa_detail(sid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    # "How it decides" is now its own apps: /decision-map (principles) + /decision-tree (interactive flow).
    return templates.TemplateResponse(request, "access_automation_detail.html",
                                      {"ms": ms, "has_secret": mgmt_creds.has_secret(db, ms),
                                       "flash": _pop_flash(request)})


_AA_OPTION_KEYS = ("aa_app_carveout", "aa_override_blocking_deny", "aa_prefer_widen",
                   "aa_emit_notes", "aa_ignore_conditions")


def _aa_option_state() -> dict:
    """The current EFFECTIVE decision knobs (after the active profile resolves) + the active profile name —
    drives the click-to-toggle pills on the decision diagram."""
    o = aa._decide_options()
    return {"profile": str(app_settings.get("aa_profile") or "custom"),
            "values": {"aa_app_carveout": o.app_carveout, "aa_override_blocking_deny": o.override_blocking_deny,
                       "aa_prefer_widen": o.prefer_widen, "aa_emit_notes": o.emit_notes,
                       "aa_ignore_conditions": o.ignore_conditions}}


@router.get("/changes", response_class=HTMLResponse)
def change_log_page(request: Request, server: int = 0, db: Session = Depends(get_db)):
    """"Change log" — its own app: the published-change audit trail + rollback, split out of the Access
    automation page. Server-scoped, so it has its own cold launcher — a server picker. ?server=<id> (or a
    single owned server) selects one; the rollback actions reuse the existing /access-automation/{id}/changes
    endpoints."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    servers = db.scalars(select(ManagementServer).where(ManagementServer.owner_id == user.id)
                         .order_by(ManagementServer.name)).all()
    sel = next((s for s in servers if s.id == server), None) if server else None
    if sel is None and len(servers) == 1:
        sel = servers[0]
    return templates.TemplateResponse(request, "change_log.html", {"servers": servers, "server": sel})


@router.get("/ticketing-webhook", response_class=HTMLResponse)
def ticketing_webhook_page(request: Request, db: Session = Depends(get_db)):
    """"Ticketing webhook" — its own app: the reference for wiring any ITSM to the webhook, split out of the
    Access automation page. Server-independent (the /access-automation/webhook endpoint is global)."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    first = db.scalar(select(ManagementServer).where(ManagementServer.owner_id == user.id)
                      .order_by(ManagementServer.id))
    return templates.TemplateResponse(request, "ticketing_webhook.html",
                                      {"example_server_id": first.id if first else 1})


@router.get("/decision-map", response_class=HTMLResponse)
def decision_map_page(request: Request, db: Session = Depends(get_db)):
    """"Decision map" — its own app: the engine's reasoning PRINCIPLES (reuse → widen → create, least-
    privilege, note-don't-stop) as a modern overview. Pure presentation, server-independent."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "decision_map.html", {})


@router.get("/decision-tree", response_class=HTMLResponse)
def decision_tree_page(request: Request, db: Session = Depends(get_db)):
    """"Decision tree" — its own app: the interactive first-match flow + a "trace a decision" walkthrough
    that steps the exact path to each outcome, plus the click-to-tune knobs. Server-independent (engine
    logic + global decision options), so it isn't scoped to a Management server."""
    import json
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "decision_tree_app.html",
                                      {"decision_graph_json": json.dumps(
                                          decision_tree.to_graph()).replace("<", "\\u003c"),
                                       "aa_options_json": json.dumps(_aa_option_state()).replace("<", "\\u003c")})


class AAOptionBody(BaseModel):
    key: str
    value: bool


@router.post("/access-automation/decision-option")
def aa_decision_option(body: AAOptionBody, request: Request, db: Session = Depends(get_db)):
    """Click-to-toggle a decision knob straight from the diagram. Sets the knob AND switches the profile to
    Custom (so the toggle takes effect — a named profile would otherwise override it). Data-only (no code)."""
    if get_user_or_none(request, db) is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if body.key not in _AA_OPTION_KEYS:
        return JSONResponse({"error": "unknown option"}, status_code=400)
    app_settings.save({body.key: bool(body.value), "aa_profile": "custom"})
    return {"ok": True, **_aa_option_state()}


def _req_snapshot(body: AccessReqBody) -> dict:
    """The request tuple as plain data — snapshotted on a recorded change for display + audit."""
    return {"source": body.source, "destination": body.destination, "protocol": body.protocol,
            "port": body.port, "service": body.service, "application": body.application,
            "source_kind": body.source_kind, "destination_kind": body.destination_kind,
            "action": body.action, "inline_layer": body.inline_layer,
            "action_settings_limit": body.action_limit, "action_settings_captive_portal": body.captive_portal,
            "content": body.content,
            "content_direction": body.content_direction, "content_negate": body.content_negate,
            "time_objects": body.time_objects, "install_on": body.install_on, "vpn": body.vpn,
            "user_check": body.user_check, "user_check_frequency": body.user_check_frequency,
            "user_check_confirm": body.user_check_confirm,
            "user_check_custom_every": body.user_check_custom_every,
            "user_check_custom_unit": body.user_check_custom_unit}


def _record_change_safe(db, **kw) -> None:
    """Record a published change for rollback — BEST-EFFORT. The SMS write has already committed by the
    time this runs, so an audit-log DB hiccup must never turn a successful publish into a 500 for the user."""
    try:
        change_log.record(db, **kw)
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger("policypilot.access_automation").exception("recording change for rollback failed")


def _perm_or_403(user: User, perm: str):
    """None if *user* may do *perm*, else a JSON 403 (these are fetch/JSON endpoints)."""
    if not permissions.can(user, perm):
        return JSONResponse(
            {"error": f"You don't have permission to {permissions.label(perm).lower()}."}, status_code=403)
    return None


def _run(db: Session, sid: int, user: User, body: AccessReqBody, *, do_apply: bool):
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    try:
        req = ticketing.build_request(body.source, body.destination, body.protocol, body.port,
                                      body.application, body.service,
                                      source_kind=body.source_kind, destination_kind=body.destination_kind,
                                      action=body.action, inline_layer=body.inline_layer or "",
                                      action_settings_limit=body.action_limit or "",
                                      action_settings_captive_portal=body.captive_portal,
                                      content=body.content, content_direction=body.content_direction,
                                      content_negate=body.content_negate, time_objects=body.time_objects,
                                      install_on=body.install_on, vpn=body.vpn,
                                      user_check=body.user_check or "",
                                      user_check_frequency=body.user_check_frequency or "",
                                      user_check_confirm=body.user_check_confirm or "",
                                      user_check_custom_every=body.user_check_custom_every or 0,
                                      user_check_custom_unit=body.user_check_custom_unit or "")
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    if not body.layer:
        return JSONResponse({"error": "No layer specified."}, status_code=400)
    if do_apply:
        result = aa.execute(ms, secret, req, body.layer, package=body.package,
                            ticket_id=body.ticket_id, publish=body.publish)
        # record a PUBLISHED change so it can be rolled back (no-op for dry-runs / no-ops / reviews).
        _record_change_safe(db, server=ms, result=result, request=_req_snapshot(body),
                            layer=body.layer, package=body.package, ticket_id=body.ticket_id,
                            actor=f"user:{user.username}")
    else:
        result = aa.preview(ms, secret, req, body.layer, package=body.package)
    code = 200 if result.get("ok") else 400
    return JSONResponse(result, status_code=code)


@router.get("/access-automation/{sid}/app-search")
def aa_app_search(sid: int, request: Request, q: str = "", db: Session = Depends(get_db)):
    """Type-ahead: real Check Point applications matching ``q`` on this server (for the Application
    field + the 'did you mean' chips). Best-effort — returns [] rather than erroring the UI."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return JSONResponse({"candidates": []})
    try:
        return JSONResponse({"candidates": applications.search_server(ms, secret, q)})
    except Exception:  # noqa: BLE001
        return JSONResponse({"candidates": []})


@router.get("/access-automation/{sid}/svc-search")
def aa_svc_search(sid: int, request: Request, q: str = "", kind: str = "", db: Session = Depends(get_db)):
    """Type-ahead: real Check Point services matching ``q`` (icmp, GRE, GTP, …). ``kind`` (the picked
    Service type: icmp/rpc/dce-rpc/gtp/other/…) narrows the suggestions to that object type so the right
    object is offered. Best-effort -> []."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return JSONResponse({"candidates": []})
    try:
        return JSONResponse({"candidates": services.search_server(ms, secret, q, kind=kind)})
    except Exception:  # noqa: BLE001
        return JSONResponse({"candidates": []})


@router.get("/access-automation/{sid}/object-search")
def aa_object_search(sid: int, request: Request, q: str = "", kind: str = "",
                     db: Session = Depends(get_db)):
    """Type-ahead: real Check Point TYPED source/destination objects (domain / access-role / dynamic-
    object / updatable-object / security-zone) matching ``q`` for the chosen endpoint ``kind`` — the
    recommendations behind the Source/Destination value field. Best-effort -> [] (never errors the UI)."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return JSONResponse({"candidates": []})
    try:
        return JSONResponse({"candidates": typed_objects.search_server(ms, secret, kind, q)})
    except Exception:  # noqa: BLE001
        return JSONResponse({"candidates": []})


@router.get("/access-automation/{sid}/usercheck-search")
def aa_usercheck_search(sid: int, request: Request, q: str = "", db: Session = Depends(get_db)):
    """Type-ahead: real Check Point UserCheck interaction objects matching ``q`` — the recommendations
    behind the Advanced-options 'UserCheck interaction' field (an Ask/Inform prompt or Drop/Reject block
    message). Best-effort -> [] (never errors the UI)."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return JSONResponse({"candidates": []})
    try:
        from ..services import usercheck
        return JSONResponse({"candidates": usercheck.search_server(ms, secret, q)})
    except Exception:  # noqa: BLE001
        return JSONResponse({"candidates": []})


@router.get("/access-automation/{sid}/field-search")
def aa_field_search(sid: int, request: Request, q: str = "", kind: str = "", db: Session = Depends(get_db)):
    """Type-ahead for the Advanced-options columns — ``kind`` = time | content | limit | gateway | vpn —
    so those fields recommend real Check Point objects like Source/Service/Application already do.
    Best-effort -> [] (never errors the UI)."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return JSONResponse({"candidates": []})
    try:
        from ..services import correlate_objects
        return JSONResponse({"candidates": correlate_objects.search_server(ms, secret, q, kind)})
    except Exception:  # noqa: BLE001
        return JSONResponse({"candidates": []})


@router.post("/access-automation/{sid}/preview")
def aa_preview(sid: int, body: AccessReqBody, request: Request, db: Session = Depends(get_db)):
    """JSON: load → decide → describe what would happen. Read-only, commits nothing."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return _run(db, sid, user, body, do_apply=False)


class TakeOverBody(BaseModel):
    session_uid: str


@router.post("/access-automation/{sid}/take-over")
def aa_take_over(sid: int, body: TakeOverBody, request: Request, db: Session = Depends(get_db)):
    """Release a 'Locked for editing' conflict by taking over the offending session and discarding its
    uncommitted changes. DESTRUCTIVE — the UI confirms first. Returns {ok} / {error}."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if (e := _perm_or_403(user, permissions.APPLY)):
        return e
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    if not (body.session_uid or "").strip():
        return JSONResponse({"error": "No session id."}, status_code=400)
    res = mgmt_api.take_over_session(ms, secret, body.session_uid.strip())
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


@router.post("/access-automation/{sid}/apply")
def aa_apply(sid: int, body: AccessReqBody, request: Request, db: Session = Depends(get_db)):
    """JSON: apply the change. ``publish:false`` validates then discards (zero commit);
    ``publish:true`` commits it."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if (e := _perm_or_403(user, permissions.APPLY)):
        return e
    if body.publish and (e := _perm_or_403(user, permissions.PUBLISH)):
        return e
    return _run(db, sid, user, body, do_apply=True)


class RevertBody(BaseModel):
    publish: bool = False     # symmetric with apply: a bodyless/defaulted call DRY-RUNS (the UI sends true)
    disable: bool = False     # undo an added-rule change by DISABLING the rule (a reversible "disabled" state)
    delete_rule: bool = False  # for a DISABLED rule: DELETE it outright (finalize, not undo)
    reenable: bool = False    # for a DISABLED rule: turn it back ON (undo the disable)


def _revert_state(r) -> str:
    """The actionable state of a recorded change (resolved | disabled | active). ONE shared state machine —
    the panel, the MCP tool, and the REST endpoint all delegate to ``change_log.revert_state`` so they can
    never disagree on what an entry allows."""
    return change_log.revert_state(r)


def _change_row(r) -> dict:
    state = _revert_state(r)
    return {"id": r.id, "at": r.created_at.isoformat() if r.created_at else "", "by": r.created_by,
            "layer": r.layer, "action": r.action, "outcome": r.outcome, "summary": r.summary,
            "ticket_id": r.ticket_id or "", "objects": list(r.objects_json or []),
            "reverted": bool(r.reverted_at), "reverted_at": r.reverted_at.isoformat() if r.reverted_at else "",
            "reverted_by": r.reverted_by or "", "revert_error": r.revert_error or "",
            "resolution": r.resolution or "", "state": state,
            "deletable_disabled": state == "disabled",
            "revertable": state in ("active", "disabled") and bool(r.inverse_json)}


@router.get("/access-automation/{sid}/changes")
def aa_changes(sid: int, request: Request, db: Session = Depends(get_db)):
    """Recent PUBLISHED changes on this server (newest first) — the data behind the rollback panel."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    rows = change_log.recent_for_server(db, ms.id, limit=25)
    return JSONResponse({"changes": [_change_row(r) for r in rows]})


@router.post("/access-automation/{sid}/changes/{cid}/revert")
def aa_revert(sid: int, cid: int, body: RevertBody, request: Request, db: Session = Depends(get_db)):
    """Roll back ONE recorded change by replaying its inverse op(s) in a single publish — surgical, not a
    full-DB revision rollback. publish=true commits the undo (default for an explicit click); publish=false
    validates then discards. Mirrors apply's lock/error handling."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if (e := _perm_or_403(user, permissions.APPLY)):
        return e
    if body.publish and (e := _perm_or_403(user, permissions.PUBLISH)):
        return e
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    change = change_log.get(db, cid)
    if change is None or change.server_id != ms.id:
        return JSONResponse({"error": "Change not found for this server."}, status_code=404)
    if not change.inverse_json:
        return JSONResponse({"error": "This change has no recorded inverse to act on."}, status_code=400)
    actor = f"user:{user.username}"
    inv0 = (change.inverse_json or [{}])[0]
    state = _revert_state(change)
    if state == "resolved":
        return JSONResponse({"error": "This change was already resolved."}, status_code=400)

    # Decide the action -> (web_api ops, whether to DISABLE an added rule instead of deleting it, the new DB
    # state to stamp on success). A "disabled" rule (present but off) can be RE-ENABLED or DELETED; an
    # "active" change can be rolled back, and an added rule can be rolled back BY disabling it (reversible —
    # it lands in the "disabled" state, NOT terminal, so it can still be deleted later).
    if body.delete_rule:
        if state != "disabled":
            return JSONResponse({"error": "Delete-rule applies only to a disabled rule."}, status_code=400)
        ops = [{"op": "delete-access-rule", "uid": inv0.get("uid"), "layer": inv0.get("layer")}]
        disable_added = False
        new_fields = {"reverted_at": utcnow(), "reverted_by": actor, "resolution": "deleted", "revert_error": ""}
    elif body.reenable:
        if state != "disabled":
            return JSONResponse({"error": "Re-enable applies only to a disabled rule."}, status_code=400)
        ops = [{"op": "set-access-rule", "uid": inv0.get("uid"), "layer": inv0.get("layer"), "enabled": True}]
        disable_added = False
        # undoing a REMOVAL that disabled a rule restores the access -> terminal; re-enabling an ADDED rule
        # we'd disabled restores the created rule -> back to ACTIVE (it can be rolled back again).
        new_fields = ({"reverted_at": utcnow(), "reverted_by": actor, "resolution": "reverted", "revert_error": ""}
                      if change.outcome == "disable"
                      else {"reverted_at": None, "reverted_by": actor, "resolution": "", "revert_error": ""})
    elif body.disable:
        if change.outcome not in ("create", "deny") or state != "active":
            return JSONResponse({"error": "Disable applies only to an active added rule."}, status_code=400)
        ops = list(change.inverse_json or [])      # rewritten to enabled=false by disable_added_rules below
        disable_added = True
        new_fields = {"reverted_at": None, "reverted_by": actor, "resolution": "disabled", "revert_error": ""}
    else:
        if state != "active":
            return JSONResponse({"error": "This change was already resolved."}, status_code=400)
        ops = list(change.inverse_json or [])
        disable_added = False
        new_fields = {"reverted_at": utcnow(), "reverted_by": actor, "resolution": "reverted", "revert_error": ""}

    if body.publish:
        # ATOMIC claim BEFORE touching the SMS so only ONE actor transitions the entry (no double publish, no
        # spurious error stamped on an already-acted row). Every actionable state has reverted_at NULL; we
        # also guard the current resolution so a concurrent action from a different state can't win. On SMS
        # failure we restore the captured prior state below (a successful SMS op is never reported as failure).
        prior = {"reverted_at": change.reverted_at, "reverted_by": change.reverted_by or "",
                 "resolution": change.resolution or "", "revert_error": change.revert_error or ""}
        if not change_log.claim(db, cid, change.resolution or "", new_fields):
            return JSONResponse({"error": "This change was already resolved or changed."}, status_code=400)
    result = aa.revert_execute(ms, secret, ops, publish=body.publish, disable_added_rules=disable_added)
    if body.publish and not (result.get("ok") and result.get("reverted")):
        try:
            change_log.restore(db, cid, prior)
        except Exception:  # noqa: BLE001
            db.rollback()
            import logging
            logging.getLogger("policypilot.access_automation").exception("releasing revert claim failed")
    return JSONResponse({**result, "change_id": cid}, status_code=200 if result.get("ok") else 400)


@router.post("/access-automation/{sid}/changes/{cid}/delete")
def aa_delete_change(sid: int, cid: int, request: Request, db: Session = Depends(get_db)):
    """Remove ONE audit/rollback entry from the list. Pure bookkeeping — NEVER touches live policy (it only
    forgets the record). After this the change can no longer be rolled back from the panel."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    change = change_log.get(db, cid)
    if change is None or change.server_id != ms.id:
        return JSONResponse({"error": "Change not found for this server."}, status_code=404)
    change_log.delete_entry(db, change)
    return JSONResponse({"ok": True, "deleted": cid})


@router.post("/access-automation/{sid}/changes/clear-resolved")
def aa_clear_resolved(sid: int, request: Request, db: Session = Depends(get_db)):
    """Bulk-remove the RESOLVED audit entries (rolled back / disabled-rule-deleted) for this server, leaving
    open + failed ones (still actionable) in place. Bookkeeping only — never touches live policy."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    removed = change_log.clear_resolved(db, ms.id)
    return JSONResponse({"ok": True, "removed": removed})


# --- Generic ticketing webhook (no portal session; authenticated by a shared token) ----------
def _allowed_server_ids() -> set:
    """Optional allowlist (Settings → Ticketing webhook → 'Restrict the webhook to server ids', falling
    back to PILOT_WEBHOOK_SERVER_IDS), comma-separated server ids. UNSET = every saved server.
    Set-but-unparseable FAILS CLOSED (raises): silently dropping a mistyped entry (e.g. "prod-3") would
    yield an empty set, which the caller reads as "allow all" — widening the blast radius of the publish
    token from a couple servers to every tenant. A scoping typo must be an error, not permission."""
    raw = (app_settings.get_or_env("webhook_server_ids", get_settings().webhook_server_ids) or "").strip()
    if not raw:
        return set()                                   # unset -> documented allow-all
    ids, bad = set(), []
    for tok in raw.split(","):
        tok = tok.strip()
        if tok.isdigit():
            ids.add(int(tok))
        elif tok:
            bad.append(tok)
    if bad or not ids:
        raise ValueError(f"the webhook server-id allowlist is malformed (bad entries: {bad or raw!r}); "
                         f"expected a comma-separated list of numeric server ids")
    return ids


@router.post("/access-automation/webhook")
async def aa_webhook(request: Request, db: Session = Depends(get_db)):
    """End-to-end automation for ANY ticketing system (ServiceNow, Jira, Remedy, a custom portal,
    curl …): the caller POSTs an access request → we decide + (optionally) apply → return the result
    JSON, and push it back via the caller's ``callback_url`` or the built-in ServiceNow adapter.

    Auth: the shared secret PILOT_WEBHOOK_TOKEN must arrive as the X-PolicyPilot-Token header. If the token
    is unset the webhook is DISABLED (503) — it never runs unauthenticated. The token grants policy
    publish on every allowed management server, so treat it as a top-tier secret; optionally scope it
    with PILOT_WEBHOOK_SERVER_IDS."""
    # Auth: the X-PolicyPilot-Token header must match the legacy webhook token (Settings/env) OR an active
    # webhook-scoped API key (Settings → API keys). Either one enables the endpoint.
    presented = request.headers.get("x-policypilot-token", "")
    legacy = (app_settings.get_secret_or_env("webhook_token", get_settings().webhook_token) or "").strip()
    if not (legacy or api_keys.any_active("webhook")):
        return JSONResponse({"error": "Webhook disabled — add a webhook key in Settings → API keys, or "
                                      "set a token in Settings → Ticketing webhook (or the "
                                      "PILOT_WEBHOOK_TOKEN env var) to enable it."},
                            status_code=503)
    via_legacy = bool(presented and legacy and hmac.compare_digest(presented, legacy))
    key_caps = None if via_legacy else (api_keys.authorize(presented, "webhook") if presented else None)
    ok = via_legacy or key_caps is not None
    if not ok:
        return JSONResponse({"error": "Invalid or missing X-PolicyPilot-Token."}, status_code=401)
    # Per-key rate limit (backstop against a runaway caller). Legacy token shares one identity.
    from ..services import rate_limit
    rl_ident = "webhook:legacy" if via_legacy else f"webhook:{key_caps['id']}"
    if not rate_limit.allow(rl_ident):
        return JSONResponse({"error": "Rate limit exceeded — too many requests; retry shortly."},
                            status_code=429)
    # Write capability: the legacy token is full-access; a webhook API key may be read-only (preview-only).
    can_write = via_legacy or bool(key_caps and key_caps["can_write"])

    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "Body must be JSON."}, status_code=400)
    try:
        ticket = ticketing.parse_payload(data)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    try:
        allow = _allowed_server_ids()
    except ValueError as exc:                          # misconfigured allowlist -> fail closed, never allow-all
        return JSONResponse({"error": "Webhook server allowlist is misconfigured; contact the admin.",
                             "detail": str(exc)}, status_code=500)
    if allow and ticket.server_id not in allow:
        return JSONResponse({"error": f"server_id {ticket.server_id} is not in the webhook allowlist."},
                            status_code=403)

    ms = db.get(ManagementServer, ticket.server_id)
    if ms is None:
        return JSONResponse({"error": f"Management server {ticket.server_id} not found."},
                            status_code=404)
    if not ms.username:
        return JSONResponse({"error": "Target server has no username configured."}, status_code=400)
    secret = mgmt_creds.get_secret(db, ms)
    if not secret:
        return JSONResponse({"error": "Target server has no stored credential."}, status_code=400)
    ensure_pinned(db, ms)

    if ticket.apply and not can_write:
        return JSONResponse({"error": "This webhook API key is read-only — it cannot apply changes. "
                                      "Send apply=false to preview, or use a write-enabled webhook key."},
                            status_code=403)
    # Idempotency: the webhook is the most redelivery-prone publish surface (ITSM/n8n retry on a slow 200),
    # so a retry with the same ticket REPLAYS the first committed result instead of publishing again —
    # mirroring the MCP/REST apply paths. Keyed on server + ticket id (only when a ticket id is present).
    from ..services import idempotency
    idem_key = f"webhook:{ms.id}:{ticket.ticket_id.strip()}" if (ticket.apply and ticket.ticket_id.strip()) else ""
    replayed = False
    result = idempotency.replay(idem_key) if idem_key else None
    if result is not None:
        replayed = True
    elif ticket.apply:
        result = aa.execute(ms, secret, ticket.request, ticket.layer, package=ticket.package,
                            ticket_id=ticket.ticket_id, publish=True)
        _record_change_safe(db, server=ms, result=result, request=change_log.snapshot_request(ticket.request),
                            layer=ticket.layer, package=ticket.package, ticket_id=ticket.ticket_id,
                            actor="webhook")
        if idem_key and isinstance(result, dict) and result.get("published"):
            idempotency.remember(idem_key, result)
    else:
        result = aa.preview(ms, secret, ticket.request, ticket.layer, package=ticket.package)

    # Push the result back to the originating system (generic callback_url, or the ServiceNow adapter).
    # A replayed result was already pushed back on the first delivery — don't double-notify.
    callback = {"skipped": "idempotent_replay"} if replayed else ticketing.notify(ticket, result)
    # Report what actually HAPPENED, not the request's intent: a no_op / review / unresolved-object run
    # commits nothing even when ticket.apply was true, so a consumer keying on the top-level flag must not
    # read "access granted". `published` mirrors the real commit; `outcome` lets the caller branch precisely.
    return JSONResponse({"ticket_id": ticket.ticket_id,
                         "applied": bool(result.get("applied")),
                         "published": bool(result.get("published")),
                         "outcome": result.get("outcome"),
                         "idempotent_replay": replayed,
                         "result": result, "callback": callback},
                        status_code=200 if result.get("ok") else 400)
