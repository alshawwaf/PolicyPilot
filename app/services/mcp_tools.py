"""The agent-facing capabilities exposed over MCP (and reusable anywhere) — PURE functions that return
plain JSON-serializable dicts, with NO dependency on the MCP SDK. ``mcp_server`` wraps these as MCP tools;
this module is what the tests exercise and what keeps the SDK glue thin.

Each tool resolves its own management server + credential from the DB (the MCP server runs outside the
HTTP request lifecycle), mirroring the webhook. Reads/preview/correlate/coverage are always available;
``apply_access`` can validate (dry-run) freely but only PUBLISHES when the admin has turned on the
``mcp_allow_publish`` setting — an LLM never commits to live policy by default."""
from __future__ import annotations

import logging

from ..db import SessionLocal
from ..models import ManagementServer

logger = logging.getLogger("policypilot.mcp_tools")


def _resolve_server(db, server_ref):
    """Find a ManagementServer by numeric id OR by name / host / domain (case-insensitive), so an agent can
    pass what the USER said ("HQ-Management", a hostname) — not only the numeric id (the portal's server name
    rarely matches the user's words). On no match, raise a ValueError that LISTS the available servers, so the
    error itself tells the agent/user what to pick."""
    ms = sid = None
    numeric = False
    if isinstance(server_ref, int) and not isinstance(server_ref, bool):
        sid, numeric = server_ref, True
    elif isinstance(server_ref, str) and server_ref.strip().isdigit():
        sid, numeric = int(server_ref.strip()), True
    if sid is not None:
        ms = db.get(ManagementServer, sid)
    # A purely-numeric ref is an ID lookup ONLY. Never fall through to fuzzy name/host substring matching for
    # it — a stale id like "5" must not silently resolve to a different server whose host contains "5"
    # (e.g. 10.0.0.5). That misroute is how a rollback of a deleted server's change hit the WRONG live SMS.
    if ms is None and not numeric and isinstance(server_ref, str) and server_ref.strip():
        ref = server_ref.strip().lower()
        rows = db.query(ManagementServer).all()
        ms = next((m for m in rows
                   if ref in ((m.name or "").lower(), (m.host or "").lower(), (m.domain or "").lower())), None)
        if ms is None:                                  # fall back to a UNIQUE partial match on name/host
            hits = [m for m in rows if ref in (m.name or "").lower() or ref in (m.host or "").lower()]
            ms = hits[0] if len(hits) == 1 else None
    if ms is None:
        avail = "; ".join(f"id {m.id} = {m.name} ({m.host})" for m in db.query(ManagementServer).all())
        raise ValueError(f"could not resolve management server “{server_ref}”. "
                         f"Available — {avail or 'none configured'}. "
                         f"Call list_management_servers and ask the user which one to use.")
    return ms


def _server_secret(db, server_id):
    """(ManagementServer, secret) for a server id OR name/host, or a ValueError the caller turns into
    {"error": …}."""
    from . import mgmt_creds
    ms = _resolve_server(db, server_id)
    if not ms.username:
        raise ValueError(f"management server “{ms.name}” (id {ms.id}) has no username configured")
    secret = mgmt_creds.get_secret(db, ms)
    if not secret:
        raise ValueError(f"management server “{ms.name}” (id {ms.id}) has no stored credential")
    try:
        from .gaia_client import ensure_pinned
        ensure_pinned(db, ms)            # trust-on-first-use before the TLS handshake
    except Exception:  # noqa: BLE001 — pinning is best-effort; the call still verifies the saved cert
        pass
    return ms, secret


def list_management_servers() -> dict:
    """The Check Point management servers PolicyPilot knows about — returns id, name, host, domain for each.
    Call this first; when the request doesn't clearly name a server, PRESENT this list to the user and ask
    which one. The other tools accept either the numeric id or the name/host as ``server_id``."""
    db = SessionLocal()
    try:
        rows = db.query(ManagementServer).all()
        return {"servers": [{"id": m.id, "name": m.name, "host": m.host, "port": m.port,
                             "domain": m.domain or ""} for m in rows]}
    finally:
        db.close()


def list_access_layers(server_id: str) -> dict:
    """The access layers (policy rulebases) on a server, so the agent names a real layer."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        db.close()
        return {"error": str(exc)}
    db.close()
    from .mgmt_api import MgmtError, read_session
    try:
        with read_session(ms, secret) as s:
            layers = [L.get("name") for L in s.list_access_layers() if L.get("name")]
        return {"server_id": ms.id, "server_name": ms.name, "layers": layers}
    except MgmtError as exc:
        return {"error": str(exc)}


def _build(source, destination, service, port, protocol, application,
           source_kind="ip", destination_kind="ip", action="Accept", inline_layer="",
           action_limit="", captive_portal=False, content=None, content_direction="any",
           content_negate=False, time_objects=None, install_on=None, vpn=None):
    from . import ticketing
    return ticketing.build_request(source, destination, protocol or "tcp", port or "",
                                   application=application, service=service,
                                   source_kind=source_kind or "ip",
                                   destination_kind=destination_kind or "ip",
                                   action=action or "Accept", inline_layer=inline_layer or "",
                                   action_settings_limit=action_limit or "",
                                   action_settings_captive_portal=bool(captive_portal),
                                   content=content, content_direction=content_direction or "any",
                                   content_negate=bool(content_negate), time_objects=time_objects,
                                   install_on=install_on, vpn=vpn)


def _autopilot(server=None, layer=None) -> bool:
    """True when the admin has enabled the Autopilot lab-demo toggle (``aa_autopilot``) — surfaced as an
    'autopilot' flag on tool results so a prompt-driven agent knows it is pre-authorized to apply AND publish
    in one turn, no confirmation. The publish itself is still independently gated by ``mcp_allow_publish``
    (so with that OFF the agent's publish is refused even under autopilot). Autopilot is an agent PERMISSION,
    not a decision posture — the engine's aggressiveness is the separate ``aa_profile``. Best-effort: any
    read failure → False (the agent then confirms as usual)."""
    try:
        from . import app_settings
        return bool(app_settings.get("aa_autopilot"))
    except Exception:  # noqa: BLE001
        return False


def decide_access(server_id: str, source: str, destination: str, layer: str, service: str | None = None,
                  port: str | None = None, protocol: str = "tcp", application: str | None = None,
                  package: str | None = None,
                  source_kind: str = "ip", destination_kind: str = "ip",
                  action: str = "Accept", inline_layer: str | None = None,
                  action_limit: str | None = None, captive_portal: bool = False,
                  content: list[str] | None = None, content_direction: str = "any",
                  content_negate: bool = False, time_objects: list[str] | None = None,
                  install_on: list[str] | None = None, vpn: list[str] | None = None) -> dict:
    """PREVIEW (read-only) what PolicyPilot would do for an access request: returns the outcome
    (no_op / widen / create / review), the reasoning, and — for an unknown service/app — `suggestions`.
    Writes nothing. This is the primary tool for an agent to reason about a change.

    ``action`` is the rule verdict: **Accept** (default) / **Drop** / **Reject** / **Ask** / **Inform** /
    **Apply Layer** (Apply Layer needs ``inline_layer`` = the layer to divert into). Drop/Reject create a
    least-privilege block above what would allow the flow; Ask/Inform/Apply-Layer always create (flagged).

    To answer "can X reach Y / does X already have access?", read **`currently_allowed`** (true / false /
    null) and **`answer`** (a ready-to-relay sentence) — NOT `ok`. `ok: true` only means the check ran;
    `currently_allowed` is whether the access exists today: no_op→true (allowed), create/widen→false (a
    change would be required), review→null (can't be sure). Never report "yes, allowed" for a create/widen.

    Source/destination default to IP/CIDR/Any; set ``source_kind``/``destination_kind`` to a typed kind
    (domain / access-role / dynamic-object / updatable-object / security-zone) to reason in that identity
    space — e.g. does a host have access to the domain ``alshawwaf.ca`` (source_kind stays ip,
    destination_kind=domain, destination='alshawwaf.ca').

    ``server_id`` is the numeric id OR the server name/host from list_management_servers."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()
    from . import access_automation as aa
    try:
        req = _build(source, destination, service, port, protocol, application,
                     source_kind, destination_kind, action=action, inline_layer=inline_layer,
                     action_limit=action_limit, captive_portal=captive_portal,
                     content=content, content_direction=content_direction, content_negate=content_negate,
                     time_objects=time_objects, install_on=install_on, vpn=vpn)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        res = aa.preview(ms, secret, req, layer, package=package)
        if isinstance(res, dict):
            res["autopilot"] = _autopilot(ms, layer)   # signal the agent it may apply+publish in one turn
        return res
    except Exception as exc:  # noqa: BLE001 — the agent must always get a structured result, never an
        logger.exception("decide_access failed (server_id=%s, layer=%r)", server_id, layer)  # opaque
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}                          # MCP error


def _record_applied(ms, result: dict, req, layer: str, package, ticket_id: str) -> None:
    """Persist a PUBLISHED change (apply or remove) so it can be rolled back from the portal. No-op for
    dry-runs / no-ops / reviews (change_log.record guards that). Best-effort — a logging failure must never
    break the result the agent receives."""
    try:
        from . import change_log
        db = SessionLocal()
        try:
            change_log.record(db, server=ms, result=result, request=change_log.snapshot_request(req),
                              layer=layer, package=package, ticket_id=ticket_id, actor="mcp")
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        logger.exception("recording MCP change for rollback failed")


def apply_access(server_id: str, source: str, destination: str, layer: str, service: str | None = None,
                 port: str | None = None, protocol: str = "tcp", application: str | None = None,
                 package: str | None = None, publish: bool = False, ticket_id: str = "",
                 source_kind: str = "ip", destination_kind: str = "ip",
                 action: str = "Accept", inline_layer: str | None = None,
                 action_limit: str | None = None, captive_portal: bool = False,
                 content: list[str] | None = None, content_direction: str = "any",
                 content_negate: bool = False, time_objects: list[str] | None = None,
                 install_on: list[str] | None = None, vpn: list[str] | None = None) -> dict:
    """APPLY an access request. ``action`` = the rule verdict: Accept (default) / Drop / Reject / Ask /
    Inform / Apply Layer (Apply Layer needs ``inline_layer``). Optional match-gating columns (all REUSE-ONLY
    object names): ``content`` (data-types) + ``content_direction`` (any/up/down) + ``content_negate``;
    ``time_objects`` (time / time-group); ``install_on`` (gateways/targets); ``vpn`` (communities; []=Any).
    With publish=false it DRY-RUNS (applies inside a session, then discards —
    nothing is committed) — always allowed. With publish=true it COMMITS to the live server — allowed ONLY
    when an admin has enabled the 'mcp_allow_publish' setting; otherwise it's refused (dry-run instead).

    ``server_id`` is the numeric id OR the server name/host from list_management_servers."""
    if publish:
        from . import app_settings
        try:
            allowed = bool(app_settings.get("mcp_allow_publish"))
        except Exception:  # noqa: BLE001
            allowed = False
        if not allowed:
            return {"ok": False, "outcome": "review", "applied": False, "published": False,
                    "error": "agentic publishing is disabled — an admin must enable 'Let the MCP agent "
                             "publish to live policy' in Settings (this gate covers the MCP and REST "
                             "apply paths). Re-run with publish=false to dry-run (validate then discard)."}
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()
    from . import access_automation as aa
    try:
        req = _build(source, destination, service, port, protocol, application,
                     source_kind, destination_kind, action=action, inline_layer=inline_layer,
                     action_limit=action_limit, captive_portal=captive_portal,
                     content=content, content_direction=content_direction, content_negate=content_negate,
                     time_objects=time_objects, install_on=install_on, vpn=vpn)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        result = aa.execute(ms, secret, req, layer, package=package, ticket_id=ticket_id, publish=publish)
    except Exception as exc:  # noqa: BLE001 — never surface an uncaught raise as a generic "Internal error";
        logger.exception("apply_access failed (server_id=%s, layer=%r)", server_id, layer)
        return {"ok": False, "applied": False, "published": False, "error": f"{type(exc).__name__}: {exc}"}
    if isinstance(result, dict):
        result.setdefault("autopilot", _autopilot(ms, layer))
    _record_applied(ms, result, req, layer, package, ticket_id)
    return result


def remove_access(server_id: str, source: str, destination: str, layer: str, service: str | None = None,
                  port: str | None = None, protocol: str = "tcp", application: str | None = None,
                  package: str | None = None, publish: bool = False, ticket_id: str = "",
                  source_kind: str = "ip", destination_kind: str = "ip") -> dict:
    """REVOKE an access (the inverse of apply_access): find the rule that grants src->dst:svc and remove it
    with the least-disruptive safe move — DISABLE a rule that grants exactly this, or insert a least-privilege
    DROP above a broader rule so first-match denies just this flow. no_op = not permitted; review = granted via
    an opaque/inline/conditional/multi-rule path (won't guess a destructive change). With publish=false it
    DRY-RUNS (validate then discard); publish=true COMMITS, allowed ONLY when 'mcp_allow_publish' is enabled.

    ``server_id`` is the numeric id OR the server name/host from list_management_servers."""
    if publish:
        from . import app_settings
        try:
            allowed = bool(app_settings.get("mcp_allow_publish"))
        except Exception:  # noqa: BLE001
            allowed = False
        if not allowed:
            return {"ok": False, "outcome": "review", "applied": False, "published": False,
                    "error": "agentic publishing is disabled — an admin must enable 'Let the MCP agent "
                             "publish to live policy' in Settings (this gate covers the MCP and REST "
                             "apply paths). Re-run with publish=false to dry-run (validate then discard)."}
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()
    from . import access_automation as aa
    try:
        req = _build(source, destination, service, port, protocol, application,
                     source_kind, destination_kind)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        result = aa.remove_execute(ms, secret, req, layer, package=package, ticket_id=ticket_id, publish=publish)
    except Exception as exc:  # noqa: BLE001
        logger.exception("remove_access failed (server_id=%s, layer=%r)", server_id, layer)
        return {"ok": False, "applied": False, "published": False, "error": f"{type(exc).__name__}: {exc}"}
    if isinstance(result, dict):
        result.setdefault("autopilot", _autopilot(ms, layer))   # carry the signal on the REMOVE turn too
    _record_applied(ms, result, req, layer, package, ticket_id)
    return result


def _amend_target_from_change(change) -> tuple:
    """(rule_uid, layer) of the rule a recorded change CREATED — and ONLY a create/deny change qualifies: its
    inverse is a ``delete-access-rule`` of the rule it added. A WIDEN or DISABLE change's inverse instead
    set-access-rule's a PRE-EXISTING rule (the broad rule it widened / the rule it disabled) — relabelling
    THAT via change_id would silently rename the wrong production rule, so this returns (None, layer) for
    those and the caller refuses (amend it by rule_uid instead). Falls back to (None, change.layer)."""
    for op in (change.inverse_json or []):
        if op.get("op") == "delete-access-rule" and op.get("uid"):
            return op["uid"], (op.get("layer") or change.layer or "")
    return None, (change.layer or "")


def amend_access_rule(server_id: str | None = None, layer: str | None = None,
                      change_id: int | None = None, rule_uid: str | None = None,
                      name: str | None = None, comment: str | None = None,
                      tags: list[str] | None = None, track: str | None = None,
                      publish: bool = False) -> dict:
    """EDIT an existing access rule's METADATA — its name, comment, tags, and/or track/logging (e.g. to add
    the rule name you forgot, or turn logging on). `track` is a track-type name: "Log" / "None" / "Detailed
    Log" / "Extended Log". Identify the rule EITHER by `change_id` (from list_changes — must be a change that
    CREATED a rule, i.e. an apply→create or a remove→deny Drop; it also supplies the layer) OR by `rule_uid` +
    `layer` + `server_id`. A widen/disable change_id is refused (its rule pre-existed — edit it by rule_uid so
    you don't relabel the wrong rule). This NEVER changes the rule's match columns (source / destination /
    service / action) — use apply_access / remove_access for those. With publish=false it DRY-RUNS (validate
    then discard); publish=true COMMITS, allowed ONLY when an admin enabled 'mcp_allow_publish'. The edit is
    itself recorded + rollback-able (revert_change restores the prior name/comment/tags/track)."""
    if publish:
        from . import app_settings
        try:
            allowed = bool(app_settings.get("mcp_allow_publish"))
        except Exception:  # noqa: BLE001
            allowed = False
        if not allowed:
            return {"ok": False, "outcome": "review", "applied": False, "published": False,
                    "error": "publishing is disabled for the MCP agent — an admin must enable 'Let the MCP "
                             "agent publish to live policy' in Settings. Re-run with publish=false to dry-run."}
    if name is None and comment is None and tags is None and track is None:
        return {"ok": False, "error": "nothing to change — provide a name, comment, tags, and/or track"}
    db = SessionLocal()
    try:
        if change_id is not None:
            from . import change_log
            change = change_log.get(db, int(change_id))
            if change is None:
                return {"ok": False, "error": f"no recorded change with id {change_id}"}
            if change.reverted_at:                       # the rule it created was rolled back (likely deleted)
                return {"ok": False, "error": f"change {change_id} was already rolled back "
                                              f"at {change.reverted_at.isoformat()} — nothing to edit"}
            # Resolve the server STRICTLY by the recorded id (never the fuzzy matcher) so a stale id can't
            # misroute this WRITE onto a different live SMS — same guard as revert_change.
            ms = db.get(ManagementServer, change.server_id) if change.server_id is not None else None
            if ms is None:
                return {"ok": False, "error": "the management server for this change no longer exists"}
            from . import mgmt_creds
            secret = mgmt_creds.get_secret(db, ms)
            if not (ms.username and secret):
                return {"ok": False, "error": f"server “{ms.name}” (id {ms.id}) has no stored credential"}
            uid, tgt_layer = _amend_target_from_change(change)
            if not uid:
                return {"ok": False, "error": f"change {change_id} did not create a new rule (it widened or "
                        f"disabled an existing one) — relabelling that rule by change_id could rename the "
                        f"wrong production rule. Identify it by rule_uid + layer instead."}
            layer = tgt_layer or layer                   # the recorded layer is authoritative for a change_id edit
        else:
            if not rule_uid or not layer:
                return {"ok": False, "error": "identify the rule by change_id, OR by rule_uid + layer "
                                              "(+ server_id)"}
            try:
                ms, secret = _server_secret(db, server_id)
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
            uid = rule_uid
        try:
            from .gaia_client import ensure_pinned
            ensure_pinned(db, ms)
        except Exception:  # noqa: BLE001 — pinning is best-effort; the call still verifies the saved cert
            pass
        ms_id, ms_layer = ms, layer
    finally:
        db.close()
    from . import access_automation as aa
    try:
        result = aa.amend_execute(ms_id, secret, uid=uid, layer=ms_layer, name=name, comment=comment,
                                  tags=tags, track=track, publish=publish)
    except Exception as exc:  # noqa: BLE001
        logger.exception("amend_access_rule failed (uid=%s, layer=%r)", uid, ms_layer)
        return {"ok": False, "applied": False, "published": False, "error": f"{type(exc).__name__}: {exc}"}
    if isinstance(result, dict):
        result.setdefault("autopilot", _autopilot(ms_id, ms_layer))
    # Record the published edit so it shows in list_changes and revert_change can undo it (restore old meta).
    if result.get("ok") and result.get("published") and result.get("applied"):
        try:
            from . import change_log
            db2 = SessionLocal()
            try:
                change_log.record(db2, server=ms_id, result=result,
                                  request={"_amend": result.get("changed", {})}, layer=ms_layer, actor="mcp")
            finally:
                db2.close()
        except Exception:  # noqa: BLE001
            logger.exception("recording amend for rollback failed")
    return result


def _change_brief(r) -> dict:
    return {"id": r.id, "at": r.created_at.isoformat() if r.created_at else None, "by": r.created_by,
            "server": r.server_name, "layer": r.layer, "action": r.action, "outcome": r.outcome,
            "summary": r.summary, "ticket_id": r.ticket_id or None, "reverted": bool(r.reverted_at),
            "reverted_at": r.reverted_at.isoformat() if r.reverted_at else None}


def list_changes(limit: int = 20) -> dict:
    """List recent access-automation changes PUBLISHED to live policy (newest first) — each with its id, what
    it did, who/when, and whether it has already been rolled back. Pass an id to revert_change to undo one.
    Read-only. Dry-runs are never recorded, so everything here actually committed."""
    from . import change_log
    db = SessionLocal()
    try:
        rows = change_log.recent(db, limit=max(1, min(int(limit or 20), 100)))
        return {"ok": True, "changes": [_change_brief(r) for r in rows]}
    except Exception as exc:  # noqa: BLE001
        logger.exception("list_changes failed")
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()


def revert_change(change_id: int, publish: bool = False, disable_instead_of_delete: bool = False) -> dict:
    """ROLL BACK a previously published change by its id (from list_changes): replays the recorded inverse —
    delete the rule that was added / re-enable the rule that was disabled / remove the object that was widened
    in — surgically, without touching the rest of the policy. For a change that ADDED a rule (create / a Drop
    from a removal), set disable_instead_of_delete=true to DISABLE that rule rather than delete it — the
    gentler, reversible undo (the rule stays in the rulebase, greyed out). With publish=false it DRY-RUNS
    (validate then discard); publish=true COMMITS, allowed ONLY when an admin has enabled 'mcp_allow_publish'.
    Refuses if the change was already rolled back. Objects the change created are left in place."""
    if publish:
        from . import app_settings
        try:
            allowed = bool(app_settings.get("mcp_allow_publish"))
        except Exception:  # noqa: BLE001
            allowed = False
        if not allowed:
            return {"ok": False, "reverted": False,
                    "error": "publishing is disabled for the MCP agent — an admin must enable 'Let the MCP "
                             "agent publish to live policy' in Settings. Re-run with publish=false to dry-run."}
    from . import change_log
    from . import access_automation as aa
    db = SessionLocal()
    try:
        change = change_log.get(db, int(change_id))
        if change is None:
            return {"ok": False, "error": f"no recorded change with id {change_id}"}
        if change.reverted_at:
            return {"ok": False, "error": f"change {change_id} was already rolled back "
                                          f"at {change.reverted_at.isoformat()}"}
        # Resolve the original server STRICTLY by id (never the fuzzy name/host matcher) so a deleted server's
        # stale id can't misroute this DESTRUCTIVE rollback onto a different live SMS.
        ms = db.get(ManagementServer, change.server_id) if change.server_id is not None else None
        if ms is None:
            return {"ok": False, "error": "the management server for this change no longer exists"}
        from . import mgmt_creds
        secret = mgmt_creds.get_secret(db, ms)
        if not (ms.username and secret):
            return {"ok": False, "error": f"server “{ms.name}” (id {ms.id}) has no stored credential"}
        try:
            from .gaia_client import ensure_pinned
            ensure_pinned(db, ms)
        except Exception:  # noqa: BLE001 — pinning is best-effort; the call still verifies the saved cert
            pass
        result = aa.revert_execute(ms, secret, list(change.inverse_json or []), publish=publish,
                                   disable_added_rules=disable_instead_of_delete)
        if result.get("ok") and result.get("reverted"):
            change_log.mark_reverted(db, change, actor="mcp")
        elif not result.get("ok"):
            change_log.mark_revert_failed(db, change, result.get("error", ""))
        return {**result, "change_id": change.id, "summary": change.summary}
    except Exception as exc:  # noqa: BLE001
        logger.exception("revert_change failed (change_id=%s)", change_id)
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()


def correlate_service(server_id: str, name: str) -> dict:
    """Map a service/protocol name (icmp, GRE, sctp, …) to the real Check Point service object, or return
    candidate matches ('did you mean'). Lets an agent fix a name before deciding."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        db.close()
        return {"error": str(exc)}
    db.close()
    from . import services
    from .mgmt_api import MgmtError, read_session
    try:
        with read_session(ms, secret) as s:
            return services.resolve(s, name)
    except MgmtError as exc:
        return {"error": str(exc)}


def correlate_application(server_id: str, name: str) -> dict:
    """Map an application/site name (Facebook, …) to the real Check Point application-site object, or
    return candidates."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        db.close()
        return {"error": str(exc)}
    db.close()
    from . import applications
    from .mgmt_api import MgmtError, read_session
    try:
        with read_session(ms, secret) as s:
            return applications.resolve(s, name)
    except MgmtError as exc:
        return {"error": str(exc)}


def _load_layer_rules(server_id: str, layer: str):
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    finally:
        db.close()
    from . import access_automation as aa
    from .mgmt_api import read_session
    with read_session(ms, secret) as s:
        rules, _ = aa.load_layer_cached(s, ms, layer)
    return rules


def summarize_layer(server_id: str, layer: str) -> dict:
    """A high-level overview of an access layer (read-only): rule counts, Accept/Drop split, how many
    rules are Any on source/destination/service, inline layers, whether a cleanup drop exists."""
    try:
        rules = _load_layer_rules(server_id, layer)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    from . import access_automation as aa
    return {"server_id": server_id, "layer": layer, "summary": aa.summarize_rules(rules)}


def analyze_policy(server_id: str, layer: str) -> dict:
    """Read-only policy INSIGHTS for an access layer: the summary, plus rules that can never match
    (shadowed by an earlier broader Accept/Drop) and overly-permissive Accept rules (Any on a whole
    dimension) — to help tighten the policy. Provably-conservative: only flags what it can prove."""
    try:
        rules = _load_layer_rules(server_id, layer)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    from . import access_automation as aa
    return {"server_id": server_id, "layer": layer,
            "summary": aa.summarize_rules(rules),
            "shadowed_rules": aa.find_shadowed(rules),
            "overly_permissive": aa.find_permissive(rules)}


def coverage_lookup(api: str = "management", name: str = "", version: str = "") -> dict:
    """Is a Check Point object (and its fields) supported by the Terraform provider / Ansible collection?
    With ``name`` returns that object's per-field 3-way support; without, the object list for the api."""
    from . import coverage
    api = api if api in ("management", "gaia") else "management"
    ver = version or coverage.latest(api)
    if name:
        detail = coverage.object_detail(api, ver, name)
        if not detail or detail.get("error"):       # object_detail returns {"error": …} for an unknown name
            return {"error": f"no object “{name}” in {api} {ver}",
                    "objects": [o["name"] for g in coverage.object_groups(api, ver) for o in g["rows"]][:50]}
        return detail
    return {"api": api, "version": ver,
            "objects": [o["name"] for g in coverage.object_groups(api, ver) for o in g["rows"]]}
