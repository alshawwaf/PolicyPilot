"""The agent-facing capabilities exposed over MCP (and reusable anywhere) — PURE functions that return
plain JSON-serializable dicts, with NO dependency on the MCP SDK. ``mcp_server`` wraps these as MCP tools;
this module is what the tests exercise and what keeps the SDK glue thin.

Each tool resolves its own management server + credential from the DB (the MCP server runs outside the
HTTP request lifecycle), mirroring the webhook. Reads/preview/correlate/coverage are always available;
``apply_access`` can validate (dry-run) freely but only PUBLISHES when the admin has turned on the
``mcp_allow_publish`` setting — an LLM never commits to live policy by default."""
from __future__ import annotations

import functools
import hashlib
import json
import logging

from ..db import SessionLocal
from ..models import DynamicLayer, Gateway, ManagementServer
from . import authz

logger = logging.getLogger("policypilot.mcp_tools")


def _apply_fingerprint(ms, req, layer, package) -> str:
    """A stable hash of the ACTUAL change an apply_access request commits — server + normalized
    source/destination/service/action/layer/package + the match-gating columns. Bound to the idempotency
    key so reusing a key for a DIFFERENT request is detected (conflict) rather than falsely replayed."""
    payload = {
        "server": getattr(ms, "id", None),
        "src_kind": req.src_kind,
        "src": sorted(req.src_cidrs) if req.src_kind == "ip" else (req.src_value or ""),
        "dst_kind": req.dst_kind,
        "dst": sorted(req.dst_cidrs) if req.dst_kind == "ip" else (req.dst_value or ""),
        "protocol": (req.protocol or "").lower(), "ports": req.ports or "",
        "application": req.application or "", "service": req.service or "",
        "action": req.canon_action, "layer": (layer or "").lower(), "package": (package or "").lower(),
        "inline_layer": req.inline_layer or "",
        "content": sorted(req.content or []), "content_negate": bool(req.content_negate),
        "content_direction": (req.content_direction or "").lower(),
        "action_limit": req.action_settings_limit or "",
        "captive_portal": bool(req.action_settings_captive_portal),
        "user_check": req.user_check or "", "uc_freq": (req.user_check_frequency or "").lower(),
        "uc_confirm": (req.user_check_confirm or "").lower(),
        "uc_custom": f"{req.user_check_custom_every or 0}/{(req.user_check_custom_unit or '').lower()}",
        "time": sorted(req.time_objects or []), "install_on": sorted(req.install_on or []),
        "vpn": (sorted(req.vpn) if req.vpn else req.vpn),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _write_tool(fn):
    """Mark a tool as a WRITE: it refuses when the calling key is read-only (see services.authz). The check
    runs before any work and returns a plain error dict, so a read-only agent gets a clear message instead of
    a side effect. ``functools.wraps`` keeps the name/docstring/signature so the MCP schema is unchanged.
    Independent of, and in addition to, the live publish/push gates."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not authz.can_write():
            return {"ok": False, "error": "this API key is read-only — it can preview and read (decide_access, "
                    "fetch_dynamic_layer, list_*, summarize/analyze, …) but cannot apply, publish, push, or "
                    "edit layers. Use a write-enabled key for changes."}
        return fn(*args, **kwargs)
    wrapper._pp_write = True                     # explicit marker: tool_catalog badges write vs read tools
    return wrapper


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
    if ms is None and not numeric:
        # A NON-numeric ref didn't match — a placeholder/guess the agent invented when the user named no
        # server ("localhost", "", "default"…), or a name that doesn't exist. If EXACTLY ONE server is
        # configured there's no ambiguity and no misroute risk, so use it instead of bouncing the user to
        # confirm. (A numeric ref still requires an exact id match — never silently retarget a stale id to
        # a different live server; that was the rollback-misroute incident.)
        only = db.query(ManagementServer).all()
        if len(only) == 1:
            ms = only[0]
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


def packages_needing_install(server_id: str) -> dict:
    """Which policy packages on a server are published-but-not-installed, or CHANGED since their last
    install — i.e. a policy install is pending. Read-only.

    After a publish, the management database is ahead of what's enforcing on the gateways until you install
    policy. This compares each package's last-modify-time to the install date on the gateways running it and
    returns, per package: ``needs_install`` (bool), a ``reason``, and the per-gateway install state
    (installed? / installed_at / stale?). Also a ``summary`` with the count + the names needing install.

    Use it to answer "does anything need reinstalling?" / "is my published change actually enforcing yet?"
    — and pair it with the change history (list_changes) to see WHAT changed. ``server_id`` is a real
    server's id, name, or host (from list_management_servers) — never a guess."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        return {"error": str(exc)}
    finally:
        db.close()
    from . import changed_policies
    from .mgmt_api import MgmtError
    try:
        out = changed_policies.install_status(ms, secret)
        return {"ok": True, "server_id": ms.id, "server_name": ms.name, **out}
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.exception("packages_needing_install failed (server_id=%s)", server_id)
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def list_unused_objects(server_id: str) -> dict:
    """The objects on a server that NOTHING references — cleanup candidates — grouped by type. Read-only.

    Returns ``objects`` (each with uid / name / type) and ``by_type`` (a count per object type), so an
    agent can answer "what unused objects can I clean up?" and summarize the cruft. Surfacing them is
    read-only and safe; actually removing them is a separate, publish-gated step (not exposed here yet).
    ``server_id`` is a real server's id, name, or host (from list_management_servers)."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        return {"error": str(exc)}
    finally:
        db.close()
    from . import unused_objects
    from .mgmt_api import MgmtError
    try:
        out = unused_objects.list_unused(ms, secret)
        return {"ok": True, "server_id": ms.id, "server_name": ms.name, **out}
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.exception("list_unused_objects failed (server_id=%s)", server_id)
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _build(source, destination, service, port, protocol, application,
           source_kind="ip", destination_kind="ip", action="Accept", inline_layer="",
           action_limit="", captive_portal=False, content=None, content_direction="any",
           content_negate=False, time_objects=None, install_on=None, vpn=None,
           user_check="", user_check_frequency="", user_check_confirm="",
           user_check_custom_every=0, user_check_custom_unit=""):
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
                                   install_on=install_on, vpn=vpn,
                                   user_check=user_check or "", user_check_frequency=user_check_frequency or "",
                                   user_check_confirm=user_check_confirm or "",
                                   user_check_custom_every=user_check_custom_every or 0,
                                   user_check_custom_unit=user_check_custom_unit or "")


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
                  install_on: list[str] | None = None, vpn: list[str] | None = None,
                  user_check: str | None = None, user_check_frequency: str | None = None,
                  user_check_confirm: str | None = None, user_check_custom_every: int = 0,
                  user_check_custom_unit: str | None = None) -> dict:
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

    When a create result also has **`partially_allowed: true`**, the destination + service ARE already
    permitted by an existing rule (see **`allowed_by`**: the rule + the narrower field + its values) — just
    not for the broader source/destination/service that was asked. Relay the `answer` verbatim ("Partially —
    already permitted for these sources … just not the one asked"); don't flatten it to a bare "No". If the
    result also has **`assumed_any_field`** (e.g. "source"), the user did not give that field so it was
    evaluated as Any — say so and offer to re-check with a specific value (the `answer` already does this).

    So: when the user leaves source (or destination/service) unspecified, pass "Any" — the answer will tell
    them it assumed Any and invite a specific value. Only assume Any for fields the user truly omitted; if
    they named a source, pass it, and the answer is precise for that source.

    Source/destination default to IP/CIDR/Any; set ``source_kind``/``destination_kind`` to a typed kind
    (domain / access-role / dynamic-object / updatable-object / security-zone) to reason in that identity
    space — e.g. does a host have access to the domain ``alshawwaf.ca`` (source_kind stays ip,
    destination_kind=domain, destination='alshawwaf.ca'). ZERO-TRUST by IDENTITY: resolve an identity phrase
    FIRST — correlate_access_role ("the finance role" → an Identity-Awareness access-role) or correlate_zone
    ("DMZ" → a security-zone) — then pass the returned match as source/destination with
    source_kind/destination_kind = "access-role" / "security-zone". Both are REUSE-ONLY (defined in Identity
    Awareness / topology; the engine never creates them) — if none matches, relay the candidates.

    RESTRICTION COLUMNS (time / content / action limit) take EXACT Check Point object names — resolve a
    natural phrase FIRST, exactly as you would a service with correlate_service:
      • "during work hours" → correlate_time(...) → pass its ``match`` as time_objects=["Work-Hours"].
      • "SQL Queries" / a data type → correlate_content(...) → pass as content=["SQL Queries"] (set
        content_direction up/down/any).
      • a bandwidth cap → correlate_limit(...) → pass as action_limit (a rate object like "Upload_10Mbps";
        a Limit is a RATE, not a volume — there is NO "max 10 GB total" control, so map a volume request to
        an existing rate limit or tell the user it can't be expressed). These objects are REUSE-ONLY (must
        already exist); if correlate returns no match, relay the candidates or say one must be created first.
    Any of these columns makes the request "restricted" → the engine always CREATEs a precise rule ABOVE a
    broad Accept (never a false no_op/widen), so the new condition actually takes effect (first-match).

    ``server_id`` MUST be a REAL server — its numeric id, name, or host from list_management_servers.
    NEVER invent or default it (not "localhost", "127.0.0.1", a hostname, or any guess — a fabricated value
    just fails to resolve). If the user named no management server: call list_management_servers — if exactly
    one exists, use it; if more than one, ASK the user which management server to use. Do not assume."""
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
                     time_objects=time_objects, install_on=install_on, vpn=vpn,
                     user_check=user_check, user_check_frequency=user_check_frequency,
                     user_check_confirm=user_check_confirm, user_check_custom_every=user_check_custom_every,
                     user_check_custom_unit=user_check_custom_unit)
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


@_write_tool
def apply_access(server_id: str, source: str, destination: str, layer: str, service: str | None = None,
                 port: str | None = None, protocol: str = "tcp", application: str | None = None,
                 package: str | None = None, publish: bool = False, ticket_id: str = "",
                 source_kind: str = "ip", destination_kind: str = "ip",
                 action: str = "Accept", inline_layer: str | None = None,
                 action_limit: str | None = None, captive_portal: bool = False,
                 content: list[str] | None = None, content_direction: str = "any",
                 content_negate: bool = False, time_objects: list[str] | None = None,
                 install_on: list[str] | None = None, vpn: list[str] | None = None,
                 user_check: str | None = None, user_check_frequency: str | None = None,
                 user_check_confirm: str | None = None, user_check_custom_every: int = 0,
                 user_check_custom_unit: str | None = None,
                 idempotency_key: str = "") -> dict:
    """APPLY an access request. ``action`` = the rule verdict: Accept (default) / Drop / Reject / Ask /
    Inform / Apply Layer (Apply Layer needs ``inline_layer``). Optional match-gating columns (all REUSE-ONLY
    object names): ``content`` (data-types) + ``content_direction`` (any/up/down) + ``content_negate``;
    ``time_objects`` (time / time-group); ``install_on`` (gateways/targets); ``vpn`` (communities; []=Any).
    Action-settings + UserCheck: ``action_limit`` (bandwidth RATE object, Accept/Ask/Inform) + ``captive_portal``;
    and ``user_check`` — the UserCheck interaction/message object (an Ask/Inform prompt, or a Drop/Reject
    blocked-message page), with ``user_check_frequency`` (once a day | once a week | once a month | custom
    frequency...) + ``user_check_confirm`` (per rule | per category | per application/site | per data type)
    for Ask/Inform, and ``user_check_custom_every`` + ``user_check_custom_unit`` (hours/days/weeks/months)
    when the frequency is custom. The interaction object is reuse-only (must already exist).
    With publish=false it DRY-RUNS (applies inside a session, then discards —
    nothing is committed) — always allowed. With publish=true it COMMITS to the live server — allowed ONLY
    when an admin has enabled the 'mcp_allow_publish' setting; otherwise it's refused (dry-run instead).

    Pass a stable ``idempotency_key`` (one per logical change) when publishing: a retry with the same key
    REPLAYS the first committed result (adds ``idempotent_replay: true``) instead of publishing twice — so an
    agent retry or webhook redelivery can't double-commit. Safe to omit for dry-runs.

    ``server_id`` MUST be a REAL server — its numeric id, name, or host from list_management_servers.
    NEVER invent or default it (not "localhost", "127.0.0.1", a hostname, or any guess — a fabricated value
    just fails to resolve). If the user named no management server: call list_management_servers — if exactly
    one exists, use it; if more than one, ASK the user which management server to use. Do not assume."""
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
                     time_objects=time_objects, install_on=install_on, vpn=vpn,
                     user_check=user_check, user_check_frequency=user_check_frequency,
                     user_check_confirm=user_check_confirm, user_check_custom_every=user_check_custom_every,
                     user_check_custom_unit=user_check_custom_unit)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    # Idempotency AFTER resolving the server + building the request, so the replay key is fingerprinted by
    # the ACTUAL change (server + normalized src/dst/svc/action/layer/columns). A key reused for a DIFFERENT
    # request returns a conflict marker (fail loud) instead of falsely replaying the earlier change's result.
    fp = _apply_fingerprint(ms, req, layer, package) if (idempotency_key and publish) else None
    if idempotency_key and publish:
        from . import idempotency
        cached = idempotency.replay(idempotency_key, fp)
        if cached is not None:
            return cached
    try:
        result = aa.execute(ms, secret, req, layer, package=package, ticket_id=ticket_id, publish=publish)
    except Exception as exc:  # noqa: BLE001 — never surface an uncaught raise as a generic "Internal error";
        logger.exception("apply_access failed (server_id=%s, layer=%r)", server_id, layer)
        return {"ok": False, "applied": False, "published": False, "error": f"{type(exc).__name__}: {exc}"}
    if isinstance(result, dict):
        result.setdefault("autopilot", _autopilot(ms, layer))
    _record_applied(ms, result, req, layer, package, ticket_id)
    if idempotency_key and publish and isinstance(result, dict) and result.get("published"):
        from . import idempotency
        idempotency.remember(idempotency_key, result, fp)
    return result


@_write_tool
def remove_access(server_id: str, source: str, destination: str, layer: str, service: str | None = None,
                  port: str | None = None, protocol: str = "tcp", application: str | None = None,
                  package: str | None = None, publish: bool = False, ticket_id: str = "",
                  source_kind: str = "ip", destination_kind: str = "ip") -> dict:
    """REVOKE an EXISTING access (the inverse of apply_access): use this ONLY for "revoke / remove / take
    away / undo X's access" — it finds the rule granting src->dst:svc and removes it (DISABLE an exact grant,
    or DROP above a broader rule).

    NOT for "block" / "deny" — that is CREATING a Drop rule: use apply_access(action="Drop"). In particular a
    block that shows a message ("block X and show the block page") MUST be apply_access(action="Drop",
    user_check=...) — remove_access has no action / user_check / service=Any and can't attach a message.
    (To block ALL traffic, apply_access with service="Any".)

    Outcomes: no_op = not permitted; review = granted via an opaque/inline/conditional/multi-rule path (won't
    guess a destructive change). With publish=false it DRY-RUNS (validate then discard); publish=true COMMITS,
    allowed ONLY when 'mcp_allow_publish' is enabled.

    ``server_id`` MUST be a REAL server — its numeric id, name, or host from list_management_servers.
    NEVER invent or default it (not "localhost", "127.0.0.1", a hostname, or any guess — a fabricated value
    just fails to resolve). If the user named no management server: call list_management_servers — if exactly
    one exists, use it; if more than one, ASK the user which management server to use. Do not assume."""
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


@_write_tool
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
    from . import change_log
    return {"id": r.id, "at": r.created_at.isoformat() if r.created_at else None, "by": r.created_by,
            "server": r.server_name, "layer": r.layer, "action": r.action, "outcome": r.outcome,
            "summary": r.summary, "ticket_id": r.ticket_id or None, "reverted": bool(r.reverted_at),
            "reverted_at": r.reverted_at.isoformat() if r.reverted_at else None,
            "state": change_log.revert_state(r), "resolution": r.resolution or ""}


def list_changes(limit: int = 20) -> dict:
    """List recent access-automation changes PUBLISHED to live policy (newest first) — each with its id, what
    it did, who/when, and its ``state``: **active** (in effect — revert_change can roll it back), **disabled**
    (the rule is OFF but still in the rulebase — revert_change can FINALIZE it with delete_rule=true or turn
    it back on with reenable=true), or **resolved** (terminal — already undone or deleted). Read-only.
    Dry-runs are never recorded, so everything here actually committed."""
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


@_write_tool
def revert_change(change_id: int, publish: bool = False, disable_instead_of_delete: bool = False,
                  delete_rule: bool = False, reenable: bool = False) -> dict:
    """ROLL BACK or FINALIZE a previously published change by its id (from list_changes). One state machine,
    shared with the portal's change panel — each entry is **active**, **disabled**, or **resolved**:

      * active   --revert_change(id)-->                              resolved.  Replays the recorded inverse
        (delete the rule that was added / re-enable the rule a removal disabled / remove the object that was
        widened in) — surgical, never a full-DB revision rollback.
      * active   --revert_change(id, disable_instead_of_delete=true)--> disabled.  A change that ADDED a rule
        (create / a Drop from a removal) is undone by DISABLING that rule instead of deleting it — the
        gentler, reversible undo: the rule stays in the rulebase greyed out, and the entry stays actionable.
      * disabled --revert_change(id, delete_rule=true)-->             resolved.  FINALIZE: delete the disabled
        rule outright ("get rid of it entirely").
      * disabled --revert_change(id, reenable=true)-->                active or resolved.  Turn the rule back
        ON: an added rule becomes active again (rollable again); re-enabling a rule that a REMOVAL disabled
        restores the original access (terminal).

    Verb routing: "undo / roll back" → plain; "disable it instead / keep it visible" →
    disable_instead_of_delete; "delete the disabled rule / finalize / remove it for good" → delete_rule;
    "turn it back on / re-enable" → reenable. Refuses an action that doesn't fit the entry's current state
    (the error says what applies). With publish=false it DRY-RUNS (validate then discard, nothing recorded);
    publish=true COMMITS, allowed ONLY when an admin has enabled 'mcp_allow_publish'. Objects the change
    created are left in place."""
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
    if delete_rule and reenable:
        return {"ok": False, "error": "pick ONE action: delete_rule (finalize) or reenable (turn back on)"}
    from ..models import utcnow
    from . import change_log
    from . import access_automation as aa
    db = SessionLocal()
    try:
        change = change_log.get(db, int(change_id))
        if change is None:
            return {"ok": False, "error": f"no recorded change with id {change_id}"}
        inv = list(change.inverse_json or [])
        if not inv:
            return {"ok": False, "error": "this change has no recorded inverse — it can't be acted on here"}
        state = change_log.revert_state(change)
        inv0 = inv[0]
        # Decide the action → (ops, disable-added-rules?, the DB state to stamp). MIRRORS the portal panel
        # (routers/access_automation.aa_revert) — same guards, same transitions, one shared state machine.
        if delete_rule:
            if state != "disabled":
                return {"ok": False, "error": f"delete_rule finalizes a DISABLED rule, but change "
                                              f"{change_id} is {state} — "
                        + ("roll it back first (optionally with disable_instead_of_delete=true)"
                           if state == "active" else "it was already resolved")}
            ops = [{"op": "delete-access-rule", "uid": inv0.get("uid"), "layer": inv0.get("layer")}]
            disable_added = False
            new_fields = {"reverted_at": utcnow(), "reverted_by": "mcp", "resolution": "deleted",
                          "revert_error": ""}
        elif reenable:
            if state != "disabled":
                return {"ok": False, "error": f"reenable turns a DISABLED rule back on, but change "
                                              f"{change_id} is {state}"}
            # When the recorded inverse IS a re-enable (a removal/cleanup disable records the full restore —
            # enabled + prior comments/custom-fields), replay it for a faithful undo; an ADDED rule rolled
            # back by disabling records a delete-inverse, so fall back to the minimal enable op there.
            # (Mirrors routers/access_automation.aa_revert.)
            if all(o.get("op") == "set-access-rule" and o.get("enabled") is True for o in inv):
                ops = inv
            else:
                ops = [{"op": "set-access-rule", "uid": inv0.get("uid"), "layer": inv0.get("layer"),
                        "enabled": True}]
            disable_added = False
            # Re-enabling a rule a REMOVAL disabled restores the original access → terminal. Re-enabling an
            # ADDED rule we'd disabled restores the created rule → back to ACTIVE (rollable again).
            new_fields = ({"reverted_at": utcnow(), "reverted_by": "mcp", "resolution": "reverted",
                           "revert_error": ""}
                          if change.outcome == "disable"
                          else {"reverted_at": None, "reverted_by": "mcp", "resolution": "",
                                "revert_error": ""})
        elif disable_instead_of_delete:
            if change.outcome not in ("create", "deny") or state != "active":
                return {"ok": False, "error": "disable_instead_of_delete undoes an ACTIVE change that ADDED "
                                              f"a rule (create/deny), but change {change_id} is "
                                              f"{state} with outcome '{change.outcome}'"}
            ops = inv                            # rewritten to enabled=false by disable_added_rules below
            disable_added = True
            new_fields = {"reverted_at": None, "reverted_by": "mcp", "resolution": "disabled",
                          "revert_error": ""}
        else:
            if state != "active":
                hint = ("it is DISABLED — use delete_rule=true to remove the rule for good, or "
                        "reenable=true to turn it back on" if state == "disabled"
                        else f"it was already resolved at {change.reverted_at.isoformat()}")
                return {"ok": False, "error": f"change {change_id} can't be rolled back: {hint}"}
            ops = inv
            disable_added = False
            new_fields = {"reverted_at": utcnow(), "reverted_by": "mcp", "resolution": "reverted",
                          "revert_error": ""}
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
        # ATOMIC claim BEFORE touching the SMS (only one actor transitions the entry), restore on SMS
        # failure. The stamp happens PRE-publish, so a committed publish can never be left unrecorded by
        # post-publish bookkeeping — the invariant behind the committed-rollback-reported-failed incident.
        cid, summary = change.id, change.summary
        prior = {"reverted_at": change.reverted_at, "reverted_by": change.reverted_by or "",
                 "resolution": change.resolution or "", "revert_error": change.revert_error or ""}
        if publish and not change_log.claim(db, cid, change.resolution or "", new_fields):
            return {"ok": False, "error": f"change {change_id} was just acted on by another session — "
                                          "re-check list_changes"}
        result = aa.revert_execute(ms, secret, ops, publish=publish, disable_added_rules=disable_added)
        if publish and not (result.get("ok") and result.get("reverted")):
            try:
                change_log.restore(db, cid, prior)          # SMS did NOT commit -> release the claim
            except Exception:  # noqa: BLE001
                logger.exception("releasing revert claim for change %s failed", cid)
            if not result.get("ok"):
                try:
                    change_log.mark_revert_failed(db, change_log.get(db, cid), result.get("error", ""))
                except Exception:  # noqa: BLE001 — best-effort error stamp
                    logger.exception("recording revert failure for change %s failed", cid)
        fresh = change_log.get(db, cid)
        return {**result, "change_id": cid, "summary": summary,
                "state": change_log.revert_state(fresh) if fresh is not None else None}
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


def _correlate_object(server_id: str, name: str, resolver_attr: str) -> dict:
    """Shared body for the column-object correlators (time / content / limit): resolve the server, then
    call correlate_objects.<resolver_attr>. Returns {term, match, confidence, candidates, note} — ``match``
    is set ONLY for a confident, UNIQUE hit the apply path will accept, else candidates to choose from."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        db.close()
        return {"error": str(exc)}
    db.close()
    from . import correlate_objects
    from .mgmt_api import MgmtError, read_session
    try:
        with read_session(ms, secret) as s:
            return getattr(correlate_objects, resolver_attr)(s, name)
    except MgmtError as exc:
        return {"error": str(exc)}


def correlate_time(server_id: str, name: str) -> dict:
    """Map a natural time phrase ("work hours", "weekends") to the real Check Point TIME / time-group object
    to use in a rule's Time column, or return candidates ('did you mean'). Call this BEFORE decide_access /
    apply_access whenever a request restricts access to a time window — pass the returned ``match`` as
    time_objects. A time object must already exist on the server (reuse-only); if none matches, tell the user
    which time objects exist (the candidates) or that one must be created in SmartConsole first."""
    return _correlate_object(server_id, name, "resolve_time")


def correlate_content(server_id: str, name: str) -> dict:
    """Map a content phrase ("SQL Queries", "credit card numbers") to the real Check Point DATA-TYPE object
    for a rule's Content column, or return candidates. Call this BEFORE decide_access / apply_access whenever
    a request restricts access by data type / content — pass the returned ``match`` as content=[…]. Data
    types are reuse-only (must exist on the server); Content inspection also requires the Content Awareness
    blade enabled on the gateway."""
    return _correlate_object(server_id, name, "resolve_content")


def _correlate_typed(server_id: str, name: str, kind: str) -> dict:
    """Shared body for the typed-identity correlators (access-role / security-zone): resolve the server,
    then typed_objects.resolve(kind). Returns {term, match, confidence, candidates, note}."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        db.close()
        return {"error": str(exc)}
    db.close()
    from . import typed_objects
    from .mgmt_api import MgmtError, read_session
    try:
        with read_session(ms, secret) as s:
            return typed_objects.resolve(s, kind, name)
    except MgmtError as exc:
        return {"error": str(exc)}


def correlate_user_check(server_id: str, name: str) -> dict:
    """Map a UserCheck phrase ("the blocked message", "company policy") to the real Check Point UserCheck
    interaction object, or return candidates. Pass the returned ``match`` as ``user_check`` on an Ask / Inform
    (the prompt) or a Drop / Reject (the blocked-message page). A LOOSE phrase auto-resolves when it's the
    ONLY UserCheck match (the message is cosmetic, not access-determining, so the user needn't type the exact
    name); if several match, it returns candidates to pick. Reuse-only — defined in SmartConsole (UserCheck);
    if none matches, relay the candidates or say one must be created first."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        db.close()
        return {"error": str(exc)}
    db.close()
    from . import usercheck
    from .mgmt_api import MgmtError, read_session
    try:
        with read_session(ms, secret) as s:
            return usercheck.resolve(s, name)
    except MgmtError as exc:
        return {"error": str(exc)}


def correlate_access_role(server_id: str, name: str) -> dict:
    """Map an identity phrase ("the finance role", "Finance_Users") to the real Check Point ACCESS-ROLE
    object (Identity Awareness), or return candidates. This is the ZERO-TRUST source: pass the returned
    ``match`` as source (with source_kind="access-role") so access follows the user's IDENTITY, not an IP.
    Access-roles are REUSE-ONLY — they're defined in Identity Awareness and the engine never creates one; if
    none matches, relay the candidates or say a role must be created in SmartConsole first."""
    return _correlate_typed(server_id, name, "access-role")


def correlate_zone(server_id: str, name: str) -> dict:
    """Map a zone phrase ("internal zone", "DMZ") to the real Check Point SECURITY-ZONE object (gateway
    topology), or return candidates. Pass the returned ``match`` as source/destination with the matching
    source_kind/destination_kind="security-zone". Security-zones are REUSE-ONLY (defined by interface
    topology); if none matches, relay the candidates or say one must be defined first."""
    return _correlate_typed(server_id, name, "security-zone")


def correlate_limit(server_id: str, name: str) -> dict:
    """Map a bandwidth phrase ("10 Mbps upload", "Upload_10Mbps") to the real Check Point LIMIT object for a
    rule's Action Settings (Accept/Ask/Inform), or return candidates — pass the returned ``match`` as
    action_limit. IMPORTANT: a Limit is a RATE (Mbps/Gbps), NOT a volume/quota — Check Point has no "max 10 GB
    total" control in the Access Policy, so a volume request must be mapped to an existing rate limit or
    declined (say so to the user). Limits are reuse-only (must exist on the server)."""
    return _correlate_object(server_id, name, "resolve_limit")


def correlate_gateway(server_id: str, name: str) -> dict:
    """Map a gateway phrase ("the perimeter gateway", "GW1") to the real Check Point gateway/server object for
    a rule's Install-On column, or return candidates ('did you mean'). Pass the returned ``match`` as
    install_on=[…]. Reuse-only (the gateway exists in the topology); if none matches, relay the candidates."""
    return _correlate_object(server_id, name, "resolve_gateway")


def correlate_vpn(server_id: str, name: str) -> dict:
    """Map a VPN phrase ("the site-to-site community", "All_GwToGw") to the real Check Point VPN community for
    a rule's VPN column, or return candidates. Pass the returned ``match`` as vpn=[…]. Reuse-only (communities
    are defined in the VPN configuration); if none matches, relay the candidates."""
    return _correlate_object(server_id, name, "resolve_vpn")


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


# --- Dynamic Layers (Rail B) — author an access rulebase and push it to a gateway via the Gaia API -------
# These tools target a DYNAMIC LAYER (sk182252) applied out-of-band to a gateway — separate from the SMS
# management access policy the other tools drive. Pushing to a REAL gateway is a commit, gated by the
# dedicated ``mcp_allow_layer_push`` admin toggle (distinct from ``mcp_allow_publish``). dry-run and the
# built-in demo target are always available.
_DL_ACTIONS = ("Accept", "Drop", "Reject", "Ask", "Inform")


def _resolve_layer(db, ref):
    """A DynamicLayer by numeric id OR by name / layer_name (case-insensitive). Raises ValueError that LISTS
    the available layers on no match (so the error tells the agent what to pick)."""
    layer = None
    if isinstance(ref, int) and not isinstance(ref, bool):
        layer = db.get(DynamicLayer, ref)
    elif isinstance(ref, str) and ref.strip().isdigit():
        layer = db.get(DynamicLayer, int(ref.strip()))
    if layer is None and isinstance(ref, str) and ref.strip():
        want = ref.strip().lower()
        rows = db.query(DynamicLayer).all()
        # Prefer an exact portal-NAME match; fall back to the gateway layer_name (which several layers can share).
        layer = (next((L for L in rows if (L.name or "").lower() == want), None)
                 or next((L for L in rows if (L.layer_name or "").lower() == want), None))
    if layer is None:
        avail = "; ".join(f"id {L.id} = {L.name}" for L in db.query(DynamicLayer).all())
        raise ValueError(f"could not resolve dynamic layer “{ref}”. Available — {avail or 'none configured'}. "
                         f"Call list_dynamic_layers and ask the user which one.")
    return layer


def _resolve_gateway(db, ref):
    """A Gateway by numeric id OR by name / host (case-insensitive). Raises ValueError listing the gateways."""
    gw = None
    if isinstance(ref, int) and not isinstance(ref, bool):
        gw = db.get(Gateway, ref)
    elif isinstance(ref, str) and ref.strip().isdigit():
        gw = db.get(Gateway, int(ref.strip()))
    if gw is None and isinstance(ref, str) and ref.strip():
        want = ref.strip().lower()
        rows = db.query(Gateway).all()
        gw = next((g for g in rows if want in ((g.name or "").lower(), (g.host or "").lower())), None)
    if gw is None:
        avail = "; ".join(f"id {g.id} = {g.name} ({g.host})" for g in db.query(Gateway).all())
        raise ValueError(f"could not resolve gateway “{ref}”. Available — {avail or 'none configured'}. "
                         f"Call list_gateways and ask the user which one.")
    return gw


def _rule_count(layer) -> int:
    rb = (layer.content or {}).get("rulebase") or []
    return len(rb) if isinstance(rb, list) else 0


def _layer_object_for(value: str):
    """Map a source/destination token to an inline layer object: an IP -> a host, a CIDR -> a network,
    anything else -> a by-name reference (name, None, None)."""
    import ipaddress
    s = (value or "").strip()
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            dash = str(net.network_address).replace(".", "-").replace(":", "-")
            name = f"n-{dash}-{net.prefixlen}"
            if net.version == 6:
                return name, "networks", {"name": name, "subnet6": str(net.network_address),
                                          "mask-length6": net.prefixlen}
            return name, "networks", {"name": name, "subnet4": str(net.network_address),
                                      "mask-length4": net.prefixlen}
        ip = ipaddress.ip_address(s)
        name = "h-" + str(ip).replace(".", "-").replace(":", "-")
        key = "ipv6-address" if ip.version == 6 else "ip-address"
        return name, "hosts", {"name": name, key: str(ip)}
    except ValueError:
        return s, None, None


def list_gateways() -> dict:
    """The saved Gaia gateways a dynamic layer can be pushed to — returns id, name, host, port for each."""
    db = SessionLocal()
    try:
        rows = db.query(Gateway).all()
        return {"gateways": [{"id": g.id, "name": g.name, "host": g.host, "port": g.port} for g in rows]}
    finally:
        db.close()


def list_dynamic_layers() -> dict:
    """The dynamic layers authored in the portal — id, name, the gateway access-layer name, and rule count.
    A dynamic layer is an access rulebase pushed straight to a gateway via the Gaia API (out-of-band of the
    SMS management policy). Use get_dynamic_layer to read one, add_dynamic_rule to edit, push_dynamic_layer
    to apply."""
    db = SessionLocal()
    try:
        rows = db.query(DynamicLayer).all()
        return {"layers": [{"id": L.id, "name": L.name, "layer_name": L.layer_name,
                            "rules": _rule_count(L)} for L in rows]}
    finally:
        db.close()


def get_dynamic_layer(layer: str) -> dict:
    """Read one dynamic layer (by id or name): its target access-layer name and its current rulebase
    (each rule's name, action, source, destination, service)."""
    db = SessionLocal()
    try:
        L = _resolve_layer(db, layer)
        content = L.content or {}
        rb = content.get("rulebase") or []
        rules = [{"name": r.get("name"), "action": r.get("action"), "source": r.get("source"),
                  "destination": r.get("destination"), "service": r.get("service")}
                 for r in rb if isinstance(r, dict)]
        return {"ok": True, "id": L.id, "name": L.name, "layer_name": L.layer_name,
                "rules": rules, "object_types": list((content.get("objects") or {}).keys())}
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()


@_write_tool
def add_dynamic_rule(layer: str, source: str, destination: str, service: str = "any",
                     action: str = "Accept", name: str = "", position: str = "bottom") -> dict:
    """Add a rule to a dynamic layer's rulebase (this only EDITS the layer — call push_dynamic_layer after to
    apply it to a gateway). ``source``/``destination`` accept an IP, a CIDR, the name of an existing object,
    or 'any'; a bare IP/CIDR is added as an inline host/network object. ``service`` is a service name (e.g.
    https, ssh) or 'any'. ``action``: Accept | Drop | Reject | Ask | Inform. ``position``: 'top' or 'bottom'."""
    act = (action or "Accept").strip().title() if (action or "").strip().lower() in {a.lower() for a in _DL_ACTIONS} else (action or "Accept").strip()
    if act not in _DL_ACTIONS:
        return {"ok": False, "error": f"unsupported action “{action}”. Use one of: {', '.join(_DL_ACTIONS)}."}
    db = SessionLocal()
    try:
        L = _resolve_layer(db, layer)
        content = dict(L.content or {})
        objects = {k: list(v) for k, v in (content.get("objects") or {}).items()}
        rulebase = list(content.get("rulebase") or [])

        def _cell(token):
            name_, kind, obj = _layer_object_for(token)
            if name_ == "any":
                return "any"
            if obj is not None:                       # inline IP/CIDR object — add it once
                lst = objects.setdefault(kind, [])
                if not any(o.get("name") == name_ for o in lst):
                    lst.append(obj)
            return name_

        src = _cell(source)
        dst = _cell(destination)
        svc = (service or "any").strip() or "any"
        rname = (name or "").strip() or f"rule-{len(rulebase) + 1}"
        rule = {"name": rname, "action": act, "track": {"type": "Log"},
                "source": "any" if src == "any" else [src],
                "destination": "any" if dst == "any" else [dst],
                "service": "any" if svc.lower() == "any" else [svc]}
        if position == "top":
            rulebase.insert(0, rule)
        else:
            rulebase.append(rule)
        content["objects"] = objects
        content["rulebase"] = rulebase
        from ..schemas.dynamic_layer import validate_layer_content
        validate_layer_content(content)               # raises ValueError on a malformed result
        L.content = content
        db.commit()
        return {"ok": True, "layer": L.name, "rule": rname, "rules": len(rulebase),
                "note": "rule added to the layer — call push_dynamic_layer to apply it to a gateway."}
    except ValueError as exc:
        db.rollback()
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()


@_write_tool
def remove_dynamic_rule(layer: str, rule: str) -> dict:
    """Remove a rule (by name) from a dynamic layer's rulebase. A layer must keep at least one rule; this
    only EDITS the layer — call push_dynamic_layer after to apply the change to a gateway."""
    db = SessionLocal()
    try:
        L = _resolve_layer(db, layer)
        content = dict(L.content or {})
        rulebase = list(content.get("rulebase") or [])
        want = (rule or "").strip().lower()
        kept = [r for r in rulebase
                if not (isinstance(r, dict) and (r.get("name") or "").lower() == want)]
        if len(kept) == len(rulebase):
            names = ", ".join(r.get("name", "") for r in rulebase if isinstance(r, dict))
            return {"ok": False, "error": f"no rule named “{rule}” in layer “{L.name}”. "
                                          f"Rules: {names or 'none'}."}
        if not kept:
            return {"ok": False, "error": "a dynamic layer must keep at least one rule — removing the last "
                                          "rule isn't allowed. Replace it or edit the layer instead."}
        content["rulebase"] = kept
        from ..schemas.dynamic_layer import validate_layer_content
        validate_layer_content(content)
        L.content = content
        db.commit()
        return {"ok": True, "layer": L.name, "removed": rule, "rules": len(kept)}
    except ValueError as exc:
        db.rollback()
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()


@_write_tool
def push_dynamic_layer(layer: str, gateway: str = "", dry_run: bool = False,
                       idempotency_key: str = "") -> dict:
    """Push a dynamic layer to a gateway via the Gaia API (set-dynamic-content), out-of-band of SmartConsole.
    ``gateway``: the saved gateway's name / id / host; leave blank (or 'mock') to push to the built-in demo
    target. ``dry_run=True`` validates without applying (always allowed). A real-gateway push (dry_run=False)
    is an admin-gated COMMIT — it requires the 'Let the MCP agent push dynamic layers to gateways' setting
    (mcp_allow_layer_push). NOTE: a push REPLACES the layer's entire rulebase on the gateway — if the layer may
    already hold policy pushed outside this portal, call fetch_dynamic_layer first so you don't wipe it.

    Pass a stable ``idempotency_key`` (one per logical push) for a real-gateway push: a retry with the same key
    REPLAYS the first successful result (adds ``idempotent_replay: true``) instead of pushing again. Returns
    the change summary + task id."""
    use_mock = (not (gateway or "").strip()) or gateway.strip().lower() == "mock"
    push_fp = None
    db = SessionLocal()
    try:
        try:
            L = _resolve_layer(db, layer)
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "autopilot": _autopilot()}
        # Fingerprint the push by target gateway + layer identity + the exact content being pushed, so a
        # reused idempotency_key that now targets a different gateway/layer, or the same layer with CHANGED
        # content, conflicts instead of silently replaying the earlier push's result.
        if idempotency_key and not dry_run and not use_mock:
            push_fp = hashlib.sha256(json.dumps(
                {"target": (gateway or "").strip().lower(), "layer_id": L.id,
                 "content": L.content or {}}, sort_keys=True, default=str).encode()).hexdigest()
            from . import idempotency
            cached = idempotency.replay(idempotency_key, push_fp)
            if cached is not None:
                return cached
        if not use_mock and not dry_run:
            from . import app_settings
            try:
                allowed = bool(app_settings.get("mcp_allow_layer_push"))
            except Exception:  # noqa: BLE001
                allowed = False
            if not allowed:
                return {"ok": False, "pushed": False, "autopilot": _autopilot(),
                        "error": "pushing a dynamic layer to a live gateway is disabled — an admin must enable "
                                 "'Let the MCP agent push dynamic layers to gateways' in Settings → MCP / agent "
                                 "(a separate toggle from the SMS publish gate). Re-run with dry_run=true to "
                                 "validate, or gateway='mock' for the demo target."}
        layer_id, layer_name = L.id, L.name
        if use_mock:
            target_name = "mock"
            kw = {"target": "mock"}
        else:
            try:
                gw = _resolve_gateway(db, gateway)
            except ValueError as exc:
                return {"ok": False, "error": str(exc), "autopilot": _autopilot()}
            if not gw.username:
                return {"ok": False, "autopilot": _autopilot(),
                        "error": f"gateway “{gw.name}” has no username — set it on the gateway profile."}
            from . import gateway_creds
            pw = gateway_creds.get_password(db, gw)
            if not pw:
                return {"ok": False, "autopilot": _autopilot(),
                        "error": f"gateway “{gw.name}” has no stored password — set one on the gateway profile."}
            try:
                from .gaia_client import ensure_pinned
                ensure_pinned(db, gw)                 # trust-on-first-use before the TLS handshake
            except Exception:  # noqa: BLE001
                pass
            target_name = gw.name
            kw = {"target": "gateway", "gateway_host": gw.host, "gateway_port": gw.port,
                  "user": gw.username, "password": pw, "cert_pem": gw.cert_pem or None}
    finally:
        db.close()

    import time
    from . import apply_runner
    try:
        pid = apply_runner.start_apply(layer_id=layer_id, dry_run=dry_run, **kw)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"could not start the push: {exc}", "autopilot": _autopilot()}
    prog = None
    for _ in range(150):                              # ~45s ceiling (login + task poll + logout finishes well under)
        prog = apply_runner.get_progress(pid)
        if prog and prog.get("status") in ("succeeded", "failed"):
            break
        time.sleep(0.3)
    if not prog:
        return {"ok": False, "error": "push status was unavailable", "autopilot": _autopilot()}
    status = prog.get("status")
    ok = status == "succeeded"
    result = {"ok": ok, "pushed": ok and not dry_run and not use_mock, "dry_run": dry_run,
              "target": target_name, "layer": layer_name, "status": status,
              "summary": prog.get("summary"), "task_id": prog.get("task_id"),
              "error": None if ok else (prog.get("error") or "push failed"), "autopilot": _autopilot()}
    if idempotency_key and result["pushed"]:
        from . import idempotency
        idempotency.remember(idempotency_key, result, push_fp)
    if result["pushed"]:
        try:                                          # governance audit — metadata only, never breaks the push
            from . import audit
            audit.emit(f"agent · pushed dynamic layer “{layer_name}” to gateway {target_name}", actor="agent")
        except Exception:  # noqa: BLE001
            logger.exception("audit emit failed for push_dynamic_layer")
    return result


def fetch_dynamic_layer(gateway: str, layer_name: str = "") -> dict:
    """Pull the dynamic-layer content CURRENTLY on a gateway — live, via the Gaia API (show-dynamic-layers +
    show-dynamic-layer). Use this to see what's ACTUALLY deployed, including policy pushed to the layer over the
    API outside this portal. Read-only (no gate). ``gateway`` = a saved gateway's name / id / host; ``layer_name``
    optionally filters to one layer. IMPORTANT: push_dynamic_layer REPLACES a layer's whole rulebase, so fetch
    first when a layer may hold rules you didn't author here — otherwise a push wipes them."""
    db = SessionLocal()
    try:
        try:
            gw = _resolve_gateway(db, gateway)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if not gw.username:
            return {"ok": False, "error": f"gateway “{gw.name}” has no username — set it on the gateway profile."}
        from . import gateway_creds
        pw = gateway_creds.get_password(db, gw)
        if not pw:
            return {"ok": False,
                    "error": f"gateway “{gw.name}” has no stored password — set one on the gateway profile."}
        try:
            from .gaia_client import ensure_pinned
            ensure_pinned(db, gw)                        # trust-on-first-use before the TLS handshake
        except Exception:  # noqa: BLE001
            pass
        from . import apply_runner
        data = apply_runner.fetch_dynamic_content(target="gateway", db=db, owner_id=gw.owner_id,
                                                  host=gw.host, port=gw.port, user=gw.username,
                                                  password=pw, cert_pem=gw.cert_pem or None, gateway_id=gw.id)
        gw_name = gw.name
    finally:
        db.close()
    if not data.get("ok"):
        return {"ok": False, "gateway": gateway, "error": data.get("error") or "fetch failed"}
    want = (layer_name or "").strip().lower()
    layers = []
    for L in data.get("layers", []):
        if want and (L.get("name") or "").lower() != want:
            continue
        rb = L.get("rulebase") or []
        rules = [{"name": r.get("name"), "action": r.get("action"), "source": r.get("source"),
                  "destination": r.get("destination"), "service": r.get("service")}
                 for r in rb if isinstance(r, dict)]
        layers.append({"name": L.get("name"), "rules": rules,
                       "object_types": list((L.get("objects") or {}).keys()),
                       "referenced": L.get("referenced") or []})
    return {"ok": True, "gateway": gw_name, "layers": layers}


@_write_tool
def import_dynamic_layer(gateway: str, layer_name: str = "", into_layer: str = "") -> dict:
    """Fetch a gateway's LIVE dynamic layer and SAVE it into a portal dynamic layer (create or overwrite) — so
    the next add_dynamic_rule + push_dynamic_layer operate on the REAL current state and the push (a REPLACE)
    keeps the rules that were already there. Use this to safely APPEND to a layer that holds policy pushed
    outside this portal: import → add_dynamic_rule → push (the push then replaces with the live rules PLUS your
    additions, wiping nothing). Writes to the portal only — it does NOT change the gateway. ``gateway`` = a saved
    gateway's name / id / host; ``layer_name`` = which live layer to import (required if the gateway has several);
    ``into_layer`` = the portal layer name to write into (default: the live layer's name)."""
    db = SessionLocal()
    try:
        try:
            gw = _resolve_gateway(db, gateway)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if not gw.username:
            return {"ok": False, "error": f"gateway “{gw.name}” has no username — set it on the gateway profile."}
        from . import gateway_creds
        pw = gateway_creds.get_password(db, gw)
        if not pw:
            return {"ok": False,
                    "error": f"gateway “{gw.name}” has no stored password — set one on the gateway profile."}
        try:
            from .gaia_client import ensure_pinned
            ensure_pinned(db, gw)
        except Exception:  # noqa: BLE001
            pass
        from . import apply_runner
        data = apply_runner.fetch_dynamic_content(target="gateway", db=db, owner_id=gw.owner_id,
                                                  host=gw.host, port=gw.port, user=gw.username,
                                                  password=pw, cert_pem=gw.cert_pem or None, gateway_id=gw.id)
        if not data.get("ok"):
            return {"ok": False, "gateway": gw.name, "error": data.get("error") or "fetch failed"}
        live = data.get("layers") or []
        want = (layer_name or "").strip().lower()
        match = [L for L in live if (L.get("name") or "").lower() == want] if want else live
        if not match:
            names = ", ".join(L.get("name", "") for L in live)
            return {"ok": False, "error": f"no dynamic layer “{layer_name or '(any)'}” on {gw.name}. "
                                          f"On the gateway: {names or 'none'}."}
        if len(match) > 1:
            names = ", ".join(L.get("name", "") for L in match)
            return {"ok": False, "error": f"the gateway has several dynamic layers ({names}); "
                                          f"pass layer_name to choose which to import."}
        src = match[0]
        gw_layer_name = src.get("name") or "dynamic_layer"
        portal_name = (into_layer or "").strip() or gw_layer_name
        content = {"operation": "replace", "objects": src.get("objects") or {},
                   "rulebase": src.get("rulebase") or []}
        from ..schemas.dynamic_layer import validate_layer_content
        validate_layer_content(content)                  # raises ValueError (e.g. a live layer with no rules)
        existing = next((L for L in db.query(DynamicLayer).all()
                         if (L.name or "").lower() == portal_name.lower()), None)
        if existing is not None:
            existing.content = content
            existing.layer_name = gw_layer_name
            created, lid, lname = False, existing.id, existing.name
        else:
            import secrets as _secrets
            row = DynamicLayer(token=_secrets.token_urlsafe(24), name=portal_name,
                               layer_name=gw_layer_name, owner_id=gw.owner_id, content=content)
            db.add(row)
            db.flush()
            created, lid, lname = True, row.id, row.name
        db.commit()
        return {"ok": True, "gateway": gw.name, "layer": lname, "layer_id": lid, "created": created,
                "rules": len(content["rulebase"]),
                "note": "imported the gateway's live layer into the portal — add_dynamic_rule then "
                        "push_dynamic_layer now replaces with these rules PLUS your edits (nothing wiped)."}
    except ValueError as exc:
        db.rollback()
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()
