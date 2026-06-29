"""Audit + rollback store for access-automation changes PUBLISHED to a live policy.

``record()`` is called by the apply / remove surfaces (UI router, ServiceNow webhook, MCP tools) AFTER a
successful publish. It saves the precomputed INVERSE op(s) the engine emitted, so ``revert()`` can surgically
undo exactly that one change in a single publish — no full-DB revision rollback, no touching the rest of the
policy. Dry-runs (publish=false) are never recorded: nothing was committed, so there is nothing to roll back.

Objects a change created (hosts / networks / services) are intentionally NOT deleted on revert — by then they
may be referenced by other rules, and removing them is a separate, riskier action — only the rule change is
undone (delete the added rule / re-enable the disabled rule / remove the widened object from the cell)."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AppliedChange


def _summary(action: str, outcome: str, req: dict) -> str:
    """A human one-liner for the history list, e.g. 'create: allow 10.1.2.250 -> Facebook'."""
    if outcome == "amend":                                   # a metadata edit (name/comment/tags)
        changed = req.get("_amend") or {}
        parts = [(f"name=“{v}”" if k == "name" else f"{k}={v}") for k, v in changed.items()]
        return "edit rule (" + ", ".join(parts) + ")" if parts else "edit rule"
    src = req.get("source") or "?"
    app = req.get("application")
    svc = req.get("service") or (f"{req.get('protocol', 'tcp')}/{req.get('port')}" if req.get("port") else None)
    dst = req.get("destination") or "Any"
    target = app or (f"{dst}:{svc}" if svc else dst)
    verb = {"create": "allow", "widen": "widen-allow", "disable": "revoke", "deny": "revoke"}.get(outcome, outcome)
    return f"{verb} {src} -> {target}"


def snapshot_request(req) -> dict:
    """Plain-data view of an AccessRequest, for the webhook / MCP surfaces (they hold the request OBJECT,
    not the raw form fields). Duck-typed — no engine import."""
    ip_src = getattr(req, "src_kind", "ip") == "ip"
    ip_dst = getattr(req, "dst_kind", "ip") == "ip"
    src = ", ".join(getattr(req, "src_cidrs", []) or []) if ip_src else getattr(req, "src_value", "")
    dst = ", ".join(getattr(req, "dst_cidrs", []) or []) if ip_dst else getattr(req, "dst_value", "")
    return {"source": src or "?", "destination": dst or "Any",
            "protocol": getattr(req, "protocol", "tcp"), "port": getattr(req, "ports", ""),
            "service": getattr(req, "service", None), "application": getattr(req, "application", None),
            "source_kind": getattr(req, "src_kind", "ip"), "destination_kind": getattr(req, "dst_kind", "ip"),
            # full-column support: preserve the verdict + match-gating columns so re-apply reconstructs the rule
            "action": getattr(req, "action", "Accept"), "inline_layer": getattr(req, "inline_layer", ""),
            "action_settings_limit": getattr(req, "action_settings_limit", ""),
            "action_settings_captive_portal": getattr(req, "action_settings_captive_portal", False),
            "content": getattr(req, "content", None), "content_direction": getattr(req, "content_direction", "any"),
            "content_negate": getattr(req, "content_negate", False),
            "time_objects": getattr(req, "time_objects", []), "install_on": getattr(req, "install_on", []),
            "vpn": getattr(req, "vpn", None)}


def record(db: Session, *, server, result: dict, request: dict, layer: str,
           package: Optional[str] = None, ticket_id: str = "", actor: str = "") -> Optional[AppliedChange]:
    """Persist a PUBLISHED change so it can be rolled back. No-op (returns None) unless the change actually
    COMMITTED something (published AND applied) — never dry-runs, no-ops, or reviews. A committed change with
    NO inverse (rare: the SMS returned no uid for an added rule) is STILL recorded for audit, just flagged
    non-revertable (empty inverse_json) rather than vanishing silently. ``request`` is the plain request tuple
    (display); ``result`` is the engine's return dict (``outcome``, ``inverse``, resolved object names)."""
    if not (result.get("ok") and result.get("published") and result.get("applied")):
        return None
    outcome = result.get("outcome", "")
    action = result.get("action", "apply")           # remove_execute stamps action="remove"; apply omits it
    objs = [o for o in (result.get("source_object"), result.get("destination_object"),
                        result.get("service_object"), result.get("widen_object")) if o]
    row = AppliedChange(
        created_by=actor or "",
        server_id=getattr(server, "id", None),
        server_name=getattr(server, "name", "") or "",
        layer=layer or "",
        package=package,
        action=action,
        outcome=outcome,
        summary=_summary(action, outcome, request),
        ticket_id=(ticket_id or "").strip(),
        request_json=request,
        inverse_json=list(result.get("inverse") or []),
        objects_json=objs,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def recent(db: Session, limit: int = 50) -> list[AppliedChange]:
    """Most-recent changes first (the history list / 'undo last' is just the first un-reverted row)."""
    return list(db.scalars(select(AppliedChange).order_by(AppliedChange.created_at.desc()).limit(limit)))


def recent_for_server(db: Session, server_id: int, limit: int = 25) -> list[AppliedChange]:
    """Most-recent changes first for ONE management server (the per-server access-automation page panel)."""
    return list(db.scalars(select(AppliedChange).where(AppliedChange.server_id == server_id)
                           .order_by(AppliedChange.created_at.desc()).limit(limit)))


def get(db: Session, change_id: int) -> Optional[AppliedChange]:
    return db.get(AppliedChange, change_id)


def _safe_commit(db: Session) -> bool:
    """Commit best-effort — a bookkeeping write must NEVER turn an already-committed SMS revert into a
    reported failure. Rolls back + logs on error; returns whether it stuck."""
    try:
        db.commit()
        return True
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger("dcsim.change_log").exception("change-log status write failed")
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return False


def mark_reverted(db: Session, change: AppliedChange, actor: str = "", resolution: str = "reverted") -> None:
    """Close a change: ``resolution`` is 'reverted' (the inverse was applied — the normal rollback) or
    'deleted' (a DISABLEd rule was then deleted outright — the removal finalized, not undone). Both stamp
    the resolved-at/by; the kind drives the panel's wording (↩ rolled back vs 🗑 rule deleted)."""
    change.reverted_at = dt.datetime.now(dt.timezone.utc)
    change.reverted_by = actor or ""
    change.revert_error = ""
    change.resolution = resolution
    _safe_commit(db)


def mark_revert_failed(db: Session, change: AppliedChange, error: str) -> None:
    change.revert_error = (error or "")[:2000]
    _safe_commit(db)


def delete_entry(db: Session, change: AppliedChange) -> None:
    """Remove ONE audit/rollback record from the list. Pure bookkeeping — never touches live policy. Once
    gone, that change can no longer be rolled back from the panel (it's a manual list-management action)."""
    db.delete(change)
    _safe_commit(db)


def clear_resolved(db: Session, server_id: int) -> int:
    """Bulk-remove the RESOLVED audit records for a server (rolled back or disabled-rule-deleted) — the done
    ones — leaving open/failed entries (still actionable) in place. Returns how many were removed."""
    rows = list(db.scalars(select(AppliedChange).where(
        AppliedChange.server_id == server_id, AppliedChange.reverted_at.is_not(None))))
    for r in rows:
        db.delete(r)
    _safe_commit(db)
    return len(rows)
