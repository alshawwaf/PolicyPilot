"""Governance audit trail for committed changes.

After every COMMITTED change — an agent/REST/webhook publish to a live SMS (Rail A) or a real dynamic-layer
push to a gateway (Rail B) — ``emit()`` raises a governance event: (1) an in-app notification to every portal
user (the audit trail in the header bell) and (2) a best-effort POST to an admin-configured outbound webhook
(Slack / Teams / ITSM). Both are opt-in-safe: notifications default ON; the webhook fires only when a URL is
set. The event carries METADATA ONLY (actor, action, target, ticket) — never rule payloads or customer data.

Best-effort + fire-and-forget end to end: it opens its OWN DB session (so it never touches the caller's
transaction) and posts the webhook on a daemon thread (so network latency never blocks the agent's result).
An audit failure is logged and swallowed — it must never turn a successful policy change into a reported error.
"""
from __future__ import annotations

import logging
import threading

from sqlalchemy import select

from ..db import SessionLocal
from ..models import User
from . import app_settings, notifications

log = logging.getLogger("policypilot.audit")


def emit(summary: str, *, actor: str = "agent", kind: str = "info") -> None:
    """Raise a governance event for a committed change. ``summary`` is metadata only."""
    summary = (summary or "").strip()
    if not summary:
        return
    _notify_in_app(summary, kind)
    _post_webhook(summary, actor)


def _notify_in_app(summary: str, kind: str) -> None:
    try:
        if not app_settings.get("audit_notify"):
            return
    except Exception:  # noqa: BLE001
        return
    try:
        db = SessionLocal()
        try:
            for uid in db.scalars(select(User.id)).all():
                notifications.add(db, uid, "Audit · " + summary, kind=kind)
        finally:
            db.close()
    except Exception:  # noqa: BLE001 — audit must never break the caller
        log.exception("audit in-app notification failed")


def _post_webhook(summary: str, actor: str) -> None:
    try:
        url = (app_settings.get_secret_or_env("audit_webhook_url", "") or "").strip()
    except Exception:  # noqa: BLE001
        url = ""
    if not url:
        return
    payload = {"text": f"PolicyPilot audit · {summary}", "actor": actor or "agent",
               "source": "PolicyPilot", "event": "policy_change"}

    def _send():
        try:
            import httpx
            with httpx.Client(timeout=8.0) as c:      # verify=True by default — TLS always verified
                c.post(url, json=payload)
        except Exception:  # noqa: BLE001 — outbound audit is best-effort
            log.warning("audit webhook POST failed", exc_info=True)

    threading.Thread(target=_send, daemon=True).start()
