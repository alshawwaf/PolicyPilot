"""Outbound email via the admin-configured SMTP settings (Settings → Email (SMTP)).

Used for the self-service "Forgot password?" flow. Everything is optional: until an SMTP host is set,
:func:`is_configured` is False and the caller falls back to administrator-driven password resets. TLS is
mandatory for authenticated submission (STARTTLS or implicit SSL) — org policy forbids disabling it, and
we never send credentials over an unencrypted channel.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from . import app_settings

_log = logging.getLogger("policypilot.mailer")


def is_configured() -> bool:
    """True when enough SMTP settings are present to attempt a send (a host at minimum)."""
    return bool((app_settings.get("smtp_host") or "").strip())


def _from() -> tuple[str, str]:
    addr = (app_settings.get("smtp_from") or "").strip() or (app_settings.get("smtp_username") or "").strip()
    name = (app_settings.get("smtp_from_name") or "PolicyPilot").strip()
    return name, addr


def send(to: str, subject: str, body: str) -> tuple[bool, str]:
    """Send a plain-text email. Returns (ok, detail). Never raises — a mail failure must degrade to the
    admin-reset path, not 500 the request. Detail is a short, non-sensitive reason on failure."""
    to = (to or "").strip()
    if not is_configured():
        return False, "SMTP is not configured."
    if not to or "@" not in to:
        return False, "No valid recipient address."

    host = (app_settings.get("smtp_host") or "").strip()
    port = int(app_settings.get("smtp_port") or 587)
    security = (app_settings.get("smtp_security") or "starttls").strip()
    username = (app_settings.get("smtp_username") or "").strip()
    password = app_settings.get_secret("smtp_password")
    from_name, from_addr = _from()
    if not from_addr:
        return False, "No From address (set smtp_from or smtp_username)."

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((from_name, from_addr))
    msg["To"] = to
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=from_addr.split("@")[-1] or None)
    msg.set_content(body)

    try:
        ctx = ssl.create_default_context()          # verifies the server cert; TLS never disabled
        if security == "ssl":
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as s:
                if username:
                    s.login(username, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.ehlo()
                if security != "none":
                    s.starttls(context=ctx)         # upgrade to TLS before auth
                    s.ehlo()
                if username:
                    s.login(username, password)
                s.send_message(msg)
        return True, "sent"
    except Exception as exc:  # noqa: BLE001 — degrade gracefully; report a short reason, no secrets
        _log.warning("mailer.send to <redacted> failed: %s", exc.__class__.__name__)
        return False, f"Mail send failed ({exc.__class__.__name__})."
