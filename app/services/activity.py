"""Write ActivityLog entries (fire-and-forget so requests aren't delayed) with secret redaction."""
import threading

from ..db import SessionLocal
from ..models import ActivityLog

# Headers that must never be logged in the clear. Includes the machine-endpoint auth headers:
# x-dcsim-token (the ticketing webhook key / shared token, which can drive policy publish).
SENSITIVE_HEADERS = {"authorization", "x-chkp-sid", "cookie", "set-cookie", "proxy-authorization",
                     "x-dcsim-token"}
# Any body/field key whose name CONTAINS one of these is redacted (covers gw_pass, basic_pass,
# auth_header_value, password, x-chkp-sid/sid, secrets/tokens, etc. across JSON and form bodies).
SENSITIVE_SUBSTRINGS = ("password", "passwd", "pwd", "pass", "secret", "token",
                        "credential", "sid", "auth_header_value", "private")


def _secret_setting_keys() -> set:
    """Exact keys of every registered "secret" Setting — so a secret form field is redacted even if its
    name doesn't contain one of the substrings above (defense-in-depth against a future rename)."""
    try:
        from . import app_settings
        return {s.key.lower() for s in app_settings.secret_settings()}
    except Exception:  # noqa: BLE001 — redaction must never crash the log path
        return set()


def _is_sensitive(key: str) -> bool:
    k = str(key).lower()
    return any(s in k for s in SENSITIVE_SUBSTRINGS) or k in _secret_setting_keys()


def redact_headers(headers: dict) -> dict:
    return {k: ("(masked)" if k.lower() in SENSITIVE_HEADERS else v) for k, v in headers.items()}


def redact_body(value):
    if isinstance(value, dict):
        return {k: ("***" if _is_sensitive(k) else redact_body(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_body(v) for v in value]
    return value


def write_activity(**fields) -> None:
    def _write():
        db = SessionLocal()
        try:
            db.add(ActivityLog(**fields))
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    threading.Thread(target=_write, daemon=True).start()
