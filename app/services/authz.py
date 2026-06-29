"""Request-scoped authorization capability — currently just "may this caller write?".

An API key carries a ``can_write`` capability (see models.ApiKey). The auth layer that recognises the key
(the MCP bearer guard, the REST dependency, the webhook check) sets this contextvar for the duration of the
request; the write tools in ``services.mcp_tools`` consult it. A contextvar (not a global) so concurrent
requests can't see each other's capability, and it's copied into any child task the request spawns.

Default is True (writes allowed) so any path that doesn't set it — e.g. the standalone ``serve()`` mode, or
a direct in-process call — behaves exactly as before. A read-only key flips it to False, and the write tools
then refuse (the live publish/push gates still apply on top of this, independently)."""
from __future__ import annotations

import contextvars

_can_write: contextvars.ContextVar[bool] = contextvars.ContextVar("policypilot_can_write", default=True)


def set_can_write(value: bool):
    """Set the capability for this context; returns a token to pass to :func:`reset_can_write`."""
    return _can_write.set(bool(value))


def reset_can_write(token) -> None:
    """Restore the capability the matching :func:`set_can_write` replaced (best-effort)."""
    try:
        _can_write.reset(token)
    except (ValueError, LookupError):
        pass


def can_write() -> bool:
    """True if the current caller may perform write operations."""
    return _can_write.get()
