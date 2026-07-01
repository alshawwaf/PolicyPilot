"""Roles & granular permissions (RBAC) — the single source of truth for "who can do what".

The model (chosen with the SE): every account is either an **Administrator** (implicitly holds every
permission, forever) or a **Standard** user carrying individual capability flags. "View" is implicit for
any *active* account — signing in is the view grant — so there is no ``perm_view``. A non-active account
(``pending`` awaiting approval, or ``disabled``) can't authenticate at all, so it holds no permission.

Enforcement is centralised here and applied at every mutating chokepoint (publish, apply, export, user
management, settings). UI templates call :func:`effective` to hide/disable controls the user can't use, so
the UI and the server never disagree.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from ..security import get_user_or_none

# --- Capability keys (the granular permissions a standard user can be granted) --------------------------
PREVIEW = "preview"            # run access decisions / previews (read-only reasoning)
APPLY = "apply"               # stage / dry-run an access change against the SMS session
PUBLISH = "publish"           # publish a change to the management server (irreversible)
EXPORT = "export"             # generate IaC (Terraform/Ansible/clish) + Gaia config exports
MANAGE_USERS = "manage_users"  # create / approve / edit / reset / disable other users
SETTINGS = "settings"         # change portal settings + secrets (admin-only; not grantable to standard)

# The five grantable-to-standard capabilities, in display order, with a label + one-line description.
GRANTABLE: list[tuple[str, str, str]] = [
    (PREVIEW, "Preview decisions", "Ask the engine whether access is allowed and see the reasoning — read-only."),
    (APPLY, "Apply changes", "Stage and dry-run a change (build objects/rules) against the management session."),
    (PUBLISH, "Publish to management", "Commit staged changes to the Security Management Server — irreversible."),
    (EXPORT, "Export IaC / Gaia", "Generate Terraform / Ansible / clish for policy and Gaia OS configuration."),
    (MANAGE_USERS, "Manage users", "Create, approve, edit, reset and disable other user accounts."),
]
_LABELS = {k: lbl for k, lbl, _d in GRANTABLE}
_LABELS[SETTINGS] = "Change settings"


def label(perm: str) -> str:
    return _LABELS.get(perm, perm)


# --- Predicates -----------------------------------------------------------------------------------------
def is_active(user: User | None) -> bool:
    return bool(user) and (getattr(user, "status", "active") or "active") == "active"


def is_admin(user: User | None) -> bool:
    return bool(user) and bool(getattr(user, "is_admin", False)) and is_active(user)


def can(user: User | None, perm: str) -> bool:
    """True iff *user* may do *perm*. Admins can do anything; ``settings`` is admin-only; every other
    capability falls back to the standard user's ``perm_<key>`` flag. Inactive accounts can do nothing.
    A user still on a temporary password (``must_change_password``) holds NO capability until they change
    it — so the forced-change control actually gates action, not just a login redirect (view/account stay
    reachable because those don't route through ``can``)."""
    if not is_active(user):
        return False
    if getattr(user, "must_change_password", False):
        return False
    if getattr(user, "is_admin", False):
        return True
    if perm == SETTINGS:            # portal settings + secrets are administrator-only, never grantable
        return False
    return bool(getattr(user, f"perm_{perm}", False))


def effective(user: User | None) -> dict:
    """The full capability map for a user — consumed by templates to show/hide controls and by the Account
    page's "My access" card. Keys are every capability plus ``admin``/``view``."""
    out = {p: can(user, p) for p in (PREVIEW, APPLY, PUBLISH, EXPORT, MANAGE_USERS, SETTINGS)}
    out["admin"] = is_admin(user)
    out["view"] = is_active(user)
    return out


# --- FastAPI dependencies -------------------------------------------------------------------------------
class PermissionError403(HTTPException):
    def __init__(self, perm: str):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN,
                         detail=f"You don't have permission to {label(perm).lower()}.")


def require(perm: str):
    """Dependency factory for JSON/API endpoints: 401 if not signed in, 403 if lacking *perm*.
    Returns the current :class:`User` so the handler can use it."""
    def _dep(request: Request, db: Session = Depends(get_db)) -> User:
        user = get_user_or_none(request, db)
        if user is None or not is_active(user):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        if not can(user, perm):
            raise PermissionError403(perm)
        return user
    return _dep


require_admin = require(SETTINGS)          # SETTINGS is admin-only, so this is an "admin required" guard
require_manage_users = require(MANAGE_USERS)
