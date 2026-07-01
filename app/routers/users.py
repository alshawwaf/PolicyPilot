"""Users & Groups — the admin app for multi-user + RBAC (create / approve / edit / reset / disable).

Every route requires the ``manage_users`` capability (admins always have it). Standard managers may run
day-to-day user administration but CANNOT create or elevate administrators, nor grant the manage-users
capability — only a full administrator can mint another privileged account (no privilege escalation).
Structural safety rails: the configured admin username is protected, you can't disable/delete yourself,
and the last active administrator can never be removed or demoted.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from pathlib import Path

from ..config import get_settings
from ..db import get_db
from ..models import User, utcnow
from ..security import get_user_or_none, hash_password, password_strength_error, username_error
from ..services import mailer, permissions

router = APIRouter(include_in_schema=False)
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _flash(request: Request, text: str, kind: str = "success") -> None:
    request.session["flash"] = {"text": (text or "")[:800], "type": kind}


# Server-side, memory-only, single-read store for the just-issued temporary password. The plaintext must
# NOT go into the session cookie — Starlette signs but does NOT encrypt it, so a cookie-stored secret would
# leave the server in base64 cleartext. Instead we stash the plaintext here and put only an opaque ref in
# the session; the next GET /users pops + shows it once. Single-worker deploy → one process, so this dict
# is shared across requests. Bounded so an abandoned flow can't grow it unbounded.
_ONE_TIME_SECRETS: "dict[str, dict]" = {}
_ONE_TIME_CAP = 64


def _stash_secret(request: Request, payload: dict) -> None:
    ref = secrets.token_urlsafe(12)
    if len(_ONE_TIME_SECRETS) >= _ONE_TIME_CAP:
        _ONE_TIME_SECRETS.pop(next(iter(_ONE_TIME_SECRETS)), None)   # evict oldest (FIFO)
    _ONE_TIME_SECRETS[ref] = payload
    request.session["reset_ref"] = ref


def _pop_secret(request: Request) -> dict | None:
    ref = request.session.pop("reset_ref", None)
    return _ONE_TIME_SECRETS.pop(ref, None) if ref else None


def _require_manager(request: Request, db: Session):
    """(user, None) when the caller may manage users, else (None, redirect). Managers reach the app;
    anyone else is bounced to the desktop with a message."""
    user = get_user_or_none(request, db)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    if not permissions.can(user, permissions.MANAGE_USERS):
        _flash(request, "You don't have permission to manage users.", "error")
        return None, RedirectResponse("/", status_code=303)
    return user, None


def _active_admin_count(db: Session, *, exclude: int | None = None) -> int:
    q = select(func.count()).select_from(User).where(User.is_admin.is_(True), User.status == "active")
    if exclude is not None:
        q = q.where(User.id != exclude)
    return db.scalar(q) or 0


def _commit_unless_orphans_admins(db: Session) -> bool:
    """Commit the pending change, but FLUSH first and abort (rollback) if it would leave zero active
    administrators. The pre-checks catch the sequential case; this transaction-time re-check closes the
    check-then-act race between a concurrent demote (update) and delete — the second committer flushes its
    change, re-counts, sees the first's committed change and backs out instead of orphaning admin access."""
    db.flush()
    if _active_admin_count(db) == 0:
        db.rollback()
        return False
    db.commit()
    return True


def _is_protected_admin(user: User) -> bool:
    """The env-configured admin username is structurally protected (can't be demoted/disabled/deleted) so
    a portal can never be locked out of its own administration."""
    return user.username == get_settings().admin_username


def _temp_password() -> str:
    """A strong random temp password that satisfies the strength policy (used for admin-set passwords)."""
    while True:
        pw = "Pilot-" + secrets.token_urlsafe(8)
        if not password_strength_error(pw):
            return pw


def _parse_perms(form: dict) -> dict:
    """Read the granular permission checkboxes off a submitted form."""
    return {f"perm_{k}": (form.get(f"perm_{k}") is not None) for k, _l, _d in permissions.GRANTABLE}


async def _form(request: Request) -> dict:
    return dict(await request.form())


# --- Views ----------------------------------------------------------------------------------------------
@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, sel: int = 0, new: int = 0, db: Session = Depends(get_db)):
    me, redir = _require_manager(request, db)
    if redir:
        return redir
    rows = db.scalars(select(User).order_by(User.is_admin.desc(), User.status, User.username)).all()
    selected = db.get(User, sel) if sel else None
    pending = [u for u in rows if u.status == "pending"]
    ctx = {
        "me": me,
        "users": rows,
        "selected": selected,
        "new_mode": bool(new),
        "pending_count": len(pending),
        "grantable": permissions.GRANTABLE,
        "admin_username": get_settings().admin_username,
        "email_configured": mailer.is_configured(),
        "flash": request.session.pop("flash", None),
        "reset_result": _pop_secret(request),
        "protected": {u.id: _is_protected_admin(u) for u in rows},
    }
    return templates.TemplateResponse(request, "users.html", ctx)


# --- Create ---------------------------------------------------------------------------------------------
@router.post("/users")
async def create_user(request: Request, db: Session = Depends(get_db)):
    me, redir = _require_manager(request, db)
    if redir:
        return redir
    form = await _form(request)
    username = (form.get("username") or "").strip()
    email = (form.get("email") or "").strip()
    want_admin = form.get("is_admin") == "1"    # the Standard radio posts is_admin="" — a VALUE check, not presence
    perms = _parse_perms(form)

    def _back(msg, kind="error"):
        _flash(request, msg, kind)
        return RedirectResponse("/users?new=1", status_code=303)

    if (e := username_error(username)):
        return _back(e)
    if db.scalar(select(User).where(func.lower(User.username) == username.lower())):
        return _back("That username is already taken.")
    if email and ("@" not in email or " " in email or len(email) > 200):
        return _back("That doesn't look like a valid email address.")

    # Only a full admin can mint an administrator; a standard manager silently can't.
    make_admin = want_admin and permissions.is_admin(me)
    if not permissions.is_admin(me):
        perms["perm_manage_users"] = False        # standard managers can't grant manage-users

    # Password: an explicit one (strength-checked) or a generated temp shown once.
    pw = form.get("password") or ""
    force_change = form.get("must_change_password") is not None
    if pw:
        if (e := password_strength_error(pw)):
            return _back(e)
        temp_shown = None
    else:
        pw = _temp_password()
        force_change = True
        temp_shown = pw

    status = "active"          # admin-created accounts are active immediately (no approval needed)
    user = User(
        username=username, password_hash=hash_password(pw),
        first_name=(form.get("first_name") or "").strip()[:80],
        last_name=(form.get("last_name") or "").strip()[:80],
        email=email, title=(form.get("title") or "").strip()[:120],
        is_admin=make_admin, status=status, must_change_password=force_change,
        **({} if make_admin else perms),   # admins ignore per-perm flags
    )
    db.add(user)
    db.commit()
    if temp_shown:
        _stash_secret(request, {"username": username, "password": temp_shown, "created": True})
    _flash(request, f"User '{username}' created.")
    return RedirectResponse(f"/users?sel={user.id}", status_code=303)


# --- Update (profile + role + permissions + status) -----------------------------------------------------
@router.post("/users/{uid}/update")
async def update_user(uid: int, request: Request, db: Session = Depends(get_db)):
    me, redir = _require_manager(request, db)
    if redir:
        return redir
    target = db.get(User, uid)
    if target is None:
        _flash(request, "No such user.", "error")
        return RedirectResponse("/users", status_code=303)
    form = await _form(request)
    email = (form.get("email") or "").strip()
    if email and ("@" not in email or " " in email or len(email) > 200):
        _flash(request, "That doesn't look like a valid email address.", "error")
        return RedirectResponse(f"/users?sel={uid}", status_code=303)

    target.first_name = (form.get("first_name") or "").strip()[:80]
    target.last_name = (form.get("last_name") or "").strip()[:80]
    target.email = email
    target.title = (form.get("title") or "").strip()[:120]

    want_admin = form.get("is_admin") == "1"    # Standard radio posts is_admin="" — value check, not presence
    new_status = (form.get("status") or target.status or "active").strip()
    if new_status not in ("active", "pending", "disabled"):
        new_status = target.status
    perms = _parse_perms(form)

    protected = _is_protected_admin(target)
    is_self = target.id == me.id

    # Role / permission changes require full-admin actor; standard managers can't elevate anyone.
    if permissions.is_admin(me):
        # Guard: never demote/disable the protected admin or the last active admin.
        removing_admin = target.is_admin and not want_admin
        disabling = new_status != "active"
        if protected and (removing_admin or disabling):
            _flash(request, "The primary administrator account can't be demoted or disabled.", "error")
            return RedirectResponse(f"/users?sel={uid}", status_code=303)
        if target.is_admin and (removing_admin or disabling) and _active_admin_count(db, exclude=target.id) == 0:
            _flash(request, "You can't remove the last active administrator.", "error")
            return RedirectResponse(f"/users?sel={uid}", status_code=303)
        if is_self and disabling:
            _flash(request, "You can't disable your own account.", "error")
            return RedirectResponse(f"/users?sel={uid}", status_code=303)
        target.is_admin = want_admin
        target.status = new_status
        if not want_admin:
            for k, v in perms.items():
                setattr(target, k, v)
    else:
        # Standard manager: profile + activate/disable of NON-admin users only, no role/perm changes.
        if target.is_admin:
            _flash(request, "Only an administrator can edit an administrator account.", "error")
            return RedirectResponse(f"/users?sel={uid}", status_code=303)
        if new_status in ("active", "disabled") and not is_self:
            target.status = new_status

    if not _commit_unless_orphans_admins(db):
        _flash(request, "You can't remove the last active administrator.", "error")
        return RedirectResponse(f"/users?sel={uid}", status_code=303)
    _flash(request, "Changes saved.")
    return RedirectResponse(f"/users?sel={uid}", status_code=303)


# --- Approve a pending signup ---------------------------------------------------------------------------
@router.post("/users/{uid}/approve")
def approve_user(uid: int, request: Request, db: Session = Depends(get_db)):
    me, redir = _require_manager(request, db)
    if redir:
        return redir
    target = db.get(User, uid)
    if target is None:
        return RedirectResponse("/users", status_code=303)
    if target.is_admin and not permissions.is_admin(me):
        _flash(request, "Only an administrator can approve an administrator account.", "error")
        return RedirectResponse(f"/users?sel={uid}", status_code=303)
    if target.status == "pending":
        target.status = "active"
        db.commit()
        _flash(request, f"'{target.username}' approved — they can sign in now.")
    return RedirectResponse(f"/users?sel={uid}", status_code=303)


# --- Reset a user's password (admin-driven) -------------------------------------------------------------
@router.post("/users/{uid}/reset-password")
def reset_user_password(uid: int, request: Request, mode: str = Form("temp"), db: Session = Depends(get_db)):
    me, redir = _require_manager(request, db)
    if redir:
        return redir
    target = db.get(User, uid)
    if target is None:
        _flash(request, "No such user.", "error")
        return RedirectResponse("/users", status_code=303)
    if target.is_admin and not permissions.is_admin(me):
        _flash(request, "Only an administrator can reset an administrator's password.", "error")
        return RedirectResponse(f"/users?sel={uid}", status_code=303)

    if mode == "email" and mailer.is_configured() and target.email:
        from ..security import hash_token, new_reset_token
        from ..services import app_settings
        import datetime as dt
        token = new_reset_token()
        target.reset_token_hash = hash_token(token)
        target.reset_token_expires = utcnow() + dt.timedelta(hours=1)
        db.commit()
        link = f"{app_settings.base_url().rstrip('/')}/reset-password/{token}"
        ok, detail = mailer.send(target.email, "Reset your PolicyPilot password",
                                 f"Hi {target.display_name},\n\nAn administrator asked us to help you reset "
                                 f"your PolicyPilot password. Open this link within 1 hour:\n\n{link}\n\n— PolicyPilot")
        _flash(request, f"Reset link emailed to {target.email}." if ok else f"Couldn't send email: {detail}",
               "success" if ok else "error")
    else:
        temp = _temp_password()
        target.password_hash = hash_password(temp)
        target.must_change_password = True
        target.reset_token_hash = ""
        target.reset_token_expires = None
        db.commit()
        _stash_secret(request, {"username": target.username, "password": temp, "created": False})
        _flash(request, f"Temporary password set for '{target.username}'.")
    return RedirectResponse(f"/users?sel={uid}", status_code=303)


# --- Delete ---------------------------------------------------------------------------------------------
@router.post("/users/{uid}/delete")
def delete_user(uid: int, request: Request, db: Session = Depends(get_db)):
    me, redir = _require_manager(request, db)
    if redir:
        return redir
    target = db.get(User, uid)
    if target is None:
        return RedirectResponse("/users", status_code=303)
    if target.id == me.id:
        _flash(request, "You can't delete your own account.", "error")
        return RedirectResponse(f"/users?sel={uid}", status_code=303)
    if _is_protected_admin(target):
        _flash(request, "The primary administrator account can't be deleted.", "error")
        return RedirectResponse(f"/users?sel={uid}", status_code=303)
    if target.is_admin and not permissions.is_admin(me):
        _flash(request, "Only an administrator can delete an administrator account.", "error")
        return RedirectResponse(f"/users?sel={uid}", status_code=303)
    if target.is_admin and _active_admin_count(db, exclude=target.id) == 0:
        _flash(request, "You can't delete the last active administrator.", "error")
        return RedirectResponse(f"/users?sel={uid}", status_code=303)
    name = target.username
    db.delete(target)
    if not _commit_unless_orphans_admins(db):     # transaction-time net vs a concurrent demote+delete race
        _flash(request, "You can't delete the last active administrator.", "error")
        return RedirectResponse(f"/users?sel={uid}", status_code=303)
    _flash(request, f"User '{name}' deleted.")
    return RedirectResponse("/users", status_code=303)
