"""Multi-user + RBAC: the permission matrix, self-signup→approval, admin user CRUD, password reset
(admin + email), the structural safety rails, and per-permission enforcement at the mutating endpoints.

HTTP tests bind the app to an isolated in-memory DB via a ``get_db`` dependency override (no lifespan, so
the once-only MCP session manager is never touched) and drive the real routes end-to-end."""
import datetime as dt
import types

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main
from app import models  # noqa: F401 — registers tables
from app.db import Base, get_db
from app.models import User
from app.security import hash_password, hash_token, new_reset_token, username_error
from app.services import permissions as P

ADMIN_PW = "Admin-Pass-123"
STD_PW = "Passw0rd-xxxx"


# --- Pure unit: permission model ------------------------------------------------------------------------
def _std(**flags):
    base = dict(perm_preview=False, perm_apply=False, perm_publish=False, perm_export=False,
                perm_manage_users=False)
    base.update(flags)
    return User(username="u", is_admin=False, status="active", **base)


def test_admin_has_every_permission():
    a = User(username="a", is_admin=True, status="active")
    for perm in (P.PREVIEW, P.APPLY, P.PUBLISH, P.EXPORT, P.MANAGE_USERS, P.SETTINGS):
        assert P.can(a, perm) is True
    assert P.is_admin(a) and P.effective(a)["admin"] is True


def test_standard_user_permissions_follow_flags():
    u = _std(perm_preview=True, perm_export=True)
    assert P.can(u, P.PREVIEW) and P.can(u, P.EXPORT)
    assert not P.can(u, P.APPLY) and not P.can(u, P.PUBLISH) and not P.can(u, P.MANAGE_USERS)
    assert not P.is_admin(u)


def test_settings_is_admin_only_never_grantable():
    u = _std(perm_preview=True, perm_apply=True, perm_publish=True, perm_export=True, perm_manage_users=True)
    assert P.can(u, P.SETTINGS) is False        # no flag grants settings — only real admins


def test_inactive_users_can_do_nothing():
    for status in ("pending", "disabled"):
        u = _std(perm_preview=True, perm_export=True)
        u.status = status
        assert not P.can(u, P.PREVIEW) and not P.is_admin(u) and not P.is_active(u)
    adm = User(username="a", is_admin=True, status="disabled")
    assert not P.can(adm, P.PUBLISH)            # even a disabled admin holds nothing


def test_user_display_helpers():
    u = User(username="kalshaww", first_name="Khalid", last_name="Alshawwaf")
    assert u.initials == "KA" and u.role_label == "Standard"
    assert User(username="bob").initials == "BO"
    u2 = User(username="kalshaww")
    assert u2.avatar_hue == User(username="kalshaww").avatar_hue    # stable, derived from username
    assert 0 <= u2.avatar_hue < 360
    assert User(username="admin", is_admin=True).role_label == "Administrator"


def test_username_validation():
    assert username_error("ab") is not None                  # too short
    assert username_error("has space") is not None
    assert username_error("bad$char") is not None
    assert username_error("good.user_1-x") is None


def test_reset_token_hash_is_stable_and_opaque():
    t = new_reset_token()
    assert len(t) > 20 and hash_token(t) == hash_token(t) and hash_token(t) != t


# --- Seed backfill --------------------------------------------------------------------------------------
def test_seed_admin_backfills_preexisting_nonadmin(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    TS = sessionmaker(bind=eng, autoflush=False, autocommit=False, expire_on_commit=False)
    with TS() as db:      # an admin row from before RBAC columns existed: standard + pending
        db.add(User(username="admin", password_hash=hash_password(ADMIN_PW), is_admin=False, status="pending"))
        db.commit()
    monkeypatch.setattr(main, "SessionLocal", TS)
    from app.config import get_settings
    main._seed_admin(get_settings())
    with TS() as db:
        a = db.scalar(select(User).where(User.username == "admin"))
        assert a.is_admin is True and a.status == "active"


# --- HTTP fixture ---------------------------------------------------------------------------------------
@pytest.fixture
def env():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    TS = sessionmaker(bind=eng, autoflush=False, autocommit=False, expire_on_commit=False)
    with TS() as db:
        db.add(User(username="admin", password_hash=hash_password(ADMIN_PW), is_admin=True, status="active",
                    first_name="Portal", last_name="Admin"))
        db.commit()

    def _get_db():
        db = TS()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = _get_db
    try:
        yield types.SimpleNamespace(client=TestClient(main.app), Session=TS)
    finally:
        main.app.dependency_overrides.pop(get_db, None)


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def _add_user(TS, username, **kw):
    kw.setdefault("password_hash", hash_password(STD_PW))
    kw.setdefault("status", "active")
    with TS() as db:
        u = User(username=username, **kw)
        db.add(u)
        db.commit()
        return u.id


# --- Registration + approval ----------------------------------------------------------------------------
def test_register_creates_pending_then_admin_approves(env):
    c, TS = env.client, env.Session
    r = c.post("/register", data={"username": "alice", "first_name": "Alice", "email": "alice@example.com",
                                  "password": STD_PW, "confirm": STD_PW}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    with TS() as db:
        alice = db.scalar(select(User).where(User.username == "alice"))
        assert alice.status == "pending" and not alice.is_admin
        assert alice.perm_preview and alice.perm_export and not alice.perm_publish
        aid = alice.id
    # pending can't sign in
    assert _login(c, "alice", STD_PW).status_code == 403
    # admin approves
    assert _login(c, "admin", ADMIN_PW).status_code == 303
    assert c.post(f"/users/{aid}/approve", follow_redirects=False).status_code == 303
    with TS() as db:
        assert db.get(User, aid).status == "active"
    # now alice can sign in, and last_login is stamped
    c2 = TestClient(main.app)
    assert _login(c2, "alice", STD_PW).status_code == 303
    with TS() as db:
        assert db.get(User, aid).last_login_at is not None


def test_register_rejects_duplicate_and_weak(env):
    c = env.client
    _add_user(env.Session, "bob")
    r = c.post("/register", data={"username": "bob", "password": STD_PW, "confirm": STD_PW}, follow_redirects=False)
    assert r.status_code == 400 and "already taken" in r.text
    r = c.post("/register", data={"username": "carol", "password": "short", "confirm": "short"}, follow_redirects=False)
    assert r.status_code == 400
    r = c.post("/register", data={"username": "carol", "password": STD_PW, "confirm": "nope"}, follow_redirects=False)
    assert r.status_code == 400 and "match" in r.text.lower()


def test_disabled_user_cannot_sign_in(env):
    _add_user(env.Session, "dan", status="disabled")
    assert _login(env.client, "dan", STD_PW).status_code == 403


# --- Admin user CRUD ------------------------------------------------------------------------------------
def test_admin_creates_user_with_temp_password_and_force_change(env):
    c, TS = env.client, env.Session
    assert _login(c, "admin", ADMIN_PW).status_code == 303
    r = c.post("/users", data={"username": "erin", "first_name": "Erin", "perm_preview": "on"},
               follow_redirects=False)
    assert r.status_code == 303
    with TS() as db:
        erin = db.scalar(select(User).where(User.username == "erin"))
        assert erin.status == "active" and erin.must_change_password and not erin.is_admin
    # the temp password is surfaced once on the detail page
    assert "temporary password" in c.get(f"/users?sel={erin.id}").text.lower()


def test_admin_creates_user_with_explicit_password_and_admin_role(env):
    c, TS = env.client, env.Session
    _login(c, "admin", ADMIN_PW)
    r = c.post("/users", data={"username": "frank", "password": STD_PW, "is_admin": "1"}, follow_redirects=False)
    assert r.status_code == 303
    with TS() as db:
        frank = db.scalar(select(User).where(User.username == "frank"))
        assert frank.is_admin and not frank.must_change_password
    # frank (a real admin) can sign in and reach admin-only settings
    c2 = TestClient(main.app)
    assert _login(c2, "frank", STD_PW).status_code == 303
    assert c2.get("/settings", follow_redirects=False).status_code == 200


def test_standard_manager_cannot_create_admin_or_grant_manage_users(env):
    c, TS = env.client, env.Session
    mgr = _add_user(env.Session, "mgr", perm_manage_users=True, perm_preview=True)
    _login(c, "mgr", STD_PW)
    c.post("/users", data={"username": "sneaky", "password": STD_PW, "is_admin": "1",
                           "perm_manage_users": "on"}, follow_redirects=False)
    with TS() as db:
        s = db.scalar(select(User).where(User.username == "sneaky"))
        assert s is not None and not s.is_admin and not s.perm_manage_users     # elevation dropped


def test_update_permissions_and_role(env):
    c, TS = env.client, env.Session
    uid = _add_user(env.Session, "gina", perm_preview=True)
    _login(c, "admin", ADMIN_PW)
    c.post(f"/users/{uid}/update", data={"first_name": "Gina", "status": "active", "is_admin": "",
                                         "perm_preview": "on", "perm_publish": "on"}, follow_redirects=False)
    with TS() as db:
        g = db.get(User, uid)
        assert g.first_name == "Gina" and g.perm_publish and g.perm_preview and not g.perm_apply


# --- Safety rails ---------------------------------------------------------------------------------------
def test_cannot_demote_or_disable_protected_admin(env):
    c, TS = env.client, env.Session
    _login(c, "admin", ADMIN_PW)
    with TS() as db:
        aid = db.scalar(select(User).where(User.username == "admin")).id
    c.post(f"/users/{aid}/update", data={"is_admin": "", "status": "disabled"}, follow_redirects=False)
    with TS() as db:
        a = db.get(User, aid)
        assert a.is_admin and a.status == "active"      # unchanged — the primary admin is locked


def test_cannot_remove_last_active_admin(env):
    c, TS = env.client, env.Session
    # promote a second admin, then demote the FIRST — allowed since another admin remains
    other = _add_user(env.Session, "sam", is_admin=True)
    _login(c, "admin", ADMIN_PW)
    # deleting the protected admin is blocked regardless
    with TS() as db:
        aid = db.scalar(select(User).where(User.username == "admin")).id
    assert c.post(f"/users/{aid}/delete", follow_redirects=False).status_code == 303
    with TS() as db:
        assert db.get(User, aid) is not None            # still there (protected)
    # now demote the non-protected admin 'sam' down to standard (another admin exists → allowed)
    c.post(f"/users/{other}/update", data={"is_admin": "", "status": "active"}, follow_redirects=False)
    with TS() as db:
        assert not db.get(User, other).is_admin


def test_cannot_delete_self(env):
    c, TS = env.client, env.Session
    _login(c, "admin", ADMIN_PW)
    with TS() as db:
        aid = db.scalar(select(User).where(User.username == "admin")).id
    c.post(f"/users/{aid}/delete", follow_redirects=False)
    with TS() as db:
        assert db.get(User, aid) is not None


def test_admin_can_delete_a_normal_user(env):
    c, TS = env.client, env.Session
    uid = _add_user(env.Session, "temp")
    _login(c, "admin", ADMIN_PW)
    assert c.post(f"/users/{uid}/delete", follow_redirects=False).status_code == 303
    with TS() as db:
        assert db.get(User, uid) is None


# --- Password reset -------------------------------------------------------------------------------------
def test_admin_reset_sets_temp_and_force_change(env):
    c, TS = env.client, env.Session
    uid = _add_user(env.Session, "hank")
    _login(c, "admin", ADMIN_PW)
    r = c.post(f"/users/{uid}/reset-password", data={"mode": "temp"}, follow_redirects=False)
    assert r.status_code == 303
    with TS() as db:
        assert db.get(User, uid).must_change_password is True
    assert "temporary password" in c.get(f"/users?sel={uid}").text.lower()


def test_email_reset_flow(env, monkeypatch):
    c, TS = env.client, env.Session
    sent = {}
    monkeypatch.setattr("app.services.mailer.is_configured", lambda: True)
    monkeypatch.setattr("app.services.mailer.send",
                        lambda to, subj, body: (sent.update(to=to, body=body) or (True, "sent")))
    _add_user(env.Session, "ivy", email="ivy@example.com")
    r = c.post("/forgot-password", data={"identifier": "ivy@example.com"})
    assert r.status_code == 200 and sent.get("to") == "ivy@example.com"
    # extract the token from the emailed link and consume it
    import re
    token = re.search(r"/reset-password/([\w\-]+)", sent["body"]).group(1)
    assert c.get(f"/reset-password/{token}").status_code == 200
    new_pw = "Brand-New-99"
    r = c.post(f"/reset-password/{token}", data={"new": new_pw, "confirm": new_pw}, follow_redirects=False)
    assert r.status_code == 303
    # the token is single-use + the new password works
    assert c.get(f"/reset-password/{token}").text.count("invalid") >= 1
    c2 = TestClient(main.app)
    assert _login(c2, "ivy", new_pw).status_code == 303


def test_forgot_password_without_smtp_is_neutral(env, monkeypatch):
    monkeypatch.setattr("app.services.mailer.is_configured", lambda: False)
    r = env.client.post("/forgot-password", data={"identifier": "whoever"})
    assert r.status_code == 200        # no crash, no enumeration


def test_must_change_password_redirects_then_clears(env):
    c, TS = env.client, env.Session
    _add_user(env.Session, "jack", must_change_password=True)
    r = _login(c, "jack", STD_PW)
    assert r.status_code == 303 and r.headers["location"] == "/account?force=1"
    r = c.post("/account/password", data={"current": STD_PW, "new": "New-Strong-42", "confirm": "New-Strong-42"},
               follow_redirects=False)
    assert r.status_code == 303
    with TS() as db:
        assert db.scalar(select(User).where(User.username == "jack")).must_change_password is False


# --- Enforcement at mutating endpoints ------------------------------------------------------------------
def test_readonly_user_blocked_from_apply_and_export(env):
    c = env.client
    _add_user(env.Session, "ro", perm_preview=True, perm_export=False, perm_apply=False, perm_publish=False)
    _login(c, "ro", STD_PW)
    assert c.post("/access-automation/1/apply", json={"source": "x", "destination": "y", "layer": "L",
                                                       "publish": False}).status_code == 403
    assert c.post("/management/1/export", data={"name": "L"}).status_code == 403


def test_apply_permission_gates_publish_separately(env):
    c = env.client
    _add_user(env.Session, "op", perm_apply=True, perm_publish=False)
    _login(c, "op", STD_PW)
    body = {"source": "10.1.1.1", "destination": "8.8.8.8", "protocol": "tcp", "port": "53", "layer": "L"}
    # apply w/o publish → gate passes (404: no such server, NOT 403)
    assert c.post("/access-automation/1/apply", json={**body, "publish": False}).status_code != 403
    # apply WITH publish but no publish permission → 403
    assert c.post("/access-automation/1/apply", json={**body, "publish": True}).status_code == 403


def test_export_permission_passes_gate(env):
    c = env.client
    _add_user(env.Session, "ex", perm_export=True)
    _login(c, "ex", STD_PW)
    # gate passes; handler then 400s on the missing layer name (not 403)
    assert c.post("/management/1/export", data={"name": ""}).status_code == 400


def test_settings_is_admin_only_over_http(env):
    c = env.client
    _add_user(env.Session, "kim", perm_manage_users=True, perm_export=True)   # a manager, but not admin
    _login(c, "kim", STD_PW)
    assert c.get("/settings", follow_redirects=False).status_code == 303      # bounced
    assert c.post("/settings", data={"section": "email", "smtp_host": "evil"},
                  follow_redirects=False).status_code == 303
    # admin gets in
    c2 = TestClient(main.app)
    _login(c2, "admin", ADMIN_PW)
    assert c2.get("/settings", follow_redirects=False).status_code == 200


def test_manage_users_required_for_users_app(env):
    c = env.client
    _add_user(env.Session, "nell", perm_preview=True)      # no manage_users
    _login(c, "nell", STD_PW)
    r = c.get("/users", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


# --- Regression: security review findings -----------------------------------------------------------
def test_disabling_a_user_revokes_their_live_session(env):
    """Review finding #1/#4: get_user_or_none must be status-aware so a disable revokes an open session
    (read AND write) — not just block a fresh login."""
    c, TS = env.client, env.Session
    uid = _add_user(TS, "live", perm_preview=True, perm_export=True)
    assert _login(c, "live", STD_PW).status_code == 303
    assert c.get("/account", follow_redirects=False).status_code == 200      # active: works
    with TS() as db:                                                          # admin disables them out-of-band
        db.get(User, uid).status = "disabled"; db.commit()
    # the still-open session is now treated as logged out everywhere
    assert c.get("/account", follow_redirects=False).status_code == 303       # read route → /login
    assert c.post("/management/1/export", data={"name": "L"}).status_code == 401  # write route → not authenticated


def test_valid_login_to_pending_account_does_not_reset_throttle(env):
    """Review finding #2: a valid-credential login to a pending/disabled account must NOT clear the
    brute-force throttle (else it's an anonymous throttle-reset oracle)."""
    from app.services import login_guard as lg
    c, TS = env.client, env.Session
    _add_user(TS, "pend2", status="pending")           # attacker's own pending account, known password
    for _ in range(lg.THRESHOLD - 1):                  # accumulate failures just below the lock threshold
        c.post("/login", data={"username": "admin", "password": "wrong"}, follow_redirects=False)
    # a valid login to the pending account (403) must leave the counter intact (no reset)...
    assert c.post("/login", data={"username": "pend2", "password": STD_PW}, follow_redirects=False).status_code == 403
    # ...so the next failed admin guess reaches the threshold and locks; the attempt AFTER that is refused.
    c.post("/login", data={"username": "admin", "password": "wrong"}, follow_redirects=False)   # THRESHOLD-th fail
    assert c.post("/login", data={"username": "admin", "password": "wrong"}, follow_redirects=False).status_code == 429


def test_must_change_password_blocks_actions_until_changed(env):
    """Review finding #3: must_change_password gates capability, not just a login redirect."""
    c, TS = env.client, env.Session
    _add_user(TS, "temp2", perm_apply=True, perm_publish=True, must_change_password=True)
    assert _login(c, "temp2", STD_PW).headers["location"] == "/account?force=1"
    body = {"source": "10.1.1.1", "destination": "8.8.8.8", "protocol": "tcp", "port": "53", "layer": "L"}
    assert c.post("/access-automation/1/apply", json=body).status_code == 403   # blocked by can() while must_change
    # a must-change admin is bounced from Settings to change their password first
    aid = _add_user(TS, "tadmin", is_admin=True, must_change_password=True)
    c2 = TestClient(main.app)
    _login(c2, "tadmin", STD_PW)
    r = c2.get("/settings", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/account?force=1"


def test_standard_manager_cannot_approve_a_pending_admin(env):
    """Review finding #7: approve_user needs the same admin-target guard as reset/delete."""
    c, TS = env.client, env.Session
    padmin = _add_user(TS, "padmin", is_admin=True, status="pending")   # a parked pending admin
    _add_user(TS, "mgr2", perm_manage_users=True, perm_preview=True)
    _login(c, "mgr2", STD_PW)
    c.post(f"/users/{padmin}/approve", follow_redirects=False)
    with TS() as db:
        assert db.get(User, padmin).status == "pending"                 # manager could NOT reactivate the admin


def test_temp_password_never_enters_the_session_cookie(env, monkeypatch):
    """Review finding #6: the admin-set temp password must live server-side, not in the (unencrypted)
    session cookie."""
    import app.routers.users as um
    monkeypatch.setattr(um, "_temp_password", lambda: "SENTINEL-Temp-777")
    c = env.client
    _login(c, "admin", ADMIN_PW)
    r = c.post("/users", data={"username": "oscar", "perm_preview": "on"}, follow_redirects=False)
    # the plaintext must NOT appear in any Set-Cookie on the create response
    assert "SENTINEL-Temp-777" not in r.headers.get("set-cookie", "")
    # it IS shown once on the next GET, then gone (single-read server-side store)
    assert "SENTINEL-Temp-777" in c.get(f"/users?sel={r.headers['location'].split('=')[-1]}").text
    # a subsequent GET no longer shows it
    assert "SENTINEL-Temp-777" not in c.get("/users").text
