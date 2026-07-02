"""Server-rendered portal UI (Jinja2 + HTMX) — auth, home, MCP guide, API explorer, system health."""
import datetime as dt
import os
import platform
import re
import time
from pathlib import Path

try:
    import resource  # POSIX-only; used for process RSS in the system-health view
except ImportError:  # pragma: no cover — non-POSIX
    resource = None

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import (ActivityLog, ApiKey, DynamicLayer, GlobalPref, Gateway, ManagementServer, User,
                      UserDesktopPref, utcnow)
from ..security import (get_user_or_none, hash_password, hash_token, new_reset_token,
                        password_strength_error, username_error, verify_password)
from ..services import coverage, login_guard, mailer, permissions

router = APIRouter(include_in_schema=False)
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
from .. import __version__ as _app_version
from .. import build as _build
templates.env.globals["app_version"] = _app_version   # surfaced in the footer (single shared templates env)
templates.env.globals["build_info"] = _build.build_info()   # {version, build (short SHA), built_at} — the About menu
# RBAC helpers available in every template: {{ can(user, 'publish') }} to show/hide controls, and
# {{ perms(user) }} for the full capability map. Single shared env, so this reaches all routers.
templates.env.globals["can"] = permissions.can
templates.env.globals["perms"] = permissions.effective


@router.get("/field-support", response_class=HTMLResponse)
def field_support_page(request: Request, db: Session = Depends(get_db)):
    """The authoritative Access-Automation field support matrix: exactly which Check Point object types the
    engine handles in each rule column, at what support level, how to discover the object, and the gaps."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    from ..services import field_support
    return templates.TemplateResponse(request, "field_support.html", {
        "matrix": field_support.matrix(),
        "levels": field_support.LEVELS,
        "review_triggers": field_support.REVIEW_TRIGGERS,
    })


@router.get("/handbook", response_class=HTMLResponse)
def handbook_page(request: Request, db: Session = Depends(get_db)):
    """The in-app Handbook: what PolicyPilot is, driving the desktop, access automation, the interfaces,
    deploying, and administration — the single onboarding read for a new user or admin."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "handbook.html", {})


@router.get("/mcp-guide", response_class=HTMLResponse)
def mcp_guide_page(request: Request, db: Session = Depends(get_db)):
    """Onboarding for the MCP server: the tool catalog + copy-paste connect config for the common
    clients (Claude Desktop / Cursor / VS Code / n8n) + live status + the safety model."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    from .. import mcp_server
    from ..services import app_settings
    return templates.TemplateResponse(request, "mcp_guide.html", {
        "tools": mcp_server.tool_catalog(),
        "sdk_installed": mcp_server.have_mcp(),
        "token_set": mcp_server.token_configured(),     # an active mcp-scope API key exists -> /mcp live
        "allow_publish": bool(app_settings.get("mcp_allow_publish")),
    })


@router.post("/mcp-guide/key")
async def mcp_guide_generate_key(request: Request, db: Session = Depends(get_db)):
    """Generate an mcp-scope API key and RETURN its plaintext once, so the MCP page can drop it straight
    into the connect-config (no copy/paste, no separate Settings trip). The key is hashed at rest; this
    response is the only time the secret is shown. This is the single way to enable /mcp."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    from ..services import api_keys
    form = await request.form()
    name = (form.get("name") or "").strip() or "mcp-agent"
    row, secret = api_keys.generate(name, "mcp", created_by=user.username)
    return JSONResponse({"key": secret, "name": row.name, "scope": row.scope})


# --- API explorer: embedded Swagger UI over the in-portal converter --------------------
def _explorer_servers(db: Session, user: User) -> dict:
    """Saved connections the explorer can target, as base URLs the spec's `servers` block uses.
    Management Servers drive web_api; Gateways expose gaia_api."""
    mgmt = db.execute(select(ManagementServer).where(ManagementServer.owner_id == user.id)).scalars().all()
    gws = db.execute(select(Gateway).where(Gateway.owner_id == user.id)).scalars().all()
    return {
        "management": [{"name": m.name, "url": f"https://{m.host}:{m.port}/web_api"} for m in mgmt],
        "gaia": [{"name": g.name, "url": f"https://{g.host}:{g.port}/gaia_api"} for g in gws],
    }


@router.get("/api-explorer", response_class=HTMLResponse)
def api_explorer_page(request: Request, api: str = "management", version: str = "",
                      db: Session = Depends(get_db)):
    """Interactive Swagger-UI explorer for the Management / Gaia API, built in-portal from the CP docs."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if api not in ("management", "gaia"):
        api = "management"
    servers = _explorer_servers(db, user)
    # Pre-select a registered server when one exists, so examples + Try it out target it by default
    # (falling back to the docs placeholder only when nothing is registered for this API).
    default_server = servers.get(api, [{}])[0].get("url", "") if servers.get(api) else ""
    return templates.TemplateResponse(request, "api_explorer.html", {
        "api_type": api, "version": version or coverage.latest(api),
        "versions": coverage.versions(), "servers": servers, "default_server": default_server,
    })


@router.get("/api-explorer/openapi.json")
def api_explorer_spec(request: Request, api: str = "management", version: str = "",
                      server_url: str = "", download: int = 0, db: Session = Depends(get_db)):
    """The full OpenAPI document Swagger UI loads — converted live from the CP docs, cached, with the
    chosen target server pre-filled. `version=''` = latest published. This is a standard OpenAPI 3.0
    document, so `download=1` serves it as a file ready to import into Postman or Bruno (which both build
    a request collection from it), with the selected target server baked into the spec's `servers`."""
    if get_user_or_none(request, db) is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if api not in ("management", "gaia"):
        api = "management"
    from ..services import coverage_build
    try:
        spec = coverage_build.openapi_spec(api, version, server_url)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"Could not build the {api} {version or 'latest'} spec — {exc}"},
                            status_code=502)
    resp = JSONResponse(spec)
    if download:
        ver = re.sub(r"[^A-Za-z0-9._-]", "", version or coverage.latest(api) or "latest")
        resp.headers["Content-Disposition"] = f'attachment; filename="checkpoint-{api}-{ver}.openapi.json"'
    return resp


def _explorer_proxy_targets(db: Session, user: User) -> dict:
    """{'host:port': server} for the user's OWN saved Management Servers + Gateways — the ONLY targets the
    explorer proxy may reach. This allowlist is the SSRF guard: the proxy is never an open relay."""
    out: dict = {}
    for m in db.execute(select(ManagementServer).where(ManagementServer.owner_id == user.id)).scalars():
        out[f"{m.host}:{m.port}".lower()] = m
    for g in db.execute(select(Gateway).where(Gateway.owner_id == user.id)).scalars():
        out[f"{g.host}:{g.port}".lower()] = g
    return out


@router.api_route("/api-explorer/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
                  include_in_schema=False)
async def api_explorer_proxy(request: Request, db: Session = Depends(get_db)):
    """Server-side proxy for the explorer's *Try it out*, so live calls work without the browser's
    cross-origin (CORS) block. STRICTLY allowlisted — it forwards ONLY to the caller's own saved
    Management Servers / Gateways (exact host:port), never an arbitrary URL, so it can't be abused as an
    open relay (SSRF). TLS is verified server-side (the server's pinned cert when set); the portal's own
    session cookie is never forwarded upstream."""
    import ssl
    import httpx
    from urllib.parse import urlparse

    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    target = request.headers.get("x-policypilot-target", "").strip()
    try:                                          # a hostile header (bad IPv6 / port) must 400, not 500
        parsed = urlparse(target) if target else None
        port = parsed.port if parsed else None
    except ValueError:
        parsed, port = None, None
    if not parsed or parsed.scheme not in ("http", "https") or not parsed.hostname:
        return JSONResponse({"error": "Missing or invalid X-PolicyPilot-Target URL."}, status_code=400)
    port = port or (443 if parsed.scheme == "https" else 80)
    key = f"{parsed.hostname}:{port}".lower()
    server = _explorer_proxy_targets(db, user).get(key)
    if server is None:
        return JSONResponse(
            {"error": f"Refused — {parsed.hostname}:{port} is not one of your saved servers. The explorer "
                      "only proxies to Management Servers / Gateways you've added (this prevents the portal "
                      "being used as an open proxy). Add it under Layers & Gateways, then retry."},
            status_code=403)

    from ..services.mgmt_api import _verify_for
    try:                                          # a malformed stored pin is a local config problem, not "upstream failed"
        verify = _verify_for(server)
    except ssl.SSLError:
        return JSONResponse({"error": f"The pinned certificate stored for {key} is invalid PEM — re-add the "
                                      "server's certificate on its Edit page.", "via": "portal-proxy"},
                            status_code=502)
    # Drop the full hop-by-hop set (RFC 7230) so httpx owns request framing from content=body — a stray
    # Transfer-Encoding alongside our Content-Length would be a request-smuggling primitive. Also never
    # forward the portal's own session cookie / forwarded-* headers upstream.
    drop = {"host", "cookie", "content-length", "connection", "accept-encoding",
            "x-policypilot-target", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
            "transfer-encoding", "te", "trailer", "trailers", "upgrade", "keep-alive",
            "proxy-authorization", "proxy-authenticate"}
    fwd = {k: v for k, v in request.headers.items() if k.lower() not in drop}
    body = await request.body()
    if len(body) > 2_000_000:                     # cap the relayed request body (parity with the response cap)
        return JSONResponse({"error": "Request body too large (max 2 MB for the explorer proxy)."},
                            status_code=413)
    try:
        async with httpx.AsyncClient(verify=verify, timeout=20.0,
                                     follow_redirects=False) as client:   # no redirect-based SSRF
            r = await client.request(request.method, target, content=body, headers=fwd)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"Upstream request to {key} failed: {exc}", "via": "portal-proxy"},
                            status_code=502)
    content = r.content[:2_000_000]   # truncate what we relay to the browser (allowlisted own-servers + 20s timeout bound the upstream size)
    return Response(content=content, status_code=r.status_code,
                    media_type=r.headers.get("content-type", "application/json"))


# --- Flash / session helpers -----------------------------------------------------------
def _flash(request: Request, text: str, kind: str = "success") -> None:
    # Cap length: the flash rides in the signed session cookie (~4KB browser limit); an overlong
    # message would silently drop the whole cookie and log the user out.
    request.session["flash"] = {"text": (text or "")[:800], "type": kind}
    # Also persist it as a notification for the header bell (review/delete later). Best-effort: a
    # notification write must never break the request that flashed.
    uid = request.session.get("uid")
    if uid:
        try:
            from ..db import SessionLocal
            from ..services import notifications
            with SessionLocal() as db:
                notifications.add(db, uid, text or "", kind)
        except Exception:  # noqa: BLE001
            pass


def _pop_flash(request: Request) -> dict | None:
    return request.session.pop("flash", None)


# --- Auth ------------------------------------------------------------------------------
def _valid_email(email: str) -> bool:
    email = (email or "").strip()
    return bool(email) and "@" in email and " " not in email and len(email) <= 200


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is not None:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html",
                                      {"error": None, "email_reset": mailer.is_configured()})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = login_guard.client_ip(request)
    wait = login_guard.locked_for(db, ip)
    email_reset = mailer.is_configured()
    if wait:
        return templates.TemplateResponse(
            request, "login.html",
            {"error": f"Too many failed attempts. Try again in {wait}s.", "email_reset": email_reset},
            status_code=429)
    user = db.scalar(select(User).where(User.username == username))
    if user is None or not verify_password(password, user.password_hash):
        login_guard.record_failure(db, ip)
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid credentials", "email_reset": email_reset},
            status_code=401)
    # Credentials are correct — now enforce the account lifecycle. Do NOT clear the brute-force throttle
    # here: a valid-credential login to an inactive account must not reset the IP's failure count (else a
    # self-signup / disabled account whose password the attacker knows becomes a throttle-reset oracle for
    # guessing OTHER accounts). Leave the counter untouched — neither a success nor a failure.
    if user.status == "pending":
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Your account is awaiting administrator approval.", "email_reset": email_reset},
            status_code=403)
    if user.status == "disabled":
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "This account has been disabled. Contact an administrator.", "email_reset": email_reset},
            status_code=403)
    login_guard.record_success(db, ip)
    user.last_login_at = utcnow()
    db.commit()
    request.session["uid"] = user.id
    # A temp password from an admin reset (or first login) forces a change before anything else.
    if user.must_change_password:
        return RedirectResponse("/account?force=1", status_code=303)
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# --- Self-service registration (self-signup → pending admin approval) -------------------
@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is not None:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "register.html", {"error": None, "form": {}})


@router.post("/register")
def register_submit(
    request: Request,
    username: str = Form(...),
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    password: str = Form(...),
    confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    username = (username or "").strip()
    email = (email or "").strip()
    form = {"username": username, "first_name": first_name, "last_name": last_name, "email": email}

    def _err(msg: str):
        return templates.TemplateResponse(request, "register.html",
                                          {"error": msg, "form": form}, status_code=400)

    if (e := username_error(username)):
        return _err(e)
    if db.scalar(select(User).where(func.lower(User.username) == username.lower())):
        return _err("That username is already taken.")
    if email and not _valid_email(email):
        return _err("That doesn't look like a valid email address.")
    if password != confirm:
        return _err("Passwords do not match.")
    if (e := password_strength_error(password)):
        return _err(e)

    # New self-signups land as a pending, standard, read-only-ish account (preview + export), disabled
    # until an admin approves — the chosen "self-signup + approval" posture.
    user = User(username=username, password_hash=hash_password(password),
                first_name=(first_name or "").strip()[:80], last_name=(last_name or "").strip()[:80],
                email=email, is_admin=False, status="pending",
                perm_preview=True, perm_export=True,
                perm_apply=False, perm_publish=False, perm_manage_users=False)
    db.add(user)
    db.commit()
    # Notify every admin so a pending request never sits unseen.
    try:
        from ..services import notifications
        for adm in db.scalars(select(User).where(User.is_admin.is_(True), User.status == "active")).all():
            notifications.add(db, adm.id, f"New user '{username}' is awaiting approval.", "info")
    except Exception:  # noqa: BLE001 — notification is best-effort
        pass
    _flash(request, "Account created — it's awaiting administrator approval. You'll be able to sign in once approved.")
    return RedirectResponse("/login", status_code=303)


# --- Forgot / reset password ------------------------------------------------------------
@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse(request, "forgot_password.html",
                                      {"sent": False, "email_reset": mailer.is_configured(), "error": None})


@router.post("/forgot-password")
def forgot_password_submit(request: Request, identifier: str = Form(...), db: Session = Depends(get_db)):
    identifier = (identifier or "").strip()
    if not mailer.is_configured():
        return templates.TemplateResponse(request, "forgot_password.html",
                                          {"sent": False, "email_reset": False, "error": None})
    # Match by username OR email. Respond identically whether or not a match exists (no user enumeration).
    user = db.scalar(select(User).where(
        (func.lower(User.username) == identifier.lower()) | (func.lower(User.email) == identifier.lower())))
    if user is not None and user.status == "active" and user.email:
        token = new_reset_token()
        user.reset_token_hash = hash_token(token)
        user.reset_token_expires = utcnow() + dt.timedelta(hours=1)
        db.commit()
        from ..services import app_settings
        link = f"{app_settings.base_url().rstrip('/')}/reset-password/{token}"
        mailer.send(user.email, "Reset your PolicyPilot password",
                    f"Hi {user.display_name},\n\n"
                    f"We received a request to reset your PolicyPilot password. Open this link to choose "
                    f"a new one (it expires in 1 hour):\n\n{link}\n\n"
                    f"If you didn't request this, you can safely ignore this email.\n\n— PolicyPilot")
    return templates.TemplateResponse(request, "forgot_password.html",
                                      {"sent": True, "email_reset": True, "error": None})


def _user_for_reset_token(db: Session, token: str) -> User | None:
    if not token:
        return None
    user = db.scalar(select(User).where(User.reset_token_hash == hash_token(token)))
    if user is None or not user.reset_token_expires:
        return None
    exp = user.reset_token_expires
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=dt.timezone.utc)
    if exp < utcnow():
        return None
    return user


@router.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_page(token: str, request: Request, db: Session = Depends(get_db)):
    user = _user_for_reset_token(db, token)
    return templates.TemplateResponse(request, "reset_password.html",
                                      {"token": token, "valid": user is not None, "error": None})


@router.post("/reset-password/{token}")
def reset_password_submit(token: str, request: Request, new: str = Form(...),
                          confirm: str = Form(...), db: Session = Depends(get_db)):
    user = _user_for_reset_token(db, token)
    if user is None:
        return templates.TemplateResponse(request, "reset_password.html",
                                          {"token": token, "valid": False, "error": None})
    if new != confirm:
        return templates.TemplateResponse(request, "reset_password.html",
                                          {"token": token, "valid": True, "error": "Passwords do not match."})
    if (e := password_strength_error(new)):
        return templates.TemplateResponse(request, "reset_password.html",
                                          {"token": token, "valid": True, "error": e})
    user.password_hash = hash_password(new)
    user.reset_token_hash = ""
    user.reset_token_expires = None
    user.must_change_password = False
    db.commit()
    _flash(request, "Password reset — you can now sign in.")
    return RedirectResponse("/login", status_code=303)


# --- Account (self-service profile + password) -----------------------------------------
@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request, force: int = 0, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "account.html",
                                      {"user": user, "flash": _pop_flash(request),
                                       "force_password": bool(force) or bool(user.must_change_password),
                                       "my_perms": permissions.effective(user),
                                       "grantable": permissions.GRANTABLE})


@router.post("/account/password")
def change_password(
    request: Request,
    current: str = Form(...),
    new: str = Form(...),
    confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not verify_password(current, user.password_hash):
        _flash(request, "Current password is incorrect.", "error")
    elif new != confirm:
        _flash(request, "New passwords do not match.", "error")
    elif (err := password_strength_error(new)):
        _flash(request, err, "error")
    else:
        user.password_hash = hash_password(new)
        user.must_change_password = False        # clears a forced-change requirement
        db.commit()
        _flash(request, "Password changed.")
    return RedirectResponse("/account", status_code=303)


@router.post("/account/profile")
def update_profile(
    request: Request,
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    title: str = Form(""),
    db: Session = Depends(get_db),
):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    email = (email or "").strip()
    if email and not _valid_email(email):
        _flash(request, "That doesn't look like a valid email address.", "error")
        return RedirectResponse("/account", status_code=303)
    user.first_name = (first_name or "").strip()[:80]
    user.last_name = (last_name or "").strip()[:80]
    user.email = email
    user.title = (title or "").strip()[:120]
    db.commit()
    _flash(request, "Profile saved.")
    return RedirectResponse("/account", status_code=303)


# --- Home ------------------------------------------------------------------------------
# --- Desktop layout (OS-style Home): which apps are on the dock + which icons sit on the desktop ------
# Server-side allowlist of app keys (anything else in a saved layout is dropped — no junk/injection).
DESKTOP_APP_KEYS = {"access", "decisionmap", "decisiontree", "changelog", "webhook", "layers", "management",
                    "policymanager", "iacexporter", "gateways", "agents", "apiexplorer", "apidocs",
                    "settings", "activity", "account", "system", "users", "fieldsupport"}
# Toggleable desktop widgets (the right-hand rail on the OS Home). Each is backed by real, DB-side data.
DESKTOP_WIDGET_KEYS = {"decisions", "activity", "last", "connections", "coverage",
                       "errors", "latency", "recent", "clock", "quick", "system"}
DEFAULT_DESKTOP_LAYOUT = {"dock": ["access", "layers", "management", "policymanager", "iacexporter",
                                   "gateways", "agents", "settings", "activity", "system"],
                          "desktop": []}


def _sanitize_layout(raw) -> dict:
    """Validate a layout dict against the app-key allowlist; clamp counts + icon positions. Falls back to
    the default dock when empty so a user is never stranded with no apps."""
    if not isinstance(raw, dict):
        return {k: list(v) for k, v in DEFAULT_DESKTOP_LAYOUT.items()}
    seen = set()
    dock = []
    for k in (raw.get("dock") or [])[:24]:
        if k in DESKTOP_APP_KEYS and k not in seen:
            seen.add(k); dock.append(k)
    desk = []
    for it in (raw.get("desktop") or [])[:48]:
        if not isinstance(it, dict):
            continue
        k = it.get("key")
        if k in DESKTOP_APP_KEYS:
            try:
                x = max(0, min(int(it.get("x", 0)), 6000)); y = max(0, min(int(it.get("y", 0)), 6000))
            except (TypeError, ValueError):
                x, y = 0, 0
            desk.append({"key": k, "x": x, "y": y})
    win = {}
    raw_win = raw.get("win") if isinstance(raw.get("win"), dict) else {}
    for k, v in list(raw_win.items())[:48]:
        if k in DESKTOP_APP_KEYS and isinstance(v, dict):
            try:
                win[k] = {"x": max(0, min(int(v.get("x", 0)), 8000)), "y": max(0, min(int(v.get("y", 0)), 8000)),
                          "w": max(300, min(int(v.get("w", 600)), 8000)), "h": max(200, min(int(v.get("h", 400)), 8000))}
            except (TypeError, ValueError):
                pass
    out = {"dock": dock or list(DEFAULT_DESKTOP_LAYOUT["dock"]), "desktop": desk, "win": win}
    # Preserve the user's enabled-widgets choice (allowlisted). Absent → the client applies its default;
    # an explicit empty list means "no widgets" and is kept distinct from absent.
    if isinstance(raw.get("widgets"), list):
        widgets = []
        for w in raw["widgets"][:12]:
            if w in DESKTOP_WIDGET_KEYS and w not in widgets:
                widgets.append(w)
        out["widgets"] = widgets
    # Per-app custom display names {key: name}. Keys allowlisted; value trimmed + length-capped + control-char
    # stripped. Stored RAW (the client escapes at render — the single XSS barrier — so don't double-escape here).
    raw_labels = raw.get("labels")
    if isinstance(raw_labels, dict):
        labels = {}
        for k, v in list(raw_labels.items())[:len(DESKTOP_APP_KEYS)]:
            if k in DESKTOP_APP_KEYS and isinstance(v, str):
                name = "".join(ch for ch in v if ch >= " ").strip()[:40]
                if name:
                    labels[k] = name
        if labels:
            out["labels"] = labels
    return out


def _is_admin(user: User) -> bool:
    """Any administrator (the seeded admin OR one promoted in Users & Groups) may set the shared default
    desktop; every other user freely customises their own on top of it."""
    return permissions.is_admin(user)


def _global_default_layout(db: Session) -> dict | None:
    row = db.get(GlobalPref, "desktop_default")
    return _sanitize_layout(row.value) if (row and isinstance(row.value, dict) and row.value) else None


def _load_desktop_layout(db: Session, user: User) -> dict:
    """A user's own arrangement wins; else the admin-set default for everyone; else the built-in default."""
    row = db.scalar(select(UserDesktopPref).where(UserDesktopPref.owner_id == user.id))
    if row and isinstance(row.layout, dict) and row.layout:
        return _sanitize_layout(row.layout)
    return _global_default_layout(db) or {k: list(v) for k, v in DEFAULT_DESKTOP_LAYOUT.items()}


# --- System health (a desktop "System" app: process + DB + activity + agent-surface health) -----------
_PROCESS_START = time.time()


def _fmt_uptime(secs: float) -> str:
    d, r = divmod(int(secs), 86400); h, r = divmod(r, 3600); m, _s = divmod(r, 60)
    out = []
    if d: out.append(f"{d}d")
    if h or d: out.append(f"{h}h")
    out.append(f"{m}m")
    return " ".join(out)


def _mem_pct() -> int | None:
    """Used-memory percent from /proc/meminfo (Linux). None where unavailable (e.g. macOS dev)."""
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                key, _, rest = line.partition(":")
                if rest:
                    info[key.strip()] = int(rest.split()[0])   # value in kB
        total = info.get("MemTotal")
        avail = info.get("MemAvailable", info.get("MemFree"))
        if total and avail is not None:
            return max(0, min(100, round((total - avail) / total * 100)))
    except (OSError, ValueError):
        pass
    return None


def _system_metrics() -> dict:
    """Process uptime + host utilization for the desktop System widget. Stdlib only; each metric degrades
    to None on a platform that doesn't expose its source (load average is POSIX; /proc is Linux-only)."""
    up_s = max(0.0, time.time() - _PROCESS_START)
    cpus = os.cpu_count() or 1
    load1 = None
    cpu_pct = None
    try:
        load1 = round(os.getloadavg()[0], 2)
        cpu_pct = max(0, min(100, round(load1 / cpus * 100)))   # 1-min load / cores, clamped
    except (OSError, AttributeError):
        pass
    disk_pct = None
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        avail = st.f_bavail * st.f_frsize
        if total > 0:
            disk_pct = max(0, min(100, round((total - avail) / total * 100)))
    except (OSError, AttributeError):
        pass
    return {"uptime": _fmt_uptime(up_s), "uptime_s": int(up_s),
            "cpu_pct": cpu_pct, "mem_pct": _mem_pct(), "disk_pct": disk_pct,
            "cpus": os.cpu_count(), "load1": load1}


def _system_health(db: Session) -> dict:
    from ..services import app_settings, conformance
    db_ok = True
    try:
        db.execute(select(func.count()).select_from(User))
    except Exception:  # noqa: BLE001
        db_ok = False
    load = None
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except (OSError, AttributeError):
        pass
    mem_mb = None
    if resource is not None:
        try:
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            mem_mb = round(rss / (1024 * 1024), 1) if rss > 500000 else round(rss / 1024, 1)  # macOS bytes vs linux KB
        except Exception:  # noqa: BLE001
            pass

    def _c(model):
        return db.scalar(select(func.count()).select_from(model)) or 0

    counts = {"users": _c(User), "connections": _c(ManagementServer), "gateways": _c(Gateway),
              "layers": _c(DynamicLayer), "api_keys": _c(ApiKey), "events": _c(ActivityLog)}
    errs = db.scalar(select(func.count()).select_from(ActivityLog).where(ActivityLog.status >= 400)) or 0
    avg_ms = db.scalar(select(func.avg(ActivityLog.duration_ms))) or 0
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    last_hour = db.scalar(select(func.count()).select_from(ActivityLog).where(ActivityLog.at >= since)) or 0
    vals = app_settings.all_values()
    p, a, pr = vals.get("mcp_allow_publish"), vals.get("aa_autopilot"), vals.get("aa_profile")
    mode = ("Autonomous" if (p and a and pr == "aggressive")
            else "Supervised" if (p and not a and pr == "balanced")
            else "Read-only" if (not p and not a and pr == "balanced") else "Custom")
    try:
        conf = conformance.run()
    except Exception:  # noqa: BLE001
        conf = {"ok": False, "tools": 0, "checks": []}
    return {
        "version": _app_version, "uptime": _fmt_uptime(time.time() - _PROCESS_START),
        "db_ok": db_ok, "load": load, "cpus": os.cpu_count(), "mem_mb": mem_mb,
        "python": platform.python_version(), "os": platform.system(),
        "counts": counts,
        "activity": {"total": counts["events"], "errors": errs, "avg_ms": round(float(avg_ms)),
                     "error_pct": round(100.0 * errs / counts["events"], 1) if counts["events"] else 0.0,
                     "last_hour": last_hour},
        "mode": mode, "publish": bool(p), "autopilot": bool(a), "rate": vals.get("agent_rate_limit_per_min") or 0,
        "conformance": {"ok": bool(conf.get("ok")), "tools": conf.get("tools", 0),
                        "checks": [{"name": c.get("name"), "ok": bool(c.get("ok")), "detail": c.get("detail", "")}
                                   for c in conf.get("checks", [])]},
    }


@router.get("/system", response_class=HTMLResponse)
def system_health_page(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "system_health.html",
                                      {"user": user, "health": _system_health(db), "flash": _pop_flash(request)})


@router.get("/system/data")
def system_health_data(request: Request, db: Session = Depends(get_db)):
    """JSON snapshot for the System app's live auto-refresh (read-only)."""
    user = get_user_or_none(request, db)
    if user is None:
        return Response(status_code=401)
    return JSONResponse(_system_health(db))


# --- Desktop widgets (the toggleable Home rail) ------------------------------------------------------
def _ago(now: dt.datetime, then: dt.datetime | None) -> str:
    if not then:
        return ""
    if then.tzinfo is None:
        then = then.replace(tzinfo=dt.timezone.utc)
    s = max(0, int((now - then).total_seconds()))
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def _widget_data(db: Session) -> dict:
    """Aggregate everything the desktop widget rail needs — purely DB-side, no live SMS calls.
    Mirrors the auth + read-only pattern of /system/data."""
    from ..models import AppliedChange, GatewayLayerSnapshot
    now = dt.datetime.now(dt.timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Decisions today — published changes grouped by outcome (no-ops publish nothing, so aren't counted).
    dec = {"create": 0, "widen": 0, "disable": 0}
    for outcome, n in db.execute(
            select(AppliedChange.outcome, func.count())
            .where(AppliedChange.created_at >= today)
            .group_by(AppliedChange.outcome)).all():
        if outcome in dec:
            dec[outcome] = int(n)

    # Last decision (most recent published change).
    last = db.scalar(select(AppliedChange).order_by(AppliedChange.created_at.desc()).limit(1))
    last_d = None
    if last is not None:
        last_d = {"outcome": last.outcome or "", "ticket": last.ticket_id or "", "layer": last.layer or "",
                  "summary": last.summary or "", "action": last.action or "apply",
                  "at": last.created_at.isoformat() if last.created_at else None}

    # API activity pulse — 20 one-minute buckets + events in the last minute.
    win_start = now - dt.timedelta(minutes=20)
    spark = [0] * 20
    rate = 0
    minute_ago = now - dt.timedelta(minutes=1)
    for at in db.scalars(select(ActivityLog.at).where(ActivityLog.at >= win_start)).all():
        if at is None:
            continue
        if at.tzinfo is None:
            at = at.replace(tzinfo=dt.timezone.utc)
        idx = int((at - win_start).total_seconds() // 60)
        if 0 <= idx < 20:
            spark[idx] += 1
        if at >= minute_ago:
            rate += 1

    # Error rate + latency, scoped to today.
    total_today = db.scalar(select(func.count()).select_from(ActivityLog).where(ActivityLog.at >= today)) or 0
    err_today = db.scalar(select(func.count()).select_from(ActivityLog)
                          .where(ActivityLog.at >= today, ActivityLog.status >= 400)) or 0
    avg_today = db.scalar(select(func.avg(ActivityLog.duration_ms)).where(ActivityLog.at >= today)) or 0

    # Connections — SMS servers (configured) + gateways with their last-fetch status. No live login here.
    conns = []
    for m in db.scalars(select(ManagementServer).order_by(ManagementServer.id).limit(4)).all():
        conns.append({"kind": "sms", "name": m.name or m.host, "ok": True, "note": "configured"})
    for gw, snap in db.execute(
            select(Gateway, GatewayLayerSnapshot)
            .join(GatewayLayerSnapshot, GatewayLayerSnapshot.gateway_id == Gateway.id, isouter=True)
            .order_by(Gateway.id).limit(4)).all():
        if snap is not None:
            conns.append({"kind": "gw", "name": gw.name, "ok": bool(snap.ok),
                          "note": (_ago(now, snap.fetched_at) if snap.ok else "fetch error")})
        else:
            conns.append({"kind": "gw", "name": gw.name, "ok": True, "note": "not fetched"})

    coverage_counts = {"layers": db.scalar(select(func.count()).select_from(DynamicLayer)) or 0,
                       "gateways": db.scalar(select(func.count()).select_from(Gateway)) or 0,
                       "connections": db.scalar(select(func.count()).select_from(ManagementServer)) or 0}

    recent = [{"method": r.method or "", "path": r.path or "", "status": r.status, "kind": r.kind or "",
               "at": r.at.isoformat() if r.at else None}
              for r in db.scalars(select(ActivityLog).order_by(ActivityLog.at.desc()).limit(6)).all()]

    return {
        "decisions": {"created": dec["create"], "widened": dec["widen"], "disabled": dec["disable"]},
        "last": last_d,
        "activity": {"rate": rate, "spark": spark},
        "errors": {"pct": round(100.0 * err_today / total_today, 1) if total_today else 0.0,
                   "err": int(err_today), "total": int(total_today)},
        "latency": {"avg": round(float(avg_today))},
        "connections": conns,
        "coverage": coverage_counts,
        "recent": recent,
        "system": _system_metrics(),
    }


@router.get("/desktop/widgets")
def desktop_widgets_data(request: Request, db: Session = Depends(get_db)):
    """JSON for the desktop widget rail's live refresh (read-only, DB-side; no live SMS calls)."""
    user = get_user_or_none(request, db)
    if user is None:
        return Response(status_code=401)
    return JSONResponse(_widget_data(db))


@router.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    def _count(model):
        return db.scalar(select(func.count()).select_from(model)
                         .where(model.owner_id == user.id)) or 0

    counts = {"gateways": _count(Gateway), "management": _count(ManagementServer),
              "layers": _count(DynamicLayer)}
    return templates.TemplateResponse(request, "home.html",
                                      {"user": user, "counts": counts, "layout": _load_desktop_layout(db, user),
                                       "is_admin": _is_admin(user),
                                       "can_manage_users": permissions.can(user, permissions.MANAGE_USERS),
                                       "flash": _pop_flash(request)})


@router.post("/desktop/default")
async def save_desktop_default(request: Request, db: Session = Depends(get_db)):
    """Admin-only: set the portal-wide DEFAULT desktop layout that users who haven't customised inherit.
    Non-admins get 403 — they can only change their own (POST /desktop/layout)."""
    user = get_user_or_none(request, db)
    if user is None:
        return Response(status_code=401)
    if not _is_admin(user):
        return Response(status_code=403)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return Response(status_code=400)
    layout = _sanitize_layout(body)
    layout.pop("labels", None)   # custom app names are per-user, not part of the org-wide default
    row = db.get(GlobalPref, "desktop_default")
    if row:
        row.value = layout
    else:
        db.add(GlobalPref(key="desktop_default", value=layout))
    db.commit()
    return Response(status_code=204)


@router.post("/desktop/layout")
async def save_desktop_layout(request: Request, db: Session = Depends(get_db)):
    """Persist the user's desktop arrangement (dock apps + desktop icon positions). Same-origin JSON from
    the desktop shell; validated against the app-key allowlist before storing."""
    user = get_user_or_none(request, db)
    if user is None:
        return Response(status_code=401)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 — malformed body
        return Response(status_code=400)
    layout = _sanitize_layout(body)
    row = db.scalar(select(UserDesktopPref).where(UserDesktopPref.owner_id == user.id))
    if row:
        row.layout = layout
    else:
        db.add(UserDesktopPref(owner_id=user.id, layout=layout))
    db.commit()
    return Response(status_code=204)
