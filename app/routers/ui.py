"""Server-rendered portal UI (Jinja2 + HTMX) — auth, home, MCP guide, API explorer."""
import re
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import DynamicLayer, Gateway, ManagementServer, User, UserDesktopPref
from ..security import get_user_or_none, hash_password, password_strength_error, verify_password
from ..services import coverage, login_guard

router = APIRouter(include_in_schema=False)
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
from .. import __version__ as _app_version
templates.env.globals["app_version"] = _app_version   # surfaced in the footer (single shared templates env)


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
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = login_guard.client_ip(request)
    wait = login_guard.locked_for(db, ip)
    if wait:
        return templates.TemplateResponse(
            request, "login.html",
            {"error": f"Too many failed attempts. Try again in {wait}s."}, status_code=429)
    user = db.scalar(select(User).where(User.username == username))
    if user is None or not verify_password(password, user.password_hash):
        login_guard.record_failure(db, ip)
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid credentials"}, status_code=401
        )
    login_guard.record_success(db, ip)
    request.session["uid"] = user.id
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "account.html",
                                      {"user": user, "flash": _pop_flash(request)})


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
    if email and ("@" not in email or " " in email or len(email) > 200):
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
DESKTOP_APP_KEYS = {"access", "layers", "management", "gateways", "agents", "apiexplorer",
                    "settings", "activity", "account"}
DEFAULT_DESKTOP_LAYOUT = {"dock": ["access", "layers", "management", "gateways", "agents", "settings", "activity"],
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
    return {"dock": dock or list(DEFAULT_DESKTOP_LAYOUT["dock"]), "desktop": desk}


def _load_desktop_layout(db: Session, user: User) -> dict:
    row = db.scalar(select(UserDesktopPref).where(UserDesktopPref.owner_id == user.id))
    return _sanitize_layout(row.layout) if (row and isinstance(row.layout, dict) and row.layout) else \
        {k: list(v) for k, v in DEFAULT_DESKTOP_LAYOUT.items()}


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
                                       "flash": _pop_flash(request)})


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
