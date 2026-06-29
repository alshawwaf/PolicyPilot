"""Application entrypoint: wiring, session middleware, DB bootstrap, admin seed."""
import asyncio
import logging
import os
import secrets
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware

from . import __version__
from .config import get_settings
from .db import SessionLocal, init_db
from .models import User
from .middleware import ActivityLogMiddleware, SecurityHeadersMiddleware


def _setup_logging() -> None:
    """Emit the app's own ``policypilot.*`` logs (MCP mount, credential / cache warnings) to stderr at
    INFO by default — uvicorn doesn't configure our loggers, so without this they're silent in a PoV. A
    dedicated handler (propagate off) avoids double-logging when a parent handler also exists."""
    raw = os.environ.get("PILOT_LOG_LEVEL", "INFO").strip()
    lvl = int(raw) if raw.isdigit() else logging.getLevelName(raw.upper())
    if not isinstance(lvl, int):          # an unknown level name -> don't abort boot, fall back to INFO
        lvl = logging.INFO
    log = logging.getLogger("policypilot")
    if not log.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        log.addHandler(h)
        log.propagate = False
    log.setLevel(lvl)
from .routers import (
    access_automation, activity, api_v1, dynamic_layers, exports, gateways,
    gaia_mock, mgmt, notifications, settings as settings_router, ui,
)
from .security import hash_password


def _seed_admin(settings) -> None:
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == settings.admin_username)):
            return
        password = settings.admin_password or secrets.token_urlsafe(12)
        db.add(User(username=settings.admin_username, password_hash=hash_password(password)))
        db.commit()
        if not settings.admin_password:
            banner = "=" * 64
            print(banner, file=sys.stderr)
            print(f"  Portal admin created:  {settings.admin_username} / {password}", file=sys.stderr)
            print("  Set PILOT_ADMIN_PASSWORD to pin your own password.", file=sys.stderr)
            print(banner, file=sys.stderr)


async def _retention_loop():
    """Storage guardrail: periodically trim the Activity log to the admin-configured caps
    so a long-running demo can't fill the disk. Defensive — an iteration failure is logged and the loop
    continues; the interval is read live so a Settings change takes effect on the next pass."""
    from .services import app_settings, retention
    await asyncio.sleep(20)   # let startup settle; the first pass also clears any pre-existing backlog
    while True:
        try:
            await asyncio.to_thread(retention.run_once)
        except Exception:  # noqa: BLE001 — housekeeping must never crash the app
            logging.getLogger("policypilot.retention").exception("retention loop iteration failed")
        try:
            interval = max(1, int(app_settings.get("retention_sweep_min"))) * 60
        except Exception:  # noqa: BLE001
            interval = 300
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db()
    _seed_admin(settings)
    retention_task = asyncio.create_task(_retention_loop())
    from . import mcp_server                          # run the mounted /mcp app's session manager (no-op
    try:                                              # if MCP isn't mounted)
        async with mcp_server.mcp_lifespan(app):
            yield
    finally:
        retention_task.cancel()
        from .services.mgmt_api import close_pool   # log out pooled read sessions on shutdown
        close_pool()


class _MCPCanonicalPath:
    """Serve a bare ``/mcp`` WITHOUT the 307 → ``/mcp/`` redirect. The Streamable-HTTP endpoint is mounted
    at ``/mcp`` with its handler at ``/`` (so it lives at ``/mcp/``); Starlette redirects the slash-less
    ``/mcp`` to ``/mcp/``, and some MCP clients — or a TLS-terminating reverse proxy — drop the
    ``Authorization`` header on that redirect, so the bearer arrives empty and the server answers 401. We
    rewrite the EXACT path ``/mcp`` to ``/mcp/`` in-place (no client-visible redirect); everything else is
    untouched, so both ``/mcp`` and ``/mcp/`` now work and keep the auth header."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("path") == "/mcp":
            scope = dict(scope, path="/mcp/", raw_path=b"/mcp/")
        await self.app(scope, receive, send)


def create_app() -> FastAPI:
    _setup_logging()
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=__version__, lifespan=lifespan)

    session_secret = settings.session_secret
    if not session_secret:
        session_secret = secrets.token_urlsafe(32)
        print(
            "WARNING: PILOT_SESSION_SECRET not set — using an ephemeral key "
            "(sessions drop on restart). Set it in production.",
            file=sys.stderr,
        )
    app.add_middleware(SessionMiddleware, secret_key=session_secret, same_site="lax",
                       https_only=settings.base_url.startswith("https"), max_age=14 * 24 * 3600)
    app.add_middleware(ActivityLogMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, https=settings.base_url.startswith("https"))
    app.add_middleware(_MCPCanonicalPath)   # /mcp served without the auth-dropping 307 -> /mcp/ redirect

    app.include_router(ui.router)
    app.include_router(gaia_mock.router)
    app.include_router(dynamic_layers.router)
    app.include_router(gateways.router)
    app.include_router(activity.router)
    app.include_router(mgmt.router)
    app.include_router(access_automation.router)
    app.include_router(settings_router.router)
    app.include_router(notifications.router)
    app.include_router(exports.router)
    app.include_router(api_v1.router)   # general REST API for any HTTP client (api-scope key auth)

    # MCP server for n8n / LLM agents — mounted at /mcp whenever the SDK is installed (Artifactory).
    # Auth is a single mechanism: an active mcp-scope API KEY, verified PER REQUEST. While none exists the
    # endpoint returns 503; generating a key (on the MCP page) activates it with no redeploy. If the SDK is
    # absent the endpoint is simply not mounted; the rest is unaffected.
    try:
        from . import mcp_server
        mcp_app = mcp_server.build_mcp_app()   # default guard: active mcp-scope API keys
        if mcp_app is not None:
            app.mount("/mcp", mcp_app)
    except Exception:  # noqa: BLE001 — never let the optional MCP mount break app startup
        pass

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
