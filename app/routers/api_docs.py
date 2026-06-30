"""PolicyPilot's OWN API docs — an in-portal, themed Swagger UI for the /dbapi/v1 REST API (the same
access-automation brain exposed over MCP and the ticketing webhook, as plain JSON).

Distinct from the Check Point "API explorer": that documents Check Point's Management/Gaia APIs; THIS
documents *this server's* API so integrators can drive PolicyPilot over HTTP. The spec is FastAPI's own
auto-generated OpenAPI, filtered to the ``api`` tag and decorated with a Bearer security scheme (api-scope
key) so Authorize + Try it out work same-origin. Pure UI — these two routes are hidden from the spec."""
from __future__ import annotations

import copy
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..db import get_db
from ..security import get_user_or_none

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

_API_TAG = "api"   # the tag on every /dbapi/v1 route (see routers/api_v1.py)


@router.get("/api-docs", response_class=HTMLResponse)
def api_docs_page(request: Request, db: Session = Depends(get_db)):
    """Themed Swagger UI for PolicyPilot's own REST API."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "api_docs.html", {})


@router.get("/api-docs/openapi.json")
def api_docs_spec(request: Request, download: int = 0, db: Session = Depends(get_db)):
    """FastAPI's live OpenAPI, filtered to the public REST API (the ``api`` tag) and decorated with a Bearer
    security scheme so Swagger shows Authorize and sends ``Authorization: Bearer <key>``. No ``servers`` is
    set, so Swagger resolves Try it out against the origin it loaded from — i.e. this same server.
    ``download=1`` serves it as a file ready to import into Postman or Bruno."""
    if get_user_or_none(request, db) is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    full = request.app.openapi()
    paths: dict = {}
    for path, item in (full.get("paths") or {}).items():
        methods = {}
        for method, op in item.items():
            if isinstance(op, dict) and _API_TAG in (op.get("tags") or []):
                op = dict(op)
                op["security"] = [{"ApiKeyAuth": []}]
                methods[method] = op
        if methods:
            paths[path] = methods
    components = copy.deepcopy(full.get("components") or {})   # keep all $ref'd schemas so bodies resolve
    components.setdefault("securitySchemes", {})["ApiKeyAuth"] = {
        "type": "http", "scheme": "bearer",
        "description": "An **api**-scope API key (Settings → API keys), sent as "
                       "`Authorization: Bearer <key>`. Read-only keys can call the read/preview endpoints; "
                       "apply/push need a write-enabled key, and publishing to a live server is "
                       "additionally admin-gated.",
    }
    spec = {
        "openapi": full.get("openapi", "3.1.0"),
        "info": {
            "title": "PolicyPilot API",
            "version": (full.get("info") or {}).get("version", "1"),
            "description": "Drive PolicyPilot over HTTP — the same access-automation engine exposed to LLM "
                           "agents (MCP) and ticketing systems (webhook), as a plain JSON REST API under "
                           "`/dbapi/v1`. Authenticate with an api-scope API key from Settings → API keys. "
                           "**Try it out** runs against this server (same origin).",
        },
        "paths": paths,
        "components": components,
        "tags": [{"name": _API_TAG, "description": "PolicyPilot REST API — /dbapi/v1"}],
        "security": [{"ApiKeyAuth": []}],
    }
    resp = JSONResponse(spec)
    if download:
        resp.headers["Content-Disposition"] = 'attachment; filename="policypilot-api.openapi.json"'
    return resp
