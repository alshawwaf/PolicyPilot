"""PolicyPilot's general REST API (/dbapi/v1) for any HTTP client — the same access-automation brain
exposed over MCP and the ticketing webhook, as plain JSON. Authenticated with an **api**-scope API key
sent as ``Authorization: Bearer <key>`` (mint one in Settings → API keys). No valid key → 401. It's a
thin, documented wrapper over services.mcp_tools (so behaviour + safety match MCP exactly: reads/preview/
correlate are always available; apply only PUBLISHES when the admin enabled the publish toggle).

The prefix is /dbapi/v1. Auto-documented in the portal's OpenAPI (/docs, /openapi.json)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..services import api_keys, mcp_tools

router = APIRouter(prefix="/dbapi/v1", tags=["api"])


def require_api_key(scope: str = "api"):
    """A dependency that requires a valid ``scope`` API key in ``Authorization: Bearer <key>`` (401 else).
    Reusable on any endpoint: ``Depends(require_api_key("api"))``."""
    def _dep(authorization: str = Header(default="")):
        presented = authorization[7:].strip() if authorization.startswith("Bearer ") else ""
        if not presented or not api_keys.verify(presented, scope):
            raise HTTPException(status_code=401,
                                detail="Invalid or missing API key — send 'Authorization: Bearer <key>' "
                                       "with an api-scope key (create one in Settings → API keys).")
        return True
    return _dep


_API = Depends(require_api_key("api"))


def _respond(result: dict):
    """Map a tool result dict to an HTTP status: an error with no decision outcome → 404/400; else 200
    (a valid decision whose publish was gated still returns 200 with published=false in the body)."""
    if isinstance(result, dict) and result.get("error") and not result.get("outcome"):
        code = 404 if "not found" in str(result["error"]).lower() else 400
        return JSONResponse(result, status_code=code)
    return result


# --- request bodies ------------------------------------------------------------------------------
class DecideBody(BaseModel):
    server_id: int
    source: str
    destination: str
    layer: str = "Network"
    service: str | None = None
    port: str | None = None
    protocol: str = "tcp"
    application: str | None = None
    package: str | None = None
    # typed endpoints + full-column support (parity with the MCP tool / webhook): the REST client must be
    # able to request every access-rule column, or decide/apply silently ignore them (a write that omits the
    # very column the caller asked for). model_dump() is splatted straight into decide_access/apply_access,
    # whose signatures define these exact names.
    source_kind: str = "ip"
    destination_kind: str = "ip"
    action: str = "Accept"
    inline_layer: str | None = None
    action_limit: str | None = None
    captive_portal: bool = False
    content: list[str] | None = None
    content_direction: str = "any"
    content_negate: bool = False
    time_objects: list[str] | None = None
    install_on: list[str] | None = None
    vpn: list[str] | None = None


class ApplyBody(DecideBody):
    publish: bool = False
    ticket_id: str = ""


class CorrelateBody(BaseModel):
    server_id: int
    name: str


# --- read ----------------------------------------------------------------------------------------
@router.get("/servers", summary="List management servers")
def api_servers(_=_API):
    return mcp_tools.list_management_servers()


@router.get("/layers", summary="List access layers on a server")
def api_layers(server_id: int, _=_API):
    return _respond(mcp_tools.list_access_layers(server_id))


@router.get("/layers/summary", summary="High-level summary of an access layer")
def api_layer_summary(server_id: int, layer: str, _=_API):
    return _respond(mcp_tools.summarize_layer(server_id, layer))


@router.get("/layers/analyze", summary="Policy insights for an access layer (shadowed / permissive)")
def api_layer_analyze(server_id: int, layer: str, _=_API):
    return _respond(mcp_tools.analyze_policy(server_id, layer))


@router.get("/coverage", summary="Terraform/Ansible coverage for a CP object")
def api_coverage(api: str = "management", name: str = "", version: str = "", _=_API):
    return _respond(mcp_tools.coverage_lookup(api, name, version))


# --- access automation ---------------------------------------------------------------------------
@router.post("/access/decide", summary="Preview a decision (read-only)")
def api_decide(body: DecideBody, _=_API):
    return _respond(mcp_tools.decide_access(**body.model_dump()))


@router.post("/access/apply", summary="Apply an access request (publish is admin-gated)")
def api_apply(body: ApplyBody, _=_API):
    return _respond(mcp_tools.apply_access(**body.model_dump()))


@router.post("/access/correlate/service", summary="Resolve a service/protocol name to a CP object")
def api_correlate_service(body: CorrelateBody, _=_API):
    return _respond(mcp_tools.correlate_service(body.server_id, body.name))


@router.post("/access/correlate/application", summary="Resolve an application/site name to a CP object")
def api_correlate_application(body: CorrelateBody, _=_API):
    return _respond(mcp_tools.correlate_application(body.server_id, body.name))


# --- dynamic layers (Rail B) — author + push an access rulebase to a gateway via the Gaia API -----
class DynRuleBody(BaseModel):
    layer: str
    source: str
    destination: str
    service: str = "any"
    action: str = "Accept"
    name: str = ""
    position: str = "bottom"


class DynRuleRemoveBody(BaseModel):
    layer: str
    rule: str


class DynPushBody(BaseModel):
    layer: str
    gateway: str = ""          # blank or "mock" = the built-in demo target; else a gateway name/id/host
    dry_run: bool = False


@router.get("/gateways", summary="List saved gateways (dynamic-layer push targets)")
def api_gateways(_=_API):
    return mcp_tools.list_gateways()


@router.get("/dynamic-layers", summary="List dynamic layers")
def api_dynamic_layers(_=_API):
    return mcp_tools.list_dynamic_layers()


@router.get("/dynamic-layers/get", summary="Read one dynamic layer's rulebase")
def api_dynamic_layer(layer: str, _=_API):
    return _respond(mcp_tools.get_dynamic_layer(layer))


@router.post("/dynamic-layers/rule", summary="Add a rule to a dynamic layer (edit only — push to apply)")
def api_dynamic_rule_add(body: DynRuleBody, _=_API):
    return _respond(mcp_tools.add_dynamic_rule(**body.model_dump()))


@router.post("/dynamic-layers/rule/remove", summary="Remove a rule from a dynamic layer")
def api_dynamic_rule_remove(body: DynRuleRemoveBody, _=_API):
    return _respond(mcp_tools.remove_dynamic_rule(body.layer, body.rule))


@router.post("/dynamic-layers/push", summary="Push a dynamic layer to a gateway (real-gateway push is admin-gated)")
def api_dynamic_push(body: DynPushBody, _=_API):
    return _respond(mcp_tools.push_dynamic_layer(body.layer, body.gateway, body.dry_run))
