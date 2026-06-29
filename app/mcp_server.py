"""MCP server exposing PolicyPilot's agent tools (services.mcp_tools) over Streamable-HTTP for n8n / LLM
agents. IMPORT-GUARDED on the `mcp` SDK: that package ships via Artifactory (not PyPI), so if it isn't
installed ``build_mcp_app()`` returns None and the app simply doesn't mount ``/mcp`` — the rest of
PolicyPilot is unaffected. All tool LOGIC lives in services.mcp_tools (SDK-independent + unit-tested); this
file is only the thin SDK wrapper + a pure-ASGI bearer-token gate.

Activate: install `mcp` via Artifactory; the endpoint mounts at /mcp whenever the SDK is present and is
ENABLED by generating an mcp-scope API key (on the MCP page or Settings → API keys). An agent authenticates
with `Authorization: Bearer <that key>`; create/revoke takes effect with no redeploy. Writes are further
gated by the `mcp_allow_publish` Setting (default OFF). The standalone `serve()` entrypoint is a separate
run mode that still uses a DCSIM_MCP_TOKEN env var. See docs/mcp-n8n.md."""
from __future__ import annotations

import contextlib
import hmac

try:
    from mcp.server.fastmcp import FastMCP
    _HAVE_MCP, _IMPORT_ERR = True, ""
except Exception as exc:  # noqa: BLE001 — SDK absent (Artifactory-only) -> feature stays dormant
    FastMCP = None
    _HAVE_MCP, _IMPORT_ERR = False, str(exc)

# The inner Streamable-HTTP ASGI app, kept so the parent app can run ITS lifespan (the session manager's
# task group). A mounted sub-app's own lifespan never fires, so without this the manager is uninitialized.
_INNER = None

# The tools an agent can call (logic in services.mcp_tools; registered by name + docstring + type hints).
_TOOLS = ("list_management_servers", "list_access_layers", "decide_access", "apply_access",
          "remove_access", "amend_access_rule", "list_changes", "revert_change", "correlate_service",
          "correlate_application", "summarize_layer", "analyze_policy", "coverage_lookup")


def have_mcp() -> bool:
    """True if the MCP SDK is importable (so /mcp can be served)."""
    return _HAVE_MCP


def tool_catalog() -> list:
    """[{name, summary}] for the tools an agent gets — names + the first docstring line. Works without
    the SDK installed (reads services.mcp_tools directly), so the /mcp-guide page always renders."""
    from .services import mcp_tools as t
    out = []
    for name in _TOOLS:
        fn = getattr(t, name, None)
        summary = ""
        if fn and fn.__doc__:
            summary = " ".join(fn.__doc__.strip().split())   # collapse the docstring to one line
        out.append({"name": name, "summary": summary})
    return out


def import_error() -> str:
    return _IMPORT_ERR


def mcp_enabled() -> bool:
    """True when /mcp is live — i.e. at least one ACTIVE mcp-scope API key exists. API keys are the single
    auth mechanism (generated on the MCP page or Settings → API keys); set/revoke takes effect with no
    redeploy. No key -> the endpoint returns 503."""
    try:
        from .services import api_keys
        return api_keys.any_active("mcp")
    except Exception:  # noqa: BLE001
        return False


def token_configured() -> bool:
    """Back-compat alias for the guide/status page: is /mcp live (an active mcp-scope API key exists)?"""
    return mcp_enabled()


def authorize_mcp(presented: str) -> bool:
    """True if a presented bearer is a valid ACTIVE mcp-scope API key (constant-time inside api_keys.verify).
    Resolved PER REQUEST so create/revoke take effect with no redeploy."""
    if not presented:
        return False
    try:
        from .services import api_keys
        return api_keys.verify(presented, "mcp")
    except Exception:  # noqa: BLE001
        return False


async def _send_json(send, status: int, body: bytes):
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


class _BearerGuard:
    """Pure-ASGI bearer gate wrapping the MCP app (no coupling to the SDK's auth). Authorization is
    decided PER REQUEST by the injected callables so tokens/keys can be set/rotated/revoked at runtime
    with no redeploy: ``enabled_fn()`` → is the endpoint configured at all (else 503), ``verify_fn(token)``
    → is this bearer valid (else 401, constant-time inside). Only the ``lifespan`` scope passes through
    unguarded (so the inner session manager starts); websocket/unknown scopes are refused."""
    def __init__(self, app, verify_fn, enabled_fn):
        self.app, self._verify, self._enabled = app, verify_fn, enabled_fn

    async def __call__(self, scope, receive, send):
        stype = scope.get("type")
        if stype == "http":
            try:
                enabled = bool(self._enabled())
            except Exception:  # noqa: BLE001
                enabled = False
            if not enabled:
                await _send_json(send, 503,
                                 b'{"error":"MCP disabled - generate an mcp-scope API key on the MCP page '
                                 b'(or Settings -> API keys) to enable /mcp"}')
                return
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"").decode("latin-1").strip()
            # Distinguish the failure modes so the client log says WHAT to fix, not just "401":
            #  - header absent  -> the request reached us without it; almost always the CLIENT isn't
            #    attaching it, or a reverse proxy dropped it on a redirect/forward (NOT a bad key).
            #  - wrong scheme   -> present but not "Bearer ...".
            #  - key rejected   -> a bearer arrived but isn't a valid active mcp-scope key. The same
            #    message for every bad/expired/revoked/wrong-scope key (no existence oracle).
            if not auth:
                await _send_json(send, 401,
                                 b'{"error":"Unauthorized - no Authorization header reached the server. '
                                 b'Set Authorization: Bearer <mcp-key> on the client, and POST the '
                                 b'trailing-slash URL /mcp/ so a proxy redirect cannot strip it."}')
                return
            if not auth.startswith("Bearer "):
                await _send_json(send, 401,
                                 b'{"error":"Unauthorized - Authorization must use the Bearer scheme: '
                                 b'Authorization: Bearer <mcp-key>"}')
                return
            presented = auth[7:].strip()   # tolerate a stray trailing newline/space from a client header field
            try:
                ok = bool(presented) and bool(self._verify(presented))
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                await _send_json(send, 401,
                                 b'{"error":"Unauthorized - the bearer is not a valid active mcp-scope API '
                                 b'key (confirm it is not revoked/expired and was generated with mcp scope)"}')
                return
            await self.app(scope, receive, send)
            return
        if stype == "lifespan":
            await self.app(scope, receive, send)   # let the inner session manager start/stop
            return
        if stype == "websocket":                   # no ws transport today; reject rather than pass unauth'd
            await send({"type": "websocket.close", "code": 1008})
            return
        # unknown scope type: do not forward to the inner app unguarded


def _open_host_security():
    """A TransportSecuritySettings that turns OFF the SDK's DNS-rebinding Host/Origin allowlist.

    Why we must: FastMCP defaults its ``host`` to 127.0.0.1, and for a localhost host it AUTO-ENABLES DNS
    rebinding protection with ``allowed_hosts=["127.0.0.1:*","localhost:*","[::1]:*"]``. Mounted in the
    portal behind a TLS-terminating reverse proxy, every real request arrives with ``Host: <your-domain>``
    — not in that allowlist — so the transport rejects it with HTTP 421 "Invalid Host header" BEFORE any
    tool runs (it works on localhost, fails through the proxy). Why it's safe to disable: /mcp is a remote,
    BEARER-authenticated API (``_BearerGuard`` is the real access control) sitting behind a proxy that owns
    the Host header. DNS-rebinding protection defends *localhost* servers a victim's browser can reach by a
    rebound name; against a token-gated remote endpoint a rebind yields nothing without the bearer. Returns
    None if the SDK predates the class (then we just don't pass it — older SDKs have no auto-allowlist)."""
    try:
        from mcp.server.transport_security import TransportSecuritySettings
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    except Exception:  # noqa: BLE001
        return None


def _new_server():
    # stateless_http=True makes each tool call independent -> no persistent session-manager lifespan, which
    # is what lets the app mount cleanly inside FastAPI. streamable_http_path="/" puts the handler at the
    # mount root so the endpoint is /mcp (not /mcp/mcp — FastMCP defaults its own path to /mcp).
    # transport_security disables the localhost Host allowlist that otherwise 421s every proxied request
    # (see _open_host_security). Degrade gracefully if an SDK version doesn't accept one of these kwargs:
    # try the richest kwargs first, then drop transport_security, then the bare forms.
    sec = _open_host_security()
    attempts = []
    if sec is not None:
        attempts += [{"stateless_http": True, "streamable_http_path": "/", "transport_security": sec},
                     {"stateless_http": True, "transport_security": sec},
                     {"transport_security": sec}]
    attempts += [{"stateless_http": True, "streamable_http_path": "/"}, {"stateless_http": True}, {}]
    for kwargs in attempts:
        try:
            return FastMCP("PolicyPilot", **kwargs)
        except TypeError:
            continue
    return FastMCP("PolicyPilot")


def _asgi_app(mcp):
    # The Streamable-HTTP ASGI app; the accessor name has shifted across SDK versions.
    for attr in ("streamable_http_app", "http_app", "sse_app"):
        fn = getattr(mcp, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:  # noqa: BLE001
                continue
    return None


def build_mcp_app(verify_fn=None, enabled_fn=None):
    """A guarded ASGI app to mount at /mcp — or None only if the MCP SDK isn't installed (then the caller
    just doesn't mount it). It is mounted REGARDLESS of whether any token/key is set yet: the guard
    decides per request via ``verify_fn``/``enabled_fn`` (default: the MCP token + active API keys) and
    returns 503 while nothing is configured, so a key/token added later in Settings activates the endpoint
    with no redeploy."""
    if not _HAVE_MCP:
        return None
    verify_fn = verify_fn or authorize_mcp
    enabled_fn = enabled_fn or mcp_enabled
    from .services import mcp_tools as t
    mcp = _new_server()
    for name in _TOOLS:
        fn = getattr(t, name, None)
        if fn is not None:
            mcp.tool()(fn)              # name = fn.__name__, description = docstring, schema from hints
    app = _asgi_app(mcp)
    if app is None:
        return None
    global _INNER
    _INNER = app                          # parent lifespan runs its session manager (see mcp_lifespan)
    return _BearerGuard(app, verify_fn, enabled_fn)


@contextlib.asynccontextmanager
async def mcp_lifespan(app):
    """Run the mounted MCP app's lifespan (its Streamable-HTTP session-manager task group) from the
    PARENT app's lifespan — a mounted sub-app's own lifespan doesn't fire, so without this a tool call
    fails with 'Task group is not initialized'. No-op when MCP isn't mounted."""
    inner = _INNER
    ctx = getattr(getattr(inner, "router", None), "lifespan_context", None)
    if inner is None or ctx is None:
        yield
        return
    async with ctx(inner):
        yield


def main():
    """Run the MCP server standalone (alternative to mounting in the portal): reads DCSIM_MCP_TOKEN +
    DCSIM_MCP_HOST/PORT and serves Streamable-HTTP. `python -m app.mcp_server`. This out-of-portal path
    has no DB-backed Settings, so the token is env-only here (the portal Setting governs the mounted /mcp)."""
    import os
    if not _HAVE_MCP:
        raise SystemExit(f"the `mcp` SDK is not installed (install via Artifactory): {_IMPORT_ERR}")
    token = os.environ.get("DCSIM_MCP_TOKEN", "")
    if not token:
        raise SystemExit("set DCSIM_MCP_TOKEN to a strong secret first")
    # Env-only auth in the standalone process (no DB-backed Settings / API keys here).
    app = build_mcp_app(verify_fn=lambda p: hmac.compare_digest(p, token), enabled_fn=lambda: True)
    if app is None:
        raise SystemExit("could not build the MCP app")
    import uvicorn
    uvicorn.run(app, host=os.environ.get("DCSIM_MCP_HOST", "127.0.0.1"),
                port=int(os.environ.get("DCSIM_MCP_PORT", "8765")))


if __name__ == "__main__":
    main()
