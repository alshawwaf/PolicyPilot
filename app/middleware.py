"""Pure-ASGI middleware that logs ALL HTTP traffic to the ActivityLog with request/response
bodies, redacting secrets. Excludes only the log viewer itself and high-frequency polling
(so the log doesn't flood with its own refreshes). JSON and form-encoded bodies are parsed and
redacted; HTML response bodies are summarized (not stored) to keep entries readable.
"""
import json
import re
from urllib.parse import parse_qs
import time

from .services.activity import redact_body, redact_headers, write_activity

_MAX_BODY = 8000


def _excluded(path: str) -> bool:
    if path.startswith(("/activity", "/healthz", "/favicon", "/static")):
        return True
    if "/apply-status/" in path:
        return True
    # The API-explorer proxy relays the user's REAL Management/Gateway request+response bodies (which can
    # carry credentials / a session sid). Don't persist those to the activity log — it's a passthrough to
    # the user's own server, not portal traffic worth capturing in full.
    if path == "/api-explorer/proxy":
        return True
    return False


def _kind(path: str) -> str:
    # The machine surfaces (REST API, MCP, the inbound ticket webhook) vs. the portal UI.
    if path.startswith(("/dbapi", "/mcp")) or path == "/access-automation/webhook":
        return "api"
    return "ui"


def _redact_xml(text: str) -> str:
    """Mask <password>…</password> in SOAP/XML bodies (e.g. the vSphere Login call)."""
    return re.sub(r"(<(?:\w+:)?password[^>]*>).*?(</(?:\w+:)?password>)", r"\1***\2", text,
                  flags=re.S | re.I)


def _parse_request(raw: bytes, content_type: str):
    if not raw:
        return None
    text = raw.decode("utf-8", "replace")
    if "json" in content_type:
        try:
            return redact_body(json.loads(text))
        except Exception:
            pass
    if "xml" in content_type or text.lstrip().startswith("<"):  # XML body — keep raw, mask password
        return _redact_xml(text)[:_MAX_BODY]
    if "x-www-form-urlencoded" in content_type or ("=" in text and not text.lstrip().startswith("{")):
        try:
            flat = {k: (v[0] if len(v) == 1 else v) for k, v in parse_qs(text).items()}
            return redact_body(flat)
        except Exception:
            pass
    try:
        return redact_body(json.loads(text))
    except Exception:
        return text[:_MAX_BODY]


def _parse_response(raw: bytes, content_type: str):
    if not raw:
        return None
    if "text/html" in content_type:
        return f"(HTML page, {len(raw)} bytes)"
    text = raw.decode("utf-8", "replace")
    if "json" in content_type:
        try:
            return redact_body(json.loads(text))
        except Exception:
            pass
    return text[:_MAX_BODY]


class SecurityHeadersMiddleware:
    """Adds defensive HTTP response headers to every reply: anti-clickjacking, MIME-sniff protection, a
    tight referrer policy, and HSTS when served over HTTPS. Deliberately minimal — no restrictive
    ``default-src`` CSP — so the embedded Swagger UI and the inline ``<script type="application/json">``
    blobs keep working; only ``frame-ancestors`` is constrained. Framing is SAME-ORIGIN: the portal frames
    its OWN pages (the desktop shell opens each tool in a window via a same-origin iframe), but no foreign
    site can frame it — so the clickjacking protection is preserved (``'self'`` / SAMEORIGIN, not DENY)."""

    _BASE = [
        (b"x-frame-options", b"SAMEORIGIN"),
        (b"content-security-policy", b"frame-ancestors 'self'"),
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"same-origin"),
    ]

    def __init__(self, app, https: bool = False):
        self.app = app
        self._headers = list(self._BASE)
        if https:
            self._headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        async def snd(msg):
            if msg.get("type") == "http.response.start":
                headers = list(msg.get("headers") or [])
                have = {k.lower() for k, _ in headers}
                headers.extend((k, v) for k, v in self._headers if k not in have)
                msg = {**msg, "headers": headers}
            await send(msg)

        await self.app(scope, receive, snd)


class ActivityLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if scope.get("type") != "http" or _excluded(path):
            return await self.app(scope, receive, send)

        method = scope.get("method", "")
        req_body = bytearray()

        async def recv():
            msg = await receive()
            if msg.get("type") == "http.request" and len(req_body) < _MAX_BODY:
                req_body.extend(msg.get("body", b""))
            return msg

        resp = {"status": 0, "headers": [], "body": bytearray()}

        async def snd(msg):
            if msg.get("type") == "http.response.start":
                resp["status"] = msg.get("status", 0)
                resp["headers"] = msg.get("headers", [])
            elif msg.get("type") == "http.response.body" and len(resp["body"]) < _MAX_BODY:
                resp["body"].extend(msg.get("body", b""))
            await send(msg)

        t0 = time.perf_counter()
        try:
            await self.app(scope, recv, snd)
        finally:
            try:
                self._log(scope, path, method, bytes(req_body), resp,
                          round((time.perf_counter() - t0) * 1000))
            except Exception:
                pass

    def _log(self, scope, path, method, req_body, resp, ms):
        req_headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
        # Trust X-Forwarded-For only for the configured number of proxy hops (else it's spoofable); fall
        # back to the direct peer. Mirrors services.login_guard.client_ip so logged + throttled IPs agree.
        try:
            from .config import get_settings
            hops = max(0, int(get_settings().trusted_proxy_hops or 0))
        except Exception:  # noqa: BLE001
            hops = 0
        src = ""
        if hops:
            parts = [p.strip() for p in req_headers.get("x-forwarded-for", "").split(",") if p.strip()]
            if len(parts) >= hops:
                src = parts[-hops]
        if not src and scope.get("client"):
            src = scope["client"][0]
        resp_headers = {k.decode(): v.decode() for k, v in resp["headers"]}
        req_ct = req_headers.get("content-type", "")
        resp_ct = resp_headers.get("content-type", "")
        detail = {
            "request": {"headers": redact_headers(req_headers),
                        "query": scope.get("query_string", b"").decode(),
                        "body": _parse_request(req_body, req_ct)},
            "response": {"status": resp["status"], "content_type": resp_ct,
                         "body": _parse_response(bytes(resp["body"]), resp_ct)},
        }
        write_activity(kind=_kind(path), direction="inbound", method=method, path=path,
                       source_ip=src, status=resp["status"], duration_ms=ms,
                       summary=f"{method} {path} → {resp['status']}", detail=detail)
