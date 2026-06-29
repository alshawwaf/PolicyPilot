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
    if path.endswith("/polls-fragment") or "/apply-status/" in path:
        return True
    # The API-explorer proxy relays the user's REAL Management/Gateway request+response bodies (which can
    # carry credentials / a session sid). Don't persist those to the activity log — it's a passthrough to
    # the user's own server, not portal traffic worth capturing in full.
    if path == "/api-explorer/proxy":
        return True
    return False


def _kind(path: str) -> str:
    if path.startswith("/gaia_api"):
        return "gaia_mock"
    if path.startswith(("/gdc/", "/netfeed/", "/ioc/")):
        return "feed_poll"
    # Datacenter mocks — token-prefixed, plus the apex (bare-host) vCenter/NSX-T endpoints.
    if (path.startswith(("/openstack/", "/vcenter/", "/nsxt/", "/policy/", "/sdk", "/rest/",
                          "/global-manager/", "/proxmox/", "/api2/json", "/aci/", "/k8s/", "/nutanix/",
                          "/api/nutanix/", "/api/vmm/", "/api/prism/",
                          "/api/aaaLogin", "/api/aaaRefresh", "/api/aaaLogout",
                          "/api/node/", "/api/class/", "/api/mo/"))
            or path.startswith("/api/session") or path.startswith("/api/v1/") or path == "/api"):
        return "datacenter"
    if path.startswith("/api"):
        return "api"
    return "ui"


def _soap_op(path: str, raw: bytes) -> str:
    """vCenter SOAP operation name (first element inside <Body>) for /sdk calls — surfaced in the
    log so each vSphere call is readable (RetrieveServiceContent / Login / RetrieveProperties...)."""
    if not (path.endswith("/sdk") and raw):
        return ""
    m = re.search(r"<(?:[\w.-]+:)?Body[^>]*>\s*<(?:[\w.-]+:)?([A-Za-z][\w.]*)",
                  raw.decode("utf-8", "replace"))
    return m.group(1) if m else ""


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
    if "xml" in content_type or text.lstrip().startswith("<"):  # SOAP / vCenter — keep raw, mask password
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
    """Adds defensive HTTP response headers to every reply: anti-clickjacking (the admin portal is never
    meant to be framed), MIME-sniff protection, a tight referrer policy, and HSTS when served over HTTPS.
    Deliberately minimal — no restrictive ``default-src`` CSP — so the embedded Swagger UI and the inline
    ``<script type="application/json">`` blobs keep working; only ``frame-ancestors`` is locked down."""

    _BASE = [
        (b"x-frame-options", b"DENY"),
        (b"content-security-policy", b"frame-ancestors 'none'"),
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
        src = req_headers.get("x-forwarded-for", "").split(",")[0].strip()
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
        op = _soap_op(path, req_body)
        disp = f"{path} · {op}" if op else path  # show the SOAP op for /sdk calls
        write_activity(kind=_kind(path), direction="inbound", method=method, path=disp,
                       source_ip=src, status=resp["status"], duration_ms=ms,
                       summary=f"{method} {disp} → {resp['status']}", detail=detail)
