"""Generic ticketing / ITSM webhook integration for access automation.

Vendor-neutral: any system that can POST JSON — ServiceNow, Jira, Remedy, Cherwell, Freshservice, a
custom portal, or plain curl — can drive the access-automation webhook. Inbound bodies are parsed with
generous field aliases into a canonical request; the result can be written back two ways:

  * GENERIC  -- the caller supplies a ``callback_url`` and we POST the result JSON there (works for any
               vendor that exposes an inbound endpoint, and for the synchronous-response pattern too),
  * BUILT-IN -- the ServiceNow Table API adapter writes a work note to the incident (DCSIM_SERVICENOW_*).

Security: TLS verification is ALWAYS on (never a skip-verify path). Inbound auth — the shared
``DCSIM_WEBHOOK_TOKEN`` checked as ``X-DCSim-Token`` — is enforced by the router BEFORE this module runs,
so a supplied ``callback_url`` always comes from an already-authenticated caller. Credentials come from
env, never hardcoded.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

import httpx

from ..config import get_settings
from . import app_settings
from .access_automation import AccessRequest, TYPED_KINDS

_TRUE = {"1", "true", "yes", "y", "on", "apply", "publish"}

# A dns-domain label set (RFC-1123-ish): one or more dot-separated labels, a 2+ char TLD. An optional
# leading dot is preserved — Check Point uses it to mean "this domain AND every sub-domain".
_DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass
class TicketRequest:
    ticket_id: str
    server_id: int
    layer: str
    request: AccessRequest
    apply: bool                         # True -> apply + publish; False -> preview/validate only
    package: Optional[str] = None
    callback_url: Optional[str] = None  # optional: where to POST the result back to (any vendor)
    callback_token: Optional[str] = None


def _first(data: dict, *names, default=None):
    for n in names:
        if n in data and data[n] not in (None, ""):
            return data[n]
    return default


def _norm_cidr(value: str) -> str:
    """A bare IP becomes a host prefix (/32 for v4, /128 for v6); a CIDR is validated and normalised.
    IPv4 and IPv6 are both supported — the engine reasons about each family in its own band (see
    access_automation._V6_BASE). Raises ValueError on garbage."""
    value = str(value).strip()
    if not value:
        raise ValueError("missing address")
    if "/" not in value:
        ip = ipaddress.ip_address(value)               # raises on garbage
        value = f"{value}/{ip.max_prefixlen}"           # /32 (v4) or /128 (v6)
    return str(ipaddress.ip_network(value, strict=False))


def _validate_port(port) -> str:
    """One service per request: a single numeric port, or a single lo-hi range. Rejects comma lists,
    named services and out-of-range values up front so the request never reaches the engine malformed
    (a bad port here becomes a clean 400, not an HTTP 500 deep in resolve_service)."""
    port = str(port if port is not None else "").strip()   # don't let integer 0 be swallowed by truthiness
    if not port:
        raise ValueError("port is required.")
    if "," in port:
        raise ValueError("port must be a single value or a single lo-hi range, not a comma list.")
    parts = [p.strip() for p in port.split("-")]
    if len(parts) > 2:
        raise ValueError("port range must be 'lo-hi'.")
    # Each part must be a CLEAN ascii-digit literal — reject '+443', ' 443 ', unicode digits, etc., which
    # int() would accept but the Check Point API rejects (the very 500 this guard exists to prevent).
    if not all(p.isascii() and p.isdigit() for p in parts):
        raise ValueError(f"port must be numeric (got {port!r}).")
    nums = [int(p) for p in parts]
    if any(n < 1 or n > 65535 for n in nums):       # 0 is not a usable destination port
        raise ValueError("port must be between 1 and 65535.")
    if len(nums) == 2 and nums[0] > nums[1]:
        raise ValueError("port range must have lo <= hi.")
    return str(nums[0]) if len(nums) == 1 else f"{nums[0]}-{nums[1]}"   # canonical form for apply + reuse


def _norm_endpoint(value) -> str:
    """A request endpoint is an IP / CIDR, or a family-agnostic literal Any (any / all / *) which maps to
    Check Point's predefined Any object (covers v4 AND v6). NOTE: 0.0.0.0/0 and ::/0 are NOT treated as
    Any — they are real, single-family networks (all-v4 / all-v6 respectively), so they resolve into one
    band only and materialise a family-correct network object; collapsing them to predefined Any would
    silently grant the OTHER family on apply."""
    v = str(value).strip()
    if v.lower() in ("any", "all", "*"):
        return "Any"
    return _norm_cidr(v)


def _norm_domain(value) -> str:
    """Validate + normalise a dns-domain request value. Lower-cased, trailing dot stripped; an optional
    leading dot (sub-domain semantics) is preserved. Raises ValueError on anything that isn't an FQDN."""
    raw = str(value).strip().lower().rstrip(".")
    sub = raw.startswith(".")
    base = raw.lstrip(".")
    if not _DOMAIN_RE.match(base):
        raise ValueError(f"'{value}' is not a valid domain (e.g. example.com, or .example.com for the "
                         f"domain and its sub-domains). If '{value}' is an APPLICATION (e.g. Facebook, "
                         f"Office365), pass it as the application — not as a domain destination.")
    return ("." if sub else "") + base


def _resolve_endpoint(value, kind, label) -> tuple[list, str, str]:
    """Normalise one source/destination by its KIND -> (cidrs, kind, typed_value). An IP endpoint
    resolves to a CIDR (typed_value empty); a typed endpoint validates its identity (a FQDN for a
    domain, an object name otherwise) and carries no CIDR. Raises ValueError on anything malformed."""
    kind = (kind or "ip").strip().lower()
    if kind == "ip":
        try:
            return [_norm_endpoint(value)], "ip", ""
        except ValueError as exc:
            raise ValueError(f"Invalid {label}: {exc}")
    if kind == "internet":
        # Check Point's predefined topology-based Internet object: a fixed singleton (the submitted value
        # is ignored), and meaningful ONLY as a destination — it scopes a rule to internet/DMZ-bound
        # traffic for Application Control / URL Filtering, which has no "source" analogue.
        if label != "destination":
            raise ValueError("the Internet object can only be used as a destination (it scopes "
                             "Application Control / URL Filtering traffic to the internet).")
        return [], "internet", "Internet"
    if kind not in TYPED_KINDS:
        raise ValueError(f"Invalid {label} type {kind!r}.")
    val = str(value or "").strip()
    if not val:
        raise ValueError(f"the {label} is typed as a {kind} but names no object.")
    if kind == "domain":
        return [], "domain", _norm_domain(val)
    # access-role / dynamic-object / updatable-object / security-zone: a Check Point object NAME. CP names
    # are permissive (spaces, etc.); reject only control characters and absurd lengths.
    if len(val) > 256 or any(ord(c) < 32 for c in val):
        raise ValueError(f"Invalid {label} object name.")
    return [], kind, val


def _to_name_list(v) -> list:
    """Normalise a string ('A, B' / 'A;B') or list into a clean, de-duped, order-preserving NAME list with
    the same length/control-char guard the endpoints use. Blank -> []."""
    if v is None:
        return []
    parts = v if isinstance(v, (list, tuple)) else re.split(r"[,;]", str(v))
    out: list = []
    for p in parts:
        nm = str(p).strip()
        if not nm:
            continue
        if len(nm) > 256 or any(ord(c) < 32 for c in nm):
            raise ValueError(f"invalid object name: {nm[:40]!r}")
        if nm not in out:
            out.append(nm)
    return out


def build_request(source, destination, protocol, port, application=None, service=None,
                  source_kind="ip", destination_kind="ip", action="Accept", inline_layer="",
                  action_settings_limit="", action_settings_captive_portal=False,
                  content=None, content_direction="any", content_negate=False,
                  time_objects=None, install_on=None, vpn=None) -> AccessRequest:
    """Validate + normalise a raw tuple into an AccessRequest. Shared by the UI and the webhook.
    Precedence: `application` (e.g. "Facebook") > `service` (a named non-port service, e.g. "icmp" /
    "GRE") > protocol+port. Source/destination may be an IP, a CIDR, 'Any', OR a typed (non-IP) object
    when ``source_kind``/``destination_kind`` is one of the typed kinds (domain / access-role /
    dynamic-object / updatable-object / security-zone) — then the value is the object's identity (an
    FQDN for a domain, the object name otherwise). ``action`` (full-column support) is Accept / Drop /
    Reject / Ask / Inform / Apply Layer; Apply Layer requires ``inline_layer``. Raises ValueError on
    anything malformed."""
    if source in (None, "") or destination in (None, ""):
        raise ValueError("source and destination are required.")
    # ACTION — canonicalize + validate up front (never a silent Accept on garbage/legacy).
    from .access_automation import canonical_action
    canon = canonical_action(action)
    if not canon:
        raise ValueError(f"unsupported action “{action}” — use one of Accept, Drop, Reject, Ask, Inform, "
                         f"Apply Layer.")
    inline_layer = str(inline_layer or "").strip()
    if canon == "Apply Layer" and not inline_layer:
        raise ValueError("action 'Apply Layer' requires an inline_layer (the layer name to divert into).")
    if canon != "Apply Layer" and inline_layer:
        raise ValueError(f"inline_layer is only valid with action 'Apply Layer', not '{canon}'.")
    # Action-settings (UserCheck limit / captive portal) only exist on an ALLOWING action (Accept/Ask/Inform).
    # Reject loud rather than silently dropping them on a Drop/Reject/Apply-Layer ticket.
    if canon not in ("Accept", "Ask", "Inform") and (str(action_settings_limit or "").strip()
                                                      or bool(action_settings_captive_portal)):
        raise ValueError(f"action-settings (limit / captive portal) are only valid with an allowing action "
                         f"(Accept/Ask/Inform), not '{canon}'.")
    # MATCH-GATING columns (full-column support). Normalize string-or-list -> clean NAME list; validate the
    # content direction enum; collapse an Any/Policy-Targets install-on to [] (omit). All object refs are
    # reuse-only — existence is validated at apply time, not here.
    # "Any"/"All" data-type == no content restriction — strip it BEFORE validating negate (matching how the
    # engine normalizes content), so a content=["Any"] ticket is not a phantom restriction and content_negate
    # over only "Any" raises a clear error instead of silently writing a permissive rule.
    content_l = [c for c in _to_name_list(content) if c.lower() not in ("any", "all", "*")]
    content_negate = bool(content_negate)
    if content_negate and not content_l:
        raise ValueError("content_negate requires a real content (data-type) name, not Any.")
    cdir = str(content_direction or "any").strip().lower()
    if cdir not in ("any", "up", "down"):
        raise ValueError("content_direction must be 'any', 'up', or 'down'.")
    time_l = _to_name_list(time_objects)
    install_l = [n for n in _to_name_list(install_on)
                 if n.lower() not in ("any", "all", "*", "policy targets")]   # default token -> omit
    vpn_l = None
    if vpn is not None:
        # directional pairs ({from,to}) are unverified in the spec -> reject BEFORE stringifying, never guess.
        if isinstance(vpn, dict) or any(isinstance(x, dict) for x in (vpn if isinstance(vpn, (list, tuple)) else [])):
            raise ValueError("directional VPN ({from, to}) is not supported — assign a VPN community by name.")
        vpn_l = [n for n in _to_name_list(vpn) if n.lower() != "any"]   # "Any"/[] -> [] (Any, omitted at write); keep communities + All_GwToGw
    s_cidrs, s_kind, s_val = _resolve_endpoint(source, source_kind, "source")
    d_cidrs, d_kind, d_val = _resolve_endpoint(destination, destination_kind, "destination")
    application = str(application).strip() if application else ""
    # Check Point best practice (R82.10 "Best Practices for Access Control Rules"): an Application Control
    # / URL Filtering rule's destination is the predefined "Internet" object, NOT "Any" — Internet scopes
    # the rule to internet/DMZ-bound traffic via gateway topology, so the gateway doesn't inspect
    # internal-to-internal flows. So when an application request left the destination as Any, build it
    # against Internet instead. A SPECIFIC destination (an internal server/network/domain) or an explicit
    # Internet pick is honored as-is; only the "anywhere" default is upgraded.
    if application and d_kind == "ip" and d_cidrs == ["Any"]:
        d_cidrs, d_kind, d_val = [], "internet", "Internet"
    common = dict(src_cidrs=s_cidrs, dst_cidrs=d_cidrs,
                  src_kind=s_kind, src_value=s_val, dst_kind=d_kind, dst_value=d_val,
                  action=canon, inline_layer=inline_layer,
                  action_settings_limit=str(action_settings_limit or "").strip(),
                  action_settings_captive_portal=bool(action_settings_captive_portal),
                  content=(content_l or None), content_direction=cdir, content_negate=content_negate,
                  time_objects=time_l, install_on=install_l, vpn=vpn_l)
    if application:
        return AccessRequest(**common, application=application)
    service = str(service).strip() if service else ""
    if service:
        return AccessRequest(**common, service=service)
    protocol = str(protocol or "tcp").lower()
    if protocol not in ("tcp", "udp", "sctp"):   # the port-based protocols; ICMP/GRE/RPC/… go via `service`
        raise ValueError("protocol must be 'tcp', 'udp', or 'sctp' (use a named service otherwise).")
    return AccessRequest(**common, protocol=protocol, ports=_validate_port(port))


def _resolve_webhook_action(data: dict) -> str:
    """Resolve the requested verdict from a webhook body WITHOUT letting the generic ``action`` field break
    back-compat. A ServiceNow ticket very often carries its OWN unrelated ``action`` field (the record's
    workflow action), so a DEDICATED verdict field (``verdict`` / ``u_action`` / ``cp_action``) wins and is
    taken strictly (a typo there errors — the caller meant a verdict). The bare ``action`` alias is honoured
    only when it actually names a Check Point verdict; an unrecognized value falls back to the default Accept
    instead of hard-failing the whole ticket (the pre-full-column behaviour)."""
    from .access_automation import canonical_action
    for key in ("verdict", "u_action", "cp_action"):
        v = str(_first(data, key, default="") or "").strip()
        if v:
            return v                                   # explicit verdict field -> strict (build_request validates)
    a = str(_first(data, "action", default="") or "").strip()
    return a if (a and canonical_action(a)) else "Accept"


def parse_payload(data: dict) -> TicketRequest:
    """Build a TicketRequest from a webhook body, accepting common vendor field aliases (ServiceNow
    ``u_*`` / ``number`` / ``sys_id``, Jira ``key``, plus plain names). Raises ValueError on anything
    malformed so the router can return a clean 400."""
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object body.")

    ticket_id = str(_first(data, "ticket_id", "ticket", "number", "key", "id", "request_id",
                            "u_number", "sys_id", default="")).strip()
    server_raw = _first(data, "server_id", "management_server_id", "sms_id", "u_server_id")
    if server_raw in (None, ""):
        raise ValueError("server_id is required (which saved management server to target).")
    try:
        server_id = int(server_raw)
    except (TypeError, ValueError):
        raise ValueError("server_id must be a number.")

    layer = str(_first(data, "layer", "policy_layer", "u_layer", default="")).strip()
    if not layer:
        raise ValueError("layer is required (the access layer name to evaluate).")

    req = build_request(
        _first(data, "source", "src", "source_ip", "u_source"),
        _first(data, "destination", "dst", "dest", "destination_ip", "u_destination"),
        _first(data, "protocol", "proto", "u_protocol", default="tcp"),
        _first(data, "port", "ports", "service_port", "u_port", default=""),
        _first(data, "application", "app", "u_application"),
        _first(data, "service", "service_name", "u_service"),
        source_kind=_first(data, "source_kind", "src_kind", "u_source_kind", default="ip"),
        destination_kind=_first(data, "destination_kind", "dst_kind", "dest_kind",
                                "u_destination_kind", default="ip"),
        action=_resolve_webhook_action(data),
        inline_layer=_first(data, "inline_layer", "inline-layer", "apply_layer", "u_inline_layer", default=""),
        action_settings_limit=_first(data, "action_limit", "u_action_limit", default=""),
        action_settings_captive_portal=str(_first(data, "captive_portal", "enable_captive_portal",
                                                  "u_captive_portal", default="")).strip().lower() in _TRUE,
        content=_first(data, "content", "data_type", "data_types", "content_type", "u_content"),
        content_direction=_first(data, "content_direction", "data_direction", "u_content_direction",
                                 default="any"),
        content_negate=str(_first(data, "content_negate", "data_negate", "u_content_negate",
                                  default="")).strip().lower() in _TRUE,
        time_objects=_first(data, "time", "time_objects", "time_object", "window", "u_time"),
        install_on=_first(data, "install_on", "install-on", "targets", "gateways", "gateway",
                          "u_install_on", "u_targets"),
        vpn=_first(data, "vpn", "vpn_community", "vpn_communities", "u_vpn"),
    )
    apply_flag = str(_first(data, "apply", "commit", "u_apply", default="")).strip().lower() in _TRUE
    return TicketRequest(
        ticket_id=ticket_id, server_id=server_id, layer=layer, request=req, apply=apply_flag,
        package=_first(data, "package", "u_package"),
        callback_url=_first(data, "callback_url", "callbackUrl", "callback", "response_url",
                            "u_callback_url"),
        callback_token=_first(data, "callback_token", "callbackToken"),
    )


# --------------------------------------------------------------------------- #
# Result write-back
# --------------------------------------------------------------------------- #
def summarize(result: dict, ticket_id: str = "") -> str:
    """A compact work-note line from an execute()/preview() result."""
    if not result.get("ok"):
        return f"[DC-Sim] access automation FAILED: {result.get('error', 'unknown error')}"
    bits = [f"[DC-Sim] outcome={result.get('outcome', '?')}", result.get("reason", "")]
    for key, label in (("source_object", "source"), ("destination_object", "destination"),
                       ("service_object", "service"), ("position", "position")):
        if result.get(key):
            bits.append(f"{label}={result[key]}")
    tgt = result.get("target_rule")
    if tgt:
        bits.append(f"rule={tgt.get('uid')}")
    bits.append("published" if result.get("published") else
                ("validated (not committed)" if result.get("applied") else "no change"))
    return " | ".join(b for b in bits if b)


def notify(ticket: TicketRequest, result: dict) -> dict:
    """Push the result back to the originating system. Dispatch order:
       1. a generic ``callback_url`` the (authenticated) caller supplied -> POST the result JSON,
       2. otherwise the built-in ServiceNow Table API adapter, if configured,
       3. otherwise nothing (the caller already has the synchronous response)."""
    if ticket.callback_url:
        return _post_callback(ticket, result)
    if servicenow_configured():
        return update_servicenow(ticket.ticket_id, summarize(result, ticket.ticket_id))
    return {"skipped": "no callback_url supplied and no ServiceNow callback configured"}


def _post_callback(ticket: TicketRequest, result: dict) -> dict:
    """Generic write-back: POST the result to the caller-supplied URL. TLS verification stays on; the
    optional ``callback_token`` is echoed as X-DCSim-Token so the receiver can authenticate us."""
    headers = {"Content-Type": "application/json"}
    if ticket.callback_token:
        headers["X-DCSim-Token"] = ticket.callback_token
    payload = {"ticket_id": ticket.ticket_id,
               "applied": bool(result.get("applied")),   # what actually committed, not the request's intent
               "published": bool(result.get("published")),
               "outcome": result.get("outcome"), "summary": summarize(result, ticket.ticket_id),
               "result": result}
    try:
        with httpx.Client(timeout=15.0, verify=True) as c:   # TLS verification ALWAYS on
            r = c.post(ticket.callback_url, json=payload, headers=headers)
            return {"ok": r.status_code in (200, 201, 202, 204), "status": r.status_code,
                    "via": "callback_url"}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"callback POST failed: {exc}", "via": "callback_url"}


# --- built-in ServiceNow Table API adapter (optional) ----------------------------------------
def _servicenow_cfg() -> tuple[str, str, str, str]:
    """(instance, user, password, table) resolved from Settings → Ticket write-back, with the
    DCSIM_SERVICENOW_* env vars as fallback. The password is decrypted from its encrypted-at-rest row."""
    s = get_settings()
    instance = app_settings.get_or_env("servicenow_instance", s.servicenow_instance)
    user = app_settings.get_or_env("servicenow_user", s.servicenow_user)
    password = app_settings.get_secret_or_env("servicenow_password", s.servicenow_password)
    table = app_settings.get_or_env("servicenow_table", s.servicenow_table) or "incident"
    return instance, user, password, table


def servicenow_configured() -> bool:
    instance, user, password, _ = _servicenow_cfg()
    return bool(instance and user and password)


def update_servicenow(ticket_id: str, work_notes: str, fields: Optional[dict] = None) -> dict:
    """Append a work note (and optional fields) to a ServiceNow incident via the Table API. Best-effort
    and config-guarded; returns {skipped} when not configured. TLS verification stays on."""
    instance, user, password, table = _servicenow_cfg()
    if not (instance and user and password):
        return {"skipped": "ServiceNow callback not configured"}
    if not ticket_id:
        return {"skipped": "no ticket id to update"}
    base = instance.rstrip("/")
    auth = (user, password)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    body = {"work_notes": work_notes, **(fields or {})}
    try:
        with httpx.Client(timeout=15.0, verify=True) as c:   # TLS verification ALWAYS on
            sys_id = ticket_id
            if not _looks_like_sys_id(ticket_id):
                r = c.get(f"{base}/api/now/table/{table}", auth=auth, headers=headers,
                          params={"sysparm_query": f"number={ticket_id}",
                                  "sysparm_fields": "sys_id", "sysparm_limit": 1})
                rows = (r.json().get("result") or []) if r.status_code == 200 else []
                if not rows:
                    return {"ok": False, "error": f"incident {ticket_id} not found", "via": "servicenow"}
                sys_id = rows[0]["sys_id"]
            r = c.patch(f"{base}/api/now/table/{table}/{sys_id}", auth=auth, headers=headers, json=body)
            return {"ok": r.status_code in (200, 201), "status": r.status_code, "sys_id": sys_id,
                    "via": "servicenow"}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"ServiceNow callback failed: {exc}", "via": "servicenow"}


def _looks_like_sys_id(value: str) -> bool:
    return len(value) == 32 and all(c in "0123456789abcdef" for c in value.lower())
