"""Check Point Reputation Service enrichment — warn before allowing traffic to a risky destination.

Queries Check Point's hosted reputation service (``rep.checkpoint.com``) for the reputation of an access
request's DESTINATION (a public IP or a domain) and returns a compact verdict the decision surfaces attach
to their result. Opt-in (``reputation_enrich`` setting, default off) and **fail-open**: any error, timeout,
missing key, or disabled setting yields ``None`` — reputation never blocks or breaks the access workflow,
it only adds an advisory.

Auth (per the service's REST contract): a one-time ``Client-Key`` fetches a bearer ``token`` valid ~1 week
from ``GET /rep-auth/service/v1.0/request``; every query sends both ``Client-Key`` and ``token``. We cache
the token (renew before expiry / on 403) and cache per-resource results briefly (the daily quota is finite).
TLS is always verified (default httpx behaviour — never disabled, org policy).

Only Check Point-controlled infrastructure is contacted, and only the destination indicator (IP / FQDN) the
operator is already asking to allow — no customer policy, rule content, or credentials leave the portal.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
import urllib.parse

import httpx

log = logging.getLogger("policypilot.reputation")

_BASE = "https://rep.checkpoint.com"
_AUTH_PATH = "/rep-auth/service/v1.0/request"
_IP_PATH = "/ip-rep/service/v3.0/query"
_URL_PATH = "/url-rep/service/v3.0/query"

_TIMEOUT = 6.0                      # a slow reputation lookup must not stall the decision — fail open instead
_TOKEN_TTL = 6 * 24 * 3600.0       # renew ~a day before the ~7-day server expiry
_RESULT_TTL = 3600.0               # cache a resource's verdict for an hour (quota protection)

# Severity → risk posture. The service returns a severity string; map it to how the UI/agent should treat it.
_HIGH = {"critical", "high"}
_MEDIUM = {"medium"}
# Classifications that are benign even if a severity slips through — never warn on these.
_BENIGN = {"benign", "trusted", "unknown", "n/a", "", "not classified", "unclassified"}

_lock = threading.Lock()
_token: dict = {"value": "", "at": -1e9}
_results: dict = {}                # resource -> (monotonic_at, verdict|None)


def _settings():
    from . import app_settings
    return app_settings


def enabled() -> bool:
    try:
        return bool(_settings().get("reputation_enrich"))
    except Exception:  # noqa: BLE001
        return False


def _api_key() -> str:
    """The Client-Key: a portal-set secret, else the PILOT_REPUTATION_API_KEY env fallback."""
    try:
        from ..config import get_settings
        env = getattr(get_settings(), "reputation_api_key", "") or ""
        return _settings().get_secret_or_env("reputation_api_key", env)
    except Exception:  # noqa: BLE001
        return ""


def _client() -> httpx.Client:
    # verify=True (default) — TLS always verified; no pinning needed for a public CP endpoint.
    return httpx.Client(base_url=_BASE, timeout=_TIMEOUT, headers={"User-Agent": "PolicyPilot"})


def _get_token(client: httpx.Client, key: str, *, force: bool = False) -> str:
    now = time.monotonic()
    with _lock:
        if not force and _token["value"] and (now - _token["at"]) < _TOKEN_TTL:
            return _token["value"]
    r = client.get(_AUTH_PATH, headers={"Client-Key": key})
    if r.status_code != 200 or not r.text.strip():
        raise RuntimeError(f"auth request failed (HTTP {r.status_code})")
    token = r.text.strip().strip('"')
    with _lock:
        _token["value"], _token["at"] = token, time.monotonic()
    return token


def _classify(reputation: dict) -> dict:
    """Turn the service's ``reputation`` object into a compact, UI/agent-ready verdict."""
    classification = str(reputation.get("classification") or "").strip()
    severity = str(reputation.get("severity") or "").strip()
    confidence = str(reputation.get("confidence") or "").strip()
    sev = severity.lower()
    benign = classification.lower() in _BENIGN
    if not benign and sev in _HIGH:
        posture = "high"
    elif not benign and sev in _MEDIUM:
        posture = "medium"
    else:
        posture = "low"
    return {"classification": classification or "Unknown", "severity": severity or "N/A",
            "confidence": confidence or "", "risk": posture}


def _query(client: httpx.Client, key: str, token: str, kind: str, resource: str) -> dict | None:
    path = _IP_PATH if kind == "ip" else _URL_PATH
    url = f"{path}?resource={urllib.parse.quote(resource, safe='')}"
    r = client.post(url, headers={"Client-Key": key, "token": token},
                    json={"request": [{"resource": resource}]})
    if r.status_code == 403:              # token expired/invalid — signal the caller to refresh once
        raise PermissionError("token rejected")
    if r.status_code != 200:
        raise RuntimeError(f"query failed (HTTP {r.status_code})")
    data = r.json()
    # The service returns either a single object or a {"response":[...]} / list wrapper — unwrap defensively.
    if isinstance(data, list):
        data = data[0] if data else {}
    if isinstance(data, dict) and isinstance(data.get("response"), list):
        data = data["response"][0] if data["response"] else {}
    reputation = (data or {}).get("reputation")
    if not isinstance(reputation, dict):
        return None
    return _classify(reputation)


def _destination(req) -> tuple[str, str] | None:
    """Extract a single reputation-checkable destination from the request, or None to skip.
    Returns ``(kind, resource)`` where kind is 'ip' or 'url'. Skips private/reserved IPs, CIDR ranges
    (only a single /32 host is checked), typed non-network kinds, and 'Any'."""
    kind = getattr(req, "dst_kind", "ip")
    if kind == "domain":
        val = (getattr(req, "dst_value", "") or "").strip()
        return ("url", val) if val else None
    if kind != "ip":
        return None                       # access-role / zone / dynamic-object — no network indicator
    cidrs = getattr(req, "dst_cidrs", []) or []
    if len(cidrs) != 1:
        return None                       # only enrich an unambiguous single destination
    try:
        net = ipaddress.ip_network(cidrs[0], strict=False)
    except ValueError:
        return None
    if net.num_addresses != 1:
        return None                       # a range, not a host — skip (too coarse to attribute reputation)
    host = net.network_address
    if not host.is_global:                # private / loopback / link-local / multicast / reserved
        return None
    return ("ip", str(host))


def _advisory(verdict: dict, resource: str) -> str:
    label = verdict["classification"]
    if verdict["risk"] == "high":
        return (f"⚠ Destination {resource} is classified {label} (severity {verdict['severity']}). "
                f"Check Point reputation flags this as high-risk — review carefully before allowing.")
    if verdict["risk"] == "medium":
        return (f"Caution: destination {resource} is classified {label} "
                f"(severity {verdict['severity']}). Consider whether this access is intended.")
    return f"Destination {resource} reputation: {label} (severity {verdict['severity']})."


def lookup(req) -> dict | None:
    """Reputation verdict for a request's destination, or None (skip / fail-open). Never raises."""
    if not enabled():
        return None
    dest = _destination(req)
    if dest is None:
        return None
    kind, resource = dest
    now = time.monotonic()
    with _lock:
        hit = _results.get(resource)
        if hit is not None and (now - hit[0]) < _RESULT_TTL:
            return hit[1]
    key = _api_key()
    if not key:
        log.info("reputation enrich on but no API key set (reputation_api_key / PILOT_REPUTATION_API_KEY)")
        return None
    verdict: dict | None = None
    try:
        with _client() as client:
            token = _get_token(client, key)
            try:
                verdict = _query(client, key, token, kind, resource)
            except PermissionError:                 # token expired mid-use — refresh once and retry
                token = _get_token(client, key, force=True)
                verdict = _query(client, key, token, kind, resource)
        if verdict is not None:
            verdict = {**verdict, "resource": resource, "source": "Check Point ThreatCloud"}
            verdict["advisory"] = _advisory(verdict, resource)
    except Exception as exc:  # noqa: BLE001 — enrichment is best-effort; never propagate
        log.warning("reputation lookup failed for %s: %s", resource, exc)
        verdict = None
    with _lock:
        _results[resource] = (time.monotonic(), verdict)
    return verdict


def attach(req, result: dict) -> dict:
    """Attach a reputation verdict to a decision result in place (when enabled + destination is checkable).
    Returns the same dict. Safe to call on any result — a skip/failure leaves it untouched."""
    try:
        verdict = lookup(req)
    except Exception:  # noqa: BLE001 — belt-and-suspenders; lookup already swallows
        verdict = None
    if verdict is not None:
        result["reputation"] = verdict
    return result
