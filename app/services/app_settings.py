"""User-tunable runtime behaviour for how the portal talks to a Check Point SMS.

Real production integrations do NOT log in and re-pull the whole policy on every request — Check Point
throttles remote API logins (3 per admin, per domain, per 60s in R81+) and caps concurrent sessions
(100). So the portal (a) reuses a shared read-only session for reads and (b) caches the pulled policy,
refreshing only when a new revision is published. Every knob here is editable from the **Settings**
page so an admin controls the behaviour from the portal — no code or env edits.

Stored in the ``AppState`` key/value table so a change from any worker/replica is shared; a small
in-process cache keeps these off the hot path (mirrors the SIEM pause toggle)."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Union

from ..db import SessionLocal
from ..models import AppState
from . import crypto

_log = logging.getLogger("dcsim.settings")
_PREFIX = "set:"            # AppState key namespace, so settings never collide with other state
_CACHE_TTL = 2.0
_cache: dict = {"at": -1e9, "vals": {}}

# Secrets ("secret" kind) are stored ENCRYPTED at rest (AES-256-GCM, org policy) and never enter the
# general value map / settings render path — they're read out-of-band via get_secret(). A short cache
# keeps the auth hot-path (e.g. the MCP bearer check) off the DB without making rotation feel laggy.
_SECRET_TTL = 5.0
_secret_cache: dict = {}    # key -> (monotonic_at, plaintext)


def _secret_info(key: str) -> bytes:
    return b"dcsim-setting:" + key.encode()


@dataclass(frozen=True)
class Setting:
    key: str
    kind: str                       # "bool" | "int" | "str" | "secret" | "choice"
    default: Union[bool, int, str]
    label: str
    help: str
    group: str = "Management API"
    min: int = 0
    max: int = 0                    # for "str": max length (0 → default cap)
    generate: bool = False          # secret-only: offer a "Generate" button (a strong random token)
    choices: tuple = ()             # choice-only: ((value, label), …) rendered as a <select>; value validated


SETTINGS: list[Setting] = [
    Setting("mgmt_session_reuse", "bool", True,
            "Reuse a shared session for reads",
            "Log in once and reuse a read-only session for all reads (layers, rulebase, export, "
            "preview) instead of logging in on every request. Check Point throttles remote logins to 3 "
            "per minute, so this is what prevents the 'too many login requests' failures. Strongly "
            "recommended — turn off only to debug."),
    Setting("mgmt_session_timeout", "int", 3600,
            "Read session timeout (seconds)",
            "Idle timeout for the shared read session. Check Point allows 60–3600s; the portal "
            "keepalives it so it survives a whole demo.", min=60, max=3600),
    Setting("mgmt_keepalive", "bool", True,
            "Keep the read session alive",
            "Send a lightweight keepalive before reusing an idle session so it never expires mid-demo "
            "(keepalive does not count against the login throttle)."),
    Setting("mgmt_policy_cache", "bool", True,
            "Cache the pulled policy",
            "Reuse the parsed rulebase while the policy is unchanged instead of pulling the whole "
            "rulebase + objects every time. Change is detected by the latest published revision, so the "
            "portal re-pulls only after someone publishes."),
    Setting("mgmt_cache_revalidate", "int", 30,
            "Revalidate interval (seconds)",
            "Minimum time between change-checks. Within this window the cached policy is served without "
            "even asking the SMS whether it changed (0 = check every request).", min=0, max=3600),
    Setting("mgmt_cache_max_age", "int", 900,
            "Force full refresh after (seconds)",
            "Re-pull the whole policy at least this often regardless of revision — a safety net for "
            "changes made outside the published-session signal.", min=30, max=86400),
    Setting("mgmt_write_fresh", "bool", True,
            "Always pull fresh before applying",
            "Before committing a change (apply / publish), re-pull the live policy so the decision is "
            "never based on a cached rulebase. Recommended."),
    Setting("mgmt_write_session_timeout", "int", 300,
            "Write session idle timeout (seconds)",
            "Idle timeout for the read-write session used by an apply/publish. An apply runs in seconds, "
            "so a short value means a lock left by an interrupted apply (a 'Locked for editing' error) "
            "clears quickly instead of lingering ~10 minutes. 60–3600.", min=60, max=3600),
    Setting("mgmt_write_session_reuse", "bool", True,
            "Reuse a session for applies",
            "Log in once and reuse a read-write session across back-to-back applies/publishes instead of "
            "logging in on every change. Check Point throttles remote logins to 3 per minute, so a burst of "
            "applies (a batch of tickets) otherwise fails with 'too many login requests'. The pooled session "
            "is always returned with no pending changes (it holds no locks while idle) and is dropped if an "
            "apply errors, so lock-safety is preserved. Turn off to force a fresh login per apply."),
    Setting("mgmt_login_retries", "int", 2,
            "Retry a throttled login",
            "If a login is rejected by Check Point's rate limit (HTTP 429, 'too many requests'), wait and "
            "retry this many times before failing. Smooths a burst of apply/publish calls that out-pace the "
            "3-logins-per-minute throttle. 0 = fail immediately.", min=0, max=5),

    # --- Storage & retention -------------------------------------------------------------------------
    # The two high-volume tables (the Activity log and the built-in SIEM receiver) are bounded so a
    # long-running demo — a Data Center importing on a schedule, or Log Exporter streaming for days —
    # can never fill the disk. A background sweep (started in main.lifespan) enforces these caps.
    Setting("activity_max_records", "int", 5000,
            "Activity log — keep newest N",
            "Hard cap on the Activity log table: older entries are trimmed (cheap indexed delete) so the "
            "database can't grow without bound while integrations run. 0 = unlimited (not recommended in "
            "production).", group="Storage & retention", min=0, max=2_000_000),
    Setting("activity_max_age_days", "int", 0,
            "Activity log — also delete older than (days)",
            "Additionally drop Activity log entries older than this many days, regardless of count. "
            "0 = keep by record count only.", group="Storage & retention", min=0, max=3650),
    Setting("siem_max_records", "int", 2000,
            "SIEM receiver — keep newest N",
            "Hard cap on the built-in SIEM (Log Exporter) table so a flooding gateway can't fill the disk "
            "— it's a live demo viewer, not a log archive. 0 = unlimited (not recommended).",
            group="Storage & retention", min=0, max=2_000_000),
    Setting("retention_sweep_min", "int", 5,
            "Housekeeping interval (minutes)",
            "How often the background pass enforces the caps above. Trimming is a cheap indexed range "
            "delete that fires only when a table is over cap, so a few minutes is plenty.",
            group="Storage & retention", min=1, max=1440),
    Setting("retention_notify", "bool", True,
            "Notify when records are trimmed",
            "Post a notification (the header bell) when a housekeeping sweep trims records, so retention "
            "is never silent. Throttled to at most once an hour.", group="Storage & retention"),

    # --- Access automation — naming of auto-created objects ------------------------------------------
    # When the engine has to CREATE an object for a request, it names it from these templates. Defaults
    # reproduce the built-in h-/n- scheme; clear a field to fall back to the default.
    Setting("name_host", "str", "h-{ip_dashed}",
            "Host object name",
            "Name for a host object auto-created for a single-address (/32) endpoint. Placeholders: "
            "{ip} (e.g. 1.2.3.4), {ip_dashed} (1-2-3-4).", group="Access automation", max=100),
    Setting("name_network", "str", "n-{ip_dashed}-{prefix}",
            "Network object name",
            "Name for a network object auto-created for a CIDR endpoint. Placeholders: {ip}, {ip_dashed}, "
            "{prefix} (the mask length, e.g. 24).", group="Access automation", max=100),
    Setting("name_service", "str", "{PROTO}-{port}",
            "Service object name",
            "Name for a TCP/UDP service auto-created for a requested port. Placeholders: {proto} (tcp), "
            "{PROTO} (TCP), {port}.", group="Access automation", max=100),
    Setting("name_rule", "str", "TKT-{ticket}",
            "New rule name",
            "Name for a rule the engine creates. Placeholders: {ticket}, {app}, {service}, {source}, "
            "{dest}, {layer}, {action}, {proto}, {port} (e.g. TKT-{ticket}-{app}). With no ticket id (and a "
            "ticket-based template) the rule is left unnamed and Check Point auto-names it.",
            group="Access automation", max=120),
    Setting("aa_rule_comment", "str", "Automated from ticket {ticket}",
            "New rule comment",
            "Comment/justification written onto a created rule. Same placeholders as the rule name "
            "({ticket}, {app}, {service}, {source}, {dest}, {layer}, …). Free text — spaces/punctuation kept.",
            group="Access automation", max=300),
    Setting("aa_rule_track", "choice", "Log",
            "New rule track / log",
            "The Track setting on a created rule.",
            group="Access automation",
            choices=(("Log", "Log"), ("None", "None"), ("Detailed Log", "Detailed Log"),
                     ("Extended Log", "Extended Log"))),
    Setting("aa_rule_tags", "str", "",
            "New rule tags",
            "Comma-separated tag names to attach to a created rule (e.g. automation, pov). The tags must "
            "already exist on the management server — Check Point won't auto-create them. Blank = none.",
            group="Access automation", max=300),
    Setting("aa_rule_section", "str", "Provisioned (automation)",
            "Provisioned-rule section",
            "When the engine places a created rule at the cleanup floor (no more-specific anchor), it groups "
            "it into a section by this name, created just ABOVE the layer's cleanup section — so a new "
            "business rule never lands INSIDE the 'Cleanup' section (Check Point's organize-by-section best "
            "practice). The rule's first-match HEIGHT is unchanged (still above the cleanup); only its "
            "section is tidied. Blank = no section management (place at the bare bottom, the old behavior).",
            group="Access automation", max=120),
    # --- Decision / placement logic (tune the engine from here — no code) ----------------------------
    # Each knob maps to one judgment call in the reuse-or-create engine; defaults are the recommended
    # behaviour, so leaving them as-is decides exactly as documented. (See the "How it decides" diagram.)
    # A PROFILE bundles all the knobs into one choice; "Custom" hands control back to the toggles below.
    Setting("aa_profile", "choice", "balanced",
            "Behavior profile",
            "A one-click preset for how aggressively the engine reshapes policy. Conservative: never "
            "touch existing rules or override a deny (always create a new rule, place it below any block, "
            "flag it). Balanced (recommended): reuse/widen where exact, carve apps and override denies by "
            "placement so the access works, conditions respected, advisories on. Aggressive: same as "
            "Balanced plus treat conditional rules (time / VPN / content / install-on) as unconditional — "
            "the fewest rules, least friction. Custom: ignore the profile and use the individual toggles "
            "below. (For the one-sentence agent demo, use the Autopilot preset under MCP / agent.)",
            group="Access automation logic",
            choices=(("balanced", "Balanced — recommended default"),
                     ("conservative", "Conservative — never modify or override existing rules"),
                     ("aggressive", "Aggressive — fewest rules, least friction"),
                     ("custom", "Custom — use the individual toggles below"))),
    Setting("aa_app_carveout", "bool", True,
            "Carve out an application above a blocking rule",
            "When an APPLICATION request (e.g. Facebook) is blocked by a rule in its path (a broad L4 "
            "port Drop, or an app-category Drop), create the new app-Accept ABOVE that rule. Check Point "
            "then identifies the app and accepts it while all other traffic still hits the blocking rule "
            "— a precise carve-out that actually achieves the request. OFF: place the new rule below and "
            "just flag it (conservative, but the rule may be shadowed and not take effect).",
            group="Access automation logic"),
    Setting("aa_override_blocking_deny", "bool", True,
            "Override a blocking deny by placement",
            "When an existing Drop already blocks the request, create the new allow ABOVE it so the access "
            "takes effect (the deny still applies to everything else). OFF: never override an admin's "
            "deny — place the new rule below it (it won't take effect until the deny is changed) and flag "
            "it for review.",
            group="Access automation logic"),
    Setting("aa_prefer_widen", "bool", True,
            "Reuse a rule by widening it when possible",
            "Prefer adding the request's value to an existing matching rule's cell (no new rule) when a "
            "rule matches exactly in the other two columns. OFF: always create a fresh least-privilege "
            "rule instead of widening a shared one.",
            group="Access automation logic"),
    Setting("aa_emit_notes", "bool", True,
            "Show advisory 'review later' notes",
            "Attach the advisory 'possible match — review later' notes (opaque/conditional rules in the "
            "path, etc.). OFF: quiet mode — the notes are hidden. Placement safety is unchanged either way; "
            "only the advisories are suppressed.",
            group="Access automation logic"),
    Setting("aa_ignore_conditions", "bool", False,
            "Evaluate conditional rules as unconditional",
            "Treat rules scoped by a column the engine doesn't model (VPN community/direction, time, "
            "data/content, install-on) as if that condition weren't there — so a conditional Accept can "
            "count as covering and a conditional Drop as blocking.",
            group="Access automation logic"),
    Setting("aa_scope_overrides", "text", "",
            "Per-scope profile overrides",
            "Use a DIFFERENT profile for specific scopes — one per line, “scope = profile”. Scope is a "
            "management server (its name or id), or “server:layer”, or “*:layer” (that layer on any server). "
            "Profile is conservative / balanced / aggressive. Most-specific match wins (exact "
            "server+layer ▸ *:layer ▸ server); anything unmatched uses the profile above. Blank lines and "
            "# comments are ignored. Example:\n"
            "Production = conservative\n"
            "*:DMZ = aggressive\n"
            "HQ-SMS:DNS_Layer = balanced",
            group="Access automation logic", max=4000),

    # --- MCP / agent ---------------------------------------------------------------------------------
    # The /mcp endpoint (for n8n / LLM agents) is enabled by an active MCP-scope API KEY (Settings → API
    # keys, generated right on the MCP page). No separate bearer-token setting — one auth mechanism. This
    # toggle only gates whether an agent may PUBLISH to a live SMS: OFF (default) -> decide/preview/correlate
    # and dry-run-apply (validate then discard) work, but apply_access(publish=true) is REFUSED — letting an
    # LLM commit to live policy is high-stakes, so it's an explicit admin opt-in.
    Setting("mcp_allow_publish", "bool", False,
            "Let the MCP agent publish to live policy",
            "Allow an MCP/LLM agent (authenticated with an MCP-scope API key) to commit + publish rules to a "
            "live management server. Leave OFF unless you intend agentic changes to reach production — with "
            "it off, agents can still decide, preview, and dry-run (validate-and-discard).",
            group="MCP / agent"),
    Setting("aa_autopilot", "bool", False,
            "Autopilot — one-turn apply & publish (lab demo)",
            "The headline lab demo: tells the agent it is pre-authorized to resolve, apply AND publish the "
            "WHOLE change in a single turn — no confirmation step. Carried as an 'autopilot' flag on the "
            "tool results. Pair with 'Let the MCP agent publish' (above) and the Aggressive profile — the "
            "Autopilot preset button on Access automation logic sets all three at once. Lab/demo only.",
            group="MCP / agent"),

    # --- Ticketing webhook ---------------------------------------------------------------------------
    # The inbound POST /access-automation/webhook (ServiceNow / Jira / custom portal). Setting the token
    # here ENABLES it with no redeploy; clearing it disables it. The token grants policy publish on every
    # ALLOWED server, so it's stored encrypted and treated as top-tier.
    Setting("webhook_token", "secret", "",
            "Inbound webhook token (X-DCSim-Token)",
            "Shared secret a ticketing system sends as the `X-DCSim-Token` header to POST an access "
            "request. Setting it here enables POST /access-automation/webhook with no redeploy; clearing "
            "it falls back to the DCSIM_WEBHOOK_TOKEN env var (the endpoint is disabled only when BOTH are "
            "unset). Stored encrypted at rest.",
            group="Ticketing webhook", generate=True),
    Setting("webhook_server_ids", "str", "",
            "Restrict the webhook to server ids",
            "Comma-separated management-server ids the webhook may target (e.g. 1,3). LEAVE BLANK to allow "
            "all allowed servers. A malformed value is rejected (the webhook fails closed — it never "
            "silently widens to all). Falls back to DCSIM_WEBHOOK_SERVER_IDS when blank.",
            group="Ticketing webhook", max=200),

    # --- Ticket write-back -----------------------------------------------------------------------------
    # Write-back is vendor-neutral: a ticket that includes a `callback_url` gets the result POSTed there
    # (any system). These fields configure the OPTIONAL built-in ServiceNow Table API adapter, used only
    # when no callback_url is supplied — it PATCHes the decision + rule UID into an incident's work notes
    # (TLS verification always on). The password is encrypted at rest; the rest are plain.
    Setting("servicenow_instance", "str", "",
            "ServiceNow instance URL",
            "Base URL of your ServiceNow instance, e.g. https://dev12345.service-now.com. The write-back "
            "is active only when instance + user + password are all set. Falls back to "
            "DCSIM_SERVICENOW_INSTANCE when blank.",
            group="Ticket write-back", max=200),
    Setting("servicenow_user", "str", "",
            "ServiceNow user",
            "Table API username for the write-back. Falls back to DCSIM_SERVICENOW_USER when blank.",
            group="Ticket write-back", max=100),
    Setting("servicenow_password", "secret", "",
            "ServiceNow password",
            "Table API password for the write-back. Stored encrypted at rest. Falls back to "
            "DCSIM_SERVICENOW_PASSWORD when empty.",
            group="Ticket write-back"),
    Setting("servicenow_table", "str", "",
            "ServiceNow table",
            "Table the decision is written to. Leave blank for 'incident'. Falls back to "
            "DCSIM_SERVICENOW_TABLE when blank.",
            group="Ticket write-back", max=60),

    # --- Portal --------------------------------------------------------------------------------------
    Setting("base_url", "str", "",
            "Public base URL",
            "The public URL this portal is reached at (e.g. https://dcsim.example.com), stamped into the "
            "feed / GDC / Keystone / gaia_api URLs shown to the SE and the MCP/webhook endpoints on the "
            "guide pages. Set it here to change the displayed URLs with no redeploy. Leave blank to use "
            "DCSIM_BASE_URL (or http://localhost:8000 in dev). NOTE: the session-cookie 'Secure' flag is "
            "still decided at startup from DCSIM_BASE_URL's scheme, so for HTTPS cookie hardening set the "
            "env var too.",
            group="Portal", max=200),
]

_BY_KEY = {s.key: s for s in SETTINGS}


def defaults() -> dict:
    # Secrets are handled out-of-band (get_secret) and never enter the general value map / render path.
    return {s.key: s.default for s in SETTINGS if s.kind != "secret"}


def _coerce(s: Setting, raw):
    if s.kind == "bool":
        return str(raw) == "1"
    if s.kind == "choice":
        v = "" if raw is None else str(raw)
        return v if v in {c[0] for c in s.choices} else s.default   # unknown value -> default (fail safe)
    if s.kind in ("str", "text"):                                   # text = multiline (rendered as a textarea)
        cap = s.max or (4000 if s.kind == "text" else 200)
        return ("" if raw is None else str(raw))[:cap]
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return s.default
    return max(s.min, min(s.max, v))


def _to_text(s: Setting, value) -> str:
    if s.kind == "bool":
        truthy = value is True or str(value).strip().lower() in ("1", "true", "on", "yes")
        return "1" if truthy else "0"
    if s.kind in ("str", "choice", "text"):
        return _coerce(s, value)
    return str(_coerce(s, str(value)))


def all_values(fresh: bool = False) -> dict:
    """The full, validated settings map (defaults overlaid with any stored values). Cached ~2s."""
    now = time.monotonic()
    if not fresh and (now - _cache["at"]) <= _CACHE_TTL and _cache["vals"]:
        return dict(_cache["vals"])
    vals = defaults()
    try:
        db = SessionLocal()
        try:
            for s in SETTINGS:
                if s.kind == "secret":        # never read/return a secret here (would leak into render)
                    continue
                row = db.get(AppState, _PREFIX + s.key)
                if row is not None:
                    vals[s.key] = _coerce(s, row.value)
        finally:
            db.close()
    except Exception:  # noqa: BLE001 — a DB read failure degrades to defaults (callers add env fallback), never 500
        _log.warning("app_settings.all_values: DB read failed; serving defaults")
        return defaults()
    _cache.update(at=now, vals=vals)
    return dict(vals)


def get(key: str):
    """One validated value (falls back to the default). Cheap — reads the ~2s cache."""
    return all_values().get(key, _BY_KEY[key].default if key in _BY_KEY else None)


def save(values: dict) -> dict:
    """Persist the provided keys (unknown keys ignored; values validated + clamped). Returns the new
    full value map and busts the cache so the change takes effect immediately across the process."""
    db = SessionLocal()
    try:
        for s in SETTINGS:
            if s.kind == "secret" or s.key not in values:
                continue                      # secrets go through set_secret/clear_secret, never here
            text = _to_text(s, values[s.key])
            row = db.get(AppState, _PREFIX + s.key)
            if row is None:
                db.add(AppState(key=_PREFIX + s.key, value=text))
            else:
                row.value = text
        db.commit()
    finally:
        db.close()
    _cache["at"] = -1e9
    return all_values(fresh=True)


# --- Secrets (encrypted at rest) ---------------------------------------------------------------------

def secret_settings() -> list[Setting]:
    return [s for s in SETTINGS if s.kind == "secret"]


def secret_available() -> bool:
    """True when secrets can actually be stored (AES-256 key material is configured). When False the UI
    must tell the admin to set DCSIM_ENCRYPTION_KEY / DCSIM_SESSION_SECRET and fall back to env vars."""
    return crypto.available()


def get_secret(key: str) -> str:
    """The decrypted plaintext of a stored secret, or "" if unset/undecryptable. Short-TTL cached so an
    auth hot-path (the MCP bearer check) doesn't hit the DB per request, while rotation still lands fast."""
    now = time.monotonic()
    hit = _secret_cache.get(key)
    if hit is not None and (now - hit[0]) <= _SECRET_TTL:
        return hit[1]
    plain = ""
    try:
        db = SessionLocal()
        try:
            row = db.get(AppState, _PREFIX + key)
            if row is not None and row.value:
                plain = crypto.decrypt(row.value, _secret_info(key)) or ""
                if not plain:
                    # a row exists but won't decrypt — wrong/rotated key, not "unset". Surface it (key
                    # name only, never the value) so a key/session-secret change doesn't silently orphan
                    # the secret and revert auth to the env fallback with no signal.
                    _log.warning("app_settings.get_secret(%s): stored value did not decrypt "
                                 "(encryption key changed?); falling back to env/disabled", key)
        finally:
            db.close()
    except Exception:  # noqa: BLE001 — a DB hiccup on the auth path must fail safe (env fallback), not 500
        _log.warning("app_settings.get_secret(%s): read failed; falling back to env/disabled", key)
        return ""
    _secret_cache[key] = (now, plain)
    return plain


def secret_is_set(key: str) -> bool:
    """True when a usable (decryptable, non-empty) secret is stored for this key."""
    return bool(get_secret(key))


def secret_status() -> dict:
    """{key: bool is_set} for every secret setting — for the UI status pills (never the value)."""
    return {s.key: secret_is_set(s.key) for s in secret_settings()}


def set_secret(key: str, plaintext: str) -> None:
    """Encrypt + store a secret. Empty plaintext is a no-op (the UI submits blank to mean 'keep current').
    Raises RuntimeError when encryption is unavailable — we never store a credential in cleartext."""
    if not plaintext:
        return
    token = crypto.encrypt(plaintext, _secret_info(key))    # raises if crypto unavailable
    db = SessionLocal()
    try:
        row = db.get(AppState, _PREFIX + key)
        if row is None:
            db.add(AppState(key=_PREFIX + key, value=token))
        else:
            row.value = token
        db.commit()
    finally:
        db.close()
    _secret_cache.pop(key, None)


def clear_secret(key: str) -> None:
    """Remove a stored secret (the endpoint/integration falls back to its env var, or off)."""
    db = SessionLocal()
    try:
        row = db.get(AppState, _PREFIX + key)
        if row is not None:
            db.delete(row)
            db.commit()
    finally:
        db.close()
    _secret_cache.pop(key, None)


# --- Runtime resolution with env fallback ------------------------------------------------------------
# A portal Setting takes precedence; a matching DCSIM_ env var is the fallback (so existing env-based
# deployments keep working and a value can be set/rotated from the UI without a redeploy).

def get_or_env(key: str, env_value) -> str:
    """A non-secret string setting if set, else the supplied env value (e.g. get_settings().webhook_server_ids)."""
    v = get(key)
    return v if v not in (None, "") else (env_value or "")


def get_secret_or_env(key: str, env_value) -> str:
    """A stored secret if set, else the supplied env value (the env var is the fallback)."""
    return get_secret(key) or (env_value or "")


def base_url() -> str:
    """The portal's public base URL: the 'base_url' Setting if set, else DCSIM_BASE_URL (default
    http://localhost:8000). Single resolution point for every emitted feed/endpoint URL."""
    from ..config import get_settings
    return get_or_env("base_url", get_settings().base_url) or "http://localhost:8000"
