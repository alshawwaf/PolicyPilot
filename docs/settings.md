# Settings (portal-configurable behaviour, secrets & API keys)

The **Settings** page is where an admin tunes the portal at runtime — no code, no env edit, no
redeploy. For a PoV that matters: you set the MCP/webhook/ServiceNow secrets, mint scoped API keys,
and dial in how the portal talks to a Check Point SMS, all from the browser while the demo is live.
Three things live here: portal-configurable integration secrets, named API keys, and the SMS
session-reuse + policy-cache knobs.

- Settings router (page + save + key create/revoke): [`app/routers/settings.py`](../app/routers/settings.py)
- Setting definitions + secret store (AES-256-GCM, env fallback): [`app/services/app_settings.py`](../app/services/app_settings.py)
- Named API keys (SHA-256 hashed, scoped, revocable): [`app/services/api_keys.py`](../app/services/api_keys.py)
- Env-var fallbacks (`PILOT_*`): [`app/config.py`](../app/config.py)

## Use it

1. Portal → **Settings** (auth-gated; an unauthenticated request redirects to `/login`).
2. Edit any group, then **Save** — `POST /settings` validates + clamps every value and it takes
   effect immediately (the ~2s value cache is busted). **Restore defaults** (`POST /settings/reset`)
   reverts the non-secret settings.
3. For secrets, type the value into the (always-blank) field and Save; tick the per-secret **clear**
   box to remove one. To mint an API key, fill name + scope + expiry under **API keys** and Save —
   the plaintext is shown **once**.

## 1. Portal-configurable integration secrets

Secrets are **write-only**: the field renders blank, a blank submit means *keep current*, a value
sets/rotates it, and a `<key>__clear` checkbox removes it. They're stored **encrypted at rest
(AES-256-GCM)** and never round-tripped to the page — the UI only shows an is-set pill via
`secret_status()`. A portal-set secret **takes precedence** over its `PILOT_*` env var (the env var
is the fallback), so you rotate from the UI with no redeploy. If at-rest encryption is unavailable
(`secret_available()` is False — neither `PILOT_ENCRYPTION_KEY` nor `PILOT_SESSION_SECRET` set) the
save **refuses** to store cleartext and tells you to set the key or keep using the env vars.

- **`mcp_token`** (MCP / agent) — bearer the `/mcp` client sends; setting it *enables* the endpoint.
  Fallback: `PILOT_MCP_TOKEN`. Two **separate** companion toggles (both default OFF) gate the two
  agent-drivable rails:
  - **`mcp_allow_publish`** — *Let the MCP agent publish to live policy.* Gates whether an agent may
    commit + publish rules to a live **SMS** (the Management rail). With it off, agents can still decide,
    preview, and dry-run (validate-and-discard), but `apply_access(publish=true)` is refused.
  - **`mcp_allow_layer_push`** — *Let the MCP agent push dynamic layers to gateways.* Gates whether an
    agent may push a **dynamic layer** to a live gateway via the Gaia API (`set-dynamic-content`). This
    is a **distinct gate** from `mcp_allow_publish` because a dynamic-layer push lands on the gateway
    out-of-band of SmartConsole. With it off, agents can still validate (`dry_run`) and push to the
    built-in demo (`mock`) target, but a real-gateway push is refused.
- **`webhook_token`** (Ticketing webhook) — the `X-PolicyPilot-Token` shared secret that enables
  `POST /access-automation/webhook`. Fallback: `PILOT_WEBHOOK_TOKEN`. Scope it with
  **`webhook_server_ids`** (fails closed on a malformed value).
- **`servicenow_password`** (ServiceNow write-back) — Table API password (instance/user/table are
  plain strings). TLS verification is always on. Fallbacks: the matching `PILOT_SERVICENOW_*` vars.

## 2. API keys

Named, scoped, revocable bearer tokens for the machine endpoints. Generated via
`POST /settings/api-keys`, **shown once** through a one-time session reveal (never written to the
notification log), then only a **SHA-256 hash** remains — a DB leak exposes no usable credential.
A token looks like `policypilot_<scope>_<random>` (256-bit). Optional **expiry** (presets 30 / 90 days /
1 year / Never, or an explicit date) stops it authenticating after that time; the table flags
expired / expiring-soon / unused keys. **Revoke** (`POST /settings/api-keys/{id}/revoke`) deletes
the key and it stops authenticating immediately.

The three scopes (`api_keys.SCOPES`):

- **`mcp`** — authenticate to the `/mcp` server (n8n / LLM agents).
- **`webhook`** — authenticate the inbound ticketing webhook.
- **`api`** — the general REST API (`/dbapi/v1`) for any HTTP client.

Each key also has an **access** capability — **read-write** (default) or **read-only** (the *Read-only*
checkbox on the create form). A read-only key may call read/preview operations but every write is refused
(MCP write tools return a read-only error; REST write endpoints → **403**; the webhook refuses `apply=true`),
so you can give an agent look-but-don't-touch access. The key table shows each key's access. This is
independent of, and on top of, the publish/push gates.

## 3. SMS session reuse + policy cache (Management API group)

Why it exists: Check Point throttles remote API logins (3 per admin/domain/60s in R81+) and caps
concurrent sessions, so the portal does **not** log in per request. Instead it reuses a shared
**read-only session** for reads and **caches the pulled policy**, re-pulling only when a new revision
is published. Every knob is admin-editable here (persisted in the `AppState` k/v table, shared across
workers):

- **`mgmt_session_reuse`** (on) — reuse one read-only session for all reads; this is what prevents
  the "too many login requests" failures. **`mgmt_session_timeout`** (3600s, 60–3600) and
  **`mgmt_keepalive`** (on) keep it alive through a whole demo (keepalive doesn't count against the throttle).
- **`mgmt_policy_cache`** (on) — reuse the parsed rulebase until a new revision is published.
  **`mgmt_cache_revalidate`** (30s) is the minimum gap between change-checks; **`mgmt_cache_max_age`**
  (900s) forces a full refresh as a safety net.
- **`mgmt_write_fresh`** (on) — re-pull live policy before an apply/publish so the decision is never
  based on cached data; **`mgmt_write_session_timeout`** (300s) keeps a stuck "Locked for editing"
  short.

> Storage & retention, Access-automation object-naming, and the Portal **`base_url`** also live on
> this page; `base_url` restamps every emitted endpoint URL (the `/mcp` and webhook URLs) with no
> redeploy (the cookie `Secure` flag is still decided at startup from `PILOT_BASE_URL`).
