# Settings (portal-configurable behaviour, secrets & API keys)

The **Settings** page is where an admin tunes the portal at runtime — no code, no env edit, no
redeploy. For a PoV that matters: you set the MCP/webhook/ServiceNow secrets, mint scoped API keys,
and dial in how the portal talks to a Check Point SMS, all from the browser while the demo is live.
Four things are documented here: portal-configurable integration secrets, named API keys, the SMS
session-reuse + policy-cache knobs, and the **RBAC / Users & Groups** model that decides who may reach
Settings (and every other privileged action) in the first place.

- Settings router (page + save + key create/revoke): [`app/routers/settings.py`](../app/routers/settings.py)
- Setting definitions + secret store (AES-256-GCM, env fallback): [`app/services/app_settings.py`](../app/services/app_settings.py)
- Named API keys (SHA-256 hashed, scoped, revocable): [`app/services/api_keys.py`](../app/services/api_keys.py)
- RBAC — roles & granular capabilities: [`app/services/permissions.py`](../app/services/permissions.py) +
  the `User` model in [`app/models.py`](../app/models.py); Users & Groups app: [`app/routers/users.py`](../app/routers/users.py)
- Env-var fallbacks (`PILOT_*`): [`app/config.py`](../app/config.py)

> Settings itself is **administrator-only** (`SETTINGS` is not a grantable capability) — the RBAC section
> below explains what other roles can do.

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

- **`/mcp` activation** (MCP / agent) — the mounted `/mcp` endpoint is enabled by minting an active
  **mcp-scope API key** (Settings → API keys, or right on `/mcp-guide`); the bearer the client sends is that
  key. There is no separate token setting. (`PILOT_MCP_TOKEN` applies only to the standalone
  `python -m app.mcp_server` run mode, not the portal-mounted endpoint.) Two **separate** toggles (both
  default OFF) gate the two agent-drivable rails:
  - **`mcp_allow_publish`** — *Let the MCP agent publish to live policy.* Gates whether an agent may
    commit + publish rules to a live **SMS** (the Management rail). With it off, agents can still decide,
    preview, and dry-run (validate-and-discard), but `apply_access(publish=true)` is refused.
  - **`mcp_allow_layer_push`** — *Let the MCP agent push dynamic layers to gateways.* Gates whether an
    agent may push a **dynamic layer** to a live gateway via the Gaia API (`set-dynamic-content`). This
    is a **distinct gate** from `mcp_allow_publish` because a dynamic-layer push lands on the gateway
    out-of-band of SmartConsole. With it off, agents can still validate (`dry_run`) and push to the
      built-in demo (`mock`) target, but a real-gateway push is refused.
  - **`agent_rate_limit_per_min`** — cap on requests **per key per minute** across /mcp, REST, and the
    webhook (backstop against a runaway agent). `0` = unlimited (default); over the cap → **429**.
- **Governance & audit** — every COMMITTED change (an agent/REST/webhook SMS publish, or a real
  dynamic-layer push) raises a governance event. **`audit_notify`** (on by default) posts an in-app
  notification to every user; **`audit_webhook_url`** (secret, optional) POSTs `{"text","actor","source",
  "event"}` to a Slack/Teams/ITSM webhook (TLS always verified). Metadata only — never rule payloads or
  customer data; fire-and-forget so it never blocks the change.
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

## 4. RBAC — roles, capabilities & the Users & Groups app

PolicyPilot is multi-user with granular permissions. The model (`app/services/permissions.py`) is the single
source of truth for "who can do what", enforced at every mutating chokepoint (publish / apply / export / user
management / settings); templates hide controls the user can't use, so UI and server never disagree.

**Two roles:**

- **Administrator** — implicitly holds **every** permission, always. Superuser; the role is **not grantable**
  as a set of flags. The env-seeded admin (`PILOT_ADMIN_USERNAME`) is structurally protected — it can't be
  demoted, disabled, or deleted, and you can never disable the last active admin or your own account.
- **Standard** — carries individual capability flags (below). **View is implicit** for any *active* account —
  signing in is the view grant, so there is no `perm_view`.

**Grantable capabilities** (`permissions.GRANTABLE`, the `perm_*` flags on the `User` model):

| Capability | Flag | Grants | Default (new standard user) |
|---|---|---|---|
| Preview decisions | `preview` | Run access decisions / previews — read-only reasoning. | on |
| Apply changes | `apply` | Stage & dry-run a change (build objects/rules) against the SMS session. | off |
| Publish to management | `publish` | Commit staged changes to the SMS — **irreversible**. | off |
| Export IaC / Gaia | `export` | Generate Terraform / Ansible / clish for policy and Gaia OS config. | on |
| Manage users | `manage_users` | Create, approve, edit, reset and disable other user accounts. | off |

Plus one **admin-only, non-grantable** capability: **`settings`** — change portal settings + secrets (this
page). It's never assignable to a standard user; `require_admin` is literally `require("settings")`.

> A user still on a temporary/forced password (`must_change_password`) holds **no** capability until they
> change it — the forced-change gate stops action, not just redirects the login.

**Account lifecycle** (`User.status`): `pending` → `active` → `disabled`.

- **Self-signup → approval.** Anyone can self-register (public sign-up route in `app/routers/ui.py`); the
  account lands **`pending`** and can't authenticate until an admin approves it in Users & Groups. A `pending`
  or `disabled` account holds no permission and can't sign in.
- **Managed in the Users & Groups app** (`app/routers/users.py`, `manage_users` capability): create / approve
  / edit role & flags / change status / reset password / delete. A standard *manager* (holds `manage_users`
  but isn't admin) can edit profiles and activate/disable **non-admin** users only — never role/permission
  changes, and only an admin may approve or reset another **admin**.
- **Password reset** is email-based (SMTP-gated): the admin issues a reset that emails a one-hour,
  single-use link (`reset_token_hash` / `reset_token_expires`). **Admin fallback** when SMTP isn't
  configured: set a temporary password (`mode=temp`) shown once, with `must_change_password` forced on so the
  user must set their own on next login.
