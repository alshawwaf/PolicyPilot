# Changelog

All notable changes to **PolicyPilot** are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## Unreleased

Post-1.0.0 hardening of the agent surface, ahead of broader live validation.

### Security hardening (audit)
A dedicated security audit (adversarially verified) found no blockers; two majors + one minor were fixed:
- **Login brute-force throttle could be bypassed via a spoofed `X-Forwarded-For`** (major) — `client_ip()` now
  trusts XFF only for `PILOT_TRUSTED_PROXY_HOPS` reverse-proxy hops (default 0; compose/DEPLOY set 1 for
  Caddy/Traefik) and reads the proxy-appended hop, so rotating the header no longer resets the lockout. The
  same trusted-proxy resolution is used for the activity-log source IP.
- **Webhook `callback_url` was an authenticated SSRF / exfiltration relay** (major) — the caller-supplied
  callback is now SSRF-guarded: http(s) only, and the resolved host must not be loopback / link-local (incl.
  the `169.254.169.254` cloud-metadata endpoint) / multicast / reserved; private ranges are refused unless an
  admin enables **`webhook_allow_private_callbacks`** (for an internal ITSM). Redirects are not followed.
- **Open redirect via a protocol-relative `next=`** (minor) — the table-prefs redirect now rejects `//host`
  and scheme-bearing targets (same-origin only).

### Customer-readiness audit pass
A full multi-dimension audit (security, engine, MCP, data, UX, docs, deploy, cruft, tests) found no blockers
and no confirmed majors; the verified items were closed:
- **Webhook idempotency** — the ticketing webhook (the most redelivery-prone publish surface) now wires the
  same `idempotency` store as the MCP/REST apply paths, keyed on `server:ticket_id`: a redelivered ticket
  replays the first committed result instead of publishing again. + a 429 rate-limit test and a
  replay-not-double-publish test (the webhook rail was previously untested for both).
- **Docs accuracy** — README badge/prose + `docs/mcp-n8n.md` now say **21** MCP tools (was 19, contradicting
  `/version`); test badge → 675; `docs/settings.md` `/mcp` activation rewritten to the real mcp-scope API-key
  mechanism (the non-existent `mcp_token` setting is gone).
- **Deploy hygiene** — `docker-compose.yml` now forwards `PILOT_ENCRYPTION_KEY` (so a compose deploy can't
  silently derive the at-rest key from the session secret and orphan credentials on rotation); removed the
  dead SIEM `PILOT_SYSLOG_PORT` ports and the Nutanix `:9440` Caddy port (lab leftovers).
- **Data hygiene** — `idempotency.prune` is now a single set-based DELETE; the retention sweep also prunes
  stale `LoginThrottle` rows (failed-only IPs never self-clear); `notifications._prune` got an `id`
  tiebreaker for deterministic trim.
- **Coverage** — a route-driven test asserts every live page redirects an anonymous caller to `/login` (and
  data endpoints deny, never 200), so a future unguarded route fails CI.
- **Cruft** — fixed the stale `models.py` module docstring + `ActivityLog.kind` comment; removed dead imports
  (`enum`, SQLAlchemy `Enum`, `_norm`); the flagship Access-automation empty state now uses the shared macro;
  the MCP-guide `tool_catalog` docstring matches reality.

### Policy Manager — staged, hidden until fully developed
- The dedicated **Policy Manager** landing is built (`app/routers/policy_manager.py` + template) but
  **intentionally not surfaced yet** — no nav entry, no home link, and the route is unmounted (`/policy-manager`
  404s) — pending the write features (add / delete / reorder). The underlying live policy **viewer + per-rule
  editor** continues to ship under each management server (`/management/{id}`): browse an access layer
  (rulebase over `web_api`, cells resolved to names, sections / negation / disabled shown) and edit a rule
  (action, track, name, comments, enabled) with a **dry-run** or **publish**, flowing through the same change
  log + governance audit.

### Governance & audit — a work-note after every committed change
- Every COMMITTED change — an agent/REST/webhook publish to a live SMS (Rail A) or a real dynamic-layer push
  to a gateway (Rail B) — now raises a **governance event**: an in-app notification to every portal user (the
  audit trail in the header bell, **`audit_notify`**, on by default) and a best-effort **outbound webhook**
  POST to an admin-configured URL (**`audit_webhook_url`** — Slack / Teams / ITSM incoming webhook, JSON
  `{"text", "actor", "source", "event"}`, TLS always verified, fires only when set). **Metadata only** (actor,
  action, outcome, server/gateway, ticket) — never rule payloads or customer data. Fire-and-forget: an audit
  failure never blocks or breaks the change. New **Governance & audit** settings group.

### Both rails — see the live policy before you change it
- **`fetch_dynamic_layer`** (MCP + `GET /dbapi/v1/dynamic-layers/fetch`) — pull a gateway's LIVE dynamic-layer
  rulebase via the Gaia API, including policy pushed over the API outside the portal. A push is a REPLACE, so
  the agent now reads reality first instead of blindly overwriting.
- **`import_dynamic_layer`** (MCP + `POST /dbapi/v1/dynamic-layers/import`) — bring a gateway's live layer INTO
  a portal layer, so the safe fetch → import → edit → push flow replaces with *live + your edits* and never
  wipes out-of-band policy. The gateway-detail page gains an **Import to portal** button for the same flow.
- Dynamic-layer rail is now **8 tools** (21 MCP tools total).

### Per-key RBAC — read-only vs write API keys
- An API key now carries a **read-only / read-write** capability (alongside its scope). A **read-only** key
  lets an agent preview and read (`decide_access`, `fetch_dynamic_layer`, `list_*`, summarize/analyze, …) but
  **every write tool refuses** — so you can hand an LLM look-but-don't-touch access. Enforced on all three
  surfaces: the MCP guard sets the request capability and the write tools refuse; the REST write endpoints
  return **403**; the webhook refuses an `apply=true` from a read-only key. Existing keys default to
  read-write (no behaviour change); mint a read-only key from **Settings → API keys** (the new *Read-only*
  checkbox; the table shows each key's access). Writes still need the publish/push gate on top.

### Per-key rate limiting
- New **`agent_rate_limit_per_min`** setting caps how many requests a single API key may make per minute
  across `/mcp`, the REST API, and the ticketing webhook — a backstop against a runaway agent loop hammering
  the SMS. **0 = unlimited (default)**, so it's opt-in and a change takes effect with no redeploy. Over the
  cap → **HTTP 429**. Fixed 60-second window per key, in-process, fail-open.

### Idempotent writes — a retry can't double-commit
- `apply_access` and `push_dynamic_layer` (MCP + REST) accept an optional **`idempotency_key`**. A repeat with
  the same key REPLAYS the first committed result (`idempotent_replay: true`) instead of publishing/pushing
  again — so an agent retry, an n8n retry-on-fail, or a redelivered webhook can't create a duplicate change.
  Records live in a new `idempotency_records` table with a 24h TTL and are pruned by the retention sweep.

### Operations
- **`GET /version`** (name, build, MCP tool count, `mcp_ready`) and **`GET /readyz`** (DB readiness, 503 when
  not ready) for deploy health checks, alongside `GET /healthz`.
- **Conformance self-check** — `python -m app.services.conformance` (prints a checklist, non-zero exit on
  failure) and **`GET /dbapi/v1/conformance`** (api-scope; 200/503) prove the agent surface is correctly
  wired and safe — tools registered, write tools RBAC-guarded, read-only enforced, DB reachable, gate states
  — without touching a live SMS/gateway or mutating policy. The first thing to run after a deploy.
- `docs/live-validation.md` — a 15-minute post-deploy smoke test covering both rails and the publish gates.

## 1.0.0 — 2026-06-28

First general release of **PolicyPilot** as a standalone, focused product: agentic Check Point access
automation. Extracted and rebranded into a single product centered on the access-automation engine and both
ways to apply its decisions. Validated against a live Check Point **R82.10** Management Server. 626 automated
tests, all green.

### Two automation rails, both agent-drivable over one `/mcp` endpoint
- **Management access policy (SMS)** — describe an access request, the engine computes the minimal
  first-match-safe change (no-op / widen / create), previews the placement, and applies it on approval, with
  one-click rollback. Full access-rule column support — action (Accept / Drop / Reject / Ask / Inform / Apply
  Layer) plus content, time, install-on, and VPN columns. Driven over the Management Web API (`web_api`).
- **Dynamic Layers (Gateway)** — author an access rulebase and push it straight to a gateway via the Gaia API
  (`set-dynamic-content`, sk182252), out-of-band of SmartConsole, or to the built-in `mock` target. The SMS
  engine treats the dynamic layer as out-of-band (skipped from matching), so the rails never overlap.
- **19 MCP tools** over `/mcp` (mcp-scope key, `Authorization: Bearer`) — 13 for the management rail
  (`list_management_servers`, `list_access_layers`, `decide_access`, `apply_access`, `remove_access`,
  `amend_access_rule`, `list_changes`, `revert_change`, `correlate_service`, `correlate_application`,
  `summarize_layer`, `analyze_policy`, `coverage_lookup`) and 6 for the dynamic-layer rail (`list_gateways`,
  `list_dynamic_layers`, `get_dynamic_layer`, `add_dynamic_rule`, `remove_dynamic_rule`, `push_dynamic_layer`).
- **Separate publish gates** — agent writes to the SMS are gated by `mcp_allow_publish`; a live gateway push is
  gated by the distinct `mcp_allow_layer_push`. dry-run and the `mock` target are always allowed.
- **Autopilot** — the `aa_autopilot` toggle lets a single sentence ending "…and publish the changes" resolve,
  apply, and publish in one turn on the management rail; the "Autopilot (lab demo)" Settings preset sets the
  aggressive profile + `mcp_allow_publish` + `aa_autopilot` together.

### Interfaces
- **REST API at `/dbapi/v1`** (api-scope key) mirroring the tools across both rails, including `/gateways`,
  `/dynamic-layers`, `/dynamic-layers/get`, `/dynamic-layers/rule`, `/dynamic-layers/rule/remove`, and
  `/dynamic-layers/push`. Auto-documented in the portal OpenAPI at `/docs`.
- **Two ready-made n8n agents** in `docs/` — `policypilot-management-agent.json` and
  `policypilot-dynamic-layer-agent.json` — both connecting to the same `/mcp` with an mcp-scope key.
- **Ticket webhook** — a ServiceNow / Jira / any webhook becomes a Check Point rule, authenticated with the
  `X-PolicyPilot-Token` header.
- In-app MCP onboarding at `/mcp-guide` and a live Swagger explorer at `/api-explorer`.

### UI
- Site-wide visual overhaul on a pink/purple gradient with full dark and light themes, driven entirely by
  design tokens (no hardcoded colors that break dark mode). The brand mark is a **compass**.
- Navigation: Home · Access automation · Dynamic Layers · Connections (Management Servers, Gateways) · Agents &
  API (MCP for agents, API explorer) · Settings · Activity.
- **In-app dialogs only** — `window.appConfirm` / `data-confirm` / `window.appToast`; no native
  `confirm()` / `alert()` / `prompt()`. No site footer.

### Security
- All gateway / SMS TLS **always verified** (trust-on-first-use cert pinning for self-signed lab boxes).
- Saved management / gateway credentials **AES-256-GCM encrypted at rest** (`PILOT_ENCRYPTION_KEY`).
- Scoped, revocable **API keys** (mcp / webhook / api), SHA-256-hashed at rest, shown once.
- Defensive HTTP response headers (anti-clickjacking, nosniff, Referrer-Policy, HSTS).
- Parameterized queries throughout; portal logins use PBKDF2; secrets never logged.
- Reproducible build (pinned dependencies, non-root container, healthcheck).

### Deploy
- Ships a `Dockerfile`; deploy on Dokploy exposing port **8000**, mounting **`/data`** for the SQLite DB
  (`/data/policypilot.db`), with env vars `PILOT_SESSION_SECRET`, `PILOT_ENCRYPTION_KEY`, `PILOT_BASE_URL`,
  and `PILOT_ADMIN_PASSWORD`.
