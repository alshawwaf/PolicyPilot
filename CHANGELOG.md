# Changelog

All notable changes to **PolicyPilot** are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## Unreleased

Post-1.0.0 hardening of the agent surface, ahead of broader live validation.

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

### Idempotent writes — a retry can't double-commit
- `apply_access` and `push_dynamic_layer` (MCP + REST) accept an optional **`idempotency_key`**. A repeat with
  the same key REPLAYS the first committed result (`idempotent_replay: true`) instead of publishing/pushing
  again — so an agent retry, an n8n retry-on-fail, or a redelivered webhook can't create a duplicate change.
  Records live in a new `idempotency_records` table with a 24h TTL and are pruned by the retention sweep.

### Operations
- **`GET /version`** (name, build, MCP tool count, `mcp_ready`) and **`GET /readyz`** (DB readiness, 503 when
  not ready) for deploy health checks, alongside `GET /healthz`.
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
