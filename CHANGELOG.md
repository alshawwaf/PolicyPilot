# Changelog

All notable changes to **PolicyPilot** are documented here. This project follows
[Semantic Versioning](https://semver.org/).

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
