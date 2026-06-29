<div align="center">

# 🧭 PolicyPilot

### Agentic Check Point access automation

*Turn a plain-language access request into the correct, first-match-safe policy change — applied to a real
**R82.10 management server** or pushed straight to the **gateway** as a dynamic layer — and drivable by an
LLM agent over MCP.*

![Version](https://img.shields.io/badge/version-1.0.0-3b82f6)
![Validated](https://img.shields.io/badge/validated-R82.10-7b3ff2)
![Tests](https://img.shields.io/badge/tests-675%20passing-34d399)
![MCP tools](https://img.shields.io/badge/MCP%20tools-21-7b3ff2)
![Python](https://img.shields.io/badge/python-3.12%2B-3b82f6)
![TLS](https://img.shields.io/badge/TLS-always%20verified-15935a)
![License](https://img.shields.io/badge/license-proprietary-5b6678)

</div>

---

PolicyPilot connects to a **real Check Point R82.10 Management Server** (and/or gateways) and does exactly
what its API account is permitted to — least privilege. You describe the access you want; the engine computes
the **minimal** change, places it **first-match-safe**, previews it, and applies it on approval — with
one-click rollback. No more hand-editing rulebases or guessing where a rule belongs.

> 💡 **One sentence → the right rule.** *"Allow 10.1.1.50 to the DNS servers and publish"* becomes a correct
> Accept rule on your SMS — reusing existing objects, placed above the right deny, and published. That's the
> whole pitch.

---

## 🛤 Two automation rails, one engine

The same decision brain drives two ways to apply a change — **both fully agent-drivable over the same `/mcp`
endpoint** (21 tools total, mcp-scope key as `Authorization: Bearer`):

| Rail | What it does | How | Publish gate |
|---|---|---|---|
| **Management access policy — SMS** | Create / widen an access rule in the policy rulebase, then **publish**. | Management Web API (`web_api`) | `mcp_allow_publish` |
| **Dynamic Layers — Gateway** | Author an access rulebase and push it **straight to the gateway** as a dynamic layer, out-of-band of SmartConsole. | Gaia API (`set-dynamic-content`, sk182252) | `mcp_allow_layer_push` |

The two rails carry **separate publish gates** — enabling agent writes to the SMS does not enable a live
gateway push, and vice versa. dry-run and the built-in `mock` target are always allowed. The SMS engine
deliberately treats the dynamic layer as **out-of-band** (skips it from matching), so the two rails are
complementary halves of "automate access," never overlapping.

---

## 🧠 The decision engine

- **Reuse / widen / create** — finds whether the access already exists (no-op), can be granted by widening an
  existing rule, or needs a new rule.
- **First-match-safe placement** — inserts above the right deny, below the right stealth/cleanup, in the right
  section — so the new rule is neither shadowed nor shadowing.
- **Every access-rule column** — action (Accept / Drop / Reject / Ask / Inform / Apply Layer) plus **content**
  (data-types), **time**, **install-on** (gateways) and **VPN** (communities).
- **Reuse-only object resolution** — resolves a source/destination/service to an *existing* Check Point object
  by dedicated commands; never blindly creates duplicates.
- **One-click rollback** — every published change records its inverse op-list; revert restores the prior state.
- **Provably conservative analysis** — `analyze_policy` only flags a rule as shadowed when it can prove it,
  and abstains on opaque/application cells rather than guessing.

See the **[access-automation white paper](docs/access-automation-whitepaper.md)** for how it reasons about a
rulebase.

---

## 🎛 Drive it four ways

- 🤖 **[MCP server](docs/mcp-n8n.md)** — both rails as **21 tools** an LLM agent (n8n, Claude Desktop, Cursor,
  VS Code, any MCP client) calls over `/mcp`. Two ready-made n8n workflows ship in `docs/`:
  **[management access agent](docs/policypilot-management-agent.json)** and
  **[dynamic-layer agent](docs/policypilot-dynamic-layer-agent.json)**, both connecting to the same `/mcp` with
  an mcp-scope key. With the **Autopilot** preset, one sentence ending *"…and publish the changes"* resolves,
  applies **and** publishes in a single turn (management rail). In-app onboarding at **`/mcp-guide`**.
- 🌐 **REST API** — the same brain at **`/dbapi/v1`** for any HTTP client (api-scope key auth), mirroring the
  tools across both rails (incl. `/gateways`, `/dynamic-layers`, `/dynamic-layers/push`), auto-documented in
  the portal OpenAPI (`/docs`).
- 🎫 **Ticket webhook** — a ServiceNow / Jira / any webhook becomes a Check Point rule, with optional write-back.
  Authenticated with the `X-PolicyPilot-Token` header.
- 🖥 **The portal UI** — review a decision, see the placement, apply on approval — plus a live **API explorer**
  (Swagger) at `/api-explorer` for testing Management / Gaia API calls directly.

> 📓 The **[MCP-agent QA battery](docs/mcp-agent-qa.md)** is a standing set of one-sentence "…and publish"
> prompts that exercise every tool, outcome, and column — the demo script and the regression check in one.

---

## 🚀 Quick start (local dev)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export PILOT_ADMIN_PASSWORD='<choose-a-strong-password>'   # else a random one is printed at startup
export PILOT_SESSION_SECRET=$(openssl rand -base64 32)
uvicorn app.main:app --reload
```

Open <http://localhost:8000>, sign in as `admin`, then:

1. **Management Servers → add** your R82.10 SMS (host + API account).
2. **Access automation** → describe an access request → preview the decision (no-op / widen / create) → apply.
3. **MCP for agents** (`/mcp-guide`) → mint an mcp-scope key and connect n8n / your agent.

> The MCP protocol layer needs the official **`mcp`** SDK (installed from your Check Point Artifactory, not
> public PyPI). Until it's present the `/mcp` endpoint is simply absent — the rest of PolicyPilot is unaffected.

---

## ☁️ Deploy (Dokploy)

Build from the **`Dockerfile`**, expose port **8000**, add a domain (Traefik handles Let's Encrypt TLS), mount
**`/data`** for the SQLite DB, and set the `PILOT_*` env vars (`PILOT_SESSION_SECRET`, `PILOT_ENCRYPTION_KEY`,
`PILOT_BASE_URL`, `PILOT_ADMIN_PASSWORD`). See **[DEPLOY.md](DEPLOY.md)**.

---

## 🔒 Security / org policy

- Portal endpoints require login; machine access uses named, scoped (`mcp` / `webhook` / `api`), revocable
  **API keys** with optional expiry (shown once, SHA-256-hashed at rest).
- **TLS to the SMS/gateway is always verified.** Self-signed lab boxes are handled by **cert pinning**
  (trust-on-first-use or a pasted cert) — verification is never disabled.
- Saved management / gateway credentials are **AES-256-GCM encrypted at rest** (`PILOT_ENCRYPTION_KEY`).
- **Publish is opt-in** — an agent cannot reach live policy unless an admin enables it; otherwise applies are
  dry-runs (validate + discard). Parameterized queries throughout; defensive HTTP headers (anti-clickjacking,
  nosniff, HSTS).
- Use a **least-privilege API account** on the SMS — PolicyPilot only does what it's permitted to.

---

## ✅ Tests

```bash
pip install pytest && pytest -q          # 626 tests, all green
```

---

## 📚 More

- **[docs/mcp-n8n.md](docs/mcp-n8n.md)** — connect n8n / an LLM agent over MCP + the REST API.
- **[docs/policypilot-management-agent.json](docs/policypilot-management-agent.json)** — ready-made n8n agent for the management access rail.
- **[docs/policypilot-dynamic-layer-agent.json](docs/policypilot-dynamic-layer-agent.json)** — ready-made n8n agent for the dynamic-layer rail.
- **[docs/mcp-agent-qa.md](docs/mcp-agent-qa.md)** — the one-sentence "…and publish" QA battery (demo + regression).
- **[docs/live-validation.md](docs/live-validation.md)** — the 15-minute post-deploy smoke test for both rails against a real lab.
- **[docs/access-automation-whitepaper.md](docs/access-automation-whitepaper.md)** — how the engine reasons.
- **[docs/integrations/access-automation.md](docs/integrations/access-automation.md)** — the ticket→rule flow.
- **[docs/integrations/management-export.md](docs/integrations/management-export.md)** — pull & export policy as Terraform / Ansible / `mgmt_cli`.
- **[docs/integrations/gaia-export.md](docs/integrations/gaia-export.md)** — export a gateway's Gaia OS config.
- **[docs/integrations/dynamic-layers.md](docs/integrations/dynamic-layers.md)** — the gateway-direct (dynamic-layer) rail.
- **[docs/settings.md](docs/settings.md)** — secrets, API keys, the SMS session cache.
- **[CHANGELOG.md](CHANGELOG.md)** — what's in this release.
