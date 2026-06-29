# MCP server — connect PolicyPilot to n8n / an LLM agent

PolicyPilot exposes its access-automation brain as **MCP tools** an LLM agent (via n8n's *MCP Client Tool*
node, or any MCP client) can call: decide on an access request, correlate a service/app name, list
servers/layers, check Terraform/Ansible coverage, and (gated) apply a change.

The tool **logic** ships in `app/services/mcp_tools.py` and is fully tested. The MCP protocol layer uses
the official **`mcp` Python SDK**, which is **not bundled** (org policy: packages come from Artifactory,
not PyPI). Until it's installed the `/mcp` endpoint is simply absent — the rest of the portal is
unaffected.

## 1. Activate

Install the MCP SDK once (it's mounted automatically when present), then set the token from the portal —
no env edit, no redeploy:

```bash
# one-time: install the MCP SDK from your Check Point Artifactory (NOT plain PyPI)
pip install mcp            # via your Artifactory-configured index, then restart PolicyPilot
```

Then create a key in the portal: **Settings → API keys → + New key** (scope **mcp**). The key is shown
**once** — copy it. Clients send it as `Authorization: Bearer <key>`. You can mint multiple named keys
(e.g. `n8n-prod`, `my-laptop`), see each one's last-used time, and **revoke** any of them individually and
immediately. Keys are stored **hashed** (SHA-256) — a DB leak exposes no usable key.

Two simpler alternatives also work and take precedence/cascade automatically:
- **Single shared token** — Settings → MCP / agent → "MCP bearer token" (stored encrypted, AES-256-GCM).
- **Env var** `DCSIM_MCP_TOKEN` — a fallback for headless/automated deploys.

`/mcp` is **mounted whenever the SDK is installed**; while nothing is configured (no key, no token) it
returns **503**. A request is authorized if its bearer matches **any active MCP key** OR the shared token.
The **MCP for agents** page (`/mcp-guide`) shows live status and links to both. (The ticketing webhook is
the same: a **webhook**-scope API key sent as `X-DCSim-Token`, or the shared webhook token.)

**Self-serve onboarding page:** the portal has a **MCP for agents** page at **`/mcp-guide`** (under
*Layers & Gateways*) — live status pills (SDK installed / endpoint enabled / publish gate), a
connect-config generator with copy-paste snippets for Claude Desktop, Cursor, VS Code and n8n (built from
the live origin + a bearer token you type in), and the full tool catalog. Same idea as
<https://mcp.checkpoint.com/>. Point teammates there instead of hand-writing config.

**Standalone alternative** (own port, e.g. if you don't want it on the portal): 
```bash
DCSIM_MCP_TOKEN=... DCSIM_MCP_PORT=8765 python -m app.mcp_server
```

## 1b. REST API (any HTTP client)

Beyond MCP and the webhook, the access-automation brain is exposed as a plain **REST API** at
**`/dbapi/v1`** (not `/api/v1` — that prefix is the Kubernetes/NSX-T datacenter mocks). Authenticate with
an **api**-scope key (Settings → API keys) sent as `Authorization: Bearer <key>`; no valid key → **401**.
It's auto-documented in the portal's OpenAPI (`/docs`, `/openapi.json`).

```bash
curl -s https://<host>/dbapi/v1/access/decide \
  -H "Authorization: Bearer <api-key>" -H "Content-Type: application/json" \
  -d '{"server_id":1,"source":"10.1.1.5","destination":"Any","service":"https"}'
# -> {"outcome":"create","reason":...}
```

Endpoints (thin wrappers over the same `services.mcp_tools`, so behaviour + safety match MCP exactly):
`GET /dbapi/v1/servers`, `GET /dbapi/v1/layers?server_id=`, `GET /dbapi/v1/layers/summary`,
`GET /dbapi/v1/layers/analyze`, `GET /dbapi/v1/coverage`, `POST /dbapi/v1/access/decide`,
`POST /dbapi/v1/access/apply` (publish admin-gated), `POST /dbapi/v1/access/correlate/{service,application}`.
The `correlate/*` endpoints take a body of `{"server_id":1,"name":"dns"}` (a fuzzy name → matching Check
Point service / application objects); each endpoint's exact request schema is also browsable at `/docs`.

## 2. Connect n8n

In the **AI Agent** → add an **MCP Client Tool** node:
- **Endpoint / SSE URL:** `https://<policypilot-host>/mcp` (or `http://<host>:8765` standalone)
- **Transport:** Streamable HTTP (or SSE, depending on your n8n version)
- **Headers:** `Authorization: Bearer <DCSIM_MCP_TOKEN>`

n8n discovers the tools automatically (`tools/list`). The agent can then call them by name.

## 3. Tools

| Tool | Does | Writes? |
|------|------|---------|
| `list_management_servers` | the saved SMS targets (id/name/host) | no |
| `list_access_layers(server_id)` | the policy layers on a server | no |
| `decide_access(server_id, source, destination, layer, service?/port?/application?, …)` | **preview** the decision (no_op/widen/create/review) + reasoning + suggestions | no |
| `correlate_service(server_id, name)` | service/protocol name → real CP object, or candidates | no |
| `correlate_application(server_id, name)` | app/site name → real CP object, or candidates | no |
| `summarize_layer(server_id, layer)` | rule counts, Accept/Drop split, Any-dimension counts, inline layers, cleanup-drop presence | no |
| `analyze_policy(server_id, layer)` | summary + shadowed rules (covered by an earlier broader Accept/Drop) + overly-permissive Accepts | no |
| `coverage_lookup(api, name?, version?)` | object/field support across API / Terraform / Ansible | no |
| `apply_access(server_id, …, publish)` | `publish=false` **dry-run** (validate + discard); `publish=true` **commit** | gated |
| `remove_access(server_id, …, publish)` | revoke an access — disable an exact-grant rule, or drop-above a broader one | gated |
| `amend_access_rule(change_id \| rule_uid+layer, name?/comment?/tags?/track?, publish)` | edit a rule's **metadata only** (name/comment/tags/track-logging) — never its match columns | gated |
| `list_changes(limit?)` | recent **published** changes (id/what/when/reverted?) for audit + undo | no |
| `revert_change(change_id, publish, disable_instead_of_delete?)` | surgically undo one published change (delete/re-enable/restore) | gated |

`summarize_layer` / `analyze_policy` are read-only and **provably conservative** — `analyze_policy` only
flags a rule as shadowed when it can prove an earlier rule fully covers it under first-match (it abstains
on application-layer / opaque cells rather than guessing), and only flags Accepts that are `Any` on a
whole dimension. Good for an agent to *understand* a policy before proposing a change.

## 4. Safety model

- **Auth:** every call requires `Authorization: Bearer <key-or-token>` (constant-time checked). Valid
  credentials are any active **MCP API key** (Settings → API keys; hashed at rest, individually revocable)
  or the shared **MCP token** (Settings → MCP / agent, encrypted at rest; `DCSIM_MCP_TOKEN` env fallback).
  Nothing configured → **503** (disabled); wrong/missing credential → **401**. A DB read failure fails
  **closed** (endpoint stays disabled / key set treated as empty), never open.
- **No accidental writes:** `decide_access` is read-only; `apply_access` with `publish=false` rehearses
  the change in a session and **discards** it (nothing committed).
- **Publish is opt-in:** `apply_access(publish=true)` only commits when an admin enables **Settings →
  MCP / agent → "Let the MCP agent publish to live policy"** (`mcp_allow_publish`, default OFF).
  Otherwise it's refused with a message telling the agent to dry-run instead. So an LLM cannot reach live
  policy unless you deliberately allow it.
- The engine's own guarantees still apply end-to-end: an unknown/ambiguous service name returns
  `review` + `suggestions` and **never** produces a wrong call to the SMS.

## 5. Example agent loop

> "Allow 10.1.1.222 to reach the DNS servers over DNS."

1. `correlate_service(server_id, "dns")` → confirms the CP service object.
2. `decide_access(server_id, "10.1.1.222", "<dns group>", "Network", service="domain-udp")` → e.g.
   `widen` with the target rule + reasoning.
3. (if approved) `apply_access(..., publish=false)` to dry-run, then `publish=true` once the admin toggle
   is on.

With the **Autopilot (lab demo)** preset on (Settings → Access automation logic), steps 1–3 collapse into a
single turn: one sentence ending “…and publish the changes” resolves, applies **and** publishes.

## 5b. QA battery

A standing set of one-sentence “…and publish” prompts that exercise **every** tool, outcome, and column —
the demo script and the regression check in one — lives in **[mcp-agent-qa.md](mcp-agent-qa.md)**. Run it
after any change to the engine or the MCP tools.

## 6. Status — validated live

Validated end-to-end against `mcp` SDK 1.28.0 (Streamable-HTTP): a request with no / wrong bearer → 401;
`initialize` → 200 (serverInfo "PolicyPilot"); `tools/list` → all tools; `tools/call coverage_lookup`
returns real data; `decide_access` with a bad server id returns its error inside the tool result (no
crash). The endpoint serves at **`/mcp`** (a bare `/mcp` 307-redirects to `/mcp/`; MCP clients, incl.
n8n, follow it preserving the POST). The mounted app's session-manager lifespan is run from the portal's
own lifespan (so you won't see "Task group is not initialized"). The SDK is declared in
`requirements.txt` (install resolves from Artifactory).
