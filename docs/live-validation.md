# Live validation — prove both rails against your real lab

A 15-minute smoke test to run **after a deploy**, against a real R82.10 management server and a real Gaia
gateway. It confirms the management rail and the (newer) dynamic-layer rail actually work end-to-end — the
dynamic-layer rail ships covered by unit + mock tests only, so this is its first contact with real Gaia.

> Use demo / lab infrastructure only. Don't point this at production until you've watched it behave on a lab.

## 0. Deploy + ops check

1. Redeploy on Dokploy so it builds the latest `main`.
2. From any shell (no auth needed):
   ```bash
   curl -s https://<your-host>/healthz   # {"status":"ok"}
   curl -s https://<your-host>/readyz    # {"status":"ready"}  (DB reachable)
   curl -s https://<your-host>/version   # {"version":"1.0.0","mcp_tools":21,"mcp_ready":…}
   ```
   `mcp_tools` should be **21**. `mcp_ready` is `true` once the `mcp` SDK is installed and an mcp-scope key exists.
3. **Conformance self-check** — proves the agent surface is wired + safe (no live SMS/gateway touched). Either:
   ```bash
   curl -s -H "Authorization: Bearer <api-key>" https://<your-host>/dbapi/v1/conformance   # 200 + {"ok":true,…}
   ```
   or, on the host: `python -m app.services.conformance` (prints a checklist, exits non-zero on failure).
   Expect every **required** check green: tools_registered (21), write_tools_rbac_guarded,
   readonly_capability_enforced, db_reachable. The gate states + MCP-SDK presence are reported as info.

## 1. Connect your lab (in the portal)

1. **Management Servers → add** your R82.10 SMS (host + a least-privilege API account). Open it → confirm the
   layers list loads (proves login + read).
2. **Gateways → add** a Gaia gateway (host, username, password); use **Fetch & trust certificate** for a
   self-signed lab box (TLS stays verified via the pinned cert).
3. **Dynamic Layers** → create one (a `dynamic_layer` access layer on the gateway must be marked *Set as a
   Dynamic Layer*), or just have one already pushed on the gateway — the import flow (step 4) will pull it.

## 2. Connect the agents

1. **MCP for agents (`/mcp-guide`)** → mint an **mcp-scope API key** (shown once — copy it).
2. Import both n8n workflows and set each MCP node's **endpoint** to `https://<your-host>/mcp/` and the
   **Bearer** credential to that key:
   - `docs/policypilot-management-agent.json`
   - `docs/policypilot-dynamic-layer-agent.json`

## 3. Management rail — read, then gated write

Paste into the **management** agent, in order:

| Prompt | Proves |
|---|---|
| `List the management servers.` | discovery |
| `Summarize the Network layer on <SMS>.` | live read of the real rulebase |
| `Allow 10.1.1.50 to the DNS servers in the Network layer.` | decide → **dry-run** (no publish yet) |
| *(enable Settings → Access automation logic → ⚡ Autopilot)* `Allow 10.1.1.50 to the DNS servers and publish the changes.` | one-turn decide → apply → **publish**, then verify the rule in SmartConsole |

**Gate proof:** with publish OFF, the publish prompt is refused (the agent dry-runs and says it's admin-gated).

## 4. Dynamic-layer rail — fetch, import, push

Paste into the **dynamic-layer** agent, in order:

| Prompt | Proves |
|---|---|
| `List my gateways.` / `List the dynamic layers.` | discovery |
| `What's actually on <GW>'s dynamic layer right now?` | **`fetch_dynamic_layer`** — the LIVE rulebase off the gateway |
| `Import <GW>'s dynamic layer into the portal.` | **`import_dynamic_layer`** — the portal copy now mirrors live |
| `Add a rule allowing 10.1.2.50 to 10.1.2.60 on ssh in that layer and push it, dry run.` | edit → **dry-run** push (validates, applies nothing) |
| *(enable Settings → MCP / agent → "Let the MCP agent push dynamic layers to gateways")* `…and push it to <GW>.` | real `set-dynamic-content` push; confirm on the gateway |

**Gate proof:** with the layer-push toggle OFF, a real-gateway push is refused — the agent falls back to a
dry-run or `gateway='mock'` and says it's admin-gated (a **separate** gate from the SMS publish toggle).
**No-clobber proof:** because you *imported* first, the push replaces with the live rules **plus** your new
one — re-run `fetch_dynamic_layer` and confirm the pre-existing rules are still there.

## 5. Where to look

- **Activity** (`/activity`) — every call the portal made, with the redacted request/response and timing.
- The agent's reply carries the **outcome / change summary / task id** verbatim.
- SmartConsole (management rail) and the gateway's dynamic layer (dynamic rail) — the actual committed state.

If anything fails, the agent reports the error verbatim (it never fabricates) and the Activity log has the full
trace. The full regression set is **[mcp-agent-qa.md](mcp-agent-qa.md)**; this page is the live smoke test.
