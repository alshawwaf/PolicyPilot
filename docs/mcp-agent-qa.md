# MCP agent QA battery — one-sentence, “…and publish/push”

A standing set of natural-language prompts to fire at an LLM agent wired to PolicyPilot over **MCP**, to
confirm the whole access-automation surface still works end-to-end. **Almost every prompt is a single
sentence ending in “…and publish the changes” (management rail) or “…and push the changes” (dynamic-layer
rail).** That's the point of this product: an SE (or a ticket, or an agent) says *one sentence* and the
change is decided, placed first-match-safe, and either **published** to the live SMS policy or **pushed** to
a gateway — in one turn.

Both rails live on the **same** `/mcp` endpoint (one mcp-scope key, sent as `Authorization: Bearer`):

- **Management access policy** (the SMS, via the Management web_api) — §1–§8 below. Publishing to live
  policy is gated by **`mcp_allow_publish`**.
- **Dynamic Layers** (an access rulebase pushed straight to a gateway via the Gaia API `set-dynamic-content`,
  out-of-band of SmartConsole) — §9 below. A real-gateway push is gated by **`mcp_allow_layer_push`**, a
  *separate* toggle from `mcp_allow_publish`; dry-run and the built-in `mock` target are always allowed.

Two ready-made n8n agents drive these rails over that same endpoint:
**`docs/policypilot-management-agent.json`** (the management battery) and
**`docs/policypilot-dynamic-layer-agent.json`** (the dynamic-layer battery).

> Run these after any change to the engine, the MCP tools, or the column support. They're the agent-level
> companion to the pytest suite (`tests/test_access_automation.py`, run with `python3 -m pytest`).

---

## Setup (once)

1. **Lab**: a real SMS saved as a Management Server, and the **SBT Lab** seeded (Settings → *Seed an
   environment* → **Seed SBT Lab Environment**) so the object names below resolve. These prompts are written
   for the lab Network layer (server **SMS**, layer **Network**) — substitute your own IPs/objects elsewhere.
2. **MCP key**: generate an **mcp**-scope key on `/mcp-guide` and connect your agent (n8n / Cursor / VS Code /
   any MCP client). Paste the **Autopilot agent system prompt** from that page.
3. **Autopilot (lab demo)**: Settings → *Access automation logic* → **Autopilot (lab demo)** (sets
   Aggressive + agent publish + the one-turn autopilot toggle). This is what lets the agent **apply AND
   publish in one turn without asking**. Without it, the agent will decide + dry-run and ask you to confirm —
   also a valid test, just not the one-sentence demo.

The exact rulebase and object map these prompts assume are in **[Reference policy](#reference-policy--the-sms-network-layer-these-prompts-assume)** below — recreate it (or adapt the prompts to your own policy) so the outcomes match.

**How to read each row:** the **Prompt** is what you paste; **Exercises** is the tool path + engine
behavior it proves; **Expect** is the result a healthy system returns.

---

## Reference policy — the SMS **Network** layer these prompts assume

The prompts in §2–§8 are calibrated against this exact rulebase (what the **Seed SBT Lab Environment** preset
builds). Recreate it — or map the prompts onto your own policy — so the outcomes match. It reads top-down,
first-match, exactly as in SmartConsole:

| # | Name | Source | Destination | Service | Action |
|--:|------|--------|-------------|---------|--------|
| 1 | Silent Drop | Any | Any | bootp, NBT, nbsession, nbname, nbdatagram | **Drop** |
| 2 | CP Updates | GW, SMS | Akamai Services, Check Point Services | http, https, proxy | Accept |
| 3 | Management | jump_host, win_client, SMS, GW | GW, SMS | ssh_v2, https | Accept |
| 4 | PILOT | SMS, GW | `.example.com` *(domain)* | Any | Accept |
| 5 | Orchestrator | ubuntu25, cloudshare | SMS, GW | Any | Accept |
| 6 | Stealth Rule | Any | GW | Any | **Drop** |
| 7 | DNS Layer | Any | Any | dns | **Apply Layer** → `DNS_Layer` (inline) |
| 8 | Dynamic Layer | Any | Any | Any | **Apply Layer** → `dynamic_layer` (inline, sk182252) |
| 9 | Outbound | net_10_1_1_0_24, net_10_1_2_0_24, net_10_1_3_0_24 | Any | http, https, proxy, icmp-requests, quic | Accept |
| 10 | Mail | net_10_1_1_0_24, net_10_1_2_0_24, jump_host | Any | mail_services | Accept |
| 11 | LDAP | win_client, SMS | win_server | LDAP_all, ntp, tcp-high-ports | Accept |
| 12 | DMZ | kali_linux | win_server | Any | Accept |
| 13 | Cleanup rule | Any | Any | Any | **Drop** |

**Objects referenced above:**

| Object | Address | | Object | Address |
|--------|---------|---|--------|---------|
| GW | 10.1.1.111 | | win_server | 10.1.2.250 |
| SMS | 10.1.1.100 | | ubuntu25 | 10.1.3.33 |
| jump_host | 10.1.1.200 | | kali_linux | 203.0.113.5 |
| win_client | 10.1.1.222 | | cloudshare | 207.121.63.12 |
| net_10_1_1_0_24 | 10.1.1.0/24 | | net_10_1_2_0_24 | 10.1.2.0/24 |
| net_10_1_3_0_24 | 10.1.3.0/24 | | DNS servers | 8.8.8.8, 8.8.4.4 |

Security zones: `InternalZone` / `DMZZone` / `ExternalZone` / `WirelessZone`. Predefined data-type
`Source Code`; built-in VPN community `All_GwToGw`. *(No access-roles exist in this lab.)*

**Why the structure matters** — it's what makes each outcome reachable:
- **Rule 9 (Outbound)** is the broad web Accept → drives the **no_op** in §2 #8 (10.1.1.50→TCP 80 is already allowed).
- **Rule 10 (Mail)** is the *only* widen-friendly rule (its non-matching dims are exactly equal, not Any) → the **widen** in #9.
- **Rule 1 (Silent Drop)** is a resolved Drop → the **create-ABOVE-a-deny** in #11 (nbsession lands above it for first-match safety).
- **Rule 6 (Stealth)** is an opaque Drop to the gateway → acts as a **placement floor** (a gateway-dest grant is floored below it + flagged).
- **Rules 7–8** are inline layers; rule 8 (dynamic, sk182252) is **skipped from matching** but still a floor.
- **Rule 12 (DMZ)** is `kali_linux → win_server` Any — the **sole exact grant**, so revoking it **disables** that rule in §5 #26.
- **Rule 13 (Cleanup)** is the catch-all Drop — anything not matched above lands here, which is why a fresh create is needed for new access.

> **On a different environment:** keep the *shape* (a broad Accept like Outbound, one tight Accept like
> Mail, a resolved Drop near the top, a stealth/cleanup Drop) and the prompt outcomes carry over — just swap
> the IPs/object names for yours. Or pull your own policy first with **"Summarize the Network layer on SMS"**
> (prompt #3) and adapt.

---

## 1. Discovery & read-only (no publish — the agent should never write here)

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 1 | "List my Check Point management servers." | `list_management_servers` | SMS (+ any others), id/name/host |
| 2 | "List the access layers on SMS." | `list_access_layers` | DNS_Layer, dynamic_layer, Network |
| 3 | "Summarize the Network layer on SMS." | `summarize_layer` | rule count, Accept/Drop split, Any-dimension counts, cleanup-drop present |
| 4 | "Analyze the Network policy on SMS for shadowed or overly-permissive rules." | `analyze_policy` | conservative findings only (no false shadow claims) |
| 5 | "On SMS, what Check Point service object matches ‘dns’?" | `correlate_service` | the DNS service object (or candidates) |
| 6 | "On SMS, what application object matches ‘Facebook’?" | `correlate_application` | the Facebook application-site |
| 7 | "Does Terraform support the management host object?" | `coverage_lookup` | `checkpoint_management_host` support + field diff |

**The correlate / "did you mean" family** (each resolves a plain phrase → the real CP object, or returns
candidates — reuse-only, so a miss is reported, never invented):

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 7a | "On SMS, which time object matches ‘work hours’?" | `correlate_time` | the matching time object, or the "did you mean" candidates / none-found |
| 7b | "On SMS, which data type matches ‘source code’?" | `correlate_content` | the `Source Code` data-type object (or candidates) |
| 7c | "On SMS, which bandwidth limit matches ‘10 Mbps upload’?" | `correlate_limit` | a rate limit object like `Upload_10Mbps`, or candidates (a Limit is a RATE, not a volume) |
| 7d | "On SMS, which access role matches ‘finance’?" | `correlate_access_role` | candidates / none — *no access-roles exist in this lab*, so it should honestly report none, never fabricate |
| 7e | "On SMS, which security zone matches ‘DMZ’?" | `correlate_zone` | the `DMZZone` security-zone (or candidates) |
| 7f | "On SMS, which UserCheck message matches ‘blocked message’?" | `correlate_user_check` | the matching UserCheck interaction object, or candidates |
| 7g | "On SMS, which gateway matches ‘GW’ for install-on?" | `correlate_gateway` | the `GW` gateway/target object (or candidates) |
| 7h | "On SMS, which VPN community matches ‘gateway to gateway’?" | `correlate_vpn` | the built-in `All_GwToGw` community (or candidates) |

---

## 2. The headline — decide → apply → **publish** in one sentence (every outcome)

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 8 | "On SMS Network, allow 10.1.1.50 to reach anything on TCP 80 and publish the changes." | NO_OP | already permitted by **Outbound** — nothing to publish; agent says so honestly |
| 9 | "On SMS Network, allow 10.1.9.9 to use mail services to anywhere and publish the changes." | WIDEN | widens the **Mail** rule's source (the one widen-friendly rule); published |
| 10 | "On SMS Network, allow 198.51.100.20 to reach 198.51.100.40 on TCP 8888 and publish the changes." | CREATE (clean, at the section floor) | new least-privilege Accept created + published |
| 11 | "On SMS Network, allow 10.1.1.50 to reach win_server over nbsession and publish the changes." | CREATE **above a resolved Drop** | new Accept placed ABOVE the *Silent Drop* (first-match-safe) + published |
| 12 | "On SMS Network, allow 10.1.1.222 to reach Facebook and publish the changes." | CREATE app→**Internet** | app-Accept to the predefined Internet object + topology note; published |
| 13 | "On SMS Network, allow the InternalZone to reach win_server on RDP and publish the changes." | CREATE, **typed source** (security-zone) | zone-sourced rule created + published |
| 14 | "On SMS Network, allow 10.1.3.33 to reach win_server over GRE and publish the changes." | CREATE, **named protocol** | GRE service resolved, rule created + published |
| 15 | "On SMS Network, allow 10.1.1.50 to reach win_server on any service and publish the changes." | **REVIEW (safety)** | too broad → **review**, nothing published; agent explains why |

---

## 3. Full ACTION column — beyond Accept (all publish)

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 16 | "On SMS Network, block 10.1.1.222 from reaching Facebook and publish the changes." | action **Drop** (app carve-out) via `apply_access` — *block, not `remove_access`* | Drop placed to take effect; published |
| 17 | "On SMS Network, reject Telnet (TCP 23) from 10.1.1.0/24 to win_server and publish the changes." | action **Reject** | Reject rule created + published |
| 17a | "On SMS Network, block ALL traffic from 203.0.113.5 to win_server and publish the changes." | **serviceless block** — `apply_access` action=Drop, **service=Any** | Drop on Any-service created + published (the agent passes `service=Any`, does **not** try to correlate "Any") |
| 17b | "On SMS Network, block 10.1.1.0/24 from Facebook and show the ‘blocked message’ page, and publish the changes." | **Drop + UserCheck block message** | `apply_access` action=Drop with `user_check` resolved via `correlate_user_check`; block page attached; published |
| 17c | "On SMS Network, reject 10.1.1.0/24 to win_server on Telnet and show the company block page, and publish the changes." | **Reject + UserCheck block message** | `apply_access` action=Reject with a `user_check` message object; published |
| 18 | "On SMS Network, add an Ask (UserCheck) rule for 10.1.1.0/24 to Facebook and publish the changes." | action **Ask** | Ask rule created + published (UserCheck default) |
| 18a | "On SMS Network, ask 10.1.1.0/24 browsing to Facebook to confirm with the company-policy message, once a day, and publish the changes." | **Ask + UserCheck + frequency/confirm** | Ask rule with `user_check` (resolved via `correlate_user_check`), `user_check_frequency=once a day`, `user_check_confirm=per rule`; published |
| 19 | "On SMS Network, add an Inform rule for 10.1.1.0/24 browsing to the Internet and publish the changes." | action **Inform** | Inform rule created + published |
| 20 | "On SMS Network, divert 10.1.1.0/24 DNS traffic into the DNS_Layer inline layer and publish the changes." | action **Apply Layer** | divert rule into the existing inline layer (validated reuse-only) + published |

---

## 4. Match-gating columns — content / time / install-on / VPN (all publish)

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 21 | "On SMS Network, allow 10.1.1.222 to the Internet over HTTPS but inspect for the Source Code data type and publish the changes." | **content** + content-direction | Accept with the `Source Code` data-type written; published |
| 22 | "On SMS Network, allow 10.1.1.50 to reach win_server on RDP only during the Off-Work time object and publish the changes." | **time** column | rule scoped to the time object + published *(create the `Off-Work` time object first, or expect a clean reuse-only “not found”)* |
| 23 | "On SMS Network, allow 10.1.1.50 to reach win_server on SSH, installed only on the GW gateway, and publish the changes." | **install-on** | rule with Install-On = GW + published |
| 24 | "On SMS Network, allow 10.1.2.0/24 to reach 10.1.1.0/24 on SMB and assign it to the All_GwToGw VPN community, and publish the changes." | **vpn** column | rule with the VPN community set + published |
| 24a | "On SMS Network, allow 10.1.1.222 to the Internet over HTTPS but cap it at 10 Mbps upload, and publish the changes." | **bandwidth Limit** (Action Settings) | `apply_access` with `action_limit` resolved via `correlate_limit` to a RATE object like `Upload_10Mbps` (a Limit is a RATE, **not** a volume/quota); Accept created above a broad Accept so the cap takes effect; published *(create/have the rate object first, else a clean reuse-only "not found")* |
| 25 | "On SMS Network, allow 10.1.1.222 to the Internet over HTTPS with the captive-portal UserCheck and publish the changes." | **action-settings** (captive portal) | Ask/Accept + captive-portal enabled; published |

---

## 5. Remove / revoke — also one sentence + publish

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 26 | "On SMS Network, revoke kali_linux's access to win_server and publish the changes." | `remove_access` → **DISABLE** (sole exact grant) | rule 12 (DMZ) disabled + published; recorded for rollback |
| 27 | "On SMS Network, stop 10.1.1.222 from reaching Facebook and publish the changes." | `remove_access` (drop-above / review) | a Drop placed above, or a flagged review if not a sole-exact grant |

> **remove_access vs. a Drop block — the agent must pick the right verb.** *Revoke / remove / take away
> an existing allow* → **`remove_access`** (#26–#27: it disables the sole-exact grant or drops above a
> broader one). *Block / deny new traffic* → **`apply_access` with `action=Drop`** (§3 #16, #17a, #17b) —
> and only `apply_access` can attach a block **message** (`user_check`) or block **all** services
> (`service=Any`). Firing #26 and §3 #17b back to back proves the router sends "revoke" to `remove_access`
> and "block … with a message" to `apply_access` — never the reverse.

---

## 6. Amend a rule's metadata (publish)

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 28 | "Rename the rule I just created to ‘PoV — allow 198.51.100.20’ and publish the changes." | `amend_access_rule` (name → new-name) | rule renamed; published |
| 29 | "Add the comment ‘opened for the PoV’ and the tag ‘pov’ to that change and publish the changes." | `amend_access_rule` (comment + tags) | metadata updated; published |
| 30 | "Turn on full logging (track = Log) for that rule and publish the changes." | `amend_access_rule` (track) | track set to Log; published |

---

## 7. Undo / rollback (publish)

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 31 | "Show me the recent changes you've published." | `list_changes` | the changes from this run, newest first, with what/when |
| 32 | "Undo the last change you made and publish the changes." | `revert_change` (delete added rule / re-enable disabled) | the change is surgically reverted + published |
| 33 | "Revert change #N but disable the rule instead of deleting it, and publish the changes." | `revert_change` (disable_instead_of_delete) | rule disabled rather than removed; published |

---

## 8. Guardrails — these *should* refuse or review (prove the safety net even with “publish”)

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 34 | "On SMS Network, allow 10.1.1.50 to reach the frobnicator service and publish the changes." | unknown service | **review + suggestions**, nothing published — never a wrong call to the SMS |
| 35 | "On SMS Network, allow 10.1.1.50 to reach win_server on any service and publish the changes." | over-broad request | **review**, not published |
| 36 | "On SMS Network, allow 10.1.1.50 to reach win_server on RDP and publish the changes." — **run it twice** | idempotency | first run creates+publishes; the second is **no_op** (already allowed) |
| 37 | *(With Autopilot OFF / publish gate off)* "On SMS Network, allow 10.1.1.50 to reach win_server on RDP and publish the changes." | publish gate | apply is **refused**, dry-run instead; agent reports publishing is admin-gated |

---

## 9. Dynamic Layers — author a rulebase and **push** it to a gateway (the other rail)

These exercise the dynamic-layer tools (the `docs/policypilot-dynamic-layer-agent.json` agent). A dynamic
layer is an access rulebase pushed straight to a gateway via the Gaia API `set-dynamic-content`, out-of-band
of SmartConsole — so the verb here is **push**, not publish, and the gate is **`mcp_allow_layer_push`** (a
separate toggle from the SMS publish gate). `add_dynamic_rule` / `remove_dynamic_rule` only **edit** the
layer in the portal; the change takes effect only when you `push_dynamic_layer`. **Almost every actionable
prompt ends “…and push the changes”** — that's the one-sentence demo for this rail.

These are written generically for a layer named **DMZ** and a gateway named **GW1** — substitute your own
saved dynamic-layer name and gateway. Leave the gateway blank or say **`mock`** for the always-allowed
built-in demo target.

| # | Prompt | Exercises | Expect |
|---|--------|-----------|--------|
| 38 | "List the gateways I can push a dynamic layer to." | `list_gateways` | GW1 (+ any others), id/name/host/port |
| 39 | "List my dynamic layers." | `list_dynamic_layers` | DMZ (+ any others), id/name/layer_name/rule count |
| 40 | "Show me the rules in the DMZ layer." | `get_dynamic_layer` | each rule's name/action/source/destination/service + object types (the **portal** copy) |
| 41 | "What's actually on GW1's dynamic layer right now?" | `fetch_dynamic_layer` | the **live** rulebase pulled from the gateway via the Gaia API (incl. any policy pushed over the API outside the portal) — read-only |
| 42 | "Add a rule allowing 10.1.2.50 to reach 10.1.2.60 over SSH in the DMZ layer and push the changes." | `add_dynamic_rule` → `push_dynamic_layer` | rule added (inline host objects), then pushed to a gateway; change summary + task id |
| 43 | "Block 10.1.9.9 from reaching anything in the DMZ layer, dry run." | `add_dynamic_rule` (action Drop) → `push_dynamic_layer` (`dry_run=true`) | Drop rule added; dry-run **validates without applying** (always allowed) — `pushed:false`, status succeeded |
| 44 | "Remove the web-ssh rule from the DMZ layer and push the changes to GW1." | `remove_dynamic_rule` → `push_dynamic_layer` (named gateway) | rule removed (layer keeps ≥1 rule), then pushed to **GW1**; change summary + task id |
| 45 | "Add a rule allowing 10.1.2.0/24 to reach win_server over HTTPS at the top of the DMZ layer and push the changes." | `add_dynamic_rule` (`position=top`, CIDR + named object) → `push_dynamic_layer` | rule placed at the top (inline network object); pushed; change summary |
| 46 | "Remove the last remaining rule from the DMZ layer and push the changes." | `remove_dynamic_rule` guardrail | **refused** — a dynamic layer must keep at least one rule; nothing pushed; agent explains |
| 47 | *(With the layer-push gate OFF)* "Add a rule allowing 10.1.2.50 to reach 10.1.2.60 over SSH in the DMZ layer and push the changes to GW1." | layer-push gate (`mcp_allow_layer_push`) | the real-gateway push is **refused**; agent falls back to a **dry-run** (or `gateway='mock'`) and reports the push is admin-gated — a separate gate from SMS publish |

> **Substitute freely:** these prompts assume a saved dynamic layer called **DMZ** with at least one rule
> (so #43/#45 have something to act on) and a saved gateway called **GW1**. Swap in your own — or run #39 /
> #38 first to see what you have, then adapt.

---

## Coverage checklist (what a full pass proves)

- **Management tools (21):** list_management_servers · list_access_layers · summarize_layer ·
  analyze_policy · coverage_lookup · decide_access · apply_access · remove_access · amend_access_rule ·
  list_changes · revert_change · **correlate_service · correlate_application · correlate_time ·
  correlate_content · correlate_limit · correlate_access_role · correlate_zone · correlate_user_check ·
  correlate_gateway · correlate_vpn**.
- **Dynamic-layer tools (8):** list_gateways · list_dynamic_layers · get_dynamic_layer · fetch_dynamic_layer ·
  import_dynamic_layer · add_dynamic_rule · remove_dynamic_rule · push_dynamic_layer.
- **Outcomes:** no_op · widen · create (clean-floor / above-deny / app-Internet / typed-source / named-proto)
  · review.
- **Action column:** Accept · Drop · Reject · Ask · Inform · Apply Layer · **serviceless block (service=Any)** ·
  **block message (Drop/Reject + UserCheck)** · action-settings (captive / bandwidth **limit**).
- **Match-gating columns:** content (+direction/negate) · time · install-on · vpn · **limit (rate)**.
- **Verb routing:** block (apply_access action=Drop/Reject) ≠ remove_access (revoke an existing allow).
- **Lifecycle:** create → amend → revert; remove → disable; idempotency; publish-gate refusal.
- **Dynamic-layer rail:** read (list/get) → edit (add/remove) → push (dry-run · `mock` · named gateway);
  keep-≥1-rule guardrail; **layer-push-gate refusal** (`mcp_allow_layer_push`, separate from `mcp_allow_publish`).
- **The promise:** for everything in §2–§6, one sentence ending “…and publish the changes” gets it **done**
  on the SMS; for §9, one sentence ending “…and push the changes” gets it **done** on the gateway.
