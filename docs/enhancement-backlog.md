# Enhancement backlog — mined from the CheckPointSW GitHub org

Survey date: **2026-07-09** · Scope: all 77 active repos at <https://github.com/orgs/CheckPointSW/repositories>,
~20 deep-dived (READMEs + source verification). Ranked by value-to-effort for PolicyPilot and the lab MCP fleet.

> License ground rules (org policy): no GPL code may be vendored into PolicyPilot (proprietary). MIT /
> Apache-2.0 are fine to port with attribution; MPL-2.0 tools are used externally, never vendored.

---

## Tier 1 — quick wins

### 1. Run `@chkp/policy-insights-mcp` in the lab MCP fleet  *(zero code — a container)*
- **Source:** [mcp-servers](https://github.com/CheckPointSW/mcp-servers) monorepo (MIT, actively developed —
  the 10 MCP containers on devhub map 1:1 to its packages; this one is missing from the fleet).
- **What it is:** the official AI policy-tightening insights server — zero-hit rules, over-permissive rules,
  disabled rules — 9 tools (`ShowSuggestions`, `ShowSuggestionsSummary`, `ShowRulesUidsWithSuggestions`,
  `ShowState`, …) against `/insights/v3.0/*`. Its README recommends pairing it with the management MCP.
- **Why:** it is the *product-side* counterpart to PolicyPilot's cleanup app — running both makes the demo
  "official insights + PolicyPilot's apply/rollback rail".
- **Requirements:** Management API v2.1 (R82.10+) and Infinity Cloud Services connectivity.
- Also new in the monorepo (June 17): `cloudguard-waf-mcp`, `cpview-history-mcp`; not running either.
  Fleet notes: upstream ships **npm/npx only** (the devhub containers are self-built wrappers); June
  releases bumped most packages (management → 1.4.7); telemetry defaults ON (`TELEMETRY_DISABLED=true` to opt out).

### 2. Port `ChangedPolicies` → a "needs reinstall" badge  ✅ DONE (2026-07-10)
- **Source:** [ChangedPolicies](https://github.com/CheckPointSW/ChangedPolicies) — answers "which policy
  packages were affected by published changes (and therefore need reinstall)". Resolves changes to packages
  via `show-changes` → layer→package map (`show-packages`, `show-nat-rulebase`, parent-layer walks) and
  `where-used` for object changes; global-properties changes flag all packages. Threat/HTTPS mapping is an
  upstream gap PolicyPilot could close.
- **PolicyPilot fit:** our change log already records every committed change — run the resolution on each
  publish and persist a per-package **"policy changed since last install"** badge in Policy Manager, plus a
  `packages_needing_install` MCP tool. The cpapi→httpx translation is mechanical.

### 3. Reputation enrichment in the decision engine  ✅ DONE (2026-07-10)
- **Source:** [reputation-service-api](https://github.com/CheckPointSW/reputation-service-api) —
  `rep.checkpoint.com` REST: URL / IP / file-hash reputation. Returns `risk` 0–100, `classification`
  (Malware, Phishing, CnC Server, …), `severity`, `confidence`. Risk ≥80 = block-recommended.
- **PolicyPilot fit:** enrich `decide_access` — when the destination is a public IP/FQDN, attach reputation
  to the decision: **risk ≥80 → require explicit human override + audit-trail warning; 64–79 → caution
  banner** (same guardrail on the MCP surface so agent-driven requests see it too). New
  `app/services/reputation.py`: token fetch/cache (`Client-Key` → one-week token), TTL result cache (daily
  quota), fail-open when unreachable.
- **Action item:** the Client-Key comes by email from `TCAPI_SUPPORT@checkpoint.com` (trial key + daily
  quota) — request early.

---

## Tier 2 — high-value features (~a week each)

### 4. Make IaC exports *state-adoptable* (Terraform) and *collection-native* (Ansible)
- **Sources:** [terraform-provider-checkpoint](https://github.com/CheckPointSW/terraform-provider-checkpoint)
  (MPL-2.0, active, v3.2.0 06/2026 — external tool only);
  [CheckPointAnsibleMgmtCollection](https://github.com/CheckPointSW/CheckPointAnsibleMgmtCollection)
  (Apache-2.0, v6.9.0, Red Hat certified);
  [CheckPointAnsibleGAIACollection](https://github.com/CheckPointSW/CheckPointAnsibleGAIACollection)
  (LICENSE file says MIT — but the GitHub sidebar says GPL-3.0+; **legal must resolve the discrepancy
  before any code reuse**; external use is fine either way).
- **Terraform:** emit Terraform 1.5+ `import` blocks next to every exported resource — objects import by
  UID, access rules by compound id `"LAYER_NAME;RULE_UID"` (PolicyPilot already holds the UIDs) — so one
  `terraform apply` adopts the exported policy as managed state with zero drift. Emit the provider block
  (`context = "web_api"`) + an explicit publish/install step (`auto_publish_batch_size` or post-apply CLI).
- **Ansible:** emit FQCN `check_point.mgmt.cp_mgmt_*` tasks (idempotent `state: present`) instead of raw
  CLI tasks, with httpapi inventory boilerplate and a pinned `requirements.yml`. Gaia export → `cp_gaia_*`
  tasks; and the Gaia collection's **`cp_gaia_dynamic_content`** module gives the Dynamic Layers rail a
  free "Export as Ansible" button (a GitOps artifact of every push).

### 5. Cleanup app stage 2: replace-then-delete + staged tag cleanup  *(MIT, small scripts)*
- **Source:** [UsefulManagementApiTools](https://github.com/CheckPointSW/UsefulManagementApiTools):
  - `reference/ReplaceReference.py` — re-point every reference from object A to object B across Access /
    NAT / Threat rules, groups, service-groups (`where-used` → `set-*` calls). → a **"replace references,
    then delete"** consolidation flow in the cleanup app; every rewrite lands in the existing per-rule
    audit/rollback.
  - `tags/AddTagToObjects.py` — bulk-tag all/used/unused objects. → **staged cleanup**: tag unused objects
    (`cleanup-candidate-<date>`), delete after a grace period via a retention-style sweep — mirrors the
    two-stage disable→delete rule lifecycle we already ship.
  - (`connect/connect_all_domains.py` — MDS/Infinity onboarding helper; low priority.)

### 6. SmartConsole extension: PolicyPilot inside SmartConsole  *(MIT SDK, 3–5 days read-only)*
- **Source:** [smart-console-extensions](https://github.com/CheckPointSW/smart-console-extensions) — an
  extension is a static HTTPS-hosted web app + `extension.json` manifest; placements include a
  **details-pane tab filtered to `access-policy`**; the SDK hands you the **selected rule at full detail**
  plus a read-only mgmt session, `query()` for mgmt reads, and `navigate(ruleUid)`.
- **PolicyPilot fit:** a "PolicyPilot" tab that shows, for the rule the admin selected: cleanup verdict +
  hit data, the access-decision that created/touched it, and its rollback/change history — with deep links
  both ways. PolicyPilot can host the bundle itself (needs CORS for the SmartConsole origin + api-key auth).
  SDK is dormant-but-stable (platform is a shipping product feature); start read-only (skip `requestCommit`).

---

## Tier 3 — mine for specs/patterns (don't port wholesale)

### 7. `ShowPolicyPackage` (Apache-2.0, Java, active v2.4.0) — *spec for an offline HTML policy report*
Self-contained tar.gz of HTML+JSON for a whole package — auditors/change boards want exactly this frozen
snapshot. Reimplement natively on our fetch layer (don't port the Java). Its command list is also the
coverage roadmap for the policy viewer: threat/HTTPS/exception rulebases, VPN communities, `show-membership`.

### 8. `ExportImportPolicyPackage` (Apache-2.0, active v6.3.0) — *"clone package to staging" recipe*
Whole-package export/import (backup, migration, lab cloning). Port the **batch-import ordering**
(objects → layers → rules → NAT) and export field-normalization tables, not the codebase — it leans on the
undocumented generic-object API (fragile across versions). Pairs with apply_runner + idempotency for a
round-trip "clone this package to a staging domain" feature.

### 9. MCP conventions from the official monorepo (MIT) — *adopt in PolicyPilot's MCP*
- **Namespaced tool names** (`management__show_objects`) + an explicit `init` handshake tool — avoids
  collisions when agents co-attach the official servers (they will).
- **Tool-visibility policy** (`mcp-utils/tool-policy.ts`) — a clean way to hide write tools unless the
  autopilot/publish gates are on, instead of refusing at call time.
- **Query-builder-as-tool** (`build_logs_query_filter`) — teach the model a DSL via a tool.
- Token-efficient **formatted-table rulebase output**; session TTL + `/health` active-session count;
  task-poll backoff; MDS domain-routing client map.
- **Positioning insight:** the official servers are 100% read-only. PolicyPilot's write/automation surface
  (apply/publish/rollback, dynamic layers) has no upstream competitor — keep owning writes; lean on their
  `simulate_packet` and management-logs for pre-flight validation instead of rebuilding them.

### 10. Event-driven dynamic objects — *clean-room only* (upstream is GPL-3.0)
[terraform-checkpoint-dynobj-nia](https://github.com/CheckPointSW/terraform-checkpoint-dynobj-nia)
(GPL-3.0, dormant since 2021) auto-syncs Consul service IPs into Check Point dynamic objects. **No code
reuse (org policy).** The concept fills a real gap: a Dynamic Layers "subscription" mode — K8s Endpoints /
Consul / webhook events trigger `set-dynamic-content` pushes. Related: `dynobj`'s `dns2dyn.py`
(Apache-2.0, dormant) — scheduled FQDN→dynamic-object sync; reimplement natively if wanted.

### 11. `LocalToGlobal` (Apache-2.0, stale 2019) — *MDS "promote to global" pattern*
Copy local-domain objects to Global with dual concurrent sessions (local read + global write). The
dual-session pattern is what our mgmt client needs for any future MDS write feature; verify behavior
against a current MDS before shipping anything.

### 12. `ExportObjects` (Apache-2.0, dormant) — *CSV serializer*
Per-type CSV formatted for `mgmt_cli add -b` batch import. A cheap alternate output format for the
exports router; the per-type field maps are directly liftable.

---

## Skips

| Repo | Why |
|---|---|
| `cpmonitor` | Frozen, 32-bit-only pcap analyzer; hit counts already answer the policy-side question. |
| `SmartMove` | Windows/.NET GUI, dormant; keep standalone. At most: parse its JSON output for a "migration pre-flight review" later. |
| `cp_mgmt_api_python_sdk` etc. | We deliberately run our own httpx web_api client. |
| CloudGuard/Infinity Terraform repos | Cloud-deployment scope, not policy automation. Watch `terraform-provider-infinity-next` only if AppSec scope ever lands. |
| Research/malware repos (Karta, Evasions, InviZzzible…) | Out of scope (InviZzzible is also GPL-3.0). |

## Suggested sequencing

1. **#1 policy-insights container** (today) → 2. **#2 ChangedPolicies badge + #3 reputation enrichment**
(next PolicyPilot program) → 3. **#4 IaC alignment** → 4. **#5 cleanup stage 2** → 5. **#6 SmartConsole
extension prototype** → then Tier 3 as roadmap items.
