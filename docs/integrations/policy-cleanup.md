# Policy Cleanup (hit-count rule cleanup)

Policy Cleanup finds access rules that hit count says are **dead weight** and removes them safely in two
stages — a faithful port of Check Point's open-source
[**PolicyCleanUp**](https://github.com/CheckPointSW/PolicyCleanUp) tool (MIT), wired onto PolicyPilot's
`web_api` client instead of the legacy `cpapi` SDK. It reuses the same pinned-TLS session pool, publish /
discard machinery, and governance audit trail as every other rail.

- Service (the ported logic): [`app/services/policy_cleanup.py`](../../app/services/policy_cleanup.py)
- Router (pages + JSON endpoints): [`app/routers/policy_cleanup.py`](../../app/routers/policy_cleanup.py)
- Page: [`app/templates/policy_cleanup.html`](../../app/templates/policy_cleanup.html)
- Management API client it drives: [`app/services/mgmt_api.py`](../../app/services/mgmt_api.py)

## How it decides

The lifecycle is driven entirely by **hit count** on the gateway:

- **Disable** — an **enabled** rule whose last hit (or, if it was never hit, its last modification) is
  older than the **disable-after** threshold (default **180 days**) is a candidate to be disabled.
- **Delete** — a **disabled** rule that *this tool* disabled more than the **delete-after** threshold
  (default **60 days**) ago is a candidate for deletion. A rule a human disabled is never deleted.

When the tool disables a rule it stamps the disable time into the rule's custom-field **`field-3`** and
appends a marker comment — exactly the convention the standalone script uses — so a later run can tell a
tool-disabled rule from a human-disabled one, and so a policy stays interoperable between PolicyPilot, the
standalone script, and SmartConsole.

### Per-rule threshold overrides

Set a rule's custom fields (SmartConsole → *Security Policies → Access Control → Policy → rule Summary
tab*) to override the global thresholds for that rule, same as the upstream tool:

| Field | Meaning |
|---|---|
| `field-1` | Override the **disable-after** days for this rule. `-1` = never disable this rule. |
| `field-2` | Override the **delete-after** days for this rule. `-1` = never delete this rule. |
| `field-3` | The disable timestamp the tool wrote (read-only — managed by the tool). |

A non-numeric or non-positive override value causes the rule to be **skipped** (surfaced with a reason),
never silently mis-handled.

## Use it

1. Portal → **Policy Cleanup** → pick a **management server** (needs a saved credential).
2. Choose an **access layer** (or *All access layers*), set the **disable-after** / **delete-after**
   thresholds, and click **Run plan**. The plan is **read-only** — it pulls the rulebase with hit counts
   and buckets rules into *disable* / *delete* / *skipped* with a reason for each.
3. Review the candidates and **uncheck** anything you want to keep.
4. Apply the reviewed selection. **Every apply first re-fetches and re-classifies each selected rule
   against the live policy** — a rule that took hits, was re-enabled, gained a never-touch pin, or was
   deleted since the plan is *skipped and reported*, never acted on (so a plan left open in a tab for days
   can't act on stale data). Then:
   - **Dry-run selected** — the disable/delete calls are validated against the SMS and then **discarded**.
     Nothing is committed; it proves the payloads are accepted.
   - **Publish selected** — after an explicit confirm, the changes are committed and **published**. A
     governance audit event (metadata only — counts + target, never rule payloads) is raised, visible in
     the header bell and any configured audit webhook.

## Rollback — every committed change is recorded

A published cleanup records **one change-history entry per rule** (the same `AppliedChange` store and
rollback panel as the other rails, under the server's Access automation page), tagged with a shared
`cleanup-<timestamp>` batch id:

- **A disable is fully revertable.** Its entry carries a precomputed inverse that re-enables the rule
  **and restores the exact comments and custom-fields it had the moment before the cleanup touched it**
  (including clearing the `field-3` stamp — so a restored rule can never be mistaken later for one the
  tool disabled). The panel offers *Re-enable* (undo) or *Delete* (finalize) — the cleanup lifecycle,
  driveable per rule from the history.
- **A delete is recorded as terminal** (`resolution: deleted`) and is not one-click revertable — the rule
  is gone from the SMS — but the entry keeps the **full pre-delete rule snapshot** (cells, action,
  comments, custom-fields, hit data) in `request_json`, so exactly what was removed is never lost and can
  be recreated manually. Recreate-on-revert (`add-access-rule` with position anchoring) is the planned
  next step.

The per-rule entries suppress their individual audit notifications; the batch raises **one** governance
event ("disabled 40, deleted 12, skipped 3") so a large cleanup doesn't flood the bell.

## Safety notes

- **Human-in-the-loop.** Nothing is committed without an explicit confirm; the default action is a
  read-only plan and applies default to dry-run.
- **Confirm hit count is on.** The plan is advisory. A rule whose gateway has hit count disabled reads as
  "never hit" and would look like a disable candidate — verify hit count is enabled on the relevant
  gateways before you rely on a plan. (The upstream tool's full install-target / hit-count validation is a
  roadmap item; this first version classifies purely on the rulebase's own hit data.)
- **TLS is always verified** — against the server's pinned certificate (trust-on-first-use) or system
  trust; never a skip-verify path.
- **Reversible.** A disable is trivially reversible — re-enable the rule from **Policy Manager**. A delete
  only ever targets rules the tool itself disabled long ago.
- **Layer-centric.** PolicyPilot operates per access **layer** (not per policy package). Scanning *All
  access layers* iterates every layer on the server/domain.

## Differences from the standalone script

| Upstream `policyCleanUp.py` | PolicyPilot Policy Cleanup |
|---|---|
| `cpapi` SDK, CLI, JSON output file | `web_api` client (`mgmt_api`), portal UI + JSON endpoints |
| Package-centric (`show-packages`) | Layer-centric (`show-access-layers`) |
| `plan` / `apply` / `apply_without_publish` | **Plan** (read-only) + **Dry-run** / **Publish** apply |
| Plan written to / read from a file | Plan reviewed in the browser, selected rows posted to apply |
| Full install-target + hit-count validation | Hit-based classification only (target validation on roadmap) |
| Custom-fields `field-1/2/3` convention | **Identical** — policies stay interoperable |

When it disables a rule, the op preserves the rule's existing `field-1` / `field-2` overrides and adds
only `field-3` — `set-access-rule` replaces the whole custom-fields object, so a naive `{field-3}` would
wipe a `field-2="-1"` never-delete pin.

## Roadmap

Deliberately scoped and human-in-the-loop. Shipped so far: per-rule **rollback & history** (revertable
disables with full metadata restore; deletes recorded with their pre-delete snapshot) and **apply-time
re-classification** (the live re-check described above). Planned next steps:

- **Install-target / hit-count validation** — port the upstream tool's check that hit count is actually
  collecting on every install target (and skip a rule modified after its policy was last installed), so the
  plan can't be skewed by a gateway with hit count off.
- **Recreate-on-revert for deletes** — rebuild a deleted rule from its recorded snapshot
  (`add-access-rule` with neighbor-anchored position), turning the terminal delete entry into a
  one-click restore.
- **Agent surface** — expose plan/apply as MCP + REST tools (the service is surface-agnostic and already
  owns the re-check, recording, and audit, so a future tool inherits all three).
