# Ticket-driven Access Automation

Turn an access request — *let `src` reach `dst` on `service`* — into the **minimal correct change** on a
Check Point access layer, over the Management `web_api`. The engine reads the live rulebase and computes
one of four outcomes: **no-op** (already allowed), **widen** an existing rule, **create** a new
least-privilege rule placed correctly, or **REVIEW** when it can't safely decide. For a PoV this is the
"ServiceNow ticket → firewall rule, with no fat-fingering and no over-grant" story — the FireMon /
Tufin / AlgoSec demo, driven straight off the customer's own policy.

**Full-column support.** A request isn't limited to source/destination/service + Accept — the engine
writes **every access-rule column**: the **Action** (Accept / Drop / Reject / Ask / Inform / Apply Layer),
**Action Settings / UserCheck** (an Ask/Inform prompt *or* a Drop/Reject block-message page, with
frequency / confirm / custom-every), a **bandwidth Limit** (a RATE object, e.g. `Upload_10Mbps`) and
Identity Captive Portal, **Content** (data-types) + **Direction**, **Time**, **Install-on** (targets), and
**VPN** (communities). Every "pick a real Check Point object" value is first *correlated* — a plain phrase
resolves to the real object, with "did you mean" candidates when it's ambiguous (see
[The correlate step](#the-correlate-step-resolve-a-phrase-to-a-real-object)).

- UI + JSON + webhook router: [`app/routers/access_automation.py`](../../app/routers/access_automation.py)
- The pure decision engine (`decide()`) + apply I/O: [`app/services/access_automation.py`](../../app/services/access_automation.py)
- Ticket payload parsing + result write-back: [`app/services/ticketing.py`](../../app/services/ticketing.py)
- Column-object correlators (time / content / limit / gateway / vpn): [`app/services/correlate_objects.py`](../../app/services/correlate_objects.py); typed source/dest objects: [`app/services/typed_objects.py`](../../app/services/typed_objects.py); UserCheck: [`app/services/usercheck.py`](../../app/services/usercheck.py)
- Decision-tree diagram export (single source of truth): [`app/services/decision_tree.py`](../../app/services/decision_tree.py)
- Reuses the Management client + encrypted creds: [`app/services/mgmt_api.py`](../../app/services/mgmt_api.py), [`app/services/mgmt_creds.py`](../../app/services/mgmt_creds.py)

## Use it

1. Portal → **Access Automation**. Pick one of your saved **Management Servers** (a stored, encrypted
   credential is required — set one on the server's **Edit** page).
2. Enter the request: **source**, **destination**, and the service — either **protocol**
   (`tcp`/`udp`/`sctp`) + **port**, a named **service** (`icmp`, `GRE`, …), or an **application** site
   (`Facebook`). Precedence is application > service > protocol+port. Each endpoint has a **type**: the
   default `IP / CIDR / Any`, or a **typed object** — `Domain` (an FQDN, e.g. `alshawwaf.ca`, or
   `.alshawwaf.ca` for the domain *and* its sub-domains), `Access role`, `Dynamic object`,
   `Updatable object`, or `Security zone`. So you can ask, e.g., *"does host `10.1.1.222` have access to
   the domain `alshawwaf.ca`?"* (see [Typed objects](#typed-non-ip-sourcedestination) below). Name the
   **layer** to evaluate (optionally a **package**), and a **ticket id** to stamp on the change.
3. **Preview** (`POST /access-automation/{sid}/preview`) — read-only. The engine pulls the layer, runs
   `decide()`, and shows the minimal change: *already allowed (no-op)* / *widen rule N's source-or-dest
   cell* / *create a rule, placed `above`/`below` rule N* / *REVIEW* with the reason it couldn't decide.
   Every "pick a real object" field is a **type-ahead search menu** that opens on focus and filters as you
   type, backed by a per-field endpoint: `/{sid}/app-search`, `/{sid}/svc-search`,
   `/{sid}/object-search` (typed source/dest), `/{sid}/usercheck-search`, and `/{sid}/field-search`
   (`kind` = `time` | `content` | `limit` | `gateway` | `vpn`) — see
   [The correlate step](#the-correlate-step-resolve-a-phrase-to-a-real-object).
4. **Apply** (`POST /access-automation/{sid}/apply`). With `publish:false` (the default) the change is
   made then **discarded** — a true dry-run that validates against the SMS with zero commit. With
   `publish:true` it commits. A "locked for editing" conflict can be resolved with
   `POST /access-automation/{sid}/take-over` (destructive; the UI confirms first).

## The decision engine

`decide()` is **pure** (no I/O) — it walks the parsed rulebase top-down honouring Check Point
**first-match** semantics, comparing every cell **by value** (IP/port intervals resolved through the
object dictionary), never by object name. The four outcomes:

- **NO_OP** — the first covering rule before any covering drop is an Accept → change nothing. The verdict is
  scoped to **this access layer** (Check Point Ordered Layers chain — a downstream layer can still restrict it).
- **WIDEN** — a reachable Accept is *exactly equal* to the request in two of {source, destination,
  service} and differs in the third → add the request's value to that **rule cell** (never to a shared
  group, which would widen every rule that references it).
- **CREATE** — nothing covers it → add a least-privilege Accept (`track: Log`, comment stamped with the
  ticket id). Placement is computed for first-match correctness: **above** any blocking deny it can fully
  resolve (an application/category is *carved out* above a rule that blocks it), **below** any more-specific
  rule, else grouped into a configurable **provisioned section** created just *above* the cleanup section —
  never *inside* it (Check Point's organize-by-section best practice). If the new allow would also shadow a
  more-specific deny **below** the one it overrides, that anomaly is flagged with an advisory. An
  **application/category** request scopes its destination to the predefined **Internet** object (App Control
  best practice), carrying a note that Internet is topology/blade-dependent.
- **REVIEW** — reserved for a request that can't be turned into a concrete change (an empty/unparsable
  service, or a typed endpoint that names no object) or an ambiguous application/service *name*. It is **not**
  a policy-review stop: the engine never hands a *resolvable* rule to a human — it reuses, widens, or creates.
  Inline ("Apply Layer") rules are pulled and recursed into; a Dynamic Layer (sk182252) is excluded as
  out-of-band but still acts as a placement floor.

**The deny is overridden by placement, not a stop.** A *resolved* covering/partial deny → CREATE the allow
ABOVE it so the access works (first-match then hits the allow); the reason names the deny. A deny it
**cannot** fully resolve (an infra object collapsed to its main IP, an opaque service category, a conditional
drop) is *not* overridden — it's noted and the new allow lands BELOW it.

**Opaque rules don't stop the flow.** A rule the engine *can't fully resolve* — an updatable feed (which
may itself contain the requested object), an unresolvable/negated cell, an over-cap wildcard, an opaque
app category, a non-Accept/Drop action — no longer halts the request with REVIEW. The walk **notes it as
a "possible match — review later" and continues** to the real NO_OP / WIDEN / CREATE. This is safe by
construction: a NO_OP writes nothing, and a new rule is always placed **below** any such opaque
possible-deny (and a WIDEN that would leap a rule over it is suppressed), so the firewall is never
weakened — the opaque rule keeps its first-match precedence. The notes ride along on the decision (and
the webhook/MCP result) so nothing is lost. (A *resolved* deny is different — it's overridden by placement,
above, not handed to a human.)

**Behaviour is tunable — data, not code (Settings → Access automation logic).** A one-click **profile**
(Conservative / Balanced = default / Aggressive / Autopilot) bundles the knobs; individually,
`aa_override_blocking_deny`, `aa_app_carveout`, `aa_prefer_widen`, `aa_emit_notes`, and `aa_ignore_conditions`
each govern one judgment call (defaults = the recommended behaviour), and `aa_rule_section` names the
provisioned section. The live decision tree is downloadable as `.drawio` / `.mmd` / `.dot` from
`/access-automation/decision-tree/{fmt}`.

## Typed (non-IP) source/destination

A source or destination isn't only an address — it can be a Check Point object that matches by a
*different identity entirely*: a **dns-domain** matches by FQDN/DNS, an **access-role** by identity, a
**security-zone** by interface, a **dynamic-object** by gateway-resolved name, an **updatable-object** by
a Check Point-curated feed. Switch either endpoint's **type** to one of these and the engine reasons in
that object's own space — the same way it already treats a service request as *ports* OR *an application*
(never confusing the two).

- **Each kind is its own match space.** A domain request is **provably disjoint** from a rule cell that
  holds only IP / role / zone objects (an IP object can never *be* a domain object), so it is never
  blocked or satisfied by one — it matches an `Any` cell, or a dns-domain object **equal to or a parent
  of** the requested FQDN (`.alshawwaf.ca` covers `alshawwaf.ca` and `www.alshawwaf.ca`). This is
  object-identity semantics: the engine reasons about the policy *as written*, not about runtime DNS
  resolution. The one uncertain cross-kind case is a domain request meeting an **updatable-object** cell
  (a feed like *Office365* can itself contain FQDNs) → that routes to **REVIEW**.
- **IP requests are unchanged.** A plain IP/CIDR request still treats every typed cell as opaque and
  never steps past it — the typed feature only adds new reasoning for typed *requests*; it never weakens
  the IP path.
- **Apply.** A missing **domain** or **dynamic-object** is created (`add-dns-domain` /
  `add-dynamic-object`) then placed; **access-role / security-zone / updatable-object** are **reuse-only**
  — they can't be fabricated from an access request (define them in Identity Awareness / the gateway
  topology / Check Point's repository first), so a missing one is reported, not invented.

## Rule columns (full-column support)

The request carries **every** access-rule column, validated in `ticketing.build_request` and written on
apply. Each object-valued column is **reuse-only** (the named object must already exist on the SMS) unless
noted — the engine never invents a Time / Content / Limit / VPN / Install-on object.

- **Action** — `Accept` (default) / `Drop` / `Reject` / `Ask` / `Inform` / `Apply Layer`. `Apply Layer`
  requires an `inline_layer` (the layer to divert into). Setting a non-Accept action means the request is a
  block/prompt: the engine **creates** the rule (placed first-match-safe), it never reuses an Accept.
- **Action Settings / UserCheck** — attach a UserCheck interaction object, matching SmartConsole's
  "Action Settings" dialog:
  - On **Ask / Inform** it's the *prompt*; `user_check_frequency` (`once a day` | `once a week` |
    `once a month` | `custom frequency…`) and `user_check_confirm` (`per rule` | `per category` |
    `per application/site` | `per data type`) apply, with `user_check_custom_every` +
    `user_check_custom_unit` (`hours`/`days`/`weeks`/`months`) when the frequency is custom.
  - On **Drop / Reject** it's the *blocked-message page*. (`remove_access` has no action / message — a
    block-with-message must go through an apply with `action=Drop`, not a removal.)
- **Bandwidth Limit** — an optional QoS **rate** object (e.g. `Upload_10Mbps`) plus **Enable Identity
  Captive Portal**, valid only on an allowing action (`Accept` / `Ask` / `Inform`). A Limit is a **RATE,
  not a volume/quota** — there is no "max N GB total" control, so a volume ask maps to an existing rate
  object or is declined.
- **Content** — one or more data-type object names + a **Direction** (`any` / `up` / `down`), optionally
  **negated**. `Any`/`All` is stripped (no restriction); `content_negate` over only `Any` is rejected.
- **Time** — a list of time / time-group object names.
- **Install-on** — a list of gateway / target names (an `Any` / `Policy Targets` value is omitted).
- **VPN** — a list of community names (incl. the built-in `All_GwToGw`); `Any`/`[]` means the `Any`
  VPN column. Directional pairs (`{from, to}`) are **rejected** rather than guessed.

**Setting any of these makes the request "restricted."** To guarantee the new condition actually takes
effect under first-match, the engine **CREATEs a precise rule above a broad Accept** (never a false
no-op / widen). Serviceless intent is handled too: a **`Drop`/`Reject` with no service named defaults to
`service=Any`** (block everything from the source), while `Accept`/`Ask`/`Inform` still require an explicit
service/port (you don't allow "everything" by omission).

## The correlate step (resolve a phrase to a real object)

Before a column is written, the plain phrase the user typed is **correlated** to a real Check Point object.
In the UI each field is a search menu (the endpoints in step 3); an agent calls the matching `correlate_*`
tool. Each returns `{term, match, confidence, candidates, note}`: `match` is set **only** for a confident,
unique hit the apply path will accept; otherwise it returns **candidates** ("did you mean") to choose from,
and a missing object is reported (never fabricated). The family:

- `correlate_service` / `correlate_application` — a service (`icmp`, `GRE`, …) or application-site
  (`Facebook`) → its object.
- `correlate_time` — "work hours" → a Time object; `correlate_content` — "SQL Queries" → a data-type;
  `correlate_limit` — "10 Mbps upload" → a rate object.
- `correlate_access_role` — "the finance role" → an Identity-Awareness access-role (zero-trust source);
  `correlate_zone` — "DMZ" → a security-zone. Both are reuse-only.
- `correlate_user_check` — "the blocked message" → a UserCheck object (a loose phrase auto-resolves when
  it's the *only* match, since the message is cosmetic, not access-determining).
- `correlate_gateway` — "the perimeter gateway" → an Install-on target; `correlate_vpn` — "the
  site-to-site community" → a VPN community.

## Inbound webhook (end-to-end automation)

`POST /access-automation/webhook` lets any ticketing system (ServiceNow, Jira, Remedy, curl …) POST an
access request and get back the decision — and, optionally, have it applied and written back.

- **Auth:** the shared secret must arrive as the **`X-PolicyPilot-Token`** header, matching a webhook-scoped
  **API key** (Settings → API keys) or the legacy token (`PILOT_WEBHOOK_TOKEN` / Settings). If neither
  is set the endpoint is **disabled (503)** — it never runs unauthenticated.
- **Body:** vendor-neutral JSON with generous aliases — `server_id` (which saved server), `layer`,
  `source`/`src`, `destination`/`dst`, `protocol`+`port` (or `service` / `application`), optional
  `source_kind`/`destination_kind` (default `ip`; or `domain` / `access-role` / `dynamic-object` /
  `updatable-object` / `security-zone` — then the value is the object identity, e.g. an FQDN), optional
  `package`, `ticket_id`, and `apply` (`true` → apply + publish; default → preview only). The full-column
  fields ride along too: a dedicated **verdict** field (`verdict` / `u_action` / `cp_action`) for the
  action (a bare `action` is honoured only when it names a real verdict, so a ServiceNow record's own
  `action` field doesn't hijack it), plus `inline_layer`, `action_limit`, `captive_portal`,
  `content` + `content_direction` + `content_negate`, `time`, `install_on`, and `vpn` (each with common
  aliases). A serviceless `Drop`/`Reject` defaults to `service=Any`.
- **Scope:** an optional allowlist (`PILOT_WEBHOOK_SERVER_IDS` / Settings) restricts the token to
  specific server ids. A *malformed* allowlist **fails closed** (500) rather than degrading to allow-all.
- **Write-back:** the result is pushed to the caller's `callback_url` if supplied, else the built-in
  **ServiceNow Table API** adapter writes a work note to the incident (`PILOT_SERVICENOW_*` / Settings).

## Security notes

- The publish webhook token grants policy publish on every allowed server — treat it as a top-tier
  secret; scope it with the server-id allowlist.
- **TLS is always verified**, on both the SMS session and every write-back HTTP call — there is no
  skip-verify path. The server's certificate is trust-on-first-use pinned (`ensure_pinned`) before the
  handshake; Management and ServiceNow credentials are stored **encrypted at rest**, never hardcoded.
- `execute()` does all work inside **one session** and publishes (commit) or discards on the dry-run /
  on any error — a half-applied change and its locks are always released, never left dangling.
- A truncated rulebase pull **fails loud** rather than deciding on a partial view (which could step over
  a covering drop it never loaded). New objects materialize at the full requested scope — a CIDR wider
  than one address becomes a **network** object, never silently narrowed to a `/32` host.

## QA — testing the engine

The decision engine is the crown jewel, so it's exercised through the **real** code path (`_parse_rule` +
`decide` / `decide_removal`, the same path `web_api` uses) against small lab-shaped rulebases with a known
Check-Point-correct outcome.

- **Regression tests:** [`tests/test_access_automation.py`](../../tests/test_access_automation.py) —
  `python3 -m pytest tests/test_access_automation.py` (part of the full **842-passing** suite,
  `python3 -m pytest -q`). Coverage spans the outcomes and object kinds the engine handles: IP / CIDR;
  typed source-dest (domain / access-role / security-zone / dynamic / updatable / Internet); L4 services
  (tcp/udp/sctp ports + ranges, service-groups); named services (icmp / icmp6, GRE, opaque); applications
  (application-site / category / app-group, app-vs-L4 carve-out); placement (floor / provisioned-section /
  above-deny / partial / shadowed-deny anomaly / Stealth / Dynamic-Layer / disabled / conditional); and
  removal (disable / deny / no_op / review).
- **Quick smoke demo (no pytest):** `python3 -m app.services.access_automation` prints a handful of
  outcomes (already-allowed / widen / over-grant-guarded / create / explicit-deny) against a built-in
  sample rulebase — a fast eyeball check that the engine loads and decides.
- **Field-support matrix:** [`app/services/field_support.py`](../../app/services/field_support.py) is the
  authoritative, drift-safe map of exactly which Check Point object types the engine handles in each rule
  column, at what support level (full / reuse-only / partial / gap) and how each is discovered. It pulls
  its type lists from the live engine constants and a test (`verify_against_engine()`) fails if the table
  ever diverges from the code — rendered in-app on the **Field support** page, so there is no guessing
  about what the engine can and can't do.
