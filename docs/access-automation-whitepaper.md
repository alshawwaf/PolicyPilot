# PolicyPilot: Turning an Access Request into the Minimal Correct Firewall Change

**Abstract.** Adding a rule to a Check Point access layer is deceptively hard: because the gateway evaluates rules top-down and the first match wins, *where* a rule lands and *what sits above it* are part of the decision, not an afterthought. PolicyPilot is an access-automation engine that takes a single request — a source, a destination, and a service or application — and returns the minimal correct change against a live access layer over the Management `web_api`. It is strictly reuse-or-create: it decides between leaving the policy untouched (`NO_OP`), widening one existing rule's cell (`WIDEN`), or generating a least-privilege rule and placing it correctly (`CREATE`). It never hard-stops on a "go ask a human" branch in the normal flow. Underneath sits a five-relation set algebra computed per dimension over a dual-band IPv4+IPv6 integer space — the same lineage that Tufin SecureChange Designer, AlgoSec FireFlow, and FireMon converge on. This paper walks the engine the way it walks your rulebase: top-down, by value, one relation at a time.

**Who should read this.** Check Point SEs and firewall engineers who want to understand *why* the engine places a rule where it does — and trust it not to silently over-grant. Read it over coffee.

## Contents

1. [The Problem & What This Tool Does](#1-the-problem--what-this-tool-does)
2. [The Model: First-Match + the Relation Algebra](#2-the-model-first-match--the-relation-algebra)
3. [The Decision: NO_OP vs WIDEN vs CREATE](#3-the-decision-no_op-vs-widen-vs-create)
4. [Where the New Rule Goes (Placement)](#4-where-the-new-rule-goes-placement)
5. [Conditions & What We Cannot Fully Resolve](#5-conditions--what-we-cannot-fully-resolve)
6. [Objects & Typed Endpoints](#6-objects--typed-endpoints)
7. [Safety, Idempotency & Execution](#7-safety-idempotency--execution)
8. [Worked Examples, the Vendor Landscape, and the Exact API Sequence](#8-worked-examples-the-vendor-landscape-and-the-exact-api-sequence)

---

## 1. The Problem & What This Tool Does

Ask any firewall engineer where a new access rule "should go" and watch them hesitate. Not because they don't know the policy — because the right answer depends on everything *above* the line they're about to add.

Check Point evaluates a layer **top-down, first match wins**. That single fact is what makes manual rule placement quietly dangerous. The same rule pasted in three different positions can do three different things:

- **Drop it too high** and you shadow a more-specific rule below it — that rule is now dead, and nobody notices until an audit or an outage.
- **Drop it too low** — below the bottom Any/Any cleanup, or below a covering deny — and your shiny new ACCEPT never fires. The request "is in the policy" and still doesn't work.
- **Drop it without reading the deny above it** and you might *override an intentional admin block* — or fail to, depending on which side of it you land. First-match doesn't care about your intent; it cares about row order.

Then there's the *contents* of the rule. The instinct under deadline pressure is to widen something that's already there — add the new server to an existing rule's destination group. But a rule cell holds a *set*, and a rule grants the full cross-product of its cells. Add one host to the destination of a rule whose source is `{win_client, win_server}` and you've just granted `win_client` reach it never had. That's **accidental over-grant**, and it's invisible in the diff. Multiply this across a few years of tickets and you get the other failure mode every SE knows: **object sprawl** — twelve near-identical host objects for one IP, groups that quietly overlap, a rulebase nobody fully understands.

And the comparison that actually matters — does this rule overlap my request? — is on *values*, not names. Two objects named differently can resolve to the same IP; an object named `Any` covers both IPv4 and IPv6; a `gateway` object's real reach may exceed the single IP you see. Doing this correctly by eye, across a 4,000-rule layer, is not a thing humans are good at.

**This tool does it for them.** You hand it a request, and it returns the *minimal correct change*. It commits to exactly one of three actions:

- **`NO_OP`** — a reachable ACCEPT already covers all three columns, ahead of any covering drop. Change nothing; just attach the rule to the ticket.
- **`WIDEN`** — a reachable ACCEPT already equals your request in two of `{source, destination, service}` and differs only in the third. Add that one value to *that rule's cell* — never to a shared group, and only when the other two match **exactly** (equality, not mere superset — the guard against the over-grant above).
- **`CREATE`** — nothing reuses it, so it generates a least-privilege rule and *places it correctly*: above a blocking deny when one sits in the path, below any more-specific rule, with the bottom Any/Any cleanup as the placement floor.

The decision that earns its keep is **deny handling**. A deny whose extent the engine can *fully prove* gets the new allow placed `{above: uid}` — the access takes effect by position. A deny it *cannot* prove — an infra object collapsed to its main IP, an opaque service like an app category or `service-other` — is treated as a possible block it must not leap over: the allow goes *below* it and the rule is flagged for review. The engine never under-grants past reach it can't see.

Crucially, this engine is built to **never hard-stop**. Anything it can't fully resolve — an updatable feed, a negated cell, a conditional rule gated on VPN or time, an inline-layer split — is noted as a "possible match, review later" and the walk *continues*. `Outcome.REVIEW` survives only for a genuinely incomplete request, or an ambiguous app name where it offers "did you mean…" suggestions. `preview()` is read-only; `execute()` loads, decides, and applies in one session, then publishes or discards. Re-run a satisfied request and you get a `NO_OP` — it's idempotent.

The rest of this paper is about *how* it knows. Under the hood is a five-relation algebra (Al-Shaer & Hamed, IEEE JSAC 2005) computed per dimension over IPv4+IPv6 interval sets — the same rule-recommendation and shadowing analysis that the commercial change-automation tools converge on.

## 2. The Model: First-Match + the Relation Algebra

A Check Point access layer is an ordered list. The gateway walks it top-down and the **first rule whose source, destination, *and* service all match the packet wins** — its action (Accept or Drop) is final, and nothing below it is consulted *within that layer*. (Check Point *Ordered Layers* chain: an Accept only advances evaluation to the next layer, so an end-to-end permit requires every layer to accept. `decide()` reasons within the single layer you target, and a NO_OP "already permitted" verdict is scoped to that layer — a downstream Ordered Layer can still restrict the flow.) That is why an access-automation engine cannot just "add a rule." Where the rule lands, and what sits above it, *is* the decision. A correct allow placed below a covering deny grants nothing; a correct allow placed above a more-specific rule shadows it. `decide()` in `app/services/access_automation.py` is, at heart, a faithful first-match walk: it iterates the rulebase **in the order the rules are supplied** (which is the on-screen top-down order — it does not sort by the `number` field), and the moment it can prove an outcome, it returns.

To walk first-match correctly you must answer one question at every rule, on every column: *how does the request relate to this cell?* PolicyPilot answers it with the **five-relation algebra** from Al-Shaer & Hamed (IEEE JSAC 2005). Two field values are exactly one of:

- **DISJOINT** — no shared values (the rule is out of the path on this column)
- **EQUAL** — identical extents
- **SUBSET** — the request is contained by the rule (the cell covers it)
- **SUPERSET** — the request contains the rule (a more-specific rule lives below)
- **OVERLAP** — they intersect partially (correlated; neither contains the other)

The crucial design choice: these are computed on **resolved value extents, never object names.** `relation(req, rule)` reduces both sides to sorted integer intervals and asks two containment questions via `_covers()` — `req ⊆ rule` and `rule ⊆ req` — then reads off the five cases. Names are noise. A rule cell naming `Net_DMZ` and a request for `10.1.4.0/24` only relate once both are resolved to intervals through the object dictionary (`show-access-rulebase` with `use-object-dictionary` and `details-level full`).

Why value-based wins: name-based comparison is blind to the three things that actually decide coverage. (1) **Containment** — a request for `10.1.4.10/32` is a SUBSET of a rule for `10.1.0.0/16`; the names share nothing, but the rule covers the request, so it's a `NO_OP`, not a redundant new rule. (2) **Aliasing** — two differently-named host objects with the same IP are EQUAL by value. (3) **Composition** — a group resolves to the union of its members' intervals (the engine dereferences groups, and computes `include ∖ except` for group-with-exclusion via `_subtract`), so it sees the *effective* extent the gateway enforces, not the label.

The algebra runs **per dimension**, and each dimension lives in its own space:

- **Addresses** use one shared integer line in two non-overlapping **bands**: IPv4 in `[0, 2³²)` and IPv6 offset into a band starting at `_V6_BASE = 1 << 33` (that is, 2³³). A v4 interval and a v6 interval are structurally DISJOINT — they sit in different bands — same-family ranges compare normally, and the predefined **`Any` spans both bands** (`ANY_IP`) so a v6 request is still correctly a SUBSET of the bottom Any/Any cleanup rather than "disjoint from everything."
- **Services** (`svc_relation`) keep tcp/udp/sctp port intervals keyed by protocol (distinct protocol keys never overlap — SCTP carries a real destination port keyed in `by_proto` just like tcp/udp), application-sites matched by name, and portless/named services (icmp, GRE) keyed by `(family, name)` — so a port request is DISJOINT from an ICMP rule, and `echo-request` under `service-icmp` never aliases the same name under `service-icmp6`.
- **Typed endpoints** (`typed_relation`) — dns-domain, access-role, dynamic-object, updatable-object, security-zone — each match in their own identity space. A domain compares by FQDN hierarchy (`.example.com` covers `www.example.com`); the rest by exact name. A domain request against an IP-only or role-only cell is DISJOINT by construction.

One honest qualification on services: **distinct port protocols and named-service families are structurally disjoint, but a port request is *not* universally disjoint from every other service cell.** A port request meeting an opaque or application-bearing service cell whose own ports don't cover the request is deliberately treated as OVERLAP/indeterminate, not disjoint — because App Control identifies L7 over arbitrary ports, so the rule might match. Such a rule stays in the path (Section 5 covers why this matters for denies). The ICMP-versus-port disjointness above still holds; only the blanket claim does not.

**Concrete example.** Request: `10.1.4.10/32 → 10.2.0.0/24 : tcp/443`. Rule 12 is `10.1.0.0/16 → 10.2.0.0/24 : tcp/443 ACCEPT`. Per-dimension: source SUBSET, destination EQUAL, service EQUAL → all SUBSET-or-EQUAL → `_is_subset` is true → first-match `NO_OP`. Now swap rule 12's service to `tcp/8080`: source SUBSET, destination EQUAL, **service DISJOINT** — the rule is out of the path, and the walk continues to find (or create) something that actually covers `tcp/443`. A name-only tool would have stared at "Net_HQ" vs "10.1.4.10" and learned nothing from either case.

## 3. The Decision: NO_OP vs WIDEN vs CREATE

Hand the engine a request and it returns exactly one of three verbs. There is no "go ask a human" branch in the normal flow. `Outcome.REVIEW` still exists in the enum, but only as a defensive guard for a request that's *incomplete* (no concrete service, or a typed endpoint naming an object that doesn't exist) or an ambiguous service *name* that needs a "did you mean…". A well-formed request always gets an actionable answer.

The whole decision is one top-down walk in `_decide()`. Every dimension is related to the rule's cell with the five-relation algebra (`Relation.DISJOINT / EQUAL / SUBSET / SUPERSET / OVERLAP`), on resolved values.

**NO_OP — already permitted.** The first rule that *fully covers* the request (`_is_subset` true on all three dimensions, `fully_covers`) and is an `is_accept`, reached *before any covering drop*, wins:

```python
if fully_covers and r.is_accept and covering_drop is None:
    return Decision(Outcome.NO_OP, f"already permitted by rule {r.number} ...")
```

Re-running a satisfied request is idempotent — it just NO_OPs again.

**WIDEN — equal in two dims, differs in one.** This is the subtle one. A reachable ACCEPT qualifies only when it is `Relation.EQUAL` to the request in *two* of the three dimensions and the third is the lone not-covered dim (`_dim_covered` returns true only for SUBSET or EQUAL). The engine then adds the request's value for that third dimension to **that rule's cell** — never to a shared group object.

Why *equality*, not superset? Because a cell holds a set, and the rule grants the full cross-product `src × dst × svc`. Take the engine's own example: a rule whose source is `{win_client, win_server}` and you only asked about `win_server`. Source reads as a SUPERSET, not EQUAL. If you widened that rule's destination, you'd also be granting the new destination to `win_client` — silent over-grant. Requiring EQUAL on the two non-differing dims guarantees you grant precisely what was asked. Two more guards: a `conditional` accept never widens (its grant only holds under a column the engine can't model), and an *approx* cell — an infra object (gateway/cluster/mgmt) collapsed to its main IP, whose true reach is wider — is excluded from the equality test (`not src_approx`), because an under-approximation that reads EQUAL would over-grant. Such a rule falls through to CREATE instead.

**CREATE — nothing fits.** Fall off the loop with no NO_OP and no widen target and you build a least-privilege rule (always `action: Accept, track: Log`). Placement matters: a *fully-resolved* specific deny in the path is overridden by position — the allow goes `{"above": r.uid}` so first-match hits it. But a deny whose extent we *can't* prove (approx infra IP, or an indeterminate service like an app-category or `service-other`) is **not** overridden: it's noted and the new allow is forced *below* it via `uncertain_deny`. That's the core safety rule — never grant past a block whose reach you can't prove. The bottom Any/Any cleanup is the placement floor.

Everything the engine can't resolve — updatable feeds, negated cells, non-Accept/Drop actions, unmodelable conditions — is noted as "review later" and the walk **continues**. It never stops the request.

## 4. Where the New Rule Goes (Placement)

Once `_decide()` has decided it must `CREATE`, the only question left is *where* the new allow lands. In a first-match firewall, position **is** policy. A correct rule in the wrong slot grants nothing — or grants too much. PolicyPilot computes the slot from two anchors collected during the single top-down walk, then resolves them in `_placement()`.

**The two anchors.** As the walk passes each fully-resolved rule, it tracks:

- `covering_drop` — the bottom catch-all cleanup (`_is_catchall(r) and r.is_drop and i == last_enabled`). This is the **placement floor**: every new allow must sit above the Any/Any cleanup, or first-match would never reach it.
- `lower_anchor` — the *last* rule strictly **more specific** than the request (`_is_proper_superset(rel_src, rel_dst, rel_svc)`). The new rule must go **below** it so it doesn't shadow that tighter rule.

`_placement(covering_drop, lower_anchor)` resolves these in order: above the cleanup if that's all we have (`{"_above_cleanup": True}`), below the more-specific anchor if one exists (`{"below": lower_anchor.uid}`), or above the cleanup uid explicitly. A floor placement is *not* dumped at the bare bottom of the layer (which would land it **inside** the trailing Cleanup section). At apply time `_floor_position()` groups the new rule into a configurable **provisioned section** (`aa_rule_section`, default *"Provisioned (automation)"*) created just **above** the cleanup section — Check Point's organize-by-section best practice. The rule's first-match *height* is unchanged (still above the cleanup); only its grouping is tidied. If the section was relocated by an admin (no longer bottom-adjacent to the cleanup), or no section is configured, placement safely degrades to anchoring on the cleanup so the rule can never be hoisted above the block that floored it.

**Shadowing, both directions.** "Below the more-specific rule" is one half of the no-shadow contract; "above the cleanup" is the other.

- *Don't get shadowed:* a tighter rule above us (say `Web-Server/443 ACCEPT`) would absorb traffic before our broader new rule ever matched. So our rule goes below it.
- *Don't shadow:* if our broad new rule sat above a tighter existing rule, **we'd** swallow that rule's traffic. `find_shadowed()` is the read-only mirror of this, flagging rules that an earlier, fully-resolved, **unconditional, non-inline** Accept/Drop already covers on all three dimensions (an Apply-Layer rule is never used as a shadower, and a candidate whose own cells are complex is skipped).

**Deny overrides by position.** A *specific* covering deny we can fully resolve doesn't floor placement — it gets jumped. The walk returns `CREATE` with `position={"above": r.uid}` and a reason like *"traffic is currently denied by rule 14 (Block-DB); creating the allow ABOVE it so the requested access takes effect."* First-match hits the new allow before the deny. The same above-placement handles a *partial* deny — a `/32` block inside a `/24` request.

The catch is in `uncertain_deny`. If the walk passed a deny it could **not** fully resolve (an infra object collapsed to its main IP, an opaque service category, a conditional drop, an inline-layer split), we must not leap over it. So before computing placement: `anchor = None if uncertain_deny else lower_anchor`. Dropping the anchor forces the rule to the cleanup floor — guaranteed **below** that possible block, honoring "never over-grant past a rule whose reach we can't prove."

**The anomaly flag.** Sometimes the rulebase is *already* disordered: a more-specific rule sits **below** the cleanup (`lower_anchor.number > covering_drop.number`). The two constraints — below the specific rule, above the cleanup — can't both be satisfied. The engine doesn't silently pick one; it places above the cleanup and stamps `{"_anomaly": True}`, surfaced in the preview as `"anomaly": True`. That's a signal to the SE: your existing ordering is odd, look before you publish.

The same flag guards the **override** case. When we create above a *partial* deny (or carve an app above a blocking rule) and a **more-specific deny sits below** the one we're jumping, the new broad allow now sits above that lower deny too — and first-match can't both override the upper deny *and* preserve the lower one. `_more_specific_deny_below()` scans for exactly this; when found, the engine still places above (the override is the operator's intent) but stamps `{"_anomaly": True}` and emits an advisory naming the shadowed deny, so the conflict is visible before publish. (A *fully-covering* deny is excluded — it already kills any subset rule below it, so nothing new is shadowed.)

## 5. Conditions & What We Cannot Fully Resolve

A real rulebase is full of cells the engine cannot reduce to a clean interval. Some rules only match *under a condition* the engine doesn't model. Some hold objects whose true reach can't be proven. The governing rule for all of them is the same, and it is the safety crux of the whole engine: **note and continue — never hard-stop, never over-grant.**

### Conditional match columns

`_rule_conditions()` flags five columns the engine deliberately does not model: **VPN** (community/direction), **time** (time window), **data** (content / data type), **install-on** (a gateway subset), and **service-resource**. A cell counts as "no restriction" only when it is empty or holds just its default object — `_cell_is_any()` treats `Any`, and `Policy Targets` for install-on, as no-ops. Anything else makes the rule `conditional=True`: it is no longer an always-on Accept/Drop, it only fires under that extra condition.

The engine splits on action (`r.conditional and interferes and not options.ignore_conditions`):

- A **conditional ACCEPT** is excluded from NO_OP / reuse / widen — its grant only holds under the condition, so trusting it would be a silent over-grant. It's recorded as `conditional_skip` and the walk moves on; a clean rule decides, or we CREATE a precise rule whose reason names the conditional rule that *didn't* grant the traffic.
- A **conditional DENY/divert** *might* block under its condition, so it is noted as a possible block and the walk continues with `uncertain_deny = True` (placement forced below it). We never override it.

The admin Setting `ignore_conditions` (a `DecideOptions` flag) flips this: conditional rules are read as unconditional — a conditional Accept can then cover, a conditional Drop becomes a resolved block.

### Writing the full rule — every column, and "restricted" requests

The five columns above are how the engine *reads* other people's rules. It also **writes every access-rule column** when the request asks for one, and does so through the same never-over-grant discipline. `build_request()` (in `ticketing.py`, shared by the UI, the webhook, and the MCP tools) validates and normalises the whole surface into an `AccessRequest`; `_apply()` renders it into one `add-access-rule` payload.

- **Action** — the request's verdict is any of `canonical_action()`'s six: **Accept / Drop / Reject / Ask / Inform / Apply Layer** (`WRITABLE_ACTIONS`). Only **Accept** runs the reuse/widen walk of §3 (it answers "is this *allow* already granted?"); every other verb is routed to `_decide_nonaccept()`, which reasons about *placement* (a Drop still lands above a lower deny, a divert respects the golden rule below) but never claims a NO_OP against an allow. **Apply Layer** requires an `inline_layer` and writes `inline-layer` (the layer to divert into). *Block is not remove:* to stop traffic you send `action=Drop/Reject` (a serviceless block defaults its service to `Any`); `remove_access` is the separate verb that takes away an existing allow.
- **Content + Direction** — Content Awareness data-type objects (`content`, OR-matched) with a `content-direction` of `any` / `up` / `down`, and an optional `content-negate`. A negate over only "Any" is dropped — you can't negate everything.
- **Time** — a *list* of time / time-group objects (union).
- **Install-on** — a *list* of gateways / targets; an `Any` / `Policy Targets` list collapses to "omit" so it isn't a phantom restriction.
- **VPN** — a *list* of communities, including the built-in `All_GwToGw`. A directional `{from, to}` pair is rejected (the spec form is unverified — never guessed). An `Any`/empty list means "omit."
- **Action Settings / UserCheck** — this mirrors SmartConsole's *Action Settings* dialog. For a non-Accept verb the request can attach a **UserCheck interaction object** (`_user_check_payload()` writes the top-level `user-check`): on **Ask / Inform** it is the interaction *plus* a **frequency** (`once a day` / `once a week` / `once a month` / `custom frequency...` with an `{every, unit}` block) and a **confirm** scope (`per rule` / `per category` / `per application/site` / `per data type`); on **Drop / Reject** it is the interaction alone — the **block-message** page. The interaction object is **reuse-only** (validated at publish; a bad name discards the whole session with the SMS's own error).
- **Bandwidth Limit + Captive Portal** — for an *allowing* verb (**Accept / Ask / Inform**), `_action_settings_payload()` can attach a **`limit`** and **`enable-identity-captive-portal`**. The limit is a **rate** object (e.g. `Upload_10Mbps` — a QoS/bandwidth ceiling), **not** a volume or quota. Like the other refs it is validated **reuse-only** at apply time.

The pivotal rule: **setting any of these advanced columns makes the request `forces_create`.** A plain covering Accept may lack the very restriction or setting the request is adding, so the engine must never reuse or widen it. `AccessRequest.is_restricted` (content/time/install-on/VPN) OR `has_action_settings` (limit/captive-portal) flips `forces_create` true — and a request that would otherwise NO_OP against a broad Accept instead **CREATEs a precise rule directly ABOVE that Accept** (`position={"above": r.uid}`), so first-match applies the new condition while the broad rule still serves its other traffic. Placing it at the floor below would be a dead rule. Every one of these object references (time, content, install-on, VPN, limit, UserCheck) is **REUSED — it must already exist on the SMS**, never fabricated; only source/destination/service objects are materialised (§6). A `WIDEN` that somehow reached `_apply()` for a `forces_create` request fails loud rather than silently dropping the column.

### The dynamic inline-layer golden rule (sk182252)

An **Apply Layer** rule can point at either an *ordered* inline layer (which the engine recurses into, above) or a **Dynamic Layer** (sk182252). A dynamic layer is managed **out-of-band** — Gaia pushes its content straight to the gateway, and the SMS never sees its sub-rulebase. The golden rule: **a rule applying a DYNAMIC inline layer is SKIPPED from matching.** The engine never descends into it, reasons about its sub-rules, or even flags it (the operator asked for it to be out of the picture). Safety still binds, though: if the *parent* rule's columns interfere with the request, that traffic is diverted into the out-of-band layer, so the new allow must never be placed **above** it (first-match would bypass the out-of-band segmentation). So a dynamic-layer rule still acts as a silent placement **floor** — it sets `uncertain_deny`, which suppresses any widen and forces the new rule below the divert. A provably-disjoint dynamic rule can't affect the request and is skipped entirely. (This is why PolicyPilot treats its dynamic-layer rail as *complementary* to the SMS rail rather than something to reason across.)

### The crucial deny split — RESOLVED above, UNRESOLVABLE below

This is the line that keeps the engine safe. When a DROP lies in the request's path:

- If we can **fully resolve its extent** (a specific covering deny, or an overlapping/partial deny), we `CREATE` the allow **ABOVE** it — `position={"above": r.uid}`. First-match then hits our allow, the deny still governs everything else, and the reason names the rule we override. The access works *by placement*.
- If we **cannot** prove its extent, we do the opposite. `r.is_drop and interferes and (svc_indeterminate or src_approx or dst_approx)` catches the unprovable cases: an **approx** infra object (a gateway/cluster/management object collapsed to its main `ipv4-address`, whose real reach may be wider) or an **indeterminate** service. These are noted and the allow is placed **BELOW** them (`uncertain_deny`).

`svc_indeterminate` is broader than just "app category or `service-other`." For a **port request**, `_svc_indeterminate` also returns true when the rule's service carries *any* application — a concrete application-site as well as a category — or an opaque member whose port leg doesn't already cover the request. App Control identifies L7 over arbitrary ports, so such a rule *might* match the port's traffic. Keeping it in the path means a DROP there routes the new allow *below* it rather than overriding a block we can't disprove.

The asymmetry is the point. A resolved deny is *exactly* the access the caller asked us to make work — we know what it blocks, so we override it. An unprovable deny might be wider than it looks, and `_provably_disjoint()` will never call an `approx` or negated cell "disjoint." Placing the new allow above it could leap over a real block we simply couldn't see. So we stay below it: **never over-grant past a rule whose reach we can't prove.**

### Opaque, negated, unparsable, and inline-layer rules

`_decide()` notes-and-continues for any in-path rule that's unresolvable for *this* request: an updatable feed, a negated or unparsable cell (`complex_eff`), an app-bearing or opaque service (`svc_uncertain` / the App-Control-over-ports case above), or a non-Accept/Drop action (`not r.is_resolved_action` — Ask, Inform, Client-Auth). Each gets a "possible match — review later" note; if it `could_block` (a drop, or an unknown action that might divert) it sets `uncertain_deny`.

**Inline ("Apply Layer") sub-rulebases** recurse purely: if the whole request is contained in the parent's match and the parent is unconditional, `decide()` re-runs *inside* the attached `inline_rules`, honouring the layer's own implicit cleanup. But if the request only *partially* matches the parent — its traffic splits across the inline and parent layers — that's a multi-rule interaction the engine won't second-guess: noted, `uncertain_deny`, walk continues.

The discipline pays off twice. Nothing the engine goes on to do can weaken the firewall: a NO_OP writes nothing, and WIDEN is suppressed entirely once `uncertain_deny` is set (`widen_target is not None and not uncertain_deny`) because widening a rule above a possible deny would pull traffic past it. The request always lands on an actionable outcome, and every uncertainty rides along as an advisory note — the firewall never gets a silent over-grant, and the automation never dead-ends.

## 6. Objects & Typed Endpoints

A firewall rule cell is not just a bag of addresses. The Source and Destination columns can hold an IP/CIDR, the predefined **Any**, or a *typed identity object* — a `dns-domain`, `access-role`, `dynamic-object`, `updatable-object`, or `security-zone`. The engine treats each of these as living in its own coordinate system, and that single design choice is what keeps the decision honest.

### IP space vs. identity space

For IP endpoints the engine reasons over integer intervals — a dual-band IPv4/IPv6 space where v4 and v6 occupy disjoint bands and the predefined `Any` spans both. That's the familiar five-relation algebra.

A typed endpoint never enters that interval math. `AccessRequest` carries `src_kind`/`dst_kind` (default `"ip"`) and, when typed, a `src_value`/`dst_value` holding the object's identity. Matching is delegated to `typed_relation()`, which mirrors how `svc_relation()` keeps ports and application-sites disjoint: **each identity kind is its own space.** A `domain` request is provably DISJOINT from a cell that holds only IPs, roles, zones, or dynamic-objects. An `access-role` request can never accidentally "equal" a host. This cross-kind disjointness is not a heuristic — it falls straight out of the data model (`_KIND_FIELD` maps each request kind to one field of `TypedExtent`, and `_typed_other()` confirms a cell holds no other kind before it will call a match EQUAL).

### How each kind matches

- **`domain` (dns-domain)** matches by **FQDN hierarchy**. Check Point writes a leading dot (`.example.com`) to mean "this domain *and* every sub-domain"; no dot means the exact FQDN. `_domain_covers()` enforces the asymmetry that bites people: a sub-domain object (`.example.com`) covers the apex and any child, but an **exact** object (`example.com`) covers only that one FQDN — and can *never* satisfy a "domain + sub-domains" request. So a rule allowing `.corp.com` covers a request for `api.corp.com`, but a rule allowing exactly `corp.com` does not.
- **access-role, dynamic-object, updatable-object, security-zone** match by **exact object name** — `value in names`, nothing fuzzy.

There's one deliberate uncertainty: a `domain` request against a cell holding an `updatable-object` returns `OVERLAP` with `unknown=True`, because a Check Point–curated feed *could* contain that FQDN. That keeps such a rule in the path (it won't be silently stepped over).

### The Internet object & application categories

When the requested service is an **application or category** (App Control / URL Filtering), Check Point's documented best practice is to scope the destination to the predefined **Internet** object, not `Any` — so `build_request` upgrades an application request whose destination is `Any` to `Internet` (a specific *internal* destination is honored as-is). The engine models `Internet` as its own identity (`TypedExtent.internet`): EQUAL to a cell holding Internet, SUBSET of `Any`, and **DISJOINT from any IP cell**. That disjointness is precisely why an Internet-destination request steps cleanly **past a Stealth rule** (`Any → gateway, Drop`): a gateway IP is provably not the Internet object, so the Stealth rule is out of the request's path — no false "may block" note, no forced-to-floor. (A *genuine* `Any`-destination request, which includes the gateway plane, still floors below the Stealth rule — that is correct, not a false positive.) Because `Internet` is **topology- and blade-dependent** — it matches only traffic egressing an External/DMZ interface, and only inside an App Control / URL Filtering layer — any rule built against it carries an advisory note to that effect, so a PoV never installs a green policy whose app rule silently matches nothing.

Application **categories** (e.g. *Social Networking*) are first-class alongside single applications. A category request is EQUAL to a rule cell holding that **same category** (so it reuses or widens it instead of creating a redundant rule), and OVERLAP/uncertain against an opaque cell that doesn't name it — kept distinct from a single application *and* from a same-named application-site **group** (which the engine can't prove covers the category).

### Apply: reuse-or-create vs. reuse-only

On `execute()`/`_apply()`, `resolve_typed_object()` splits the kinds by the `creatable` flag in `_TYPED_OBJ`:

- **domain and dynamic-object are reuse-or-create** — looked up, and made via `add-dns-domain` / `add-dynamic-object` if absent.
- **access-role, security-zone, updatable-object are REUSE-ONLY.** If the object doesn't exist, you get a hard `MgmtError` telling you to define it first (an access-role in Identity Awareness, a zone in gateway topology, an updatable-object from Check Point's repository). The engine refuses to fabricate an empty one, because an empty access-role grants nothing and would quietly mislead you.

Domain reuse has a safety latch: `_find_dns_domain()` reuses an existing object only when its `is-sub-domain` flag matches the request's intent. A same-name object with the *opposite* flag is a `name_clash` — it fails loud rather than reuse `.example.com` for an exact request and silently grant `*.example.com`.

### Dedup by value, not by name

IP objects are deduped by **value**: `lookup_host()` compares addresses numerically (so a differently-formatted IPv6 literal still matches), and `lookup_network()` matches subnet + prefix. A `/32` (or `/128` for IPv6) reuses-or-creates a host; a wider CIDR materializes as a **network** object so the committed rule covers the exact scope `decide()` reasoned over — never narrowed to one IP. The literal `Any` references the predefined object and is never created.

### Correlation: a plain phrase → the exact Check Point object

Before the engine can reason about a request, every free-typed name has to become a *real* object on the SMS. That is the **correlate / discovery** family — the read-only step that turns "work hours", "SQL Queries", "10 Mbps upload", or "Facebook" into the one object name the apply path requires. It spans every column that references a named object: service (`services.resolve()`), application/category (`applications.resolve()`), and — reusing the same pure matchers — **time** and **content** (`correlate_objects`), **bandwidth limit** (also `correlate_objects`, backed by `show-limits`), **UserCheck** interaction (`usercheck`), and the typed source/destination kinds — **access-role, security-zone, dynamic-object, updatable-object, domain** (`typed_objects`). An LLM agent reaches each of these through a matching `correlate_*` MCP tool / `/access/correlate/*` REST endpoint.

Every resolver obeys the same conservative contract, because a wrong time/content/limit is a wrong *rule*: a `match` is returned **only** for a unique exact (or normalized-exact) hit proven over a **complete** (non-truncated) result page — a page that hit its `limit`, or whose server `total` exceeds what came back, is treated as truncated and never auto-matched, since a hidden twin past the cutoff would mean wrong access. Each `correlate_objects` resolver deliberately queries the *same* object classes the apply-side validator accepts (`_TIME_TYPES`, `_CONTENT_DT_TYPES`, `show-limits`), so a name it auto-matches always validates and applies cleanly — no "resolved here, rejected there" gap. When there's no confident single hit, `match` is `None` and ranked `candidates` come back with a *"…is ambiguous — choose the exact Check Point object"* note; the agent (or the type-ahead form) picks. This is the "did you mean?" path.

This is also where the surviving `Outcome.REVIEW` lives. It is **not** part of the normal NO_OP / WIDEN / CREATE flow — it's a defensive signal for an *incomplete* request (no concrete service, or a typed endpoint naming no object) and for an ambiguous service/application name. The web layer surfaces those candidates as a top-level `suggestions` list plus a `did you mean: …?` hint, so a human (or webhook) picks the real object before anything is written.

## 7. Safety, Idempotency & Execution

Everything in the preceding sections — the relation algebra, the reuse-or-create walk, the placement logic — exists to serve one promise: the engine only ever makes the firewall *more* permissive in exactly the way you asked, and never by accident. This section is about the guardrails that make that promise hold, and the transactional machinery that turns a decision into a published rule.

### The four correctness guarantees

**Never over-grant.** WIDEN is the dangerous outcome — you're editing an existing rule's cell — so it is the most tightly constrained. The engine widens only when a reachable ACCEPT is `Relation.EQUAL` to the request in two dimensions and differs in the third (`eq[...]` in the widen block). Equality, not mere superset, is the whole game: adding a value grants it crossed with every other member. If a rule's source is `{win_client, win_server}` and you only asked for `win_server`, widening its destination would silently also grant `win_client`. So `_apply()` adds the value to *that rule's cell* (`field: {"add": obj_name}`), never to a shared group object — touching a group would widen every rule that references it. An `approx` cell is excluded from `eq` too, because an under-approximation reading EQUAL could be hiding extra addresses.

**Never silently step over a possible block.** A rule only leaves the request's path when it is *provably disjoint* — `_provably_disjoint(rel, unknown)` returns true only when the cell was fully resolved *and* the relation is DISJOINT. A negated cell, an unenumerable group, a gateway resolved to one IP, an opaque service category — none of these can ever prove disjointness, so the rule stays in the path. A resolved covering or partial DROP gets the new allow created *above* it. But a DROP whose extent the engine *cannot* prove (`svc_indeterminate or src_approx or dst_approx`) is treated as a possible block: it sets `uncertain_deny` and placement is forced to the bottom. Under-approximating a deny is the one error the engine refuses to make.

**Least-privilege.** A CREATE materializes the narrowest object that still covers what `decide()` reasoned over. `resolve_endpoint()` makes a `/32` (or `/128`) into a host object but a wider CIDR into a *network* object, so the committed rule is neither broader nor narrower than the request. The new rule is always `action: Accept, track: Log`.

**First-match preserved.** Every comparison is on resolved values, never names, and the walk honors top-down evaluation: the first covering ACCEPT before any covering DROP wins (NO_OP). Placement is bounded below by `lower_anchor` and floored by the bottom Any/Any cleanup.

### What REVIEW means now

`Outcome.REVIEW` is **not** part of the decision flow. The engine never hard-stops because a rule looks complicated. Anything it can't fully resolve is appended to `notes` ("possible match — review later") and the walk *continues*, with placement forced below it. REVIEW survives only as a defensive signal for an **incomplete or ambiguous request**: Guard 2 fires when no concrete service/port/application is given; Guard 3 fires when a typed endpoint names no object or an IP endpoint resolves to nothing; and `_obj_review()` fires when an application or service *name* matches no single Check Point object, returning "did you mean…" suggestions. Those are all problems with the *input*, caught before any write reaches the SMS — not the engine throwing up its hands at the policy.

### Idempotency

Re-running a satisfied request is a NO_OP. The first covering ACCEPT returns `Decision(Outcome.NO_OP, ...)` and `_apply()` is never reached — `execute()` short-circuits NO_OP and REVIEW before the apply block (`applied: False, published: False`). So a webhook that fires twice, or a ticket re-processed after a retry, writes nothing the second time. There is no "create if not exists" race to get wrong; the decision *is* the existence check.

### Preview vs. execute

`preview()` is strictly read-only. It runs inside a pooled, read-only `read_session` (no login per call), correlates the app/service name, loads the layer through the revision cache, decides, and hands back exactly what `execute()` *would* do via `build_preview()` — outcome, reason, the resolved source/destination/service objects with `exists` flags, the human-readable placement, and any advisory notes. Nothing is written.

`execute()` does load → decide → apply in **one** isolated read-write `MgmtSession` (deliberately *not* the shared read pool), so it always decides on fresh, just-pulled rules with locks held only for this transaction. Then the transactional contract:

- `publish=True` → `s.publish()` commits, and `invalidate_cache(server)` drops the read cache because the revision just advanced.
- `publish=False` → the change is applied and then **`s.discard()`**. This is validate / dry-run mode: it actually sends the `add-access-rule` / `set-access-rule` to the management server — so you get real server-side validation (object types, layer permissions, position resolution) — and then throws the transaction away with zero commit (`validated: True`).
- **Any error mid-apply → discard.** The `except` around `_apply()` calls `s.discard()` to release pending changes and locks. This matters because on Check Point a read-write *logout* does not discard — without the explicit discard, a half-applied object and its locks would linger until the session timed out. If the discard itself fails, the engine reports `lock_conflict` with the offending sessions rather than leaving you guessing.

### Removing access — the inverse of `decide()`

`decide_removal()` (driven by the `remove_access` tool) is the mirror image: given a source/destination/service it finds what *grants* the flow and takes it away with the least-disruptive **safe** move, honouring first-match. It walks top-down to the first fully-covering, fully-resolved ACCEPT before any covering Drop and returns one of two write outcomes:

- **DISABLE** — that one rule grants *exactly* this access and nothing else relies on it (proven sole+exact), so the rule is simply turned off (`enabled: false`) — the gentlest, fully reversible revoke. `_still_granted_below()` first proves no rule beneath would re-grant the flow if this one went dark; a dynamic layer, an inline layer, a conditional, or any opaque cell below can't be proven harmless, so it forces the safer DENY instead.
- **DENY** — a *broader* rule grants it (disabling it would over-remove), so a least-privilege **Drop is inserted ABOVE** that rule for exactly `src→dst:svc`. First-match then denies just this flow while the broad rule keeps serving everyone else — never an over-removal.

If the grant is opaque, inline, conditional, partial, or multi-rule, removal returns `REVIEW` rather than guess. This is deliberately distinct from *blocking* new traffic: to block, you send an `action=Drop/Reject` request through the normal apply path; `remove_access` is only for taking away an access that already exists.

### One-click rollback (the recorded inverse op-list)

Every write the engine commits records its **exact inverse** as a small op-list on the change record — a WIDEN records `set-access-rule {field: {remove: obj}}`, a CREATE records `delete-access-rule {uid}`, a removal-DISABLE records re-enable, a removal-DENY records deleting the Drop (and re-adding any narrowed source member). `revert_change` (or the REST/UI equivalent) replays that list to undo the change. Two safety properties make this trustworthy: `_apply_inverse_op()` is **strictly whitelisted** — only delete-a-rule, re-enable-a-rule, restore-whitelisted-metadata, and remove/re-add-an-object-from-a-cell are ever executed, so a tampered or garbled row can never become an arbitrary management call, and a metadata undo can only relabel, never re-open what a rule matches. And each op runs **idempotently**: if the target rule is already gone (deleted out-of-band), the revert notes it and moves on rather than failing. Reused/created *objects* are intentionally left in place on revert (they may now be referenced elsewhere; deleting them is a separate, riskier action), and an admin can choose to have added rules **disabled rather than deleted** on rollback (`disable_added_rules`) — the greyed-out, auditable undo.

### The revision-based policy cache

Pulling a full rulebase plus its object dictionary on every preview is expensive, so reads go through `cached_raw()` (which lives in `mgmt_api`, not access_automation). The cache key is composed there as `(server, layer, package, max_rules)`; access_automation passes `server`/`layer`/`package` and inherits the module's `max_rules` default. The invalidation signal is the **latest published-session token** (`_policy_token()` — the published session uid plus publish-time), which is monotonic and server-authoritative; publish modify-times are unreliable, so they're never used. Within a short revalidate window the cache is served without even asking the server; past that, the token is compared and the cache is served only if the policy is genuinely unchanged. Crucially, a truncated pull (a rulebase over the `max_rules` cap) raises in `_raw_pull()` *before* it can be cached or reasoned over — deciding on a partial rulebase could mean missing a cleanup or a deny past the cap and under-denying, so the engine refuses. Our own `publish()` calls `invalidate_cache()`, closing the loop so the next read re-pulls.

The thread connecting all of this: the engine is built to act, not to stall — but every place where acting could weaken the firewall, it either proves it's safe or steps below the uncertainty and tells you why.

## 8. Worked Examples, the Vendor Landscape, and the Exact API Sequence

Theory is cheap. Here is the engine actually walking a rulebase. The examples use the smoke-test fixture baked into the bottom of `access_automation.py`, runnable via `python -m app.services.access_automation`, so you can reproduce every one. The engine walks the list in the order rules are supplied — which is the on-screen top-down order — not by sorting the `number` field:

```
8   web farm      src 10.1.0.0/24   dst 172.16.5.10   svc tcp/443    Accept
3   dns one       src 10.1.2.250    dst 9.9.9.9        svc tcp/53     Accept
9   block db      src Any           dst 172.16.5.20   svc tcp/1521   Drop
99  Cleanup rule  src Any           dst Any           svc Any         Drop
```

**1. Already permitted → `NO_OP`.** Request `10.1.0.50 → 172.16.5.10 : tcp/443`. The host sits inside `10.1.0.0/24` (`relation` returns `SUBSET`), the destination is `EQUAL`, the service is `EQUAL`. `_is_subset` is true, the rule `is_accept`, and `covering_drop` is still `None`, so the first branch fires: `Decision(Outcome.NO_OP, "already permitted by rule 8 (web farm)")`. Nothing is written — the result simply attaches rule 8 to the ticket. Re-running stays a `NO_OP`; that is the idempotency guarantee.

**2. Clean source-widen → `WIDEN`.** Request `192.168.9.9 → 172.16.5.10 : tcp/443`. The destination and service are `EQUAL` to rule 8, but the source is `DISJOINT`. In the widen block, `not_covered` is exactly `["source"]` (length 1), and both other dimensions pass the strict `eq` test — equality, not superset, is required, and an `approx` cell is excluded from `eq`. So `widen_field = "source"` and the engine returns `WIDEN`, adding the new host to **rule 8's own source cell** — never a shared group, since editing a group widens every rule that references it.

**3. Create above a covering deny → `CREATE` with `position {above}`.** Request `192.168.9.9 → 172.16.5.20 : tcp/1521`. The walk reaches rule 9, which fully covers the request and `is_drop`. It is *not* the catch-all cleanup (`_is_catchall` is false), so the engine does not treat it as a placement floor — it returns `CREATE` with `position={"above": r.uid}` and the reason "traffic is currently denied by rule 9 (block db); creating the allow ABOVE it." First-match then hits the new allow before the deny. This is deny-override-by-placement: a deny whose extent we can *prove* gets stepped above.

**4. Unresolvable deny → note + create *below*.** Suppose rule 9 instead denied on a gateway object (resolved to its main IP, so `dst_approx` is true) or on `service-other`. Now the `is_drop and (svc_indeterminate or src_approx or dst_approx)` branch fires: the engine appends a "may block this request — its extent can't be fully resolved" note, sets `uncertain_deny = True`, and **continues**. At the end, `uncertain_deny` suppresses any widen and drops `lower_anchor`, forcing placement to the bottom floor — strictly *below* the unprovable deny. The invariant: never leap a rule whose reach you can't prove.

**5. Typed domain request.** `src Any → domain api.example.com : tcp/443`. The domain is reasoned in its own identity space via `typed_relation` / `_domain_covers` (a `.example.com` cell covers it; an exact `example.com` cell does not). On apply, `resolve_typed_object` is reuse-or-create for domains (`add-dns-domain`, leading dot = sub-domains); access-roles, security-zones, and updatable-objects are **reuse-only** and raise a clear "define it first" error if absent.

### How this maps to the commercial tools

This is the same lineage as **Tufin SecureChange Designer**, **AlgoSec FireFlow** (with ActiveChange), and **FireMon** rule recommendation: take a request, check whether existing policy already permits it, and otherwise compute the *minimal* least-privilege change with correct placement and shadowing awareness. The novel-to-this-engine bias is the explicit reuse-or-create taxonomy (`NO_OP` / `WIDEN` / `CREATE`) and the never-hard-stop posture — where a Designer often kicks ambiguity back for human review, PolicyPilot notes it and keeps walking, only ever placing the new rule somewhere provably safe.

### The exact web_api sequence per outcome

Every path begins identically — the read in `_pull_items`:

```
show-access-rulebase  { name, use-object-dictionary: true,
                        details-level: full, dereference-group-members: true }
```

Then, inside one session (`execute()`):

- **NO_OP / REVIEW** — no writes; `discard()` (preview is read-only via a pooled `read_session`).
- **WIDEN** — `set-access-rule { uid, layer, <source|destination|service>: { add: <obj> } }` (the cell `.add`, never a group).
- **CREATE** — materialize the source/destination/service objects reuse-or-create: `add-host` / `add-network` (a wider CIDR stays a NETWORK object, not a `/32`), `add-dns-domain` / `add-dynamic-object`, or `add-service-tcp|udp|sctp`; then `add-access-rule { layer, position, source, destination, service, action, track: Log }`. `action` is the requested verb (default `Accept`; `Apply Layer` also carries `inline-layer`). Any advanced column the request set is written on the *same* payload from **reuse-only** refs: `content` + `content-direction` (+`content-negate`), `time`, `install-on`, `vpn`, an `action-settings { limit, enable-identity-captive-portal }` (allowing verbs), and a top-level `user-check { interaction, frequency, confirm }` (Ask/Inform) or `user-check { interaction }` block-message (Drop/Reject). `position` is `{above: uid}`, `{below: uid}`, or a floor placement (routed into the provisioned section, still above the implicit cleanup).
- **Removal (`remove_access`)** — **DISABLE** is `set-access-rule { uid, layer, enabled: false }`; **DENY** is `add-access-rule { … action: Drop … position: {above: uid} }` for exactly `src→dst:svc` (optionally a `set-access-rule { source: { remove: <member> } }` to narrow a shadowed grant, proven safe at apply time).
- **Commit** — `publish()` on success (then `invalidate_cache`), or `discard()` on validate-only and on **any** mid-apply error, releasing pending changes and locks. Every committed write records its exact inverse op for one-click `revert_change`.

---

## Summary in one breath

You hand PolicyPilot a source, a destination, and a service; it walks the access layer top-down by resolved value through a five-relation algebra over a dual-band IPv4+IPv6 space, and returns the minimal correct change — `NO_OP` if a reachable ACCEPT already covers all three columns before any covering drop, `WIDEN` if one reachable ACCEPT is exactly equal in two dimensions and differs in the third (added to that rule's own cell, never a group, equality enforced to avoid over-grant), or `CREATE` of a least-privilege Accept placed above any deny it can *prove*, below any more-specific rule, and floored by the bottom cleanup — while every deny or cell it *cannot* prove is noted and the new allow is kept strictly below it, so the walk never hard-stops, never over-grants, and (via one-session preview/execute with publish-or-discard) stays idempotent.

*The live decision-tree diagram in the portal (`app/services/decision_tree.py`) renders this exact flow as data — the same branches, anchors, and uncertainty splits described here.*
