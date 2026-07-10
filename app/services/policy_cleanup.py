"""Policy Cleanup — flag and remove rules that hit-count says are dead weight.

A faithful port of Check Point's open-source **PolicyCleanUp** tool
(https://github.com/CheckPointSW/PolicyCleanUp, MIT) onto PolicyPilot's ``web_api`` client
(:mod:`app.services.mgmt_api`) instead of the legacy ``cpapi`` SDK — so it reuses the same pinned-TLS,
session-pooled, publish/discard machinery as every other rail. Two-stage lifecycle, driven by hit count:

* **disable** — an ENABLED rule whose last hit (or, if never hit, last modification) is older than the
  *disable-after* threshold is a candidate to be disabled. On apply it is disabled AND stamped with the
  disable time in custom-field ``field-3`` (the same field the original tool uses) so a later run can tell
  it was disabled by the tool.
* **delete** — a DISABLED rule that the tool disabled (``field-3`` set) more than *delete-after* days ago
  is a candidate for deletion.

Per-rule threshold overrides use the same custom-field convention as the upstream tool: ``field-1``
overrides *disable-after*, ``field-2`` overrides *delete-after*; a value of ``-1`` means "never touch this
rule". This keeps a policy interoperable between PolicyPilot and the standalone script / SmartConsole.

Operating unit is an **access layer** (PolicyPilot is layer-centric), not a policy package. Target/hit-count
validation (confirming hit count is actually collecting on every install target) is deliberately out of
scope for this first version — the plan is advisory and always reviewed by a human before apply. See
``docs/integrations/policy-cleanup.md``.
"""
from __future__ import annotations

import datetime as dt

from . import mgmt_api

# Custom-field convention shared with the upstream PolicyCleanUp tool (and SmartConsole's rule Summary tab):
# field-1 overrides the disable threshold, field-2 the delete threshold, field-3 holds the tool's disable time.
FIELD_DISABLE_OVERRIDE = "field-1"
FIELD_DELETE_OVERRIDE = "field-2"
FIELD_DISABLED_TIME = "field-3"

# Timestamp format written to / read from field-3 — identical to the upstream tool so a policy stays
# interoperable between PolicyPilot and the standalone script.
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Appended to a rule's comments when the tool disables it, so the change is self-describing in SmartConsole.
DISABLE_MARKER = " — disabled automatically by PolicyPilot Policy Cleanup"

DEFAULT_DISABLE_AFTER = 180
DEFAULT_DELETE_AFTER = 60


# --- date helpers (ported from PolicyCleanUp) ------------------------------------------------

def _to_datetime(date_object) -> dt.datetime | None:
    """Convert a Check Point date reply ({'posix': <ms>, ...}) to a naive local datetime, matching the
    upstream tool's ``datetime.fromtimestamp(posix/1000)``. Returns None on missing/garbage input."""
    if not isinstance(date_object, dict):
        return None
    posix = date_object.get("posix")
    if posix in (None, ""):
        return None
    try:
        return dt.datetime.fromtimestamp(int(posix) / 1000)
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def _iso(date_object) -> str:
    """A display ISO-ish string for a CP date object, or '' if absent."""
    d = _to_datetime(date_object)
    return d.strftime(DATETIME_FORMAT) if d else ""


def _last_hit_time(rule: dict) -> dt.datetime | None:
    """The later of the rule's last-hit and last-modify times — a rule modified after its last hit is
    effectively "active as of" the modification. If it was never hit, fall back to last-modify-time.
    Mirrors PolicyCleanUp.get_rule_last_hit_time."""
    modify = _to_datetime((rule.get("meta-info") or {}).get("last-modify-time"))
    hits = rule.get("hits") or {}
    last_hit = _to_datetime(hits.get("last-date")) if "last-date" in hits else None
    if last_hit is None:
        return modify
    if modify is None:
        return last_hit
    return max(last_hit, modify)


def _disabled_time(rule: dict) -> dt.datetime | None:
    """When THIS tool disabled the rule (from field-3), or None if it wasn't tool-disabled / unparsable.
    Mirrors PolicyCleanUp.get_rule_disabled_time."""
    raw = (rule.get("custom-fields") or {}).get(FIELD_DISABLED_TIME)
    if not raw:
        return None
    try:
        return dt.datetime.strptime(raw, DATETIME_FORMAT)
    except (ValueError, TypeError):
        return None


# --- threshold resolution (ported from PolicyCleanUp.get_rule_final_threshold) ---------------

class _Skip(Exception):
    """Raised to skip a rule with a human reason (invalid per-rule override)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _final_threshold(rule: dict, field: str, global_threshold: int) -> int | None:
    """Resolve the effective threshold (days) for one rule, honouring a per-rule custom-field override.

    Returns the number of days, or None to mean "don't touch this rule". Raises :class:`_Skip` with a
    reason for an invalid override value. Rules (from the upstream tool):
      * global threshold of -1  -> None (feature globally disabled)
      * empty override          -> use the global threshold
      * override == "-1"        -> None (pin: never touch this rule)
      * non-numeric / < 1       -> skip with a reason
      * otherwise               -> the override value
    """
    if global_threshold == -1:
        return None
    local = (rule.get("custom-fields") or {}).get(field)
    if not local:
        return global_threshold
    local = str(local).strip()
    if local == "-1":
        return None
    try:
        value = int(local)                     # int() — not isdigit(): "--1"/"1.5"/"" all skip cleanly
    except (TypeError, ValueError):
        raise _Skip(f"{field} override is non-numeric ({local!r})")
    if value < 1:
        raise _Skip(f"{field} override is not a positive number ({local!r})")
    return value


# --- classification --------------------------------------------------------------------------

def classify_rule(rule: dict, *, disable_after: int, delete_after: int, now: dt.datetime,
                  installed_at: dt.datetime | None = None) -> tuple[str, str]:
    """Decide what should happen to one rule. Returns ``(verdict, reason)`` where verdict is one of
    ``"disable"``, ``"delete"``, ``"skip"`` or ``"keep"``. Pure — no I/O — so it is unit-testable with a
    plain rule dict. ``installed_at`` is the OLDEST install time of the layer's package across its targets
    (when known): an ENABLED rule modified after that was never enforced, so its zero hits are meaningless —
    skip it rather than flag it (the upstream tool's validate_rule check)."""
    enabled = rule.get("enabled", True)
    if enabled:
        if installed_at is not None:
            modified = _to_datetime((rule.get("meta-info") or {}).get("last-modify-time"))
            if modified is not None and modified > installed_at:
                return "skip", "modified after the last policy install — the change isn't enforcing yet, " \
                               "so its hit count can't be trusted"
        try:
            threshold = _final_threshold(rule, FIELD_DISABLE_OVERRIDE, disable_after)
        except _Skip as s:
            return "skip", s.reason
        if threshold is None:
            return "keep", "disable pinned off for this rule"
        last = _last_hit_time(rule)
        if last is None:
            return "skip", "no hit-count or modification date available"
        if last + dt.timedelta(days=threshold) < now:
            hits = rule.get("hits") or {}
            when = "never hit" if "last-date" not in hits else f"last hit {_iso(hits.get('last-date'))}"
            return "disable", f"{when}; older than {threshold} days"
        return "keep", "recently active"

    # Disabled rule: a delete candidate only if THIS tool disabled it long enough ago.
    try:
        threshold = _final_threshold(rule, FIELD_DELETE_OVERRIDE, delete_after)
    except _Skip as s:
        return "skip", s.reason
    if threshold is None:
        return "keep", "delete pinned off for this rule"
    disabled_at = _disabled_time(rule)
    if disabled_at is None:
        return "keep", "disabled, but not by this tool (no disable stamp)"
    if disabled_at + dt.timedelta(days=threshold) < now:
        return "delete", f"disabled by the tool on {disabled_at.strftime(DATETIME_FORMAT)}; " \
                         f"older than {threshold} days"
    return "keep", "disabled recently"


# --- environment validation (ported from PolicyCleanUp's target/hit-count checks) -------------

def hitcount_environment(session) -> dict:
    """Best-effort check that hit counts are actually being COLLECTED — the plan's ground truth.
    Returns ``{"domain_hitcount_on": bool|None, "targets_hitcount_off": [names], "warnings": [str]}``.
    Uses the generic-object API exactly like the upstream tool (documented there as schema-fragile), so any
    failure degrades to ``None``/empty with no warning-noise — the plan still runs, just unvalidated."""
    out = {"domain_hitcount_on": None, "targets_hitcount_off": [], "warnings": []}
    try:
        props = session.call("show-generic-objects",
                             {"class-name": "com.checkpoint.objects.classes.dummy.CpmiFirewallProperties",
                              "details-level": "full"}).get("objects") or []
        flags = [o.get("enableHitCount") for o in props if "enableHitCount" in o]
        if flags:
            on = all(bool(f) for f in flags)
            out["domain_hitcount_on"] = on
            if not on:
                out["warnings"].append(
                    "Hit Count is DISABLED in this domain's global properties — every rule reads as "
                    "“never hit”, so this plan cannot be trusted. Enable Hit Count and re-plan.")
    except Exception:  # noqa: BLE001 — generic API drift must never break the scan
        pass
    try:
        gws = session.call_paged("show-gateways-and-servers", key="objects")
        for gw in gws:
            if not (gw.get("network-security-blades") or {}).get("firewall"):
                continue                              # not an enforcement target
            try:
                g = session.call("show-generic-object", {"uid": gw.get("uid"), "details-level": "full"})
                if (g.get("firewallSetting") or {}).get("hitCountFw1Enable") is False:
                    out["targets_hitcount_off"].append(gw.get("name") or gw.get("uid"))
            except Exception:  # noqa: BLE001
                continue
        if out["targets_hitcount_off"]:
            out["warnings"].append(
                "Hit Count is off on gateway(s): " + ", ".join(out["targets_hitcount_off"]) +
                " — rules enforced only there read as “never hit”.")
    except Exception:  # noqa: BLE001
        pass
    return out


def install_context(session) -> dict:
    """Map each access LAYER (by name and uid) to the oldest install time of the package containing it —
    the reference point for the modified-after-install skip. A layer whose package has an uninstalled/
    unassigned target maps to None-with-warning (rules can't be validated against an install that never
    happened). Returns ``{"layers": {name_or_uid: datetime|None}, "warnings": [str]}``."""
    from . import changed_policies as cp
    out: dict = {"layers": {}, "warnings": []}
    try:
        packages = session.call_paged("show-packages", key="packages")
        gateways = session.call_paged("show-gateways-and-servers", key="objects")
    except Exception:  # noqa: BLE001 — no package context -> scan proceeds without the install check
        return out
    for pkg in packages:
        running = cp._targets_running(pkg.get("name") or "", gateways)
        installs = []
        incomplete = False
        for gw in running:
            pol = gw.get("policy") or {}
            inst = cp._posix_dt(pol.get("access-policy-installation-date"))
            if not pol.get("access-policy-installed") or inst is None:
                incomplete = True
            else:
                installs.append(inst)
        oldest = min(installs) if installs and not incomplete else None
        if running and oldest is None:
            out["warnings"].append(f"package “{pkg.get('name')}” has target(s) without an "
                                   "installed policy — its rules' hit data can't be fully validated")
        for layer in pkg.get("access-layers") or []:
            for key in (layer.get("name"), layer.get("uid")):
                if key:
                    out["layers"][key] = oldest
    return out


# --- rulebase pull with hit counts -----------------------------------------------------------

def _flatten(items: list[dict]) -> list[dict]:
    """Flatten sections into a flat list of access-rules (drop section headers), like the tool's
    conceal_sections."""
    out: list[dict] = []
    for it in items or []:
        if it.get("type") == "access-section":
            out.extend(r for r in (it.get("rulebase") or []) if r.get("type") == "access-rule")
        elif it.get("type") == "access-rule":
            out.append(it)
    return out


def _pull_rulebase_with_hits(session, layer: str, max_rules: int = 50000) -> tuple[list[dict], dict]:
    """Pull ``layer``'s access rulebase WITH hit counts and its object dictionary, reusing the shared
    ``mgmt_api._raw_pull`` (which pages, merges the object dictionary, and raises MgmtError on truncation
    so a partial rulebase is never reasoned over). Returns ``(rules, objdict)`` — rules flattened
    (sections concealed)."""
    raw = mgmt_api._raw_pull(session, layer, None, max_rules, hits=True)
    return _flatten(raw["items"]), raw["objdict"]


def _rule_summary(rule: dict, layer: str, objdict: dict, verdict: str, reason: str) -> dict:
    """A compact, display-ready record for one classified rule (what the UI + apply both consume). Reuses
    ``mgmt_api``'s cell resolvers so a rule renders identically here and in Policy Manager. Carries the
    rule's ``custom-fields`` so a disable op can preserve the field-1/field-2 overrides when it stamps
    field-3 (a bare ``{field-3}`` would REPLACE the whole object and wipe the pins)."""
    hits = rule.get("hits") or {}
    cf = rule.get("custom-fields") or {}
    return {
        "uid": rule.get("uid"),
        "layer": layer,
        "number": rule.get("rule-number"),
        "name": rule.get("name") or "",
        "enabled": rule.get("enabled", True),
        "source": mgmt_api._obj_names(rule.get("source"), objdict),
        "destination": mgmt_api._obj_names(rule.get("destination"), objdict),
        "service": mgmt_api._obj_names(rule.get("service"), objdict),
        "action": mgmt_api._one_name(rule.get("action"), objdict),
        "comments": rule.get("comments") or "",
        "custom_fields": cf,
        "hit_count": hits.get("value") if isinstance(hits, dict) else None,
        "last_hit": _iso(hits.get("last-date")) if "last-date" in hits else "",
        "last_modified": _iso((rule.get("meta-info") or {}).get("last-modify-time")),
        "disabled_at": cf.get(FIELD_DISABLED_TIME, "") if verdict == "delete" else "",
        "verdict": verdict,
        "reason": reason,
    }


def scan_layer(session, layer: str, *, disable_after: int, delete_after: int,
               now: dt.datetime, max_rules: int = 50000,
               installed_at: dt.datetime | None = None) -> dict:
    """Scan ONE layer (over an already-open read session) and bucket its rules. Returns
    ``{layer, disable, delete, skipped, counts}`` (or ``{layer, error}`` if the pull failed)."""
    try:
        rules, objdict = _pull_rulebase_with_hits(session, layer, max_rules)
    except mgmt_api.MgmtError as exc:
        return {"layer": layer, "error": str(exc), "disable": [], "delete": [], "skipped": []}

    disable, delete, skipped = [], [], []
    for rule in rules:
        verdict, reason = classify_rule(rule, disable_after=disable_after,
                                        delete_after=delete_after, now=now, installed_at=installed_at)
        if verdict == "disable":
            disable.append(_rule_summary(rule, layer, objdict, verdict, reason))
        elif verdict == "delete":
            delete.append(_rule_summary(rule, layer, objdict, verdict, reason))
        elif verdict == "skip":
            skipped.append(_rule_summary(rule, layer, objdict, verdict, reason))
    return {"layer": layer, "disable": disable, "delete": delete, "skipped": skipped,
            "counts": {"disable": len(disable), "delete": len(delete), "skipped": len(skipped),
                       "scanned": len(rules)}}


def scan(server, secret: str, *, layers: list[str] | None = None,
         disable_after: int = DEFAULT_DISABLE_AFTER, delete_after: int = DEFAULT_DELETE_AFTER,
         now: dt.datetime | None = None, max_rules: int = 50000) -> dict:
    """Build a cleanup PLAN (read-only) for ``server``. ``layers`` limits the scan; None/[] scans every
    access layer. Returns ``{thresholds, layers:[per-layer results], totals}``.

    Each layer is scanned under its OWN short read-session acquisition rather than one session held across
    all layers: the shared read pool serializes every read for a server behind one lock, so holding it for
    a whole multi-layer MDS scan would stall every other portal read (Policy Manager, access automation) —
    releasing between layers lets them interleave. The login is amortised by the pool either way."""
    now = now or dt.datetime.now().replace(microsecond=0)
    disable_after = int(disable_after)
    delete_after = int(delete_after)
    # Environment validation first (one short session): is hit count actually being collected, and when
    # was each layer's package last installed? Both are best-effort — the scan proceeds either way, the
    # findings become plan warnings + per-rule skips instead of hard failures.
    with mgmt_api.read_session(server, secret) as s:
        env = hitcount_environment(s)
        ctx = install_context(s)
        if layers:
            target_layers = list(layers)
        else:
            target_layers = [l.get("name") for l in s.list_access_layers() if l.get("name")]
    results = []
    for name in target_layers:
        with mgmt_api.read_session(server, secret) as s:
            results.append(scan_layer(s, name, disable_after=disable_after, delete_after=delete_after,
                                      now=now, max_rules=max_rules,
                                      installed_at=ctx["layers"].get(name)))
    totals = {"disable": 0, "delete": 0, "skipped": 0, "scanned": 0, "layer_errors": 0}
    for r in results:
        if r.get("error"):
            totals["layer_errors"] += 1
            continue
        for k in ("disable", "delete", "skipped", "scanned"):
            totals[k] += r.get("counts", {}).get(k, 0)
    return {"thresholds": {"disable_after": disable_after, "delete_after": delete_after},
            "layers": results, "totals": totals,
            "warnings": env["warnings"] + ctx["warnings"],
            "validation": {"domain_hitcount_on": env["domain_hitcount_on"],
                           "targets_hitcount_off": env["targets_hitcount_off"]}}


# --- apply -----------------------------------------------------------------------------------

def build_ops(disable: list[dict], delete: list[dict], *, now: dt.datetime) -> list[dict]:
    """Build the ordered write ops for an apply: disables first (stamp field-3 + append the marker
    comment), then deletes. Each op is the ``{command, payload, summary}`` shape ``apply_changes``
    consumes. Pure — testable without a session."""
    stamp = now.strftime(DATETIME_FORMAT)
    ops: list[dict] = []
    for r in disable:
        if not r.get("uid") or not r.get("layer"):
            continue
        comments = (r.get("comments") or "")
        if DISABLE_MARKER.strip() not in comments:
            comments = (comments + DISABLE_MARKER)[:2000]
        # set-access-rule REPLACES the whole custom-fields object, so carry the rule's existing fields
        # forward and only add field-3 — otherwise a field-1/field-2 override (incl. a "-1" never-touch
        # pin) would be wiped when the rule is disabled.
        custom_fields = {k: v for k, v in (r.get("custom_fields") or {}).items()
                         if k in (FIELD_DISABLE_OVERRIDE, FIELD_DELETE_OVERRIDE)}
        custom_fields[FIELD_DISABLED_TIME] = stamp
        ops.append({
            "command": "set-access-rule",
            "payload": {"uid": r["uid"], "layer": r["layer"], "enabled": False,
                        "custom-fields": custom_fields, "comments": comments},
            "summary": f"disable rule {r.get('number') or ''} “{r.get('name') or r['uid']}”".strip(),
        })
    for r in delete:
        if not r.get("uid") or not r.get("layer"):
            continue
        ops.append({
            "command": "delete-access-rule",
            "payload": {"uid": r["uid"], "layer": r["layer"]},
            "summary": f"delete rule {r.get('number') or ''} “{r.get('name') or r['uid']}”".strip(),
        })
    return ops


def _disable_inverse(fresh_row: dict) -> dict:
    """The precomputed inverse of a cleanup disable: re-enable the rule AND restore the comments +
    custom-fields it had immediately before we touched it. One atomic op in the shape
    ``access_automation._apply_inverse_op`` replays (whitelisted metadata only, never a match column).
    The field-3 stamp is explicitly blanked (not just omitted) so the restore clears it whether the SMS
    replaces or merges custom-fields — a lingering stale stamp would make a later HUMAN disable of the
    restored rule read as tool-disabled and eligible for deletion."""
    restore = dict(fresh_row.get("custom_fields") or {})
    restore.setdefault(FIELD_DISABLED_TIME, "")
    return {"op": "set-access-rule", "uid": fresh_row["uid"], "layer": fresh_row["layer"],
            "enabled": True,
            "set": {"comments": fresh_row.get("comments") or "", "custom-fields": restore}}


def _reclassify(server, secret: str, rows: list[tuple[dict, str]], *, disable_after: int,
                delete_after: int, now: dt.datetime, max_rules: int) -> tuple[list[dict], list[dict], list[dict]]:
    """Re-fetch every affected layer WITH hits and re-run the classification on the LIVE rule — the plan
    may be stale (left open in a tab for days). Returns ``(fresh_disable, fresh_delete, skipped)``:
    fresh rows rebuilt from live data (so the apply writes back current comments/custom-fields, never a
    plan-time snapshot), and skips for rules that vanished or whose verdict changed (got hits, was
    re-enabled, or gained a never-touch pin). Raises MgmtError if a layer can't be pulled — a partial
    re-check must fail loud, not silently apply the un-checked remainder."""
    with mgmt_api.read_session(server, secret) as s:
        ctx = install_context(s)          # same modified-after-install guard the plan applies
    by_layer: dict[str, dict] = {}
    for layer in {row.get("layer") for row, _ in rows if row.get("layer")}:
        with mgmt_api.read_session(server, secret) as s:
            raw = mgmt_api._raw_pull(s, layer, None, max_rules, hits=True)
        ordered = _flatten(raw["items"])
        by_layer[layer] = {"rules": {r.get("uid"): r for r in ordered},
                           "order": [r.get("uid") for r in ordered],
                           "objdict": raw["objdict"]}

    fresh_disable, fresh_delete, skipped = [], [], []
    for row, want in rows:
        uid, layer = row.get("uid"), row.get("layer")
        pulled = by_layer.get(layer) or {"rules": {}, "order": [], "objdict": {}}
        fresh = pulled["rules"].get(uid)
        if fresh is None:
            skipped.append({"uid": uid, "layer": layer, "number": row.get("number"),
                            "name": row.get("name") or "", "requested": want,
                            "reason": "rule no longer exists in this layer"})
            continue
        verdict, reason = classify_rule(fresh, disable_after=disable_after,
                                        delete_after=delete_after, now=now,
                                        installed_at=ctx["layers"].get(layer))
        summary = _rule_summary(fresh, layer, pulled["objdict"], verdict, reason)
        if verdict == want:
            if want == "delete":
                # Recreate-on-revert needs the FULL pre-delete rule + where it sat: keep the raw rule
                # (minus the volatile hit/meta blobs) and anchor the position to the rule that FOLLOWS it,
                # so a revert can put it back in place even after other rules shift.
                raw_rule = {k: v for k, v in fresh.items() if k not in ("hits", "meta-info")}
                order = pulled["order"]
                idx = order.index(uid) if uid in order else -1
                summary["raw_rule"] = raw_rule
                summary["position_anchor"] = ({"above": order[idx + 1]}
                                              if 0 <= idx < len(order) - 1 else "bottom")
            (fresh_disable if want == "disable" else fresh_delete).append(summary)
        else:
            skipped.append({"uid": uid, "layer": layer, "number": summary["number"],
                            "name": summary["name"], "requested": want,
                            "reason": f"verdict changed since the plan — now “{verdict}” ({reason})"})
    return fresh_disable, fresh_delete, skipped


def _recreate_inverse(fresh_row: dict) -> dict | None:
    """The precomputed inverse of a cleanup DELETE: recreate the rule from its pre-delete snapshot,
    anchored where it sat. Deliberate safety choices baked into the op:
      * the rule is recreated **disabled** (it WAS disabled — cleanup only deletes tool-disabled rules) —
        a rollback never silently re-opens traffic;
      * the ``field-3`` disable stamp is CLEARED so the recreated rule reads "disabled, but not by this
        tool" — the next scan won't immediately re-flag it for deletion; a human decides its fate.
    Returns None when the apply didn't capture a snapshot (a hand-crafted API row) — then the delete is
    recorded non-revertable, exactly as before."""
    raw = fresh_row.get("raw_rule")
    if not isinstance(raw, dict) or not raw:
        return None
    rule = {k: v for k, v in raw.items() if k not in ("uid", "type", "rule-number")}
    cf = dict(rule.get("custom-fields") or {})
    cf[FIELD_DISABLED_TIME] = ""
    rule["custom-fields"] = cf
    rule["enabled"] = False
    return {"op": "add-access-rule", "layer": fresh_row["layer"],
            "position": fresh_row.get("position_anchor") or "bottom", "rule": rule}


def _record_batch(server, *, fresh_disable: list[dict], fresh_delete: list[dict],
                  inverses: dict, actor: str, now: dt.datetime) -> int:
    """Persist one revertable AppliedChange row per committed rule. Disables carry the full-fidelity
    re-enable inverse; deletes carry a RECREATE inverse (add-access-rule from the pre-delete snapshot,
    recreated disabled + unstamped) — rows without a snapshot fall back to a terminal, non-revertable
    record so nothing vanishes silently. Rows share a cleanup batch id (ticket_id) and suppress the
    per-row audit emit — the caller raises ONE governance event for the batch. Best-effort: a bookkeeping
    failure must never turn the committed change into a reported error."""
    from ..db import SessionLocal
    from . import change_log
    batch_id = f"cleanup-{now.strftime('%Y%m%d-%H%M%S')}"
    recorded = 0
    with SessionLocal() as db:
        for r in fresh_disable:
            change_log.record_committed(
                db, server=server, layer=r["layer"], action="cleanup", outcome="disable",
                summary=f"cleanup: disable rule {r.get('number') or '?'} “{r.get('name') or r['uid']}” — {r['reason']}",
                request=r, inverse=[inverses[r["uid"]]], ticket_id=batch_id, actor=actor,
                emit_audit=False)
            recorded += 1
        for r in fresh_delete:
            recreate = _recreate_inverse(r)
            request_snapshot = {k: v for k, v in r.items() if k != "raw_rule"}
            request_snapshot["raw_rule"] = r.get("raw_rule")   # keep the full snapshot in the record
            change_log.record_committed(
                db, server=server, layer=r["layer"], action="cleanup", outcome="delete",
                summary=f"cleanup: delete rule {r.get('number') or '?'} “{r.get('name') or r['uid']}” — {r['reason']}",
                request=request_snapshot,
                inverse=[recreate] if recreate else [],
                ticket_id=batch_id, actor=actor,
                resolution="" if recreate else "deleted", emit_audit=False)
            recorded += 1
    return recorded


def apply_plan(server, secret: str, *, disable: list[dict], delete: list[dict], publish: bool,
               now: dt.datetime | None = None, actor: str = "",
               disable_after: int = DEFAULT_DISABLE_AFTER, delete_after: int = DEFAULT_DELETE_AFTER,
               max_rules: int = 50000, record: bool = True) -> dict:
    """Disable + delete the reviewed candidate rules on ``server``. ``publish=False`` is a dry-run
    (validate the ops against the SMS, then discard — zero commit); ``publish=True`` commits.

    Safety pipeline (both modes): every requested rule is RE-FETCHED and RE-CLASSIFIED against the live
    policy first — a rule that got hits, was re-enabled, gained a never-touch pin, or vanished since the
    plan is SKIPPED and reported, never acted on. Ops and the disable inverses are built from the fresh
    state, so the write-back never clobbers comment/custom-field edits made after the plan.

    A COMMITTED apply (published + ok) then: records one revertable AppliedChange row per rule (disables
    can be re-enabled with full restore from the rollback panel; deletes are recorded terminal with the
    full pre-delete snapshot) and raises ONE governance audit event — both here in the service so every
    surface (UI today, a future MCP/REST tool) inherits them. Returns the ``apply_changes`` result plus
    ``{applied, disabled, deleted, skipped, recorded}``. Raises MgmtError only for the re-fetch phase;
    SMS-side apply errors come back as ``{ok: False, error, ...}`` (possibly with ``lock_conflict``)."""
    now = now or dt.datetime.now().replace(microsecond=0)
    requested = [(r, "disable") for r in (disable or []) if r.get("uid") and r.get("layer")] \
              + [(r, "delete") for r in (delete or []) if r.get("uid") and r.get("layer")]
    if not requested:
        return {"ok": False, "published": False, "applied": False, "results": [], "skipped": [],
                "disabled": 0, "deleted": 0, "recorded": 0,
                "error": "No valid rules to apply (missing rule id / layer)."}

    fresh_disable, fresh_delete, skipped = _reclassify(
        server, secret, requested, disable_after=int(disable_after), delete_after=int(delete_after),
        now=now, max_rules=max_rules)

    if not fresh_disable and not fresh_delete:
        return {"ok": True, "published": False, "applied": False, "results": [], "skipped": skipped,
                "disabled": 0, "deleted": 0, "recorded": 0,
                "note": "Nothing to apply — every selected rule was skipped by the live re-check."}

    ops = build_ops(fresh_disable, fresh_delete, now=now)
    inverses = {r["uid"]: _disable_inverse(r) for r in fresh_disable}

    result = mgmt_api.apply_changes(server, secret, ops, publish=publish)
    ok = bool(result.get("ok"))
    result["applied"] = ok
    result["skipped"] = skipped
    result["disabled"] = len(fresh_disable) if ok else 0
    result["deleted"] = len(fresh_delete) if ok else 0
    result["recorded"] = 0

    if ok and result.get("published"):
        if record:
            try:
                result["recorded"] = _record_batch(server, fresh_disable=fresh_disable,
                                                   fresh_delete=fresh_delete, inverses=inverses,
                                                   actor=actor, now=now)
            except Exception:  # noqa: BLE001 — bookkeeping must never fail a committed change
                import logging
                logging.getLogger("policypilot.policy_cleanup").exception("change-log recording failed")
        try:
            from . import audit
            skipped_note = f", skipped {len(skipped)}" if skipped else ""
            audit.emit(f"{actor or 'portal'} · policy-cleanup on "
                       f"{getattr(server, 'name', '') or getattr(server, 'host', 'server')} "
                       f"— disabled {result['disabled']}, deleted {result['deleted']} rule(s){skipped_note}",
                       actor=actor or "portal")
        except Exception:  # noqa: BLE001 — audit must never turn a committed change into a reported error
            import logging
            logging.getLogger("policypilot.policy_cleanup").exception("audit emit failed")
    return result
