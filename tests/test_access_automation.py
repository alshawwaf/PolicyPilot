"""Ticket-driven access automation: the pure decision engine, rule parsing, the I/O entry points
(preview/execute) against a fake session, ServiceNow payload handling, the webhook auth gate, and
template rendering. No live SMS needed."""
import asyncio
import contextlib
import ipaddress
import json
import types

import pytest

from app.routers import access_automation as aar
from app.routers.ui import templates
from app.services import access_automation as aa
from app.services import decision_tree as dt
from app.services import ticketing as tk
from app.services.access_automation import (
    AccessRequest,
    Outcome,
    ParsedRule,
    Relation,
    ServiceSet,
)

ANY = aa.ANY_IP


# --- helpers ---------------------------------------------------------------------------------
def _host(ip):
    return [(aa._ip_int(ip), aa._ip_int(ip))]


def _net(cidr):
    n = ipaddress.ip_network(cidr)
    return [(int(n.network_address), int(n.broadcast_address))]


def _tcp(p):
    return ServiceSet(by_proto={"tcp": aa._ports_to_iv(str(p))})


def _app(names=None, opaque=False):
    return ServiceSet(apps=set(names or []), opaque=opaque)


def _rule(uid, num, action, src, dst, svc, *, groups=None, dest_groups=None, enabled=True, complex=False,
          conditions=()):
    return ParsedRule(uid=uid, number=num, name=uid, enabled=enabled, action=action,
                      src=src, dst=dst, svc=svc, source_group_uids=groups or [],
                      dest_group_uids=dest_groups or [], complex=complex,
                      conditional=bool(conditions), conditions=tuple(conditions))


WEB = _rule("r8", 8, "Accept", _net("10.1.0.0/24"), _host("172.16.5.10"), _tcp(443),
            groups=["grp-web-src"])
WEB_CELL = _rule("r7", 7, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443))  # no group
DENY_DB = _rule("r9", 9, "Drop", ANY, _host("172.16.5.20"), _tcp(1521))
CLEANUP = _rule("rC", 99, "Drop", ANY, ANY, ServiceSet(any=True))


# --- interval / relation primitives ----------------------------------------------------------
def test_relation_subset_superset_disjoint_equal():
    assert aa.relation(_host("10.1.0.5"), _net("10.1.0.0/24")) == Relation.SUBSET
    assert aa.relation(_net("10.1.0.0/24"), _host("10.1.0.5")) == Relation.SUPERSET
    assert aa.relation(_host("10.1.0.5"), _host("10.1.0.5")) == Relation.EQUAL
    assert aa.relation(_host("10.1.0.5"), _host("192.168.0.1")) == Relation.DISJOINT


def test_service_set_covers_and_any():
    assert ServiceSet(any=True).covers(_tcp(443))
    assert not _tcp(443).covers(ServiceSet(any=True))
    assert _tcp("1-1024").covers(_tcp(443))
    assert not _tcp(443).covers(_tcp(80))


# --- decide(): the four outcomes --------------------------------------------------------------
def test_decide_no_op_source_inside_network():
    d = aa.decide(AccessRequest(["10.1.0.50/32"], ["172.16.5.10/32"], "tcp", "443"), [WEB, CLEANUP])
    assert d.outcome is Outcome.NO_OP and d.target_rule.uid == "r8"


def test_decide_widen_source_adds_to_cell_not_group():
    # WEB references a source group, but we widen the rule's CELL (never the shared group) to avoid
    # granting the new source in every other rule that uses that group.
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [WEB, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source" and d.widen_group_uid is None


def test_decide_widen_falls_back_to_source_cell_when_no_group():
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [WEB_CELL, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_group_uid is None and d.target_rule.uid == "r7"
    assert d.widen_field == "source"


def test_decide_widen_destination_when_only_dest_differs():
    # the rule-7.4 case: same source + service, only the destination differs -> widen the DESTINATION
    dns = _rule("r74", 74, "Accept", _host("10.1.2.250"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"), [dns, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "destination"
    assert d.target_rule.uid == "r74" and d.widen_group_uid is None


def test_decide_dest_widen_via_cell_not_group():
    dns = _rule("rg", 74, "Accept", _host("10.1.2.250"), _net("9.9.9.0/24"), _tcp(53),
                dest_groups=["grp-dns-dst"])
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"), [dns, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "destination" and d.widen_group_uid is None


def test_execute_widen_destination_adds_to_rule_dest_cell(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    dns = _rule("r74", 74, "Accept", _host("10.1.2.250"), _host("9.9.9.9"), _tcp(53))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [dns, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"), "DNS", publish=True)
    assert res["outcome"] == "widen" and res["widen_field"] == "destination"
    assert res["widen_object"] == "h-1-1-1-1"
    setr = next(p for c, p in calls if c == "set-access-rule")
    assert setr["uid"] == "r74" and setr["destination"] == {"add": "h-1-1-1-1"}
    assert not any(c == "add-access-rule" for c, _ in calls)   # widened, not created


def test_decide_widen_service_when_only_service_differs():
    # same source + destination, only the service differs -> widen the SERVICE cell
    rule = _rule("rs", 5, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["10.1.0.9/32"], ["172.16.5.10/32"], "tcp", "8443"), [rule, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "service" and d.target_rule.uid == "rs"


def test_execute_widen_service_adds_to_rule_service_cell(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    rule = _rule("rs", 5, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [rule, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.0.9/32"], ["172.16.5.10/32"], "tcp", "8443"), "L", publish=True)
    assert res["outcome"] == "widen" and res["widen_field"] == "service" and res["widen_object"] == "TCP-8443"
    setr = next(p for c, p in calls if c == "set-access-rule")
    assert setr["service"] == {"add": "TCP-8443"} and not any(c == "add-access-rule" for c, _ in calls)


# --- application requests (Facebook / YouTube etc. live in the Services & Applications cell) ----
def test_decide_app_no_op_when_app_already_allowed():
    rule = _rule("ra", 5, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"Facebook"}))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [rule, CLEANUP])
    assert d.outcome is Outcome.NO_OP and d.target_rule.uid == "ra"


def test_decide_app_widens_service_when_app_differs():
    rule = _rule("ra", 5, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"YouTube"}))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [rule, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "service"


def test_decide_app_opaque_category_notes_and_continues():
    # rule allows an app CATEGORY we can't expand -> can't tell if Facebook is inside. It's an ACCEPT, so
    # we NOTE it ("may already permit it") and continue -> a clean CREATE (never a hard REVIEW stop).
    rule = _rule("ra", 5, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app(opaque=True))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [rule, CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 5")


def test_decide_app_create_when_two_dims_differ():
    rule = _rule("ra", 5, "Accept", _host("10.9.9.9"), _host("2.2.2.2"), _app({"Facebook"}))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [rule, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_decide_app_widens_accept_above_drop_instead_of_carving_out():
    # The reported case: a win_client Facebook ACCEPT sits ABOVE a "Silent Drop"; a win_server Facebook
    # request should WIDEN that accept's source (it already sits above the drop -> first-match grants it)
    # rather than create a NEW carve-out rule. Tidier, same effect.
    acc = _rule("acc", 2, "Accept", _host("10.1.2.222"), ANY, _app({"Facebook"}))
    drop = _rule("sdrop", 3, "Drop", ANY, ANY, _tcp(443))      # a web port (could carry the app) -> in the path
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), [acc, drop, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source" and d.target_rule.uid == "acc"


def test_decide_app_carves_out_above_drop_when_no_widen_candidate():
    # No accept candidate above the drop -> the conservative carve-out (create ABOVE the drop) still applies.
    drop = _rule("sdrop", 3, "Drop", ANY, ANY, _tcp(443))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), [drop, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "sdrop"}


def test_decide_app_carveout_when_prefer_widen_off():
    # prefer_widen OFF: widen is never chosen even with a candidate -> carve out above the drop (knob honored).
    acc = _rule("acc", 2, "Accept", _host("10.1.2.222"), ANY, _app({"Facebook"}))
    drop = _rule("sdrop", 3, "Drop", ANY, ANY, _tcp(443))
    opts = aa.DecideOptions(prefer_widen=False)
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), [acc, drop, CLEANUP], opts)
    assert d.outcome is Outcome.CREATE and d.position == {"above": "sdrop"}


def test_decide_app_carveout_off_places_below_not_widen_even_with_candidate():
    # carve-out OFF = "do not put an app-grant above the drop". Even with a widen candidate above the drop,
    # we must NOT widen (that would override the drop) -> create BELOW the drop, honoring the operator choice.
    acc = _rule("acc", 2, "Accept", _host("10.1.2.222"), ANY, _app({"Facebook"}))
    drop = _rule("sdrop", 3, "Drop", ANY, ANY, _tcp(443))
    opts = aa.DecideOptions(app_carveout=False)              # prefer_widen stays default True
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), [acc, drop, CLEANUP], opts)
    assert d.outcome is Outcome.CREATE and d.position == {"below": "sdrop"}


def test_decide_app_does_not_carve_above_a_conditional_drop():
    # M1: a CONDITIONAL (VPN-gated) drop is a possible block we can't model — an app request must NOT be
    # carved ABOVE it (a silent override of an unmodeled deny). It is NOTED and placed BELOW, symmetric with
    # the port path; previously the app path leapt above it with no note.
    cond = _rule("cd", 3, "Drop", ANY, ANY, _tcp(443), conditions=("VPN community",))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), [cond, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position != {"above": "cd"}
    assert any("rule 3" in n for n in d.notes)               # the conditional possible-block is flagged


def test_decide_app_carveout_honors_override_blocking_deny_off():
    # M1: carving an app ABOVE a resolved deny IS overriding that deny -> it honors override_blocking_deny.
    # With that knob OFF (app_carveout still ON), a resolved tcp/443 drop is NOT overridden -> placed below.
    drop = _rule("sd", 3, "Drop", ANY, ANY, _tcp(443))
    opts = aa.DecideOptions(app_carveout=True, override_blocking_deny=False)
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), [drop, CLEANUP], opts)
    assert d.outcome is Outcome.CREATE and d.position == {"below": "sd"}


def test_decide_widens_accept_above_covering_deny():
    # Same principle for a port request: an accept (same dst+service, differing source) above a covering
    # deny is widened instead of creating a new allow above the deny.
    acc = _rule("acc", 2, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443))
    deny = _rule("dny", 3, "Drop", ANY, _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [acc, deny, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source" and d.target_rule.uid == "acc"


def test_execute_app_create_references_app_name_without_creating_it(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    rule = _rule("ra", 5, "Accept", _host("10.9.9.9"), _host("2.2.2.2"), _app({"Facebook"}))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [rule, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="YouTube"), "L", publish=True)
    assert res["outcome"] == "create" and res["service_object"] == "YouTube"
    rule_op = next(p for c, p in calls if c == "add-access-rule")
    assert rule_op["service"] == "YouTube"
    assert not any(c in ("add-service-tcp", "add-service-udp") for c, _ in calls)   # apps are predefined


def test_build_request_and_parse_payload_application():
    req = tk.build_request("10.1.2.250", "1.1.1.1", "tcp", "", application="Facebook")
    assert req.application == "Facebook" and req.svc().apps == {"Facebook"}
    t = tk.parse_payload({"server_id": 1, "layer": "L", "source": "10.1.2.250",
                          "destination": "1.1.1.1", "application": "YouTube"})
    assert t.request.application == "YouTube"


def test_decide_create_above_cleanup_for_new_dst():
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"), [WEB, CLEANUP])
    assert d.outcome is Outcome.CREATE
    assert d.position == {"above": "rC"}            # above the catch-all cleanup, never 'bottom'


def test_decide_explicit_deny_creates_above_it():
    # A specific covering deny no longer stops for review — the engine creates the allow ABOVE the deny so
    # the requested access takes effect (first-match then hits the allow before the block).
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.20/32"], "tcp", "1521"), [DENY_DB, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.target_rule.uid == "r9"
    assert d.position == {"above": "r9"}


def test_decide_negated_rule_in_path_notes_and_continues():
    # a negated/unresolvable ACCEPT in the path is noted (not a hard REVIEW) and the walk continues to a
    # safe CREATE — the new rule sits below it, so nothing is over-granted.
    weird = _rule("rx", 3, "Accept", _host("172.16.5.10"), _host("172.16.5.10"), _tcp(443), complex=True)
    d = aa.decide(AccessRequest(["172.16.5.10/32"], ["172.16.5.10/32"], "tcp", "443"), [weird, CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 3")


def test_decide_disabled_rule_is_skipped():
    disabled = _rule("rd", 1, "Accept", ANY, _host("172.16.5.10"), _tcp(443), enabled=False)
    d = aa.decide(AccessRequest(["1.2.3.4/32"], ["172.16.5.10/32"], "tcp", "443"), [disabled, CLEANUP])
    assert d.outcome is Outcome.CREATE         # the disabled covering accept does NOT make it a no-op


def test_decide_no_explicit_cleanup_creates_at_bottom():
    d = aa.decide(AccessRequest(["1.2.3.4/32"], ["9.9.9.9/32"], "tcp", "80"), [WEB])
    assert d.outcome is Outcome.CREATE and d.position == {"_above_cleanup": True}


def test_decide_widen_source_via_cell_first_match():
    # dst + svc equal, source differs -> widen the SOURCE cell of the first matching rule (cell add,
    # never a shared group)
    r1 = _rule("rn", 6, "Accept", _net("10.2.0.0/24"), _host("172.16.5.10"), _tcp(443), groups=["grp-X"])
    r2 = _rule("rg", 7, "Accept", _net("10.3.0.0/24"), _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"),
                  [r1, r2, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source"
    assert d.target_rule.uid == "rn" and d.widen_group_uid is None


def test_decide_no_widen_when_source_cell_broader_creates_instead():
    # the rule-7.3 over-grant: source {win_client, win_server}, only win_server requested. Widening the
    # destination would also grant win_client -> 1.1.1.1, so we must CREATE a precise rule instead.
    multi = _rule("r73", 73, "Accept", aa._merge(_host("10.1.2.249") + _host("10.1.2.250")),
                  _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"), [multi, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_decide_no_widen_when_dest_cell_broader_creates_instead():
    # rule destination is a /24; widening the source would grant the new source the whole /24.
    rule = _rule("rb", 5, "Accept", _host("10.1.0.5"), _net("172.16.5.0/24"), _tcp(443))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [rule, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_decide_no_widen_when_service_cell_broader_creates_instead():
    # rule allows the whole 1-1024 range; widening the source would grant the new source all of it.
    rule = _rule("rw", 5, "Accept", _host("10.1.0.5"), _host("172.16.5.10"), _tcp("1-1024"))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [rule, CLEANUP])
    assert d.outcome is Outcome.CREATE


# --- audit fixes A/B/C: inline layers, mixed port+app service cells, partial drops --------------
def _mixed_svc(port, app):
    return ServiceSet(by_proto={"tcp": aa._ports_to_iv(str(port))}, apps={app})


def test_decide_inline_layer_unloaded_notes_and_continues():
    # a non-Accept/Drop action whose sub-rulebase wasn't attached (inline_rules is None — e.g. a load
    # failure, or an Ask/Inform action) can't be evaluated, but it may divert/handle the traffic. We note
    # it and continue to a CREATE placed BELOW it (so if it does handle the traffic, it still wins).
    inl = _rule("ri", 2, "Some Inline Layer", _host("10.0.0.5"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["9.9.9.9/32"], "tcp", "53"), [inl, CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 2")


def test_decide_inline_layer_disjoint_is_create():
    inl = _rule("ri", 2, "Some Inline Layer", _host("10.0.0.5"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["8.8.8.8/32"], "tcp", "53"), [inl, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_svc_relation_mixed_port_app_is_subset_not_equal():
    assert aa.svc_relation(_tcp(443), _mixed_svc(443, "Facebook")) is Relation.SUBSET


def test_decide_no_overgrant_when_service_cell_mixes_port_and_app():
    # rule svc = {tcp/443 + Facebook}; src equal, dst differs. Widening dst would drag Facebook in -> CREATE
    mixed = _rule("rm", 5, "Accept", _host("10.0.0.1"), _host("9.9.9.9"), _mixed_svc(443, "Facebook"))
    d = aa.decide(AccessRequest(["10.0.0.1/32"], ["1.1.1.1/32"], "tcp", "443"), [mixed, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_decide_no_op_when_port_already_in_mixed_service_cell():
    mixed = _rule("rm", 5, "Accept", _host("10.0.0.1"), _host("9.9.9.9"), _mixed_svc(443, "Facebook"))
    d = aa.decide(AccessRequest(["10.0.0.1/32"], ["9.9.9.9/32"], "tcp", "443"), [mixed, CLEANUP])
    assert d.outcome is Outcome.NO_OP   # rule already permits tcp/443 (plus Facebook) for that exact flow


def test_mixed_kind_request_vs_single_leg_rule_is_not_a_false_no_op():
    # H3: a service-GROUP REQUEST bundling tcp/443 + Facebook, against a rule granting ONLY the Facebook leg
    # (same src/dst). svc_relation must MEET both legs -> OVERLAP (port leg ungranted), so decide() does NOT
    # report a false NO_OP "already permitted" while the tcp/443 leg is actually dropped by cleanup.
    req = AccessRequest(["10.0.0.5/32"], ["1.1.1.1/32"]); req.svc_set = _mixed_svc(443, "Facebook")
    fb_only = _rule("fb", 1, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _app({"Facebook"}))
    assert aa.svc_relation(req.svc(), fb_only.svc) is Relation.OVERLAP
    assert aa.decide(req, [fb_only, CLEANUP]).outcome is not Outcome.NO_OP
    # symmetric: a rule granting only the tcp/443 leg is likewise not a clean cover (the app leg is ungranted)
    port_only = _rule("pt", 1, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _tcp(443))
    assert aa.svc_relation(req.svc(), port_only.svc) is Relation.OVERLAP


def test_mixed_kind_request_covered_when_rule_holds_both_legs():
    # the genuine match: a rule granting BOTH tcp/443 AND Facebook covers the mixed group request (no false miss)
    req_svc = ServiceSet(by_proto={"tcp": aa._ports_to_iv("443")}, apps={"Facebook"})
    assert aa.svc_relation(req_svc, _mixed_svc(443, "Facebook")) in (Relation.SUBSET, Relation.EQUAL)
    # and a named+port group (icmp + tcp/443) vs a rule granting only icmp -> OVERLAP, never EQUAL
    grp = ServiceSet(by_proto={"tcp": aa._ports_to_iv("443")}, named={("icmp", "echo-request")})
    icmp_only = ServiceSet(named={("icmp", "echo-request")})
    assert aa.svc_relation(grp, icmp_only) is Relation.OVERLAP


def test_decide_partial_drop_in_path_creates_above_it():
    # a /32 deny inside the /24 request: it's fully RESOLVED, so we create the allow ABOVE it to make the
    # full /24 work (first-match hits the allow before the partial deny).
    drop = _rule("d1", 1, "Drop", _host("10.0.0.5"), _host("9.9.9.9"), _tcp(53))
    acc = _rule("a1", 2, "Accept", _net("10.0.0.0/24"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.0.0.0/24"], ["9.9.9.9/32"], "tcp", "53"), [drop, acc, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.target_rule.uid == "d1" and d.position == {"above": "d1"}


def test_decide_disjoint_drop_does_not_review():
    drop = _rule("d1", 1, "Drop", _host("10.0.0.5"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["192.168.0.0/24"], ["8.8.8.8/32"], "tcp", "53"), [drop, CLEANUP])
    assert d.outcome is Outcome.CREATE


# --- audit fixes D/E + Any endpoints ----------------------------------------------------------
def test_decide_non_bottom_catchall_drop_creates_above_it():
    # an Any/Any/Any DROP that ISN'T the bottom cleanup is a resolved broad block (e.g. lockdown) -> create
    # the allow ABOVE it so the requested access takes effect
    lockdown = _rule("rL", 1, "Drop", ANY, ANY, ServiceSet(any=True))
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["172.16.0.5/32"], "tcp", "443"), [lockdown, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.target_rule.uid == "rL" and d.position == {"above": "rL"}


def test_decide_bottom_cleanup_is_the_create_floor():
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["172.16.0.5/32"], "tcp", "443"), [CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "rC"}


def test_decide_opaque_app_drop_notes_and_creates_below():
    # an app category/group DROP might match L7 over tcp/443 -> we can't PROVE its service extent, so we
    # don't override it (no create-above). It's NOTED and the walk continues; the new allow lands BELOW it.
    drop = _rule("rD", 5, "Drop", _host("10.1.1.1"), _host("8.8.8.8"), _app(opaque=True))
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443"), [drop, CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "rD") and d.position == {"above": "rC"}


def test_decide_opaque_app_accept_does_not_block_a_port_create():
    acc = _rule("rA", 5, "Accept", _host("10.1.1.1"), _host("8.8.8.8"), _app(opaque=True))
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443"), [acc, CLEANUP])
    assert d.outcome is Outcome.CREATE   # an app ACCEPT is harmless to create around (redundant at worst)


def test_build_request_accepts_any_endpoint():
    r = tk.build_request("10.1.2.250", "any", "tcp", "443")
    assert r.dst_cidrs == ["Any"] and r.dst_iv() == aa.ANY_IP
    r2 = tk.build_request("Any", "1.1.1.1", "tcp", "443")
    assert r2.src_cidrs == ["Any"] and r2.src_iv() == aa.ANY_IP


def test_decide_create_with_any_destination():
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), [CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_execute_any_destination_references_predefined_any(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), "L", publish=True)
    assert res["outcome"] == "create" and res["destination_object"] == "Any"
    rule = next(p for c, p in calls if c == "add-access-rule")
    assert rule["destination"] == "Any"
    assert not any(c == "add-network" for c, _ in calls)   # Any is predefined, never created


# --- IPv6: now reasoned about (dual-band integer space), not guarded out ----------------------
_V6_OD = {
    "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "h6": {"uid": "h6", "type": "host", "name": "h6", "ipv6-address": "2001:db8::5"},
    "n6": {"uid": "n6", "type": "network", "name": "n6", "subnet6": "2001:db8::", "mask-length6": 64},
    "h4": {"uid": "h4", "type": "host", "name": "h4", "ipv4-address": "10.0.0.5"},
    "t443": {"uid": "t443", "type": "service-tcp", "name": "https", "port": "443"},
    "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
}


def _r6(src="2001:db8::5/128", dst="2001:db8::9/128"):
    return AccessRequest(src_cidrs=[src], dst_cidrs=[dst], protocol="tcp", ports="443")


def test_ipv6_bands_separate_v4_and_v6():
    v6 = aa._cidrs_to_iv(["2001:db8::5/128"])
    v4 = aa._cidrs_to_iv(["10.0.0.5/32"])
    assert v6[0][0] >= aa._V6_BASE                          # v6 sits in its own band
    assert aa.relation(v6, aa.ANY_IP) is Relation.SUBSET    # Any (both bands) covers v6
    assert aa.relation(v4, aa.ANY_IP) is Relation.SUBSET    # ...and v4
    assert aa.relation(v6, v4) is Relation.DISJOINT         # v4 and v6 never overlap


def test_ipv6_host_object_resolves_to_v6_band():
    r = _irule(1, ["h6"], ["any"], ["t443"], "acc", _V6_OD)
    assert not r.complex and r.src and r.src[0][0] >= aa._V6_BASE   # resolved into the v6 band


def test_ipv6_request_no_op_by_v6_rule():
    rules = [_irule(1, ["n6"], ["any"], ["t443"], "acc", _V6_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _V6_OD)]
    assert aa.decide(_r6(), rules).outcome is Outcome.NO_OP        # 2001:db8::5 is in 2001:db8::/64


def test_ipv6_request_not_covered_by_v4_rule_creates_above_cleanup():
    # the v4 host Accept is disjoint (different band); only the Any/Any cleanup covers -> CREATE above it
    rules = [_irule(1, ["h4"], ["any"], ["t443"], "acc", _V6_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _V6_OD)]
    assert aa.decide(_r6(), rules).outcome is Outcome.CREATE


def test_ipv6_request_respects_a_v6_deny():
    # a specific, fully-resolved v6 DROP covering the request is overridden by creating the allow ABOVE it
    # (never silently stepped over — the old blocker was the reverse)
    rules = [_irule(1, ["n6"], ["any"], ["t443"], "drp", _V6_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _V6_OD)]
    d = aa.decide(_r6(), rules)
    assert d.outcome is Outcome.CREATE and d.position == {"above": "r1"}


def test_v4_request_not_covered_by_v6_rule():
    # symmetry: a v6 Accept must never NO_OP a v4 request
    rules = [_irule(1, ["n6"], ["any"], ["t443"], "acc", _V6_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _V6_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["10.0.0.9/32"], protocol="tcp", ports="443")
    assert aa.decide(req, rules).outcome is Outcome.CREATE


def test_build_request_accepts_ipv6():
    r = tk.build_request("2001:db8::1", "2001:db8::2", "tcp", "443")
    assert r.src_cidrs == ["2001:db8::1/128"] and r.dst_cidrs == ["2001:db8::2/128"]
    r2 = tk.build_request("10.1.2.250", "2001:db8::/64", "tcp", "443")
    assert r2.dst_cidrs == ["2001:db8::/64"]


def test_decide_empty_service_is_review_not_noop():
    # no concrete service -> empty interval set -> must NOT read as "covered by anything"
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", ""), [WEB_CELL, CLEANUP])
    assert d.outcome is Outcome.REVIEW and "no concrete service" in d.reason


# --- conditional-scope columns (vpn / time / content / install-on / service-resource) ---------
def test_decide_conditional_accept_is_create_not_noop():
    # a VPN-only ACCEPT matching the tuple does NOT permit clear traffic -> CREATE, not NO_OP
    vpn = _rule("rV", 5, "Accept", _host("10.1.1.1"), _host("8.8.8.8"), _tcp(443), conditions=("VPN",))
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443"), [vpn, CLEANUP])
    assert d.outcome is Outcome.CREATE and "VPN" in d.reason and "rV" in d.reason


def test_decide_conditional_drop_overlapping_notes_and_continues():
    # a time-restricted DROP only blocks under a column we can't model -> NOTE it and keep going (the new
    # allow lands below it so it can't leap over the possible block), never a hard stop.
    time_drop = _rule("rT", 5, "Drop", _host("10.1.1.1"), _host("8.8.8.8"), _tcp(443), conditions=("time",))
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443"), [time_drop, CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "rT", "time") and d.position == {"above": "rC"}


def test_decide_conditional_accept_is_not_a_widen_target():
    # same dst+svc, source differs by one host: normally a source-widen, but the rule is data-restricted
    cond = _rule("rW", 7, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443), conditions=("data",))
    d = aa.decide(AccessRequest(["10.1.0.10/32"], ["172.16.5.10/32"], "tcp", "443"), [cond, CLEANUP])
    assert d.outcome is Outcome.CREATE   # never widen a rule whose match we can't verify


def test_parse_rule_flags_conditional_columns():
    objd = {
        "u-comm": {"uid": "u-comm", "name": "RemoteAccess", "type": "vpn-community-meshed"},
        "u-time": {"uid": "u-time", "name": "WorkHours", "type": "time"},
    }
    base = {"uid": "r1", "rule-number": 1, "action": "Accept",
            "source": [], "destination": [], "service": []}
    assert aa._parse_rule({**base, "vpn": ["u-comm"]}, objd).conditions == ("VPN",)
    assert aa._parse_rule({**base, "time": ["u-time"]}, objd).conditions == ("time",)
    assert aa._parse_rule({**base, "content": ["u-x"], "content-negate": True}, {}).conditional is True
    assert aa._parse_rule({**base, "install-on": [{"uid": "gw1", "name": "gw1"}]}, {}).conditional is True
    assert aa._parse_rule({**base, "service-resource": "uri-res"}, {}).conditional is True


def test_parse_rule_default_any_cells_are_not_conditional():
    objd = {"u-any": {"uid": "u-any", "name": "Any"},
            "u-pt": {"uid": "u-pt", "name": "Policy Targets"}}
    rule = aa._parse_rule(
        {"uid": "r1", "rule-number": 1, "action": "Accept", "source": [], "destination": [], "service": [],
         "vpn": ["u-any"], "time": ["u-any"], "content": ["u-any"], "install-on": ["u-pt"]}, objd)
    assert rule.conditional is False and rule.conditions == ()


# --- object-type safety net (every cell type the source/dest/service fields can hold) ----------
_OBJD = {
    "any":   {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    "h8888": {"uid": "h8888", "name": "dns", "type": "host", "ipv4-address": "8.8.8.8"},
    "hsrc":  {"uid": "hsrc", "name": "client", "type": "host", "ipv4-address": "10.1.1.1"},
    "s443":  {"uid": "s443", "name": "https", "type": "service-tcp", "port": "443"},
    "arfin": {"uid": "arfin", "name": "Finance", "type": "access-role"},
    "zone":  {"uid": "zone", "name": "Zone", "type": "security-zone"},
    "uoint": {"uid": "uoint", "name": "Internet", "type": "updatable-object"},
    "hv6":   {"uid": "hv6", "name": "v6", "type": "host", "ipv6-address": "2001:db8::5"},
    "sgre":  {"uid": "sgre", "name": "gre", "type": "service-other", "ip-protocol": 47},
    "sgweb": {"uid": "sgweb", "name": "grp", "type": "service-group", "members": ["s443"]},
}


def _pr(uid, num, action, src, dst, svc):
    return aa._parse_rule({"uid": uid, "rule-number": num, "name": uid, "action": action,
                           "enabled": True, "source": src, "destination": dst, "service": svc}, _OBJD)


_LIVE_CLEANUP = _pr("rC", 99, "Drop", ["any"], ["any"], ["any"])
_OBJ_REQ = AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443")


def _noted(d, *fragments):
    """The decision carries an advisory 'possible match — review later' note mentioning every fragment.
    (Behaviour 2026-06-23: an opaque rule in the path no longer HARD-STOPS the flow with REVIEW — the
    walk notes it and continues; the note is the audit trail. See decide()/_decide.)"""
    blob = " ".join(d.notes or []).lower()
    return bool(d.notes) and all(str(f).lower() in blob for f in fragments)


@pytest.mark.parametrize("src,dst,svc", [
    (["arfin"], ["h8888"], ["s443"]),   # access-role (Identity Awareness) source
    (["zone"],  ["h8888"], ["s443"]),   # security-zone source
    (["uoint"], ["h8888"], ["s443"]),   # updatable-object (Internet / geo)
    # (IPv6 host objects are now ENUMERABLE — resolved into the v6 band — so a v6-sourced rule is no
    #  longer "extent-unknown"; covered by the IPv6 tests above, not here.)
    # (service-other is now a named+opaque service: create-around an ACCEPT, REVIEW only for a possible
    #  DROP — covered by test_service_other_drop_keeps_port_request_in_path)
])
def test_unenumerable_cell_objects_note_and_continue(src, dst, svc):
    # any cell holding an object whose IP/port extent we can't enumerate is "extent-unknown" -> the rule
    # is NEVER treated as provably disjoint. It's an ACCEPT here, so the walk NOTES it and continues to a
    # clean CREATE (below it) rather than hard-stopping the whole request with REVIEW.
    d = aa.decide(_OBJ_REQ, [_pr("rX", 1, "Accept", src, dst, svc), _LIVE_CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 1")


def test_live_any_object_cleanup_is_recognized_as_floor():
    # the predefined Any object (CpmiAnyObject), as a real cleanup uses -> catch-all -> placement floor
    d = aa.decide(_OBJ_REQ, [_LIVE_CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "rC"}


def test_service_group_members_are_resolved():
    d = aa.decide(_OBJ_REQ, [_pr("rSG", 1, "Accept", ["hsrc"], ["h8888"], ["sgweb"]), _LIVE_CLEANUP])
    assert d.outcome is Outcome.NO_OP and d.target_rule.uid == "rSG"


@pytest.mark.parametrize("extra", [
    {"enable-tcp-resource": True},           # legacy URI/CIFS/FTP resource match
    {"match-by-protocol-signature": True},   # L7 protocol-signature match
    {"source-port": "53"},                   # client-side source-port restriction
])
def test_resource_or_signature_service_is_not_reused(extra):
    # a service that matches more narrowly than its dest port must not be NO_OP'd / widened on the port
    objd = {"u":  {"uid": "u", "name": "narrow-80", "type": "service-tcp", "port": "80", **extra},
            "any": {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
            "hs":  {"uid": "hs", "name": "c", "type": "host", "ipv4-address": "10.1.2.250"},
            "hd":  {"uid": "hd", "name": "w", "type": "host", "ipv4-address": "172.16.5.10"}}
    acc = aa._parse_rule({"uid": "ra", "rule-number": 1, "name": "narrow", "action": "Accept",
                          "enabled": True, "source": ["hs"], "destination": ["hd"], "service": ["u"]}, objd)
    cleanup = aa._parse_rule({"uid": "rC", "rule-number": 99, "name": "cleanup", "action": "Drop",
                              "enabled": True, "source": ["any"], "destination": ["any"],
                              "service": ["any"]}, objd)
    # The narrow service is NEVER reused: not a false NO_OP (same flow) and never an unsafe WIDEN
    # (differing source). It's noted + skipped, and the walk continues to a clean CREATE for the exact
    # port requested. The key safety property holds — the resource service is not consumed as a match.
    same = aa.decide(AccessRequest(["10.1.2.250/32"], ["172.16.5.10/32"], "tcp", "80"), [acc, cleanup])
    widen = aa.decide(AccessRequest(["192.168.7.7/32"], ["172.16.5.10/32"], "tcp", "80"), [acc, cleanup])
    assert same.outcome is Outcome.CREATE and _noted(same, "rule 1")
    assert widen.outcome is Outcome.CREATE and widen.outcome is not Outcome.WIDEN


# --- BLOCKER regression: a rule whose extent is UNKNOWN must never be treated as out-of-path -----
def _zone_rule(uid, num, action, dst, svc):
    """An accept/drop whose source is a security-zone / dynamic-object: parses to [] + src_unknown."""
    return ParsedRule(uid=uid, number=num, name=uid, enabled=True, action=action,
                      src=[], dst=dst, svc=svc, src_unknown=True, complex=True)


def test_decide_unresolved_source_accept_notes_not_widens():
    # an unresolvable-source ACCEPT must never be WIDENED (its real source is unknown -> over-grant). It's
    # noted and skipped; the walk continues to a clean CREATE instead (never a widen of the opaque rule).
    zone = _zone_rule("rz", 5, "Accept", _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [zone, CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 5")


def test_decide_unresolved_drop_above_accept_notes_the_possible_block():
    # an unresolvable DROP above a covering ACCEPT might block the flow. We can't prove it, so we NOTE it
    # ("may block...") and continue -> NO_OP on the covering accept (which writes NOTHING, so the firewall
    # is never weakened); the note flags that the drop may still block it. The drop is never overridden.
    drop = _zone_rule("rd", 3, "Drop", _host("172.16.5.10"), _tcp(443))
    broad = _rule("rb", 4, "Accept", ANY, _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"),
                  [drop, broad, CLEANUP])
    assert d.outcome is Outcome.NO_OP and _noted(d, "rule 3", "block")


def test_decide_unresolved_rule_on_different_dst_does_not_spurious_review():
    zone_other = _zone_rule("ro", 2, "Accept", _host("10.9.9.9"), _tcp(443))   # provably disjoint dst
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "80"), [zone_other, CLEANUP])
    assert d.outcome is Outcome.CREATE


# --- placement unit ---------------------------------------------------------------------------
def test_placement_below_more_specific_and_anomaly():
    assert aa._placement(None, WEB) == {"below": "r8"}
    assert aa._position_payload({"below": "r8"}) == {"below": "r8"}
    assert aa._position_payload({"_above_cleanup": True}) == "bottom"
    drop = _rule("rdrop", 5, "Drop", ANY, ANY, ServiceSet(any=True))
    specific = _rule("rs", 10, "Accept", _host("1.1.1.1"), _host("2.2.2.2"), _tcp(1))
    hint = aa._placement(drop, specific)        # specific (10) sits below the cleanup (5)
    assert hint["above"] == "rdrop" and hint["_anomaly"] is True


# --- rule parsing from a show-access-rulebase entry + object dictionary ------------------------
def test_parse_rule_resolves_objdict_group_and_service():
    objdict = {
        "u-grp": {"uid": "u-grp", "name": "g", "type": "group", "members": ["u-h"]},
        "u-h": {"uid": "u-h", "name": "h", "type": "host", "ipv4-address": "10.0.0.5"},
        "u-net": {"uid": "u-net", "name": "n", "type": "network", "subnet4": "172.16.0.0", "mask-length4": 16},
        "u-https": {"uid": "u-https", "name": "https", "type": "service-tcp", "port": "443"},
        "u-accept": {"uid": "u-accept", "name": "Accept", "type": "RulebaseAction"},
    }
    entry = {"type": "access-rule", "rule-number": 4, "name": "allow", "enabled": True, "uid": "r4",
             "source": ["u-grp"], "destination": ["u-net"], "service": ["u-https"], "action": "u-accept"}
    r = aa._parse_rule(entry, objdict)
    assert r.is_accept and r.uid == "r4" and r.source_group_uids == ["u-grp"]
    assert r.src == _host("10.0.0.5")                       # group member resolved
    assert aa.relation(_host("172.16.9.9"), r.dst) == Relation.SUBSET
    assert r.svc.covers(_tcp(443)) and not r.complex


def test_parse_rule_negate_marks_complex():
    objdict = {"u-any": {"uid": "u-any", "name": "Any", "type": "CpmiAnyObject"}}
    entry = {"type": "access-rule", "rule-number": 2, "name": "x", "uid": "r2",
             "source": ["u-any"], "destination": ["u-any"], "service": ["u-any"],
             "action": "Drop", "source-negate": True}
    assert aa._parse_rule(entry, objdict).complex is True


# --- I/O entry points against a fake session --------------------------------------------------
def _fake_session_factory(calls, hosts=None, services=None, fail_on=None, rule=None, layers=None):
    hosts = hosts or {}
    services = services or {}

    class FS:
        def __init__(self, server, secret, timeout=30.0, **kwargs):
            self.trace = []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def call(self, command, payload=None, **kwargs):
            calls.append((command, payload or {}))
            if fail_on and command == fail_on:
                raise aa.MgmtError("server said no")
            if command == "show-objects":
                p = payload or {}
                if (p.get("type") or "").startswith("application-site"):
                    f = p.get("filter") or ""        # echo the searched app so it resolves exactly (it exists)
                    return {"objects": [{"name": f, "uid": "app-" + f, "type": "application-site"}]} if f else {"objects": []}
                ip = p.get("filter")
                return {"objects": [{"name": hosts[ip], "ipv4-address": ip}]} if ip in hosts else {"objects": []}
            if command in ("show-services-tcp", "show-services-udp"):
                proto = "tcp" if command.endswith("tcp") else "udp"
                port = str((payload or {}).get("filter"))
                name = services.get((proto, port))
                return {"objects": [{"name": name, "port": port}]} if name else {"objects": []}
            if command == "add-access-rule":          # the SMS returns the created rule incl. its uid
                return {"uid": f"new-rule-{sum(1 for c, _ in calls if c == 'add-access-rule')}"}
            if command == "show-access-rule":          # amend reads current values to build the inverse
                if rule is None:
                    raise aa.MgmtError("Requested object [r1] not found")
                return dict(rule)
            if command == "set-access-rule":
                # The real web_api has NO "name" write field (rename is "new-name") — reject it so the
                # name->new-name mapping can't silently regress in a test that only echoes the payload.
                if "name" in (payload or {}):
                    raise aa.MgmtError("set-access-rule: unrecognized parameter [name] (rename uses new-name)")
                return {"uid": (payload or {}).get("uid")}
            if command == "show-access-layers":        # Apply-Layer validation reads the layer list
                return {"access-layers": layers or []}
            return {}

        def publish(self):
            calls.append(("publish", {}))

        def discard(self):
            calls.append(("discard", {}))

    return FS


def _fake_read_session(calls, hosts=None, services=None, fail_on=None):
    """A stand-in for mgmt_api.read_session: yields a fake read-only session (the pool/login is mocked
    away). Used by preview tests, which now acquire their session via read_session."""
    factory = _fake_session_factory(calls, hosts=hosts, services=services, fail_on=fail_on)

    @contextlib.contextmanager
    def _rs(server, secret):
        yield factory(server, secret)

    return _rs


def test_execute_widen_adds_to_source_cell(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"),
                     "Network", ticket_id="INC1", publish=True)
    assert res["ok"] and res["outcome"] == "widen" and res["published"] is True
    cmds = [c for c, _ in calls]
    assert "add-host" in cmds and "set-access-rule" in cmds and "publish" in cmds
    assert "set-group" not in cmds and "add-access-rule" not in cmds   # cell add: no group, no new rule
    setr = next(p for c, p in calls if c == "set-access-rule")
    assert setr["source"] == {"add": "h-192-168-9-9"}


def test_execute_create_publishes_rule_and_objects(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"),
                     "Network", ticket_id="INC2", publish=True)
    assert res["ok"] and res["outcome"] == "create" and res["published"] is True
    cmds = [c for c, _ in calls]
    assert cmds.count("add-host") == 2 and "add-service-tcp" in cmds and "add-access-rule" in cmds
    rule = next(p for c, p in calls if c == "add-access-rule")
    assert rule["position"] == {"above": "rC"} and rule["action"] == "Accept"


def test_execute_dry_run_discards(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"),
                     "Network", publish=False)
    assert res["applied"] is True and res["published"] is False and res["validated"] is True
    cmds = [c for c, _ in calls]
    assert "discard" in cmds and "publish" not in cmds


def test_execute_no_op_writes_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.0.50/32"], ["172.16.5.10/32"], "tcp", "443"),
                     "Network", publish=True)
    assert res["outcome"] == "no_op" and res["applied"] is False
    assert calls == [] or all(c not in ("add-host", "add-access-rule", "publish") for c, _ in calls)


def test_execute_discards_on_error(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, fail_on="add-access-rule"))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"),
                     "Network", publish=True)
    assert res["ok"] is False and "server said no" in res["error"]
    cmds = [c for c, _ in calls]
    assert "discard" in cmds and "publish" not in cmds


def test_preview_is_read_only_and_reports_reuse(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "read_session",
                        _fake_read_session(calls, hosts={"192.168.9.9": "existing-host"}))
    monkeypatch.setattr(aa, "load_layer_cached", lambda s, srv, layer, package=None: ([WEB, CLEANUP], False))
    res = aa.preview(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), "Network")
    assert res["ok"] and res["outcome"] == "widen" and res["widen"]["field"] == "source"
    assert res["widen"]["object"]["exists"] is True and res["widen"]["object"]["name"] == "existing-host"
    cmds = [c for c, _ in calls]
    assert "add-host" not in cmds and "set-group" not in cmds and "publish" not in cmds


def test_execute_cidr_request_materializes_network_not_host(monkeypatch):
    # a /24 source must become a NETWORK object covering the full /24, never a single /32 host
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.50.0.0/24"], ["172.16.5.10/32"], "tcp", "443"),
                     "Network", publish=True)
    assert res["outcome"] == "widen" and res["widen_field"] == "source"
    assert res["widen_object"] == "n-10-50-0-0-24"
    addnet = [p for c, p in calls if c == "add-network"]
    assert addnet and addnet[0]["subnet4"] == "10.50.0.0" and addnet[0]["mask-length4"] == 24
    assert not any(c == "add-host" for c, _ in calls)


def test_execute_cidr_create_uses_network_for_src_and_dst(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.50.0.0/24"], ["172.16.9.0/24"], "tcp", "22"),
                     "Network", publish=True)
    assert res["outcome"] == "create"
    assert res["source_object"] == "n-10-50-0-0-24" and res["destination_object"] == "n-172-16-9-0-24"
    assert {p["subnet4"] for c, p in calls if c == "add-network"} == {"10.50.0.0", "172.16.9.0"}


def test_preview_cidr_reports_network_and_stays_read_only(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "read_session", _fake_read_session(calls))
    monkeypatch.setattr(aa, "load_layer_cached", lambda s, srv, layer, package=None: ([WEB, CLEANUP], False))
    res = aa.preview(object(), "secret",
                     AccessRequest(["10.50.0.0/24"], ["172.16.5.10/32"], "tcp", "443"), "Network")
    assert res["widen"]["object"]["name"] == "n-10-50-0-0-24" and res["widen"]["object"]["ip"] == "10.50.0.0/24"
    assert not any(c in ("add-network", "add-host") for c, _ in calls)   # preview never writes


# --- generic ticketing payload handling -------------------------------------------------------
def test_build_request_normalises_bare_ip_to_cidr():
    req = tk.build_request("192.168.9.9", "172.16.5.10", "TCP", "443")
    assert req.src_cidrs == ["192.168.9.9/32"] and req.dst_cidrs == ["172.16.5.10/32"]
    assert req.protocol == "tcp"


def test_build_request_rejects_bad_input():
    with pytest.raises(ValueError):
        tk.build_request("not-an-ip", "172.16.5.10", "tcp", "443")
    with pytest.raises(ValueError):
        tk.build_request("1.1.1.1", "2.2.2.2", "icmp", "443")
    with pytest.raises(ValueError):
        tk.build_request("1.1.1.1", "2.2.2.2", "tcp", "")


def test_build_request_validates_port_shape():
    # non-numeric, comma list, malformed range, out-of-range, reversed range all rejected at the boundary
    for bad in ["http", "443,80", "1-2-3", "70000", "500-100"]:
        with pytest.raises(ValueError):
            tk.build_request("1.1.1.1", "2.2.2.2", "tcp", bad)
    assert tk.build_request("1.1.1.1", "2.2.2.2", "tcp", "8000-8100").ports == "8000-8100"


def test_parse_payload_flat_and_vendor_aliases():
    t = tk.parse_payload({"ticket_id": "INC1", "server_id": "3", "layer": "Network",
                          "source": "10.0.0.9", "destination": "172.16.5.10",
                          "protocol": "tcp", "port": "443", "apply": "true"})
    assert t.server_id == 3 and t.layer == "Network" and t.apply is True
    assert t.request.dst_cidrs == ["172.16.5.10/32"]
    # ServiceNow-style (number / u_*) and Jira-style (key) aliases both parse
    t2 = tk.parse_payload({"number": "INC2", "u_server_id": 5, "u_layer": "L",
                           "u_source": "10.0.0.0/24", "u_destination": "8.8.8.8",
                           "u_protocol": "udp", "u_port": "53"})
    assert t2.ticket_id == "INC2" and t2.server_id == 5 and t2.apply is False
    assert t2.request.protocol == "udp"
    t3 = tk.parse_payload({"key": "NET-7", "server_id": 2, "layer": "L", "src": "1.1.1.1",
                           "dest": "2.2.2.2", "port": "22", "callback_url": "https://itsm/cb",
                           "callback_token": "tok"})
    assert t3.ticket_id == "NET-7" and t3.callback_url == "https://itsm/cb" and t3.callback_token == "tok"


def test_parse_payload_requires_server_and_layer():
    with pytest.raises(ValueError):
        tk.parse_payload({"layer": "L", "source": "1.1.1.1", "destination": "2.2.2.2", "port": "80"})
    with pytest.raises(ValueError):
        tk.parse_payload({"server_id": 1, "source": "1.1.1.1", "destination": "2.2.2.2", "port": "80"})


def test_summarize_published_and_failed():
    ok = tk.summarize({"ok": True, "outcome": "create", "reason": "r", "source_object": "h-1",
                       "destination_object": "h-2", "service_object": "TCP-22",
                       "position": "above rule 99 (Cleanup rule)", "applied": True, "published": True})
    assert "outcome=create" in ok and "published" in ok and "TCP-22" in ok
    bad = tk.summarize({"ok": False, "error": "boom"})
    assert "FAILED" in bad and "boom" in bad


def test_notify_posts_to_generic_callback_url(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200

    class FakeClient:
        def __init__(self, *a, **k):
            captured["verify"] = k.get("verify")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None, headers=None):
            captured.update(url=url, json=json, headers=headers)
            return FakeResp()

    monkeypatch.setattr(tk.httpx, "Client", FakeClient)
    ticket = tk.parse_payload({"ticket_id": "INC9", "server_id": 1, "layer": "L", "source": "1.1.1.1",
                               "destination": "2.2.2.2", "port": "22", "callback_url": "https://itsm/cb",
                               "callback_token": "t0k"})
    res = tk.notify(ticket, {"ok": True, "outcome": "create", "reason": "r",
                             "applied": True, "published": True})
    assert res["ok"] and res["via"] == "callback_url"
    assert captured["url"] == "https://itsm/cb" and captured["verify"] is True   # TLS never disabled
    assert captured["headers"]["X-DCSim-Token"] == "t0k"
    assert captured["json"]["ticket_id"] == "INC9" and captured["json"]["outcome"] == "create"


def test_notify_skips_when_nothing_configured(monkeypatch):
    monkeypatch.setattr(tk, "servicenow_configured", lambda: False)
    ticket = tk.parse_payload({"ticket_id": "INC9", "server_id": 1, "layer": "L",
                               "source": "1.1.1.1", "destination": "2.2.2.2", "port": "22"})
    assert "skipped" in tk.notify(ticket, {"ok": True, "outcome": "no_op"})


# --- webhook auth gate (route function, no DB needed for these branches) ----------------------
def _run(coro):
    return asyncio.run(coro)


def test_webhook_disabled_without_token(monkeypatch):
    # the token resolves from Settings (encrypted) with env fallback; stub it transparently here
    monkeypatch.setattr(aar.app_settings, "get_secret_or_env", lambda k, env: "")
    monkeypatch.setattr(aar, "get_settings", lambda: types.SimpleNamespace(webhook_token=""))
    req = types.SimpleNamespace(headers={})
    resp = _run(aar.aa_webhook(req, db=None))
    assert resp.status_code == 503


def test_webhook_rejects_bad_token(monkeypatch):
    monkeypatch.setattr(aar.app_settings, "get_secret_or_env", lambda k, env: "s3cret")
    monkeypatch.setattr(aar, "get_settings", lambda: types.SimpleNamespace(webhook_token="s3cret"))
    req = types.SimpleNamespace(headers={"x-dcsim-token": "wrong"})
    resp = _run(aar.aa_webhook(req, db=None))
    assert resp.status_code == 401


def test_webhook_server_allowlist_parsing(monkeypatch):
    # the allowlist resolves from Settings with env fallback; stub it to pass the env value through
    monkeypatch.setattr(aar.app_settings, "get_or_env", lambda k, env: env)
    # a clean list parses
    monkeypatch.setattr(aar, "get_settings",
                        lambda: types.SimpleNamespace(webhook_server_ids="1, 3 ,5"))
    assert aar._allowed_server_ids() == {1, 3, 5}
    # unset = allow-all (empty set)
    monkeypatch.setattr(aar, "get_settings", lambda: types.SimpleNamespace(webhook_server_ids=""))
    assert aar._allowed_server_ids() == set()
    # a malformed entry FAILS CLOSED (raises) instead of silently dropping to allow-all
    monkeypatch.setattr(aar, "get_settings", lambda: types.SimpleNamespace(webhook_server_ids="1,x,5"))
    with pytest.raises(ValueError):
        aar._allowed_server_ids()
    monkeypatch.setattr(aar, "get_settings", lambda: types.SimpleNamespace(webhook_server_ids="prod-3"))
    with pytest.raises(ValueError):
        aar._allowed_server_ids()


# --- webhook end-to-end (parse -> execute -> record -> notify -> response) ----------------------
def _webhook_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app import models  # noqa: F401 — registers tables
    from app.db import Base
    from app.models import ManagementServer
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    s.add(ManagementServer(id=1, name="HQ", host="hq", username="admin", owner_id=1))
    s.commit()
    return s


class _WReq:
    def __init__(self, body, token="t0k"):
        self.headers = {"x-dcsim-token": token}
        self._body = body

    async def json(self):
        return self._body


def _webhook_auth(monkeypatch):
    monkeypatch.setattr(aar.app_settings, "get_secret_or_env", lambda k, env: "t0k")
    monkeypatch.setattr(aar.app_settings, "get_or_env", lambda k, env: env)
    monkeypatch.setattr(aar, "get_settings",
                        lambda: types.SimpleNamespace(webhook_token="t0k", webhook_server_ids=""))
    monkeypatch.setattr(aar.mgmt_creds, "get_secret", lambda db, ms: "secret")
    monkeypatch.setattr(aar, "ensure_pinned", lambda db, ms: None)
    monkeypatch.setattr(aar.ticketing, "notify", lambda ticket, result: {"skipped": "test"})


def test_webhook_applied_reflects_reality_not_intent(monkeypatch):
    # M4: apply=true but the engine returns no_op -> the webhook's top-level "applied"/"published" must report
    # what actually committed (nothing), NOT the request's intent — an ITSM consumer must not read "granted".
    _webhook_auth(monkeypatch)
    monkeypatch.setattr(aa, "execute",
                        lambda *a, **k: {"ok": True, "applied": False, "published": False, "outcome": "no_op"})
    db = _webhook_db()
    body = {"ticket_id": "INC1", "server_id": 1, "layer": "L", "source": "10.0.0.5",
            "destination": "1.1.1.1", "port": "443", "apply": True}
    out = json.loads(_run(aar.aa_webhook(_WReq(body), db=db)).body)
    assert out["applied"] is False and out["published"] is False and out["outcome"] == "no_op"
    db.close()


def test_webhook_happy_path_publishes_and_records(monkeypatch):
    # M7: the unattended publish surface end-to-end — parse -> execute(publish=True) -> record(actor='webhook')
    # -> notify -> truthful response. (Previously only the auth/allowlist gates were covered.)
    _webhook_auth(monkeypatch)
    notified, seen = {}, {}
    monkeypatch.setattr(aar.ticketing, "notify",
                        lambda ticket, result: notified.update(outcome=result.get("outcome")) or {"skipped": "t"})
    monkeypatch.setattr(aa, "execute", lambda *a, **k: seen.update(publish=k.get("publish")) or {
        "ok": True, "applied": True, "published": True, "outcome": "create", "source_object": "h",
        "inverse": [{"op": "delete-access-rule", "uid": "u1", "layer": "L"}]})
    db = _webhook_db()
    body = {"ticket_id": "INC2", "server_id": 1, "layer": "L", "source": "10.0.0.5",
            "destination": "1.1.1.1", "port": "443", "apply": True}
    out = json.loads(_run(aar.aa_webhook(_WReq(body), db=db)).body)
    assert seen["publish"] is True                                  # apply=true publishes
    assert out["applied"] is True and out["published"] is True and out["outcome"] == "create"
    assert notified["outcome"] == "create"                          # the result was pushed back
    from app.services import change_log
    rows = change_log.recent_for_server(db, 1)
    assert rows and rows[0].created_by == "webhook" and rows[0].ticket_id == "INC2"   # recorded for rollback
    db.close()


def test_webhook_preview_does_not_publish_or_record(monkeypatch):
    # apply=false -> preview only: never calls execute, records nothing.
    _webhook_auth(monkeypatch)
    called = {"execute": False}
    monkeypatch.setattr(aa, "execute", lambda *a, **k: called.update(execute=True) or {})
    monkeypatch.setattr(aa, "preview", lambda *a, **k: {"ok": True, "outcome": "create"})
    db = _webhook_db()
    body = {"ticket_id": "INC3", "server_id": 1, "layer": "L", "source": "10.0.0.5",
            "destination": "1.1.1.1", "port": "443", "apply": False}
    out = json.loads(_run(aar.aa_webhook(_WReq(body), db=db)).body)
    assert out["applied"] is False and called["execute"] is False
    from app.services import change_log
    assert change_log.recent_for_server(db, 1) == []
    db.close()


# --- template rendering -----------------------------------------------------------------------
def _render(name, **ctx):
    ctx.setdefault("request", None)
    return templates.env.get_template(name).render(**ctx)


def test_access_automation_list_renders():
    ms = types.SimpleNamespace(id=1, name="SMS-A", host="10.0.0.1", port=443, domain="")
    html = _render("access_automation_list.html", rows=[{"ms": ms, "has_secret": True}], flash=None)
    assert "Access automation" in html and 'href="/access-automation/1"' in html


def test_access_automation_detail_renders_form_and_webhook():
    ms = types.SimpleNamespace(id=7, name="SMS-B", host="10.0.0.2", port=443, domain="dom1")
    req = types.SimpleNamespace(base_url="https://portal.example/")
    html = _render("access_automation_detail.html", ms=ms, has_secret=True, flash=None, request=req,
                   decision_graph_json=json.dumps(dt.to_graph()))
    assert "Preview decision" in html and "aa-source" in html
    assert "/access-automation/webhook" in html and "X-DCSim-Token" in html
    assert "callback_url" in html and "any ITSM" in html
    # Internet object: a destination-only kind (App Control / URL Filtering), with the JS that couples it
    # to an Application service (pick an app -> destination defaults to Internet).
    assert 'value="internet"' in html and "Internet (to the internet / DMZ)" in html
    assert "dt.value = 'internet'" in html       # syncSvcType auto-selects Internet for an app request
    # rollback panel: a "disabled" rule is a non-terminal state (Re-enable | Delete rule), and re-enable maps
    assert "c.state === 'disabled'" in html and "bodyObj.reenable = true" in html
    # the "behind the scenes" decision tree — a custom canvas the client renders from the engine's own
    # graph JSON, still exportable to the user's diagram tool (.drawio / .mmd / .dot)
    assert 'id="aa-flow-canvas"' in html and "How it decides" in html
    assert "/access-automation/decision-tree/drawio" in html and "decision-tree/mmd" in html
    for leaf in ("No-op", "Widen the rule", "Create least-privilege rule", "Note & keep going"):
        assert leaf in html        # leaf labels live in the embedded decision-graph JSON
    assert "Review" not in html    # the flow is reuse-or-create — no policy "review" stop


def test_access_automation_diagram_shows_without_credential():
    ms = types.SimpleNamespace(id=9, name="No-Secret", host="10.0.0.9", port=443, domain="")
    req = types.SimpleNamespace(base_url="https://portal.example/")
    html = _render("access_automation_detail.html", ms=ms, has_secret=False, flash=None, request=req,
                   decision_graph_json=json.dumps(dt.to_graph()))
    # the explainer is educational, so it renders even when policy can't be pulled
    assert 'id="aa-flow-canvas"' in html and "How it decides" in html


# --- group dereferencing: an unresolved group source must REVIEW; a resolved one must not block -----
def _dns_layer(group_members):
    """A DNS-style layer mirroring the live demo: rule 1 has a group source (internal_nets), rule 6 is
    the Facebook allow (win_server -> Any). `group_members` is the group's resolved member list."""
    od = {
        "u-net": {"uid": "u-net", "type": "network", "name": "net_203_0_113_0_24",
                  "subnet4": "203.0.113.0", "mask-length4": 24},
        "u-grp": {"uid": "u-grp", "type": "group", "name": "internal_nets", "members": group_members},
        "u-ws": {"uid": "u-ws", "type": "host", "name": "win_server", "ipv4-address": "10.1.1.50"},
        "u-any": {"uid": "u-any", "type": "CpmiAnyObject", "name": "Any"},
        "u-fb": {"uid": "u-fb", "type": "application-site", "name": "Facebook"},
        "u-acc": {"uid": "u-acc", "name": "Accept"}, "u-drop": {"uid": "u-drop", "name": "Drop"},
    }
    raw = [
        {"uid": "r1", "rule-number": 1, "name": "Internal DNS Server", "enabled": True,
         "source": ["u-net", "u-grp"], "destination": ["u-ws"], "service": ["u-any"], "action": "u-acc"},
        {"uid": "r6", "rule-number": 6, "name": "Facebook allow", "enabled": True,
         "source": ["u-ws"], "destination": ["u-any"], "service": ["u-fb"], "action": "u-acc"},
        {"uid": "r7", "rule-number": 7, "name": "DNS log and drop", "enabled": True,
         "source": ["u-any"], "destination": ["u-any"], "service": ["u-any"], "action": "u-drop"},
    ]
    return [aa._parse_rule(e, od) for e in raw]


_FB_REQ = AccessRequest(src_cidrs=["10.1.1.222/32"], dst_cidrs=["Any"], application="Facebook")


def test_unresolved_group_source_does_not_block_widen():
    # group members absent (bare UID) -> rule 1's source is unknown. It's an ACCEPT with a SPECIFIC
    # destination (win_server), so it can NOT cover this Any-destination request -> it isn't flagged as a
    # possible allow at all, and the walk still reaches the CORRECT outcome: WIDEN the Facebook rule's
    # source. (Live-lab symptom: an unresolvable DNS rule used to spuriously REVIEW the whole request; now
    # it doesn't even add noise, because a specific-destination rule can't allow an Any-destination request.)
    rules = _dns_layer(["u-missing-member"])
    assert rules[0].complex and rules[0].src_unknown
    d = aa.decide(_FB_REQ, rules)
    assert d.outcome is Outcome.WIDEN and d.target_rule.number == 6
    assert not _noted(d, "rule 1")     # specific destination (win_server) can't cover an Any request


def test_dereferenced_group_source_lets_engine_widen():
    # group members nested as full objects (what dereference-group-members returns), and 10.1.1.222 is
    # NOT among them -> rule 1 resolves + is disjoint -> engine reaches the clean WIDEN on the FB rule.
    member = {"uid": "u-mem", "type": "host", "name": "an_internal_host", "ipv4-address": "10.1.1.99"}
    rules = _dns_layer([member])
    assert not rules[0].complex and not rules[0].src_unknown
    d = aa.decide(_FB_REQ, rules)
    assert d.outcome is Outcome.WIDEN and d.target_rule.number == 6 and d.widen_field == "source"


# --- network-cell resolution: infra objects (gateway/cluster/mgmt) resolve; opaque objects REVIEW -----
def _od_infra():
    return {
        "h": {"uid": "h", "type": "host", "name": "win_server", "ipv4-address": "10.1.1.50"},
        "gw": {"uid": "gw", "type": "simple-gateway", "name": "GW", "ipv4-address": "10.1.1.1"},
        "sms": {"uid": "sms", "type": "checkpoint-host", "name": "SMS", "ipv4-address": "10.1.1.100"},
        "rng": {"uid": "rng", "type": "address-range", "name": "r",
                "ipv4-address-first": "10.2.0.1", "ipv4-address-last": "10.2.0.9"},
        "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
        "fb": {"uid": "fb", "type": "application-site", "name": "Facebook"},
        "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
        "zone": {"uid": "zone", "type": "security-zone", "name": "InternalZone"},
        "dyn": {"uid": "dyn", "type": "dynamic-object", "name": "DynSrv"},
        "role": {"uid": "role", "type": "access-role", "name": "Finance"},
        "wild": {"uid": "wild", "type": "wildcard", "name": "odd",
                 "ipv4-address": "10.0.0.0", "ipv4-mask-wildcard": "0.0.255.0"},
    }


def _irule(n, src, dst, svc, act, od):
    return aa._parse_rule({"uid": f"r{n}", "rule-number": n, "name": f"r{n}", "enabled": True,
                           "source": src, "destination": dst, "service": svc, "action": act}, od)


def test_gateway_and_checkpoint_host_resolve_as_approx():
    od = _od_infra()
    r = _irule(1, ["h", "gw", "sms"], ["any"], ["any"], "acc", od)
    assert not r.complex          # gateway + checkpoint-host now resolve to their ipv4-address
    assert r.src_approx           # ...but flagged approx (main IP only)
    assert not r.src_unknown


def test_range_resolves_exact_not_approx():
    od = _od_infra()
    r = _irule(1, ["rng"], ["any"], ["any"], "acc", od)
    assert not r.complex and not r.src_approx


def test_opaque_network_objects_still_review():
    od = _od_infra()
    req = AccessRequest(src_cidrs=["10.9.9.9/32"], dst_cidrs=["Any"], application="Facebook")
    # NB: wildcard objects are now RESOLVED (reducer #3), so they are no longer opaque — see the
    # test_wildcard_* tests. The genuinely-unresolvable types stay REVIEW.
    for opaque in ("zone", "dyn", "role"):
        rules = [_irule(1, [opaque], ["any"], ["any"], "acc", od),
                 _irule(2, ["any"], ["any"], ["any"], "drp", od)]
        assert rules[0].complex, opaque
        d = aa.decide(req, rules)        # opaque-source ACCEPT -> noted + continue -> clean CREATE
        assert d.outcome is Outcome.CREATE and _noted(d, "rule 1"), opaque


def test_approx_accept_is_harmless_request_widens_later_rule():
    od = _od_infra()
    rules = [_irule(1, ["gw", "sms"], ["any"], ["any"], "acc", od),    # approx accept, disjoint source
             _irule(2, ["h"], ["any"], ["fb"], "acc", od),             # the real widen target
             _irule(3, ["any"], ["any"], ["any"], "drp", od)]
    req = AccessRequest(src_cidrs=["10.4.4.4/32"], dst_cidrs=["Any"], application="Facebook")
    d = aa.decide(req, rules)
    assert d.outcome is Outcome.WIDEN and d.target_rule.number == 2 and d.widen_field == "source"


def test_approx_drop_stepped_over_only_when_resolved_disjoint():
    # An approx DROP (a gateway resolved to its main IP — true reach may be wider) is judged on its RESOLVED
    # extent (the signed-off resolved-disjointness rule, _out_of_path):
    #  (a) resolved-DISJOINT from the request -> an UNRELATED gateway -> stepped over (not flagged, not a floor).
    #  (b) resolved-OVERLAP with the request -> kept IN the path: NOTED + placed below, never silently stepped
    #      over. So an approx drop that actually applies is still never under-approximated.
    od = _od_infra()
    drop_gw = _irule(1, ["gw"], ["any"], ["any"], "drp", od)          # gw main IP 10.1.1.1, approx
    cleanup = _irule(2, ["any"], ["any"], ["any"], "drp", od)
    # (a) request for an unrelated host -> the gateway drop is resolved-disjoint -> stepped over (no rule-1 note)
    d1 = aa.decide(AccessRequest(src_cidrs=["10.7.7.7/32"], dst_cidrs=["Any"], application="Facebook"),
                   [drop_gw, cleanup])
    assert d1.outcome is Outcome.CREATE and not any("rule 1" in n for n in d1.notes)
    # (b) request BROADER than the gw main IP (a /24 that only partially overlaps the approx drop) -> kept
    #     IN the path, NOTED + placed below (carving the whole /24 above would over-grant the gw-IP part).
    d2 = aa.decide(AccessRequest(src_cidrs=["10.1.1.0/24"], dst_cidrs=["Any"], application="Facebook"),
                   [drop_gw, cleanup])
    assert d2.outcome is Outcome.CREATE and d2.position != {"above": "r1"} and any("rule 1" in n for n in d2.notes)
    # (c) request for the gateway's OWN main IP -> the drop PROVABLY covers it (request == resolved extent;
    #     approx only widens the drop) -> below would be a dead/shadowed rule, so the allow is carved ABOVE it.
    d3 = aa.decide(AccessRequest(src_cidrs=["10.1.1.1/32"], dst_cidrs=["Any"], application="Facebook"),
                   [drop_gw, cleanup])
    assert d3.outcome is Outcome.CREATE and d3.position == {"above": "r1"}


def test_malformed_port_reviews_not_crashes():
    # _ports_to_iv must tolerate garbage (mirror the rule-side _parse_port) so decide() guard 2 -> REVIEW
    assert aa._ports_to_iv("443x") == [] and aa._ports_to_iv("443-abc") == [] and aa._ports_to_iv("-1x") == []
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"}, "drp": {"uid": "drp", "name": "Drop"}}
    rules = [_irule(1, ["any"], ["any"], ["any"], "drp", od)]
    for bad in ("443x", "443-abc", "abc"):          # FULLY unparsable -> empty service -> guard 2 -> REVIEW
        req = AccessRequest(src_cidrs=["10.1.1.1/32"], dst_cidrs=["Any"], protocol="tcp", ports=bad)
        assert aa.decide(req, rules).outcome is Outcome.REVIEW, bad
    # partial ("443,xyz" keeps the valid 443) is a real request -> a normal decision, just never a crash
    req = AccessRequest(src_cidrs=["10.1.1.1/32"], dst_cidrs=["Any"], protocol="tcp", ports="443,xyz")
    assert aa.decide(req, rules).outcome in (Outcome.CREATE, Outcome.NO_OP, Outcome.WIDEN, Outcome.REVIEW)


# --- named (non-tcp/udp) services: resolve like apps + reason by name ------------------------------
_SVC_OD = {
    "h": {"uid": "h", "type": "host", "name": "h", "ipv4-address": "10.0.0.5"},
    "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "t443": {"uid": "t443", "type": "service-tcp", "name": "https", "port": "443"},
    "echo": {"uid": "echo", "type": "service-icmp", "name": "echo-request"},
    "gre": {"uid": "gre", "type": "service-other", "name": "GRE"},
    "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
}


def test_icmp_request_disjoint_from_tcp_rule_creates():
    rules = [_irule(1, ["h"], ["any"], ["t443"], "acc", _SVC_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SVC_OD)]
    # different source so there's no exact-two-cell widen candidate; icmp ≠ tcp/443 -> create
    req = AccessRequest(src_cidrs=["10.9.9.9/32"], dst_cidrs=["Any"], service="echo-request", service_kind="icmp")
    assert aa.decide(req, rules).outcome is Outcome.CREATE     # icmp not covered by the tcp/443 rule


def test_named_service_already_permitted_is_no_op():
    rules = [_irule(1, ["any"], ["any"], ["echo"], "acc", _SVC_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SVC_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["Any"], service="echo-request", service_kind="icmp")
    assert aa.decide(req, rules).outcome is Outcome.NO_OP


def test_named_service_widens_exact_two_cells():
    # rule: src h, dst Any, svc echo-request, Accept ; request src 10.0.0.9 -> widen the source
    rules = [_irule(1, ["h"], ["any"], ["echo"], "acc", _SVC_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SVC_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.9/32"], dst_cidrs=["Any"], service="echo-request", service_kind="icmp")
    d = aa.decide(req, rules)
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source"


def test_service_other_drop_keeps_port_request_in_path():
    # a DROP whose service is service-other (ambiguous protocol) must not be assumed disjoint from a
    # tcp/443 request -> we can't prove it applies, so we NOTE it and create the allow BELOW it (never
    # step over a possible deny by creating above one we can't resolve).
    rules = [_irule(1, ["any"], ["any"], ["gre"], "drp", _SVC_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SVC_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["Any"], protocol="tcp", ports="443")
    d = aa.decide(req, rules)
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 1") and d.position == {"above": "r2"}


# --- SCTP is PORT-based (a real port), not a portless named service like ICMP ---------------------
_SCTP_OD = {
    "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "s9000": {"uid": "s9000", "type": "service-sctp", "name": "sctp-9000", "port": "9000"},
    "t9000": {"uid": "t9000", "type": "service-tcp", "name": "tcp-9000", "port": "9000"},
    "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
}


def test_sctp_rule_parses_to_by_proto_not_named():
    r = _irule(1, ["any"], ["any"], ["s9000"], "acc", _SCTP_OD)
    assert r.svc.by_proto.get("sctp") == [(9000, 9000)]      # keyed by value under its own protocol
    assert not r.svc.named                                   # NOT a named service


def test_sctp_request_no_op_by_port():
    rules = [_irule(1, ["any"], ["any"], ["s9000"], "acc", _SCTP_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SCTP_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["Any"], protocol="sctp", ports="9000")
    assert aa.decide(req, rules).outcome is Outcome.NO_OP


def test_sctp_disjoint_from_same_port_tcp_rule_creates():
    # sctp/9000 must NEVER be read as covered by a tcp/9000 rule (distinct protocols)
    rules = [_irule(1, ["any"], ["any"], ["t9000"], "acc", _SCTP_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SCTP_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["Any"], protocol="sctp", ports="9000")
    assert aa.decide(req, rules).outcome is Outcome.CREATE


def test_icmp_still_parses_to_named_not_by_proto():
    r = _irule(1, ["any"], ["any"], ["echo"], "acc", _SVC_OD)
    assert ("icmp", "echo-request") in r.svc.named and not r.svc.by_proto   # portless -> named


def test_build_request_accepts_sctp_rejects_other_protocols():
    assert tk.build_request("1.1.1.1", "2.2.2.2", "sctp", "9000").protocol == "sctp"
    for bad in ("icmp", "gre", "esp"):
        with pytest.raises(ValueError):
            tk.build_request("1.1.1.1", "2.2.2.2", bad, "9000")


def test_build_request_named_service_and_precedence():
    r = tk.build_request("10.0.0.5", "Any", "tcp", "", service="icmp")
    assert r.service == "icmp" and r.application is None
    r2 = tk.build_request("10.0.0.5", "Any", "tcp", "443", application="Facebook", service="icmp")
    assert r2.application == "Facebook" and r2.service is None     # application wins


# --- service protocol-family must not alias (v4 icmp != v6 icmp of the same name) ------------------
def test_named_service_family_not_aliased():
    od = dict(_SVC_OD)
    od["echo6"] = {"uid": "echo6", "type": "service-icmp6", "name": "echo-request"}  # same NAME, v6 family
    # rule allows the v6 echo-request; a v4 (icmp) echo-request request must NOT be read as covered
    rules = [_irule(1, ["any"], ["any"], ["echo6"], "acc", od),
             _irule(2, ["any"], ["any"], ["any"], "drp", od)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["Any"],
                        service="echo-request", service_kind="icmp")
    assert aa.decide(req, rules).outcome is Outcome.CREATE     # not NO_OP — different protocol family


# --- configurable aggressiveness (DecideOptions) ---------------------------------------------------
_DENY_OD = {
    "h": {"uid": "h", "type": "host", "name": "h", "ipv4-address": "10.0.0.5"},
    "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "t443": {"uid": "t443", "type": "service-tcp", "name": "https", "port": "443"},
    "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
}


def _req443():
    return AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["Any"], protocol="tcp", ports="443")


def test_specific_covering_deny_creates_above_it():
    # a specific (non-cleanup), fully-resolved covering DROP -> the allow is created ABOVE it so the
    # requested access takes effect (there is no "review" stop; a deny is overridden by placement)
    rules = [_irule(1, ["h"], ["any"], ["t443"], "drp", _DENY_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _DENY_OD)]
    d = aa.decide(_req443(), rules)
    assert d.outcome is Outcome.CREATE and d.position == {"above": "r1"}


def test_ignore_conditions_lets_conditional_accept_cover():
    # a conditional (time-scoped) ACCEPT that covers the request
    raw = {"uid": "r1", "rule-number": 1, "name": "biz-hours", "enabled": True,
           "source": ["any"], "destination": ["any"], "service": ["t443"], "action": "acc",
           "time": ["worktime"]}
    od = dict(_DENY_OD, worktime={"uid": "worktime", "type": "time", "name": "WorkHours"})
    r1 = aa._parse_rule(raw, od)
    cleanup = _irule(2, ["any"], ["any"], ["any"], "drp", od)
    assert r1.conditional                                                            # it IS conditional
    assert aa.decide(_req443(), [r1, cleanup]).outcome is Outcome.CREATE             # default: skip -> create
    assert aa.decide(_req443(), [r1, cleanup], aa.DecideOptions(ignore_conditions=True)).outcome is Outcome.NO_OP


# --- inline-layer recursion ("Apply Layer") --------------------------------------------------------
def _inline(uid, num, src, dst, svc, sub, *, cleanup="drop", name=None, conditions=()):
    """An 'Apply Layer' parent rule whose inline-layer sub-rulebase (`sub`) is already attached, as the
    loader would. `cleanup` is the inline layer's implicit-cleanup-action."""
    return ParsedRule(uid=uid, number=num, name=uid, enabled=True, action="Apply Layer",
                      src=src, dst=dst, svc=svc, conditional=bool(conditions), conditions=tuple(conditions),
                      inline_uid=f"{uid}-L", inline_layer_name=name or f"{uid}-inline",
                      inline_rules=list(sub), inline_cleanup=cleanup)


def _req(src="10.1.0.5/32", dst="172.16.5.10/32", proto="tcp", port="443"):
    return AccessRequest(src_cidrs=[src], dst_cidrs=[dst], protocol=proto, ports=port)


# parent gates the whole 10.1.0.0/24 -> 172.16.5.10 :443 domain into the inline layer
def _parent(sub, **kw):
    return _inline("p1", 5, _net("10.1.0.0/24"), _host("172.16.5.10"), _tcp(443), sub, **kw)


def test_inline_explicit_accept_inside_is_no_op():
    sub = [_rule("i1", 1, "Accept", _host("10.1.0.5"), _host("172.16.5.10"), _tcp(443))]
    d = aa.decide(_req(), [_parent(sub), CLEANUP])
    assert d.outcome is Outcome.NO_OP and "inline layer" in d.reason


# a sub rule that neither covers NOR widens the request (differs in dst AND svc) -> forces the inline
# layer's own implicit cleanup to be the verdict
_NONMATCH_SUB = [_rule("i1", 1, "Accept", _host("10.1.0.9"), _host("8.8.8.8"), _tcp(22))]


def test_inline_no_match_drop_cleanup_creates_inside_layer():
    d = aa.decide(_req(), [_parent(_NONMATCH_SUB, cleanup="drop"), CLEANUP])
    assert d.outcome is Outcome.CREATE
    assert d.layer == "p1-inline"                          # the change lands INSIDE the inline layer
    assert "above its cleanup" in d.reason


def test_inline_no_match_accept_cleanup_is_no_op():
    d = aa.decide(_req(), [_parent(_NONMATCH_SUB, cleanup="accept"), CLEANUP])
    assert d.outcome is Outcome.NO_OP and "implicit cleanup (accept)" in d.reason


def test_inline_no_match_unknown_cleanup_creates_inside_layer():
    # cleanup unknown -> an explicit allow INSIDE the layer grants the request regardless of what the
    # implicit cleanup would do, so we create inside it (no review stop)
    d = aa.decide(_req(), [_parent(_NONMATCH_SUB, cleanup=""), CLEANUP])
    assert d.outcome is Outcome.CREATE and d.layer == "p1-inline" and "above its cleanup" in d.reason


def test_inline_partial_match_splits_notes_and_continues():
    # request dst (a /24) is a SUPERSET of the parent's /32 -> traffic splits across layers. We don't
    # second-guess the split: NOTE it and keep going (the new rule lands below the parent).
    req = AccessRequest(src_cidrs=["10.1.0.5/32"], dst_cidrs=["172.16.5.0/24"], protocol="tcp", ports="443")
    sub = [_rule("i1", 1, "Accept", ANY, ANY, _tcp(443))]
    d = aa.decide(req, [_parent(sub), CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "splits across")


def test_inline_widen_targets_a_rule_inside_the_layer():
    # inline rule equals request in dst+svc, differs only in source -> WIDEN that inline rule
    sub = [_rule("i1", 1, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443))]
    req = AccessRequest(src_cidrs=["10.1.0.5/32"], dst_cidrs=["172.16.5.10/32"], protocol="tcp", ports="443")
    d = aa.decide(req, [_parent(sub), CLEANUP])
    assert d.outcome is Outcome.WIDEN
    assert d.target_rule.uid == "i1" and d.layer == "p1-inline"


def test_inline_explicit_drop_inside_creates_above_it():
    # an explicit, resolved DROP inside the inline layer covers the request -> create the allow ABOVE that
    # drop, INSIDE the layer (no review stop)
    sub = [_rule("i1", 1, "Drop", _host("10.1.0.5"), _host("172.16.5.10"), _tcp(443))]
    d = aa.decide(_req(), [_parent(sub), CLEANUP])
    assert d.outcome is Outcome.CREATE and d.layer == "p1-inline"


def test_inline_conditional_parent_notes_then_ignored_no_ops():
    sub = [_rule("i1", 1, "Accept", _host("10.1.0.5"), _host("172.16.5.10"), _tcp(443))]
    parent = _parent(sub, conditions=("time",))
    d = aa.decide(_req(), [parent, CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "p1")          # noted & continued, not a hard stop
    d2 = aa.decide(_req(), [parent, CLEANUP], aa.DecideOptions(ignore_conditions=True))
    assert d2.outcome is Outcome.NO_OP                              # condition ignored -> descends -> allowed


def test_inline_parent_disjoint_is_not_entered():
    # request outside the parent's domain -> never descends; falls to a normal CREATE at the cleanup
    sub = [_rule("i1", 1, "Drop", ANY, ANY, ServiceSet(any=True))]   # would block if (wrongly) entered
    req = AccessRequest(src_cidrs=["192.168.50.5/32"], dst_cidrs=["8.8.8.8/32"], protocol="tcp", ports="53")
    d = aa.decide(req, [_parent(sub), CLEANUP])
    assert d.outcome is Outcome.CREATE and d.layer is None


def test_inline_nested_two_levels():
    inner = [_rule("j1", 1, "Accept", _host("10.1.0.5"), _host("172.16.5.10"), _tcp(443))]
    mid = [_inline("m1", 1, _net("10.1.0.0/24"), _host("172.16.5.10"), _tcp(443), inner, name="mid")]
    d = aa.decide(_req(), [_parent(mid), CLEANUP])
    assert d.outcome is Outcome.NO_OP


# --- loader: attach inline sub-rulebases (I/O), with cycle + cleanup guards -------------------------
class _FakeSession:
    """Minimal stand-in for MgmtSession.call covering the loader's show-access-rulebase / -layer calls.
    `layers` maps a layer NAME -> its rulebase; `objs` is the shared object dictionary returned with every
    rulebase page (so the inline-layer name resolves like a real pull); `cleanups` maps a layer UID -> its
    implicit-cleanup-action for the show-access-layer fallback."""
    def __init__(self, layers, objs=None, cleanups=None, dynamics=None):
        self.layers, self.objs, self.cleanups, self.calls = layers, objs or [], cleanups or {}, []
        self.dynamics = dynamics or {}          # layer UID -> is-dynamic-layer (sk182252)

    def call(self, cmd, payload):
        self.calls.append((cmd, payload))
        if cmd == "show-access-rulebase":
            return {"rulebase": self.layers.get(payload.get("name"), []),
                    "objects-dictionary": self.objs, "total": 0, "to": 0}
        if cmd == "show-access-layer":
            ref = payload.get("uid") or payload.get("name")
            return {"implicit-cleanup-action": self.cleanups.get(ref, ""),
                    "dynamic-layer": self.dynamics.get(ref, False)}
        return {}


def _ap_rule(uid, num, inline_uid):
    return {"type": "access-rule", "uid": uid, "rule-number": num, "name": uid, "enabled": True,
            "source": ["Any"], "destination": ["Any"], "service": ["Any"], "action": "Apply Layer",
            "inline-layer": inline_uid}


def test_loader_attaches_inline_rules_and_cleanup():
    # object dictionary names the inline layer (so the pull uses its name); cleanup is NOT in the dict,
    # so the loader falls back to a show-access-layer lookup.
    objs = [{"uid": "L-DMZ", "type": "access-layer", "name": "DMZ"}]
    top = [_ap_rule("p", 1, "L-DMZ")]
    dmz = [{"type": "access-rule", "uid": "d1", "rule-number": 1, "name": "d1", "enabled": True,
            "source": ["Any"], "destination": ["Any"], "service": ["Any"], "action": "Accept"}]
    sess = _FakeSession({"DMZ": dmz, "topL": top}, objs=objs, cleanups={"L-DMZ": "drop"})
    rules = aa.load_layer(sess, "topL")
    assert rules[0].inline_layer_name == "DMZ"             # resolved from the object dictionary
    assert rules[0].inline_rules is not None and len(rules[0].inline_rules) == 1
    assert rules[0].inline_cleanup == "drop"               # looked up via show-access-layer fallback
    assert ("show-access-layer", {"uid": "L-DMZ"}) in sess.calls


def test_loader_keeps_objdict_cleanup_but_still_checks_dynamic_flag():
    # cleanup carried in the object dictionary is kept; but the dynamic-layer flag (sk182252) is returned
    # ONLY by show-access-layer (never in show-access-rulebase's object dictionary), so the loader MUST
    # still consult it — here it learns the layer is NOT dynamic and descends normally.
    objs = [{"uid": "L-DMZ", "type": "access-layer", "name": "DMZ", "implicit-cleanup-action": "Accept"}]
    sess = _FakeSession({"DMZ": [], "topL": [_ap_rule("p", 1, "L-DMZ")]}, objs=objs)
    rules = aa.load_layer(sess, "topL")
    assert rules[0].inline_cleanup == "accept"          # kept from the object dictionary
    assert rules[0].dynamic_layer is False and rules[0].inline_rules is not None   # not dynamic -> descended
    assert any(c[0] == "show-access-layer" for c in sess.calls)   # consulted for the dynamic-layer flag


def test_loader_cycle_guard_does_not_recurse_forever():
    # an inline layer whose rulebase re-applies itself -> the visited-uid guard stops the recursion
    objs = [{"uid": "L-LOOP", "type": "access-layer", "name": "LOOP"}]
    selfref = [_ap_rule("s", 1, "L-LOOP")]
    sess = _FakeSession({"LOOP": selfref, "topL": selfref}, objs=objs, cleanups={"L-LOOP": "drop"})
    rules = aa.load_layer(sess, "topL")        # must terminate
    assert rules[0].inline_rules is not None    # attached; the self-reference inside resolves to []
    assert rules[0].inline_rules[0].inline_rules == []   # the cycle was cut at the second encounter


# ---- a rule with a specific destination can't ALLOW an Any-destination request (no false "may permit") ----
def test_specific_dest_accept_not_flagged_as_possible_allow():
    # opaque ACCEPT (unresolvable service) with a SPECIFIC destination, request destination = Any.
    # A specific destination can never cover Any, so this rule can't "already permit" the request -> NO note.
    acc = _rule("r11", 11, "Accept", _host("10.1.1.222"), _host("10.9.9.9"), _app(opaque=True))
    d = aa.decide(AccessRequest(["10.1.1.222/32"], ["Any"], application="Facebook"), [acc, CLEANUP])
    assert d.outcome is Outcome.CREATE and not d.notes


def test_opaque_accept_that_could_cover_is_still_flagged():
    # request is NOT Any and the rule's src/dst are Any with an UNRESOLVABLE service -> the rule COULD
    # cover it, so it is still flagged "may already permit it" (we only suppress provable non-covers).
    acc = _rule("ra", 2, "Accept", ANY, ANY, ServiceSet(complex=True))
    acc.svc_unknown = True
    d = aa.decide(AccessRequest(["10.1.1.5/32"], ["8.8.8.8/32"], "tcp", "443"), [acc, CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 2")


def test_specific_dest_drop_vs_any_port_request_still_blocks_below():
    # a specific/approx-destination DROP overlapping an Any PORT request can block that subset, so it is
    # still noted + the new rule placed BELOW it. (The app carve-out is application-only; a port request
    # stays conservative — placing above a port-drop would grant the whole port, not a precise carve-out.)
    drop = _rule("r6", 6, "Drop", ANY, _host("172.16.0.1"), ServiceSet(any=True))
    drop.dst_approx = True
    d = aa.decide(AccessRequest(["10.1.1.222/32"], ["Any"], "tcp", "443"), [drop, CLEANUP])
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 6")


# ---- Dynamic Layers (sk182252) are managed out-of-band -> excluded from the engine entirely ----
def test_dynamic_layer_rule_is_excluded_from_decide():
    dyn = _inline("p1", 5, _net("10.1.0.0/24"), _host("172.16.5.10"), _tcp(443), [], name="dynamic_layer")
    dyn.dynamic_layer = True                                    # marked by the loader
    d = aa.decide(_req(), [dyn, CLEANUP])
    assert d.outcome is Outcome.CREATE and not d.notes and d.layer is None   # skipped, not descended/flagged


def _accept_any():
    return {"type": "access-rule", "uid": "x", "rule-number": 1, "name": "x", "enabled": True,
            "source": ["Any"], "destination": ["Any"], "service": ["Any"], "action": "Accept"}


def test_loader_excludes_dynamic_layer_from_object_dictionary():
    # the object dictionary marks the inline layer as a Dynamic Layer -> excluded: never pulled, no lookup
    objs = [{"uid": "L-DYN", "type": "access-layer", "name": "dynamic_layer", "dynamic-layer": True}]
    sess = _FakeSession({"dynamic_layer": [_accept_any()], "topL": [_ap_rule("p", 1, "L-DYN")]}, objs=objs)
    rules = aa.load_layer(sess, "topL")
    assert rules[0].dynamic_layer is True and rules[0].inline_rules is None
    assert not any(c[0] == "show-access-layer" for c in sess.calls)   # flag came from the object dictionary


def test_loader_excludes_dynamic_layer_via_lookup():
    # object dictionary lacks the flag (and the cleanup) -> the fallback lookup detects dynamic-layer
    objs = [{"uid": "L-DYN", "type": "access-layer", "name": "dynamic_layer"}]
    sess = _FakeSession({"dynamic_layer": [_accept_any()], "topL": [_ap_rule("p", 1, "L-DYN")]},
                        objs=objs, dynamics={"L-DYN": True})
    rules = aa.load_layer(sess, "topL")
    assert rules[0].dynamic_layer is True and rules[0].inline_rules is None
    assert ("show-access-layer", {"uid": "L-DYN"}) in sess.calls


def test_loader_detects_dynamic_layer_when_objdict_has_cleanup_but_not_flag():
    # the REALISTIC Check Point shape (adversarial-review finding): show-access-rulebase's object
    # dictionary carries the layer's implicit-cleanup-action but NOT the dynamic-layer flag (that flag is
    # ONLY on show-access-layer). The loader must STILL consult show-access-layer and detect + exclude it,
    # never descend into the out-of-band layer just because the cleanup happened to be in the dict.
    objs = [{"uid": "L-DYN", "type": "access-layer", "name": "dynamic_layer",
             "implicit-cleanup-action": "Drop"}]
    sess = _FakeSession({"dynamic_layer": [_accept_any()], "topL": [_ap_rule("p", 1, "L-DYN")]},
                        objs=objs, dynamics={"L-DYN": True})
    rules = aa.load_layer(sess, "topL")
    assert rules[0].dynamic_layer is True and rules[0].inline_rules is None   # detected despite objdict cleanup


def test_dynamic_divert_floors_placement_below_it():
    # adversarial-review finding: a dynamic-layer divert that INTERFERES must keep the new rule BELOW it
    # even when a more-specific rule sits above and there is NO catch-all cleanup floor — otherwise
    # first-match could serve the new allow ABOVE the divert and bypass the out-of-band segmentation.
    # uncertain_deny must drop the lower_anchor and force bottom placement.
    r1 = _rule("r1", 1, "Accept", _host("10.1.0.5"), _host("172.16.5.10"), _tcp(443))
    rd = _inline("rd", 5, ANY, _net("172.16.0.0/16"), ServiceSet(any=True), [], name="dynamic_layer")
    rd.dynamic_layer = True
    req = AccessRequest(src_cidrs=["10.1.0.0/24"], dst_cidrs=["172.16.0.0/16"], protocol="tcp", ports="443")
    d = aa.decide(req, [r1, rd])                       # no catch-all cleanup below the divert
    assert d.outcome is Outcome.CREATE
    assert d.position != {"below": "r1"}               # must NOT anchor ABOVE the divert
    assert d.position == {"_above_cleanup": True}      # forced to the bottom, below the divert


# ===== L7 application carve-out (find the BEST position to ACHIEVE an app request) + tunable knobs =====
def test_app_request_carves_out_above_an_L4_port_drop():
    # HIGH-bug fix: an application request blocked by a broad L4 port DROP must NOT read as NO_OP (the
    # gateway drops it today). The correct, precise outcome is CREATE the app-Accept ABOVE the L4 Drop.
    drop = _rule("r10", 10, "Drop", ANY, ANY, _tcp(443))
    allow = _rule("r20", 20, "Accept", ANY, ANY, ServiceSet(any=True))      # a lower Accept that used to win
    d = aa.decide(AccessRequest(["Any"], ["Any"], application="Facebook"), [drop, allow])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "r10"}   # carved out above the L4 Drop
    assert d.outcome is not Outcome.NO_OP


def test_app_carveout_off_places_below_and_does_not_false_noop():
    # carve-out OFF (conservative): place the new rule BELOW the blocking drop and STOP — it must NOT fall
    # through to the lower Accept and report a false NO_OP.
    drop = _rule("r10", 10, "Drop", ANY, ANY, _tcp(443))
    allow = _rule("r20", 20, "Accept", ANY, ANY, ServiceSet(any=True))
    d = aa.decide(AccessRequest(["Any"], ["Any"], application="Facebook"), [drop, allow],
                  aa.DecideOptions(app_carveout=False))
    assert d.outcome is Outcome.CREATE and d.position == {"below": "r10"}


def test_app_request_carves_out_above_an_opaque_category_drop():
    # an opaque app-category/group DROP can't be proven to contain the app, but a single-app Accept ABOVE
    # it is a harmless precise carve-out that achieves the request if the app IS in the category.
    cat = _rule("rc", 10, "Drop", ANY, ANY, _app(opaque=True))
    d = aa.decide(AccessRequest(["Any"], ["Any"], application="Facebook"), [cat, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "rc"}


def test_port_request_vs_app_plus_port_rule_still_noops():
    # lock-in (no regression from the L7 symmetry fix): a tcp/443 PORT request is genuinely covered by a
    # rule whose service is {Facebook + tcp443} on the port leg -> NO_OP (not a spurious carve-out/create).
    both = _rule("rb", 10, "Accept", ANY, ANY, ServiceSet(apps={"Facebook"}, by_proto={"tcp": [(443, 443)]}))
    d = aa.decide(AccessRequest(["10.1.1.0/24"], ["Any"], "tcp", "443"), [both, CLEANUP])
    assert d.outcome is Outcome.NO_OP


def test_prefer_widen_off_always_creates():
    r = _rule("rn", 6, "Accept", _net("10.2.0.0/24"), _host("172.16.5.10"), _tcp(443))
    req = AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443")
    assert aa.decide(req, [r, CLEANUP]).outcome is Outcome.WIDEN                       # default: reuse
    assert aa.decide(req, [r, CLEANUP], aa.DecideOptions(prefer_widen=False)).outcome is Outcome.CREATE


def test_emit_notes_off_is_quiet():
    op = _rule("ro", 2, "Accept", ANY, ANY, ServiceSet(complex=True))
    op.svc_unknown = True
    req = AccessRequest(["10.1.1.5/32"], ["8.8.8.8/32"], "tcp", "443")
    assert aa.decide(req, [op, CLEANUP]).notes                                         # default: noted
    assert not aa.decide(req, [op, CLEANUP], aa.DecideOptions(emit_notes=False)).notes  # quiet


def test_override_blocking_deny_off_places_below():
    # a resolved covering deny: default overrides by placing ABOVE; OFF -> place BELOW (don't override),
    # and STOP (no false NO_OP from a lower rule).
    deny = _rule("rd", 1, "Drop", _host("10.0.0.5"), _host("172.16.5.10"), _tcp(443))
    req = AccessRequest(["10.0.0.5/32"], ["172.16.5.10/32"], "tcp", "443")
    assert aa.decide(req, [deny, CLEANUP]).position == {"above": "rd"}                  # default: override
    d = aa.decide(req, [deny, CLEANUP], aa.DecideOptions(override_blocking_deny=False))
    assert d.outcome is Outcome.CREATE and d.position == {"below": "rd"}                # don't override


# --- behavior PROFILES bundle the knobs (one-click presets); custom falls back to the toggles -----
def test_decide_options_resolves_named_profiles(monkeypatch):
    from app.services import app_settings
    store = {}
    monkeypatch.setattr(app_settings, "get", lambda k: store.get(k))

    store["aa_profile"] = "balanced"                       # == the recommended defaults
    o = aa._decide_options()
    assert (o.app_carveout, o.override_blocking_deny, o.prefer_widen, o.emit_notes, o.ignore_conditions) \
        == (True, True, True, True, False)

    store["aa_profile"] = "conservative"                   # never modify/override; always create-below, flag
    o = aa._decide_options()
    assert (o.app_carveout, o.override_blocking_deny, o.prefer_widen, o.emit_notes, o.ignore_conditions) \
        == (False, False, False, True, False)

    store["aa_profile"] = "aggressive"                      # fewest rules, ignore conditions, notes ON
    o = aa._decide_options()
    assert o.prefer_widen and o.app_carveout and o.override_blocking_deny and o.ignore_conditions \
        and o.emit_notes

    store["aa_profile"] = "autopilot"                       # NOT a profile anymore -> falls through to the
    o = aa._decide_options()                                # Custom toggles (unset in this stub store -> all off)
    assert (o.app_carveout, o.override_blocking_deny, o.prefer_widen, o.emit_notes, o.ignore_conditions) \
        == (False, False, False, False, False)


def test_scoped_profile_overrides_global_by_specificity(monkeypatch):
    import types
    from app.services import app_settings
    store = {"aa_profile": "balanced"}
    monkeypatch.setattr(app_settings, "get", lambda k: store.get(k))
    srv = types.SimpleNamespace(id=7, name="HQ-SMS")

    store["aa_scope_overrides"] = (
        "Production = conservative\n"
        "*:DMZ = aggressive\n"
        "HQ-SMS:DNS_Layer = conservative\n"
        "# a comment line and a junk line\n"
        "garbage without equals\n")

    # exact server+layer wins -> conservative (never modify/override)
    c = aa._decide_options(srv, "DNS_Layer")
    assert not c.app_carveout and not c.override_blocking_deny and not c.ignore_conditions
    # *:DMZ matches the layer on any server -> aggressive (ignore conditions, notes ON)
    o = aa._decide_options(srv, "DMZ")
    assert o.ignore_conditions and o.emit_notes
    # server name match (by name) on a different server -> conservative
    prod = types.SimpleNamespace(id=9, name="Production")
    c = aa._decide_options(prod, "AnyLayer")
    assert not c.app_carveout and not c.override_blocking_deny and not c.prefer_widen
    # no scope match -> global profile (balanced)
    b = aa._decide_options(srv, "SomeOtherLayer")
    assert b.app_carveout and b.override_blocking_deny and b.prefer_widen and not b.ignore_conditions
    # server matched by ID also works
    store["aa_scope_overrides"] = "7 = conservative\n"
    assert not aa._decide_options(srv, "X").prefer_widen


def test_scoped_profile_layer_beats_server_on_collision(monkeypatch):
    # H1: when BOTH a bare-server line and a more-specific *:layer line match the SAME (server, layer), the
    # layer-scoped line must win — documented order is exact ▸ *:layer ▸ server. (Previously server-
    # specificity was weighted above layer-specificity, so the bare-server line wrongly won the tie.)
    import types
    from app.services import app_settings
    store = {"aa_scope_overrides": "Production = conservative\n*:DMZ = aggressive\n"}
    monkeypatch.setattr(app_settings, "get", lambda k: store.get(k))
    prod = types.SimpleNamespace(id=9, name="Production")
    assert aa._scoped_profile(app_settings, prod, "DMZ") == "aggressive"      # *:DMZ beats bare Production
    assert aa._scoped_profile(app_settings, prod, "Other") == "conservative"  # only the server line matches
    store["aa_scope_overrides"] = "Production:DMZ = balanced\n*:DMZ = aggressive\n"
    assert aa._scoped_profile(app_settings, prod, "DMZ") == "balanced"        # exact server:layer still wins


def test_decision_option_endpoint_toggles_and_switches_to_custom(monkeypatch):
    import types
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.db import get_db
    from app.routers import access_automation as aar
    from app.services import app_settings

    store, saved = {"aa_profile": "balanced"}, {}
    monkeypatch.setattr(app_settings, "get", lambda k: store.get(k))
    monkeypatch.setattr(app_settings, "save", lambda d: (saved.update(d), store.update(d)))
    app = FastAPI(); app.include_router(aar.router); app.dependency_overrides[get_db] = lambda: None
    c = TestClient(app)

    monkeypatch.setattr(aar, "get_user_or_none", lambda req, db: None)            # unauth -> 401
    assert c.post("/access-automation/decision-option",
                  json={"key": "aa_prefer_widen", "value": False}).status_code == 401

    monkeypatch.setattr(aar, "get_user_or_none", lambda req, db: types.SimpleNamespace(username="admin"))
    assert c.post("/access-automation/decision-option",
                  json={"key": "bogus", "value": True}).status_code == 400          # unknown key rejected
    r = c.post("/access-automation/decision-option", json={"key": "aa_prefer_widen", "value": False})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert saved["aa_prefer_widen"] is False and saved["aa_profile"] == "custom"     # toggle -> Custom profile


def test_decide_options_custom_uses_individual_toggles(monkeypatch):
    from app.services import app_settings
    store = {"aa_profile": "custom", "aa_app_carveout": False, "aa_override_blocking_deny": True,
             "aa_prefer_widen": False, "aa_emit_notes": True, "aa_ignore_conditions": True}
    monkeypatch.setattr(app_settings, "get", lambda k: store.get(k))
    o = aa._decide_options()
    assert (o.app_carveout, o.override_blocking_deny, o.prefer_widen, o.emit_notes, o.ignore_conditions) \
        == (False, True, False, True, True)


def test_choice_setting_coercion_fails_safe_to_default():
    from app.services import app_settings as A
    s = A._BY_KEY["aa_profile"]
    assert s.kind == "choice" and s.default == "balanced"
    assert A._coerce(s, "aggressive") == "aggressive"        # valid choice kept
    assert A._coerce(s, "nonsense") == "balanced"            # unknown value -> default (fail safe)
    assert A._coerce(s, None) == "balanced"


# ===== REMOVE-access engine (decide_removal — the inverse of decide) ==========================
def test_decide_removal_no_op_when_not_permitted():
    d = aa.decide_removal(AccessRequest(["10.5.5.5/32"], ["9.9.9.9/32"], "tcp", "443"), [WEB, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.NO_OP                       # nothing grants it -> nothing to remove


def test_decide_removal_already_denied_is_no_op():
    drop = _rule("rd", 1, "Drop", _host("10.1.2.250"), _host("1.1.1.1"), _app({"Facebook"}))
    d = aa.decide_removal(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [drop, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.NO_OP and d.target_rule.uid == "rd"


def test_decide_removal_disable_exact_rule():
    r = _rule("rx", 3, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"Facebook"}))
    d = aa.decide_removal(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [r, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DISABLE and d.target_rule.uid == "rx"   # rule is exactly this access


def test_decide_removal_deny_above_a_broader_rule():
    # the lab case: a broad Accept grants 10.1.2.0/24 -> Facebook; removing one host = least-privilege Drop above it
    r = _rule("r2", 2, "Accept", _net("10.1.2.0/24"), ANY, _app({"Facebook"}))
    d = aa.decide_removal(AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), [r, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DENY and d.position == {"above": "r2"}


def test_decide_removal_reviews_an_opaque_granting_rule():
    op = _rule("ro", 2, "Accept", ANY, ANY, ServiceSet(complex=True)); op.svc_unknown = True
    d = aa.decide_removal(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [op, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.REVIEW                      # can't reason past it -> don't guess


def test_execute_removal_disable_then_publish(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    rule = _rule("rx", 3, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"Facebook"}))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [rule, CLEANUP])
    res = aa.remove_execute(object(), "secret",
                            AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"),
                            "L", publish=True)
    assert res["outcome"] == "disable" and res["applied"] is True and res["published"] is True
    setr = next(p for c, p in calls if c == "set-access-rule")
    assert setr.get("enabled") is False and not any(c == "add-access-rule" for c, _ in calls)


def test_app_vs_netbios_drop_is_provably_disjoint():
    # the screenshot case: a "Sillent Drop" on NetBIOS / DHCP services can NEVER carry a web app, so it is
    # provably disjoint from a Facebook request — not "indeterminate". A real web-port drop still is.
    fb = _app({"Facebook"})
    nbt = ServiceSet(by_proto={"tcp": [(139, 139)], "udp": [(67, 68), (137, 138)]})   # nbsession + bootp + nbname/datagram
    assert aa._svc_indeterminate(fb, nbt) is False
    assert aa.svc_relation(fb, nbt) is Relation.DISJOINT
    web_drop = ServiceSet(by_proto={"tcp": [(443, 443)]})
    assert aa._svc_indeterminate(fb, web_drop) is True                 # 443 could carry the app -> still uncertain
    assert aa._svc_indeterminate(fb, ServiceSet(by_proto={"tcp": [(1, 65535)]})) is True   # broad range covers 443


def test_decide_removal_steps_over_netbios_silent_drop_to_no_op():
    # remove 10.1.2.250 -> Facebook with a NetBIOS "Sillent Drop" Any/Any in the path and NO rule granting
    # Facebook to that host -> the drop is irrelevant (can't carry a web app), so it's a clean NO_OP, not a
    # false REVIEW blamed on the silent drop. (Exactly the reported behaviour.)
    nbt = ServiceSet(by_proto={"tcp": [(139, 139)], "udp": [(67, 68), (137, 138)]})
    silent_drop = _rule("sd", 3, "Drop", ANY, ANY, nbt)
    win_fb = _rule("r2", 2, "Accept", _host("10.1.2.10"), ANY, _app({"Facebook"}))   # grants another host, not us
    req = AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook")
    d = aa.decide_removal(req, [win_fb, silent_drop, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.NO_OP


def test_decide_removal_finds_grant_below_a_netbios_drop():
    # if the granting Facebook accept sits BELOW the NetBIOS drop, the walk must step over the (disjoint)
    # drop and act on the real grant — not stop at the drop with REVIEW.
    nbt = ServiceSet(by_proto={"tcp": [(139, 139)], "udp": [(137, 138)]})
    silent_drop = _rule("sd", 3, "Drop", ANY, ANY, nbt)
    fb_grant = _rule("r9", 9, "Accept", _host("10.1.2.250"), ANY, _app({"Facebook"}))
    req = AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook")
    d = aa.decide_removal(req, [silent_drop, fb_grant, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DISABLE and d.target_rule.uid == "r9"


def test_decide_removal_reviews_when_app_meets_a_web_port_drop():
    # a DROP on a web port (443) genuinely could carry the app -> we can't prove it disjoint -> REVIEW stands
    # (don't guess a destructive change past a possible block). The narrowing must not lose this safety.
    web_drop = _rule("wd", 3, "Drop", ANY, ANY, ServiceSet(by_proto={"tcp": [(443, 443)]}))
    req = AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook")
    d = aa.decide_removal(req, [web_drop, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.REVIEW


def test_decide_removal_approx_exact_falls_back_to_deny():
    # the rule's source resolves to a gateway's MAIN ip (reads EQUAL to the /32) but its true reach may be
    # wider (multi-homed under-approximation) -> disabling the whole rule would over-remove the unseen
    # addresses; the safe move is a precise Drop-above for exactly this flow.
    r = _rule("rx", 3, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"Facebook"}))
    r.src_approx = True
    d = aa.decide_removal(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [r, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DENY and d.position == {"above": "rx"}


def test_decide_removal_exact_but_regranted_below_falls_back_to_deny():
    # rx grants EXACTLY this, but a broader Accept BELOW also grants it -> disabling rx alone would let
    # first-match fall through and the access would SURVIVE (under-removal). Drop-above rx removes it regardless.
    rx = _rule("rx", 3, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"Facebook"}))
    broad = _rule("rb", 4, "Accept", _net("10.1.2.0/24"), _host("1.1.1.1"), _app({"Facebook"}))
    d = aa.decide_removal(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"),
                          [rx, broad, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DENY and d.position == {"above": "rx"}


def test_decide_removal_exact_disables_despite_unrelated_accept_below():
    # a DIFFERENT accept below rx (disjoint destination) does NOT re-grant THIS flow -> rx is the sole
    # granter -> DISABLE stays safe (the under-removal guard must not over-trigger on disjoint rules).
    rx = _rule("rx", 3, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"Facebook"}))
    other = _rule("ro", 4, "Accept", _host("10.1.2.250"), _host("2.2.2.2"), _app({"Facebook"}))
    d = aa.decide_removal(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"),
                          [rx, other, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DISABLE and d.target_rule.uid == "rx"


def test_decide_removal_disable_blocked_by_dynamic_layer_below_falls_back_to_deny():
    # an exact-match ACCEPT, but a Dynamic Layer (sk182252 "Apply Layer") COVERING the request sits BELOW it.
    # Disabling the ACCEPT would expose the dynamic layer, whose out-of-band sub-rulebase (invisible to us)
    # MAY still grant the flow -> a silent UNDER-removal. The walk must fall back to the safe Drop-above.
    exact = _rule("ex", 1, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _tcp(443))
    dyn = _rule("dl", 2, "Accept", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True))
    dyn.dynamic_layer = True
    req = AccessRequest(["10.0.0.5/32"], ["1.1.1.1/32"], "tcp", "443")
    d = aa.decide_removal(req, [exact, dyn, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DENY and d.position == {"above": "ex"}


def test_decide_removal_disables_past_a_disjoint_dynamic_layer_below():
    # a Dynamic Layer below that is PROVABLY disjoint (different source/destination) can't re-grant THIS flow
    # -> the exact ACCEPT is still the sole granter -> DISABLE stays safe (the dyn-layer guard must not over-fire).
    exact = _rule("ex", 1, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _tcp(443))
    dyn = _rule("dl", 2, "Accept", _net("192.168.0.0/24"), _host("2.2.2.2"), ServiceSet(any=True))
    dyn.dynamic_layer = True
    req = AccessRequest(["10.0.0.5/32"], ["1.1.1.1/32"], "tcp", "443")
    d = aa.decide_removal(req, [exact, dyn, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DISABLE and d.target_rule.uid == "ex"


def test_decide_removal_skips_a_dynamic_layer_to_reach_the_real_grant():
    # GOLDEN RULE: a dynamic-layer rule in the path is SKIPPED from matching (out-of-band, Gaia-managed). The
    # walk looks PAST it to the real management-visible grant and acts on that — never bails to REVIEW.
    dyn = _rule("dl", 1, "Accept", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True))
    dyn.dynamic_layer = True
    grant = _rule("g", 2, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _tcp(443))
    req = AccessRequest(["10.0.0.5/32"], ["1.1.1.1/32"], "tcp", "443")
    d = aa.decide_removal(req, [dyn, grant, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DISABLE and d.target_rule.uid == "g"


def test_decide_removal_dynamic_layer_only_is_not_a_review():
    # a dynamic layer covering the request, with NO management grant below -> skipped -> NO_OP (nothing in
    # the MANAGEMENT policy grants it; the dynamic layer is the user's out-of-band Gaia concern), never REVIEW.
    dyn = _rule("dl", 1, "Accept", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True))
    dyn.dynamic_layer = True
    req = AccessRequest(["10.0.0.5/32"], ["1.1.1.1/32"], "tcp", "443")
    assert aa.decide_removal(req, [dyn, CLEANUP]).outcome is aa.RemovalOutcome.NO_OP


def test_decide_removal_conditional_drop_never_asserts_full_deny_under_ignore_conditions():
    # M3: with ignore_conditions ON (the Aggressive profile), a conditional DROP must NOT terminate the removal
    # walk as a full deny — it only blocks UNDER its condition, so a broad ACCEPT below still grants the flow
    # when the condition is unmet. The honest, safe answer is REVIEW (don't claim "already denied / removed").
    cond_drop = _rule("cd", 1, "Drop", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True),
                      conditions=("VPN community",))
    broad = _rule("ba", 2, "Accept", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True))
    req = AccessRequest(["10.0.0.5/32"], ["1.1.1.1/32"], "tcp", "443")
    opt = aa.DecideOptions(ignore_conditions=True)
    assert aa.decide_removal(req, [cond_drop, broad, CLEANUP], opt).outcome is aa.RemovalOutcome.REVIEW


def test_decide_removal_disable_not_chosen_when_conditional_drop_below_under_ignore_conditions():
    # the _still_granted_below mirror: an exact ACCEPT with a conditional DROP (then a broad ACCEPT) below it,
    # ignore_conditions ON -> the conditional drop can't prove the flow is denied -> DENY-above, not DISABLE.
    exact = _rule("ex", 1, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _tcp(443))
    cond_drop = _rule("cd", 2, "Drop", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True),
                      conditions=("VPN community",))
    broad = _rule("ba", 3, "Accept", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True))
    req = AccessRequest(["10.0.0.5/32"], ["1.1.1.1/32"], "tcp", "443")
    opt = aa.DecideOptions(ignore_conditions=True)
    d = aa.decide_removal(req, [exact, cond_drop, broad, CLEANUP], opt)
    assert d.outcome is aa.RemovalOutcome.DENY and d.position == {"above": "ex"}


def test_decide_removal_disable_blocked_by_opaque_rule_below_falls_back_to_deny():
    # L10: pins the safety hinge — an exact ACCEPT with an UNRESOLVABLE rule (opaque service) in the path
    # BELOW it. _still_granted_below can't prove the flow is denied past it, so the reversible DISABLE is
    # NOT chosen -> the always-safe Drop-above (DENY).
    exact = _rule("ex", 1, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _tcp(443))
    opaque = _rule("op", 2, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), ServiceSet(complex=True))
    opaque.svc_unknown = True
    req = AccessRequest(["10.0.0.5/32"], ["1.1.1.1/32"], "tcp", "443")
    d = aa.decide_removal(req, [exact, opaque, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DENY and d.position == {"above": "ex"}


def test_decide_removal_disables_despite_an_unrelated_gateway_http_accept_below():
    # The reported false-positive: removing 10.1.2.250 -> Facebook with the SINGLE granting Accept, plus an
    # unrelated "CP Updates" accept below — a gateway source resolved to its main IP (approx) on http/https.
    # That is NOT a PROVABLE re-grant of the app (resolved-disjoint on service; only an approx + App-Control
    # caveat makes it "interfere"), so it must NOT force a Drop-above — the engine cleanly DISABLEs the one
    # rule that grants it.
    exact = _rule("ex", 4, "Accept", _host("10.1.2.250"), ANY, _app({"Facebook"}))
    cpupd = _rule("cu", 6, "Accept", _host("10.1.2.1"), ANY, _tcp("80,443"))   # gateway-ish -> http/https
    cpupd.src_approx = True
    req = AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook")
    d = aa.decide_removal(req, [exact, cpupd, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DISABLE and d.target_rule.uid == "ex"


# ===== Rollback / undo: each applied change records its exact INVERSE op-list =====================
def test_execute_create_records_inverse_delete(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"),
                     "Network", publish=True)
    assert res["outcome"] == "create" and res["created_uid"]
    assert res["inverse"] == [{"op": "delete-access-rule", "uid": res["created_uid"], "layer": "Network"}]


def test_execute_widen_records_inverse_remove(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"),
                     "Network", publish=True)
    assert res["outcome"] == "widen"
    assert res["inverse"] == [{"op": "set-access-rule", "uid": "r8", "layer": "Network",
                               "field": "source", "remove": "h-192-168-9-9"}]


def test_remove_disable_records_inverse_reenable(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    rule = _rule("rx", 3, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"Facebook"}))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [rule, CLEANUP])
    res = aa.remove_execute(object(), "secret",
                            AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"),
                            "L", publish=True)
    assert res["outcome"] == "disable"
    assert res["inverse"] == [{"op": "set-access-rule", "uid": "rx", "layer": "L", "enabled": True}]


def test_remove_deny_records_inverse_delete(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    broad = _rule("r2", 2, "Accept", _net("10.1.2.0/24"), ANY, _app({"Facebook"}))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [broad, CLEANUP])
    res = aa.remove_execute(object(), "secret",
                            AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"),
                            "L", publish=True)
    assert res["outcome"] == "deny" and res["created_uid"]
    assert res["inverse"] == [{"op": "delete-access-rule", "uid": res["created_uid"], "layer": "L"}]


def test_revert_execute_replays_each_op_kind_and_publishes(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    ops = [{"op": "delete-access-rule", "uid": "u1", "layer": "L"},
           {"op": "set-access-rule", "uid": "u2", "layer": "L", "enabled": True},
           {"op": "set-access-rule", "uid": "u3", "layer": "L", "field": "source", "remove": "h-x"}]
    res = aa.revert_execute(object(), "secret", ops, publish=True)
    assert res["ok"] and res["reverted"] is True
    assert ("delete-access-rule", {"uid": "u1", "layer": "L"}) in calls
    assert ("set-access-rule", {"uid": "u2", "layer": "L", "enabled": True}) in calls
    assert ("set-access-rule", {"uid": "u3", "layer": "L", "source": {"remove": "h-x"}}) in calls
    assert ("publish", {}) in calls and ("discard", {}) not in calls


def test_revert_execute_dry_run_discards(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    res = aa.revert_execute(object(), "secret",
                            [{"op": "delete-access-rule", "uid": "u1", "layer": "L"}], publish=False)
    assert res["ok"] and res["reverted"] is False and res["validated"] is True
    cmds = [c for c, _ in calls]
    assert "delete-access-rule" in cmds and "discard" in cmds and "publish" not in cmds


def test_revert_execute_rejects_unknown_op_and_discards(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    res = aa.revert_execute(object(), "secret",
                            [{"op": "add-host", "uid": "u1", "layer": "L"}], publish=True)
    assert res["ok"] is False and "unsupported" in res["error"]
    cmds = [c for c, _ in calls]
    assert "add-host" not in cmds and "publish" not in cmds and "discard" in cmds


def test_revert_execute_no_inverse_is_an_error():
    res = aa.revert_execute(object(), "secret", [], publish=True)
    assert res["ok"] is False and "inverse" in res["error"]


class _GoneSession:
    """A write session whose rule edits all fail 'not found' — models a rule deleted out-of-band."""
    def __init__(self, *a, **k):
        self.trace = []
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def call(self, cmd, payload=None, **k):
        if cmd in ("delete-access-rule", "set-access-rule"):
            raise aa.MgmtError("Requested object [Entities can not be found] not found")
        return {}
    def publish(self):
        pass
    def discard(self):
        pass


def test_revert_execute_idempotent_when_rule_gone_out_of_band(monkeypatch):
    # the reported case: the rule the rollback targets was deleted out-of-band -> the web_api errors
    # 'not found'. The rollback's intent (that rule absent) is ALREADY met, so it succeeds, not stuck.
    monkeypatch.setattr(aa, "MgmtSession", _GoneSession)
    r1 = aa.revert_execute(object(), "secret", [{"op": "delete-access-rule", "uid": "gone", "layer": "L"}], publish=True)
    assert r1["ok"] and r1["reverted"] is True and any("already absent" in o for o in r1["ops"])
    # re-enabling a rule that no longer exists is likewise moot -> success (nothing to undo)
    r2 = aa.revert_execute(object(), "secret",
                           [{"op": "set-access-rule", "uid": "gone", "layer": "L", "enabled": True}], publish=True)
    assert r2["ok"] and r2["reverted"] is True


def test_revert_execute_real_error_still_fails(monkeypatch):
    # a genuine (non-not-found) error must NOT be swallowed by the idempotent-missing handling.
    class _RejectSession(_GoneSession):
        def call(self, cmd, payload=None, **k):
            if cmd == "delete-access-rule":
                raise aa.MgmtError("server rejected the change: invalid payload")
            return {}
    monkeypatch.setattr(aa, "MgmtSession", _RejectSession)
    res = aa.revert_execute(object(), "secret", [{"op": "delete-access-rule", "uid": "u", "layer": "L"}], publish=True)
    assert res["ok"] is False and "rejected" in res["error"]


def test_revert_execute_disable_mode_maps_delete_to_disable(monkeypatch):
    # Check Point lets a rule be disabled instead of deleted -> the gentler, reversible undo. With
    # disable_added_rules, a delete-access-rule inverse becomes set-access-rule enabled=false; the
    # widen-remove (and re-enable) inverses are untouched.
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    ops = [{"op": "delete-access-rule", "uid": "u1", "layer": "L"},
           {"op": "set-access-rule", "uid": "u2", "layer": "L", "field": "source", "remove": "h-x"}]
    res = aa.revert_execute(object(), "secret", ops, publish=True, disable_added_rules=True)
    assert res["ok"] and res["mode"] == "disable"
    assert ("set-access-rule", {"uid": "u1", "layer": "L", "enabled": False}) in calls   # delete -> disable
    assert not any(c == "delete-access-rule" for c, _ in calls)                          # never deleted
    assert ("set-access-rule", {"uid": "u2", "layer": "L", "source": {"remove": "h-x"}}) in calls  # untouched


# ===== services-group / named-service request must MATCH dereferenced rule cells (DNS-layer miss) =====
def test_services_group_request_descends_into_matching_inline_layer():
    # a 'dns' services-group request, expanded by correlation to its member ports, matches a rule that
    # applies a DNS inline layer for the same group -> the engine DESCENDS and creates the rule INSIDE the
    # layer (above its cleanup), NOT a shadowed top-level rule below the divert. (The live-lab failure.)
    dns_ports = ServiceSet(by_proto={"tcp": [(53, 53)], "udp": [(53, 53)]})
    inner = [
        _rule("d1", 1, "Accept", _host("10.1.1.50"), _host("172.16.5.10"), ServiceSet(any=True)),
        _rule("d2", 2, "Accept", _host("10.1.1.222"), _host("8.8.8.8"), ServiceSet(any=True)),
        _rule("d3", 3, "Drop", ANY, ANY, ServiceSet(any=True)),               # the layer's cleanup
    ]
    rule7 = _inline("p7", 7, ANY, ANY, dns_ports, inner, name="DNS_Layer")
    req = AccessRequest(["10.1.1.222/32"], ["Any"])
    req.svc_set = dns_ports                                                   # as correlation expands "dns"
    d = aa.decide(req, [rule7, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.layer == "DNS_Layer"             # created INSIDE the DNS layer

    # without the expansion (the OLD coarse named token) it would NOT descend -> shadowed top-level rule
    named = AccessRequest(["10.1.1.222/32"], ["Any"]); named.service = "dns"; named.service_kind = "group"
    assert aa.decide(named, [rule7, CLEANUP]).layer is None


class _SvcSession:
    def __init__(self, group=None, svc=None): self.group, self.svc = group, svc
    def call(self, cmd, payload):
        if cmd == "show-service-group": return self.group or {}
        if cmd.startswith("show-service-"): return self.svc or {}
        return {}


def test_expand_request_service_group_to_member_ports():
    g = {"uid": "g-dns", "name": "dns", "members": [
        {"uid": "u1", "type": "service-udp", "name": "domain-udp", "port": "53"},
        {"uid": "u2", "type": "service-tcp", "name": "domain-tcp", "port": "53"}]}
    sset = aa._expand_request_service(_SvcSession(group=g), "dns", "group")
    assert sset.by_proto.get("tcp") and sset.by_proto.get("udp") and "g-dns" in sset.group_uids


def test_expand_request_service_tcp_to_port():
    s = {"uid": "s1", "name": "https", "port": "443"}
    sset = aa._expand_request_service(_SvcSession(svc=s), "https", "tcp")
    assert sset.by_proto.get("tcp") == [(443, 443)]


def test_expand_request_service_portless_keeps_named():
    # icmp / other / rpc … already match by name on both sides -> no expansion (returns None)
    assert aa._expand_request_service(_SvcSession(), "echo-request", "icmp") is None


# ================= regression tests for the 2026-06-22 comprehensive audit =================
# [1 BLOCKER] inline layer: an explicit bottom DROP must not be masked into NO_OP by implicit-accept
def test_inline_explicit_drop_not_masked_by_implicit_accept():
    sub = [_rule("i1", 1, "Accept", _host("10.1.0.9"), _host("8.8.8.8"), _tcp(22)), CLEANUP]
    parent = _inline("p1", 5, _net("10.1.0.0/24"), _host("172.16.5.10"), _tcp(443), sub,
                     cleanup="accept", name="L")
    d = aa.decide(_req(), [parent, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.layer == "L" and "explicit" in d.reason


# [2 BLOCKER] a group / service-group with NO members key is extent-unknown -> REVIEW, never disjoint
def test_members_less_group_routes_to_review():
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "g": {"uid": "g", "type": "group", "name": "blocked"},          # no 'members'
          "drp": {"uid": "drp", "name": "Drop"}}
    rules = [_irule(1, ["any"], ["g"], ["any"], "drp", od), _irule(2, ["any"], ["any"], ["any"], "drp", od)]
    assert rules[0].dst_unknown and rules[0].complex
    req = AccessRequest(src_cidrs=["10.9.9.9/32"], dst_cidrs=["10.5.5.5/32"], protocol="tcp", ports="443")
    # an unenumerable-member DROP could block -> noted + continue, the new allow is forced BELOW it (bottom)
    # so it can never override the possible block. Outcome CREATE, not a hard REVIEW.
    d = aa.decide(req, rules)
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 1", "block")


def test_explicitly_empty_group_stays_disjoint():
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "g": {"uid": "g", "type": "group", "name": "empty", "members": []},
          "drp": {"uid": "drp", "name": "Drop"}}
    r = _irule(1, ["any"], ["g"], ["any"], "drp", od)
    assert not r.complex and not r.dst_unknown          # a real empty set, not "unknown"


def test_members_less_service_group_routes_to_review():
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "sg": {"uid": "sg", "type": "service-group", "name": "blocked-svcs"},   # no 'members'
          "drp": {"uid": "drp", "name": "Drop"}}
    rules = [_irule(1, ["any"], ["any"], ["sg"], "drp", od), _irule(2, ["any"], ["any"], ["any"], "drp", od)]
    assert rules[0].svc.complex
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["Any"], protocol="tcp", ports="443")
    d = aa.decide(req, rules)   # unenumerable-service DROP -> noted + continue + CREATE below it (safe)
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 1", "block")


# [3 BLOCKER] a rulebase larger than max_rules must FAIL LOUD, never decide on a truncated view
def test_pull_items_fails_loud_on_truncation():
    class _Trunc:
        def call(self, cmd, payload):
            off = payload.get("offset", 0)
            return {"rulebase": [{"type": "access-rule", "uid": f"r{off}"}],
                    "objects-dictionary": [], "total": 200, "to": off + 1}
    with pytest.raises(aa.MgmtError):
        aa._pull_items(_Trunc(), "big-layer", None, max_rules=5)


# [3b CRITICAL regression] a SECTIONED layer (the standard "Network" layer) wraps its rules in sections,
# so the TOP-LEVEL rulebase has far fewer items than the rule `total`. The truncation guard must compare
# total to the CAP, not to len(top-level items) — else every sectioned layer falsely "over the cap".
def test_pull_items_sectioned_layer_not_falsely_truncated():
    rules = [{"type": "access-rule", "uid": f"r{i}", "rule-number": i, "name": f"r{i}", "enabled": True,
              "source": ["Any"], "destination": ["Any"], "service": ["Any"], "action": "Accept"}
             for i in range(1, 14)]                       # 13 rules
    section = {"type": "access-section", "uid": "sec", "name": "Section A", "rulebase": rules}

    class _Sectioned:                                     # one page: a single section that wraps all 13
        def call(self, cmd, payload):
            return {"rulebase": [section], "objects-dictionary": [], "total": 13, "to": 13}

    items, _ = aa._pull_items(_Sectioned(), "Network", None)   # must NOT raise (13 << cap)
    flat = [e for e in aa._flatten(items) if e.get("type") == "access-rule"]
    assert len(flat) == 13                                # all rules recovered from inside the section


# [4 MAJOR] WIDEN must not use an approx (under-approximated infra) cell as its EQUAL guard
def test_widen_excludes_approx_equal_dimension():
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "gw": {"uid": "gw", "type": "simple-gateway", "name": "gw", "ipv4-address": "10.0.0.1"},
          "h": {"uid": "h", "type": "host", "name": "h", "ipv4-address": "172.16.5.10"},
          "t443": {"uid": "t443", "type": "service-tcp", "name": "https", "port": "443"},
          "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"}}
    rules = [_irule(1, ["gw"], ["h"], ["t443"], "acc", od), _irule(2, ["any"], ["any"], ["any"], "drp", od)]
    assert rules[0].src_approx
    req = AccessRequest(src_cidrs=["10.0.0.1/32"], dst_cidrs=["172.16.99.99/32"], protocol="tcp", ports="443")
    assert aa.decide(req, rules).outcome is Outcome.CREATE     # approx src can't serve as EQUAL -> no widen


# [5 MAJOR] a malformed IP in the object dictionary degrades that cell to REVIEW, never crashes the pull
def test_malformed_ip_object_degrades_not_crashes():
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "bad": {"uid": "bad", "type": "host", "name": "bad", "ipv4-address": "10.0.0.300"},
          "acc": {"uid": "acc", "name": "Accept"}}
    r = _irule(1, ["bad"], ["any"], ["any"], "acc", od)        # must not raise
    assert r.complex and r.src_unknown


# [9 MAJOR] 0.0.0.0/0 and ::/0 are single-family networks, NOT the dual-family predefined Any
def test_norm_endpoint_zero_route_is_per_family_not_any():
    assert tk._norm_endpoint("0.0.0.0/0") == "0.0.0.0/0"
    assert tk._norm_endpoint("::/0") == "::/0"
    assert tk._norm_endpoint("any") == "Any" and tk._norm_endpoint("*") == "Any"
    assert tk.build_request("0.0.0.0/0", "10.0.0.5", "tcp", "443").src_cidrs == ["0.0.0.0/0"]


# [10 MAJOR] a non-MgmtError raised during apply must still DISCARD (no leaked locks) + report cleanly
def test_apply_non_mgmt_error_discards_and_reports(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    monkeypatch.setattr(aa, "_apply", lambda *a, **k: (_ for _ in ()).throw(ValueError("kaboom")))
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"),
                     "Net", publish=True)
    assert res["ok"] is False and "apply failed" in res["error"]
    assert ("discard", {}) in calls and ("publish", {}) not in calls


# [11 MINOR] inline-layer placement renders against the inline rulebase, so the anchor resolves
def test_rules_for_layer_resolves_inline_anchor():
    inner = [_rule("inner1", 1, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _tcp(22))]
    parent = _inline("p1", 5, _net("10.0.0.0/24"), _host("1.1.1.1"), _tcp(22), inner, name="InnerL")
    dec = aa.Decision(Outcome.CREATE, "x", layer="InnerL", position={"below": "inner1"})
    picked = aa._rules_for_layer(dec, [parent, CLEANUP])
    assert [r.uid for r in picked] == ["inner1"]            # the inline layer's own rules, not the top
    assert "inner1" in aa._position_human(dec.position, picked)


# [12/13 MINOR] _validate_port normalises and rejects dirty/zero ports
def test_validate_port_normalises_and_rejects_dirty():
    assert tk._validate_port("443") == "443"
    assert tk._validate_port("8000- 8100") == "8000-8100"
    for bad in ("+443", "4 43", "٤٤٣", "0", "8000- ", "-5"):
        with pytest.raises(ValueError):
            tk._validate_port(bad)
    with pytest.raises(ValueError):
        tk._validate_port(0)                                   # int 0 not swallowed by truthiness


# [15 MINOR] _apply fails loud on a multi-CIDR request instead of silently applying only the first
def test_apply_rejects_multi_cidr():
    s = _fake_session_factory([])(object(), "x")
    dec = aa.Decision(Outcome.CREATE, "x", position={"above": "rC"})
    req = AccessRequest(["10.0.0.0/24", "10.1.0.0/24"], ["1.1.1.1/32"], "tcp", "443")
    with pytest.raises(aa.MgmtError):
        aa._apply(s, dec, req, "Net", [CLEANUP], "TKT")


# ============ reducer #3: resolve dynamic extents — wildcard + group-with-exclusion ============
def test_wildcard_resolves_to_exact_member_set():
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "wc": {"uid": "wc", "type": "wildcard", "name": "odd-hosts",
                 "ipv4-address": "10.0.0.1", "ipv4-mask-wildcard": "0.0.0.6"},   # bits 1,2 free -> .1/.3/.5/.7
          "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"}}
    r = _irule(1, ["wc"], ["any"], ["any"], "acc", od)
    assert not r.complex
    assert {lo for lo, hi in r.src} == {aa._ip_int(x) for x in ("10.0.0.1", "10.0.0.3", "10.0.0.5", "10.0.0.7")}
    assert all(lo == hi for lo, hi in r.src)
    rules = [r, _irule(2, ["any"], ["any"], ["any"], "drp", od)]
    assert aa.decide(AccessRequest(["10.0.0.5/32"], ["Any"], "tcp", "443"), rules).outcome is Outcome.NO_OP
    assert aa.decide(AccessRequest(["10.0.0.4/32"], ["Any"], "tcp", "443"), rules).outcome is Outcome.CREATE  # not a member


def test_wildcard_over_cap_stays_opaque_review():
    # a mask with many SCATTERED free bits (255.255.0.255 -> 16 disjoint ranges) exceeds the cap -> opaque
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "wcb": {"uid": "wcb", "type": "wildcard", "name": "big",
                  "ipv4-address": "10.0.0.0", "ipv4-mask-wildcard": "255.255.0.255"},
          "drp": {"uid": "drp", "name": "Drop"}}
    r = _irule(1, ["wcb"], ["any"], ["any"], "drp", od)
    assert r.complex                                   # over-cap -> kept opaque (never an over-approximation)
    rules = [r, _irule(2, ["any"], ["any"], ["any"], "drp", od)]
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["Any"], "tcp", "443"), rules)   # opaque DROP -> note + CREATE below
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 1", "block")


def test_group_with_exclusion_resolves_include_minus_except():
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "ninc": {"uid": "ninc", "type": "network", "name": "dmz", "subnet4": "10.0.0.0", "mask-length4": 24},
          "nexc": {"uid": "nexc", "type": "network", "name": "block", "subnet4": "10.0.0.128", "mask-length4": 25},
          "gwe": {"uid": "gwe", "type": "group-with-exclusion", "name": "dmz-except", "include": "ninc", "except": "nexc"},
          "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"}}
    r = _irule(1, ["gwe"], ["any"], ["any"], "acc", od)
    assert not r.complex
    assert r.src == [(aa._ip_int("10.0.0.0"), aa._ip_int("10.0.0.127"))]   # include ∖ except, exactly
    rules = [r, _irule(2, ["any"], ["any"], ["any"], "drp", od)]
    assert aa.decide(AccessRequest(["10.0.0.5/32"], ["Any"], "tcp", "443"), rules).outcome is Outcome.NO_OP
    assert aa.decide(AccessRequest(["10.0.0.200/32"], ["Any"], "tcp", "443"), rules).outcome is Outcome.CREATE  # excluded


def test_group_with_exclusion_inexact_except_stays_opaque():
    # an 'except' that's only an under-approximation (a gateway resolved to its main IP) could OVER-state
    # include∖except -> must stay opaque (REVIEW), never subtract.
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "ninc": {"uid": "ninc", "type": "network", "name": "dmz", "subnet4": "10.0.0.0", "mask-length4": 24},
          "gw": {"uid": "gw", "type": "simple-gateway", "name": "gw", "ipv4-address": "10.0.0.130"},  # approx
          "gwe": {"uid": "gwe", "type": "group-with-exclusion", "name": "x", "include": "ninc", "except": "gw"},
          "acc": {"uid": "acc", "name": "Accept"}}
    r = _irule(1, ["gwe"], ["any"], ["any"], "acc", od)
    assert r.complex


# ============ API/webhook: unknown service -> suggestions, never a wrong SMS call ============
def test_obj_review_surfaces_top_level_suggestions():
    unresolved = {"term": "echoo", "match": None, "note": "",
                  "candidates": [{"name": "echo-request"}, {"name": "echo-reply"}]}
    out = aa._obj_review({"svc_resolution": unresolved}, unresolved, "service", {})
    assert out["outcome"] == "review" and out["unresolved"] == "service"
    assert out["suggestions"] == ["echo-request", "echo-reply"]            # top-level, API-friendly
    assert "did you mean: echo-request, echo-reply?" in out["reason"]
    assert out["svc_resolution"]["candidates"]                            # nested copy still there (portal chips)
    # no candidates -> fall back to the note, empty suggestions
    nc = {"term": "zzz", "match": None, "candidates": [], "note": "No Check Point service matches “zzz”."}
    out2 = aa._obj_review({"svc_resolution": nc}, nc, "service", {})
    assert out2["suggestions"] == [] and "No Check Point service" in out2["reason"]


def test_execute_unknown_service_reviews_without_writing_to_sms(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.1.222/32"], ["Any"], service="totally-unknown-svc"),
                     "Net", publish=True)
    assert res["outcome"] == "review" and res["applied"] is False and res["published"] is False
    assert "did you mean" in res["reason"] or "No Check Point" in res["reason"]
    assert "suggestions" in res                                           # always present for the caller
    assert not any(c[0] in ("add-access-rule", "add-service-tcp", "add-host", "publish") for c in calls)


# ============ read-only policy analysis (MCP analyze tools) ============
def test_summarize_rules_counts():
    s = aa.summarize_rules([WEB, DENY_DB, CLEANUP])      # accept, specific drop, Any/Any/Any drop
    assert s["total_rules"] == 3 and s["enabled"] == 3
    assert s["accept"] == 1 and s["drop_or_reject"] == 2
    assert s["any_service"] == 1 and s["has_cleanup_drop"] is True


def test_find_shadowed_flags_covered_rule():
    broad = _rule("rb", 1, "Accept", _net("10.0.0.0/8"), ANY, ServiceSet(any=True))
    narrow = _rule("rn", 2, "Accept", _host("10.1.2.3"), _host("1.1.1.1"), _tcp(443))   # ⊆ broad on all dims
    other = _rule("ro", 3, "Accept", _host("192.168.5.5"), _host("1.1.1.1"), _tcp(22))  # not covered
    sh = aa.find_shadowed([broad, narrow, other])
    assert [x["rule"] for x in sh] == [2] and sh[0]["shadowed_by"] == 1


def test_find_shadowed_is_conservative_on_app_service():
    # an app-service rule must NOT be falsely reported as shadowed by a port rule (can't prove coverage)
    broad = _rule("rb", 1, "Accept", ANY, ANY, _tcp("1-65535"))
    appr = _rule("ra", 2, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _app(["Facebook"]))
    assert aa.find_shadowed([broad, appr]) == []


def test_find_permissive_flags_any_dimensions():
    wide = _rule("rw", 1, "Accept", ANY, _host("1.1.1.1"), _tcp(443))      # Any source
    perm = aa.find_permissive([WEB, wide, CLEANUP])
    assert [p["rule"] for p in perm] == [1] and perm[0]["any_dimensions"] == ["source"]
    # CLEANUP is a Drop -> never flagged as a permissive accept
    assert all(p["rule"] != 99 for p in perm)


# ============================================================================================= #
# Typed (non-IP) source/destination framework — domain / access-role / dynamic / updatable / zone
# ============================================================================================= #
_TYPED_OD = {
    "any":   {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "dom":   {"uid": "dom", "type": "dns-domain", "name": ".alshawwaf.ca"},      # domain + sub-domains
    "domx":  {"uid": "domx", "type": "dns-domain", "name": ".evil.com"},
    "role":  {"uid": "role", "type": "access-role", "name": "Finance_Users"},
    "dyn":   {"uid": "dyn", "type": "dynamic-object", "name": "DObj_App"},
    "upd":   {"uid": "upd", "type": "updatable-object", "name": "Office365"},
    "zone":  {"uid": "zone", "type": "security-zone", "name": "InternalZone"},
    "dmz":   {"uid": "dmz", "type": "network", "name": "dmz", "subnet4": "172.16.5.0", "mask-length4": 24},
    "h222":  {"uid": "h222", "type": "host", "name": "cli", "ipv4-address": "10.1.1.222"},
    "https": {"uid": "https", "type": "service-tcp", "name": "https", "port": "443"},
}


def _trule(uid, num, action, src, dst, svc=("https",)):
    return aa._parse_rule({"uid": uid, "rule-number": num, "name": uid, "enabled": True,
                           "action": action, "source": list(src), "destination": list(dst),
                           "service": list(svc)}, _TYPED_OD)


_TCLEAN = _trule("rC", 99, "Drop", ["any"], ["any"], ["any"])


def _domreq(dst="alshawwaf.ca", src="10.1.1.222/32"):
    return AccessRequest([src], [], "tcp", "443", dst_kind="domain", dst_value=dst)


# --- parse: typed objects are captured, not lumped into complex (but IP path still treats opaque) ---
def test_parse_captures_typed_objects_without_complex():
    r = _trule("r1", 1, "Accept", ["any"], ["dom"])
    assert r.dst_typed.domains == {".alshawwaf.ca"}
    assert r.dst_cx is False                         # not truly-unresolvable
    assert r.dst_unknown is True                     # IP-path: a typed cell stays opaque (preserves safety)
    assert r.complex is True


def test_parse_role_zone_dynamic_updatable_routed_to_their_sets():
    r = _trule("r1", 1, "Accept", ["role", "dyn"], ["upd", "zone"])
    assert r.src_typed.roles == {"Finance_Users"} and r.src_typed.dynamic == {"DObj_App"}
    assert r.dst_typed.updatable == {"Office365"} and r.dst_typed.zones == {"InternalZone"}
    assert r.src_cx is False and r.dst_cx is False


# --- domain request matching ---
def test_domain_request_no_op_when_covered_by_parent():
    rules = [_trule("r1", 1, "Accept", ["any"], ["dom"]), _TCLEAN]
    assert aa.decide(_domreq("alshawwaf.ca"), rules).outcome is Outcome.NO_OP


def test_domain_subdomain_is_subset_no_op():
    rules = [_trule("r1", 1, "Accept", ["any"], ["dom"]), _TCLEAN]
    assert aa.decide(_domreq("www.alshawwaf.ca"), rules).outcome is Outcome.NO_OP


def test_domain_create_when_no_rule_covers():
    rules = [_trule("r1", 1, "Accept", ["any"], ["dom"]), _TCLEAN]
    d = aa.decide(_domreq("not-covered.com"), rules)
    assert d.outcome is Outcome.CREATE


def test_domain_disjoint_from_ip_only_drop():
    # A Drop whose destination is an IP network must NOT block a DOMAIN request (different identity
    # space — object semantics, mirroring apps-vs-ports). The domain request proceeds to CREATE.
    rules = [_trule("r1", 1, "Drop", ["any"], ["dmz"]), _TCLEAN]
    assert aa.decide(_domreq("alshawwaf.ca"), rules).outcome is Outcome.CREATE


def test_domain_updatable_feed_notes_and_continues():
    # An updatable feed (Office365, …) can itself contain FQDNs -> can't prove coverage. It's an ACCEPT,
    # so the walk NOTES it ("may already permit it") and continues to a clean CREATE — no hard stop. This
    # is the exact case from the live screenshot (rule "CP Updates").
    rules = [_trule("r1", 1, "Accept", ["any"], ["upd"]), _TCLEAN]
    d = aa.decide(_domreq("alshawwaf.ca"), rules)
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 1")


def test_domain_any_dest_accept_no_op_and_drop_creates_above():
    accept = [_trule("r1", 1, "Accept", ["any"], ["any"]), _TCLEAN]
    assert aa.decide(_domreq(), accept).outcome is Outcome.NO_OP
    drop = [_trule("r1", 1, "Drop", ["any"], ["any"]), _TCLEAN]   # specific (https) Any/Any drop
    d = aa.decide(_domreq(), drop)                                # resolved covering deny -> create above it
    assert d.outcome is Outcome.CREATE and d.position == {"above": "r1"}


def test_domain_widen_adds_to_a_matching_rule_dest():
    # src (host) and svc EQUAL, dst is a DIFFERENT domain -> widen the destination cell with our domain.
    rules = [_trule("r1", 1, "Accept", ["h222"], ["domx"]), _TCLEAN]
    d = aa.decide(_domreq("alshawwaf.ca"), rules)
    assert d.outcome is Outcome.WIDEN and d.widen_field == "destination"


# --- safety: an IP request is unchanged by typed cells (still REVIEW, never stepped past) ---
def test_ip_request_notes_on_typed_dest_cell():
    # an IP request still treats a typed (domain) cell as opaque (a domain could resolve to IPs we can't
    # see) — but it's an ACCEPT, so the walk NOTES it and continues to a clean CREATE instead of stopping.
    rules = [_trule("r1", 1, "Accept", ["any"], ["dom"]), _TCLEAN]
    ipreq = AccessRequest(["10.1.1.222/32"], ["203.0.113.5/32"], "tcp", "443")
    d = aa.decide(ipreq, rules)
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 1")


# --- access-role / zone / dynamic exact-identity matching ---
def test_access_role_exact_match_no_op_and_mismatch_create():
    rules = [_trule("r1", 1, "Accept", ["any"], ["role"]), _TCLEAN]
    hit = AccessRequest(["10.1.1.222/32"], [], "tcp", "443",
                        dst_kind="access-role", dst_value="Finance_Users")
    assert aa.decide(hit, rules).outcome is Outcome.NO_OP
    miss = AccessRequest(["10.1.1.222/32"], [], "tcp", "443",
                         dst_kind="access-role", dst_value="HR_Users")
    assert aa.decide(miss, rules).outcome is Outcome.CREATE


def test_role_request_disjoint_from_domain_drop():
    # An access-role request is a different identity than a dns-domain -> a domain Drop doesn't block it.
    rules = [_trule("r1", 1, "Drop", ["any"], ["dom"]), _TCLEAN]
    rolereq = AccessRequest(["10.1.1.222/32"], [], "tcp", "443",
                            dst_kind="access-role", dst_value="Finance_Users")
    assert aa.decide(rolereq, rules).outcome is Outcome.CREATE


def test_negated_typed_cell_notes_and_continues():
    neg = aa._parse_rule({"uid": "rn", "rule-number": 1, "name": "rn", "enabled": True, "action": "Accept",
                          "source": ["any"], "destination": ["dom"], "destination-negate": True,
                          "service": ["https"]}, _TYPED_OD)
    d = aa.decide(_domreq("alshawwaf.ca"), [neg, _TCLEAN])   # negated cell -> noted + continue (Accept)
    assert d.outcome is Outcome.CREATE and _noted(d, "rule 1")


def test_typed_request_empty_value_is_review():
    req = AccessRequest(["10.1.1.222/32"], [], "tcp", "443", dst_kind="domain", dst_value="")
    assert aa.decide(req, [_TCLEAN]).outcome is Outcome.REVIEW


# --- build_request typed validation ---
def test_build_request_domain_valid_and_normalised():
    req = tk.build_request("10.1.1.222", "ALSHAWWAF.CA", "tcp", "443", destination_kind="domain")
    assert req.dst_kind == "domain" and req.dst_value == "alshawwaf.ca" and req.dst_cidrs == []
    sub = tk.build_request("10.1.1.222", ".alshawwaf.ca", "tcp", "443", destination_kind="domain")
    assert sub.dst_value == ".alshawwaf.ca"          # leading dot preserved (sub-domain semantics)


def test_build_request_rejects_bad_domain_and_kind():
    with pytest.raises(ValueError):
        tk.build_request("10.1.1.222", "not a domain!", "tcp", "443", destination_kind="domain")
    with pytest.raises(ValueError):
        tk.build_request("10.1.1.222", "x", "tcp", "443", destination_kind="bogus-kind")
    with pytest.raises(ValueError):
        tk.build_request("10.1.1.222", "", "tcp", "443", destination_kind="domain")


def test_build_request_role_name_passthrough():
    req = tk.build_request("10.1.1.222", "Finance Users", "tcp", "443", destination_kind="access-role")
    assert req.dst_kind == "access-role" and req.dst_value == "Finance Users"


# --- apply: reuse/create the typed object + place it ---
def test_execute_create_materialises_domain_object(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [_TCLEAN])
    res = aa.execute(object(), "secret", _domreq("alshawwaf.ca"), "Network",
                     ticket_id="INC9", publish=True)
    assert res["ok"] and res["outcome"] == "create" and res["published"] is True
    cmds = [c for c, _ in calls]
    assert "add-dns-domain" in cmds and "add-access-rule" in cmds
    dom = next(p for c, p in calls if c == "add-dns-domain")
    assert dom["name"] == ".alshawwaf.ca" and dom["is-sub-domain"] is False
    rule = next(p for c, p in calls if c == "add-access-rule")
    assert rule["destination"] == ".alshawwaf.ca"


def test_resolve_typed_object_reuse_only_kind_errors_when_missing():
    s = _fake_session_factory([])(object(), "x")     # show-objects returns nothing -> not found
    with pytest.raises(aa.MgmtError):
        aa.resolve_typed_object(s, "access-role", "Finance_Users")
    with pytest.raises(aa.MgmtError):
        aa.resolve_typed_object(s, "security-zone", "InternalZone")


def test_typed_object_preview_marks_non_creatable_missing():
    s = _fake_session_factory([])(object(), "x")
    p = aa.typed_object_preview(s, "access-role", "Finance_Users")
    assert p["exists"] is False and p["creatable"] is False and p["kind"] == "access-role"
    pd = aa.typed_object_preview(s, "domain", "alshawwaf.ca")
    assert pd["creatable"] is True and pd["name"] == ".alshawwaf.ca"


# --- domain sub-domain semantics (adversarial-review findings) -----------------------------------
def test_domain_exact_cell_does_not_cover_subdomain_request():
    # FINDING 1: an EXACT domain object (no leading dot) must NOT cover a "domain + sub-domains" request
    # (a leading-dot value) — that was a false NO_OP. The reverse direction stays covered.
    od = dict(_TYPED_OD, domf={"uid": "domf", "type": "dns-domain", "name": "alshawwaf.ca"})  # exact, no dot
    rule = aa._parse_rule({"uid": "r1", "rule-number": 1, "name": "r1", "enabled": True, "action": "Accept",
                           "source": ["any"], "destination": ["domf"], "service": ["https"]}, od)
    sub_req = AccessRequest(["10.1.1.222/32"], [], "tcp", "443", dst_kind="domain", dst_value=".alshawwaf.ca")
    assert aa.decide(sub_req, [rule, _TCLEAN]).outcome is Outcome.CREATE          # not falsely NO_OP
    exact_req = AccessRequest(["10.1.1.222/32"], [], "tcp", "443", dst_kind="domain", dst_value="alshawwaf.ca")
    assert aa.decide(exact_req, [rule, _TCLEAN]).outcome is Outcome.NO_OP         # exact still covered


def test_domain_covers_helper_directionality():
    assert aa._domain_covers(".x.com", "x.com")          # sub cell covers the apex
    assert aa._domain_covers(".x.com", "www.x.com")      # sub cell covers a sub-domain
    assert aa._domain_covers("x.com", "x.com")           # exact == exact
    assert aa._domain_covers(".x.com", ".x.com")         # sub == sub
    assert not aa._domain_covers("x.com", ".x.com")      # exact cell can't cover a sub-domain request
    assert not aa._domain_covers("x.com", "www.x.com")   # exact cell can't cover a sub-domain
    assert not aa._domain_covers(".x.com", "evilx.com")  # suffix that isn't a sub-domain boundary


class _DomSession:
    """A minimal session whose show-objects returns a fixed dns-domain object list (for apply tests)."""
    def __init__(self, objs):
        self.objs, self.calls = objs, []

    def call(self, cmd, payload=None, **k):
        self.calls.append((cmd, payload or {}))
        return {"objects": self.objs} if cmd == "show-objects" else {}


def test_resolve_domain_reuses_only_matching_is_sub_domain():
    # FINDING 2: a broad sub-domain object must NOT be reused for an EXACT request (would grant *.example.com)
    s = _DomSession([{"name": ".example.com", "type": "dns-domain", "is-sub-domain": True}])
    with pytest.raises(aa.MgmtError):
        aa.resolve_typed_object(s, "domain", "example.com")      # exact request, only a sub object -> clash
    assert not any(c == "add-dns-domain" for c, _ in s.calls)    # never silently widened
    s2 = _DomSession([{"name": ".example.com", "type": "dns-domain", "is-sub-domain": True}])
    assert aa.resolve_typed_object(s2, "domain", ".example.com") == ".example.com"   # sub request reuses it
    assert not any(c == "add-dns-domain" for c, _ in s2.calls)


def test_resolve_domain_creates_with_correct_is_sub_domain():
    s = _DomSession([])
    assert aa.resolve_typed_object(s, "domain", "example.com") == ".example.com"
    assert next(p for c, p in s.calls if c == "add-dns-domain") == {"name": ".example.com", "is-sub-domain": False}


class _AddrSession:
    """show-objects honoring the payload's ``type`` filter (like the real API) — so a gateway is found
    only by the no-type infra lookup, never by the type=host query. Records add-* calls."""
    def __init__(self, objs):
        self.objs, self.calls = objs, []

    def call(self, cmd, payload=None, **k):
        payload = payload or {}
        self.calls.append((cmd, payload))
        if cmd == "show-objects":
            t = payload.get("type")
            return {"objects": [o for o in self.objs if not t or (o.get("type") == t)]}
        return {}


def test_endpoint_reuses_any_address_object_by_exact_scope():
    # Endpoint reuse must identify ALL supported address-bearing object types by EXACT scope — not just
    # host. A /32 to a gateway/cluster/CP-host reuses that object; a CIDR reuses a matching network OR an
    # equivalent address-range; and a BROADER container is never reused (would over-grant) -> create instead.
    gw = {"name": "GW", "type": "simple-gateway", "ipv4-address": "10.1.1.111"}
    cph = {"name": "SMS", "type": "checkpoint-host", "ipv4-address": "10.1.1.100"}
    net = {"name": "net24", "type": "network", "subnet4": "10.1.5.0", "mask-length4": 24}
    rng = {"name": "rng", "type": "address-range", "ipv4-address-first": "10.1.6.0", "ipv4-address-last": "10.1.6.255"}

    # /32 -> gateway, and a Check Point host, each by exact IP
    assert aa.lookup_endpoint(_AddrSession([gw]), "10.1.1.111/32") == "GW"
    assert aa.lookup_endpoint(_AddrSession([cph]), "10.1.1.100/32") == "SMS"
    # CIDR -> a network, OR an address-range spanning exactly the same /24
    assert aa.lookup_endpoint(_AddrSession([net]), "10.1.5.0/24") == "net24"
    assert aa.lookup_endpoint(_AddrSession([rng]), "10.1.6.0/24") == "rng"

    # apply reuses the gateway and never fabricates a duplicate host
    sap = _AddrSession([gw])
    assert aa.resolve_endpoint(sap, "10.1.1.111/32") == "GW"
    assert not any(c == "add-host" for c, _ in sap.calls)

    # an exact HOST wins a tie over a same-IP gateway (most specific / canonical)
    both = [{"name": "h-x", "type": "host", "ipv4-address": "10.1.1.111"}, gw]
    assert aa.lookup_endpoint(_AddrSession(both), "10.1.1.111/32") == "h-x"

    # SAFETY: a BROADER container is never reused for a narrower request -> None (caller creates exact obj)
    assert aa.lookup_endpoint(_AddrSession([net]), "10.1.5.42/32") is None         # /32 inside the /24
    assert aa.lookup_endpoint(_AddrSession([rng]), "10.1.6.10/32") is None         # /32 inside the range
    snew = _AddrSession([net])
    aa.resolve_endpoint(snew, "10.1.5.42/32")
    assert any(c == "add-host" for c, _ in snew.calls)                             # creates the /32 host
    s2 = _DomSession([])
    aa.resolve_typed_object(s2, "domain", ".example.com")
    assert next(p for c, p in s2.calls if c == "add-dns-domain")["is-sub-domain"] is True


# --- note+continue safety guarantees (2026-06-23: opaque rules no longer hard-stop the flow) ----------
def test_resolved_covering_deny_creates_above_it():
    # a RESOLVED, provable covering deny is overridden: the allow is created ABOVE it so the access works.
    # (An UNRESOLVABLE possible-deny is different — it's noted & the allow lands below it; see the approx /
    # opaque-service / service-other tests.)
    deny = _rule("rd", 1, "Drop", _host("10.0.0.5"), _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["172.16.5.10/32"], "tcp", "443"), [deny, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "rd"}


def _ow_od():
    return {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
            "zone": {"uid": "zone", "type": "security-zone", "name": "Z"},
            "hd": {"uid": "hd", "type": "host", "name": "w", "ipv4-address": "172.16.5.10"},
            "hs": {"uid": "hs", "type": "host", "name": "c", "ipv4-address": "10.0.0.5"},
            "t443": {"uid": "t443", "type": "service-tcp", "name": "https", "port": "443"},
            "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"}}


def test_widen_allowed_when_target_is_below_an_opaque_deny():
    # An opaque (zone) DROP ABOVE a clean widen target. The target sits BELOW the opaque deny, so widening
    # it CANNOT leap the request over the block (first-match still hits the deny first for traffic it
    # matches) -> widening is safe AND preferable to a duplicate. (The live Dynamic-Layer-above-rule-13
    # case.) The opaque deny is still flagged for review.
    od = _ow_od()
    odrop = aa._parse_rule({"uid": "od", "rule-number": 1, "name": "zone drop", "enabled": True,
                            "action": "drp", "source": ["zone"], "destination": ["hd"],
                            "service": ["t443"]}, od)                       # opaque (zone) DROP, on top
    acc = aa._parse_rule({"uid": "wa", "rule-number": 2, "name": "win", "enabled": True, "action": "acc",
                          "source": ["hs"], "destination": ["hd"], "service": ["t443"]}, od)  # widen target BELOW
    cleanup = aa._parse_rule({"uid": "rC", "rule-number": 99, "name": "cleanup", "enabled": True,
                              "action": "drp", "source": ["any"], "destination": ["any"],
                              "service": ["any"]}, od)
    req = AccessRequest(["10.0.0.9/32"], ["172.16.5.10/32"], "tcp", "443")   # src differs from acc -> widen
    d = aa.decide(req, [odrop, acc, cleanup])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source" and d.target_rule.uid == "wa"
    assert _noted(d, "rule 1", "block")                      # opaque deny still flagged


def test_widen_suppressed_when_target_is_above_an_opaque_deny():
    # SAFETY (unchanged): the widen target sits ABOVE the opaque deny. Widening it WOULD pull the request's
    # traffic over the block (first-match leaps the deny) -> under-deny. So WIDEN is suppressed -> CREATE
    # below the deny.
    od = _ow_od()
    acc = aa._parse_rule({"uid": "wa", "rule-number": 1, "name": "win", "enabled": True, "action": "acc",
                          "source": ["hs"], "destination": ["hd"], "service": ["t443"]}, od)  # widen target ON TOP
    odrop = aa._parse_rule({"uid": "od", "rule-number": 2, "name": "zone drop", "enabled": True,
                            "action": "drp", "source": ["zone"], "destination": ["hd"],
                            "service": ["t443"]}, od)                       # opaque (zone) DROP, BELOW
    cleanup = aa._parse_rule({"uid": "rC", "rule-number": 99, "name": "cleanup", "enabled": True,
                              "action": "drp", "source": ["any"], "destination": ["any"],
                              "service": ["any"]}, od)
    req = AccessRequest(["10.0.0.9/32"], ["172.16.5.10/32"], "tcp", "443")
    d = aa.decide(req, [acc, odrop, cleanup])
    assert d.outcome is Outcome.CREATE                       # WIDEN suppressed (target above the deny)
    assert _noted(d, "rule 2", "block")


# --- Predefined "Internet" object (App Control / URL Filtering destination) ----------------------
_INET_OD = {
    "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "inet": {"uid": "inet", "name": "Internet"},                      # predefined topology object (no IP)
    "ws": {"uid": "ws", "type": "host", "name": "win_server", "ipv4-address": "10.1.2.250"},
    "gw": {"uid": "gw", "type": "simple-gateway", "name": "GW", "ipv4-address": "10.0.0.1"},  # -> approx
    "srv": {"uid": "srv", "type": "host", "name": "intranet", "ipv4-address": "172.16.5.10"},
    "fb": {"uid": "fb", "type": "application-site", "name": "Facebook"},
    "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
}


def _inet_rule(uid, num, action, source, destination, service):
    return aa._parse_rule({"uid": uid, "rule-number": num, "name": uid, "enabled": True,
                           "action": action, "source": source, "destination": destination,
                           "service": service}, _INET_OD)


def _req_fb_internet():
    """What build_request now yields for "win_server -> Facebook": destination defaulted to Internet."""
    return AccessRequest(["10.1.2.250/32"], [], application="Facebook",
                         dst_kind="internet", dst_value="Internet")


def _blocked(d):
    return any("block" in n.lower() or "stealth" in n.lower() for n in (d.notes or []))


def test_parse_net_detects_internet_object_no_ip():
    iv, cx, groups, approx, typed = aa._parse_net([{"name": "Internet"}], {})
    assert typed.internet == {"Internet"} and typed.any_members()
    assert iv == [] and not cx and not approx                        # no IP extent, not opaque/REVIEW


def test_parse_net_host_named_internet_still_resolves_by_ip():
    # a customer host pathologically named "Internet" must NOT be mistaken for the global object
    iv, cx, _, _, typed = aa._parse_net(
        [{"name": "Internet", "type": "host", "ipv4-address": "10.9.9.9"}], {})
    assert not typed.internet and iv == _host("10.9.9.9")


def test_internet_request_reuses_internet_dest_rule():
    r = _inet_rule("rI", 13, "acc", ["ws"], ["inet"], ["fb"])
    cleanup = _inet_rule("rC", 99, "drp", ["any"], ["any"], ["any"])
    d = aa.decide(_req_fb_internet(), [r, cleanup])
    assert d.outcome is Outcome.NO_OP and d.target_rule.uid == "rI"   # Internet == Internet -> reuse


def test_internet_request_covered_by_any_dest_rule():
    r = _inet_rule("rA", 5, "acc", ["ws"], ["any"], ["fb"])          # Any dest is a superset of Internet
    cleanup = _inet_rule("rC", 99, "drp", ["any"], ["any"], ["any"])
    assert aa.decide(_req_fb_internet(), [r, cleanup]).outcome is Outcome.NO_OP


def test_internet_request_not_covered_by_specific_ip_dest_rule():
    r = _inet_rule("rS", 5, "acc", ["ws"], ["srv"], ["fb"])          # to a specific internal server
    cleanup = _inet_rule("rC", 99, "drp", ["any"], ["any"], ["any"])
    assert aa.decide(_req_fb_internet(), [r, cleanup]).outcome is Outcome.CREATE


def test_internet_request_steps_past_stealth_gw_drop():
    # the user's scenario: a Stealth rule (Any -> GW, drop) must NOT block / floor an Internet-dest app
    # request — a gateway IP is provably DISJOINT from the Internet object, so the rule is out of path.
    stealth = _inet_rule("r6", 6, "drp", ["any"], ["gw"], ["any"])
    cleanup = _inet_rule("rC", 99, "drp", ["any"], ["any"], ["any"])
    d = aa.decide(_req_fb_internet(), [stealth, cleanup])
    assert d.outcome is Outcome.CREATE and not _blocked(d)           # no "Stealth Rule may block" note


def test_any_dest_app_still_floored_below_approx_gw_drop():
    # a GENUINE Any-destination app request still respects an approx (gateway) DROP in the path: it can
    # include the gateway plane, so the new allow is placed BELOW the drop and the note is kept.
    stealth = _inet_rule("r6", 6, "drp", ["any"], ["gw"], ["any"])
    cleanup = _inet_rule("rC", 99, "drp", ["any"], ["any"], ["any"])
    req = AccessRequest(["10.1.2.250/32"], ["0.0.0.0/0"], application="Facebook")   # Any dest (IP)
    d = aa.decide(req, [stealth, cleanup])
    assert d.outcome is Outcome.CREATE and _blocked(d)               # uncertain-deny note preserved


def test_build_request_app_any_defaults_to_internet():
    r = tk.build_request("10.1.2.250", "Any", "tcp", "", application="Facebook")
    assert r.dst_kind == "internet" and r.dst_value == "Internet" and r.dst_cidrs == []
    assert r.application == "Facebook"


def test_build_request_app_specific_destination_kept_as_ip():
    r = tk.build_request("10.1.2.250", "172.16.5.10", "tcp", "", application="Facebook")
    assert r.dst_kind == "ip" and r.dst_cidrs == ["172.16.5.10/32"]   # specific dest is honored, not upgraded


def test_build_request_explicit_internet_destination_kind():
    r = tk.build_request("10.1.2.250", "ignored-value", "tcp", "443", destination_kind="internet")
    assert r.dst_kind == "internet" and r.dst_value == "Internet" and r.dst_cidrs == []


def test_build_request_internet_rejected_as_source():
    with pytest.raises(ValueError):
        tk.build_request("anything", "Any", "tcp", "443", source_kind="internet")


def test_build_request_non_app_any_stays_any():
    r = tk.build_request("10.1.2.250", "Any", "tcp", "443")           # a port request, not an app
    assert r.dst_kind == "ip" and r.dst_cidrs == ["Any"]


def test_internet_destination_resolves_without_session_calls():
    req = _req_fb_internet()

    class _Boom:
        def call(self, *a, **k):
            raise AssertionError("Internet is predefined — no object lookup/creation expected")

    assert aa._resolve_endpoint_object(_Boom(), req, "destination") == "Internet"
    prev = aa._endpoint_object_preview(_Boom(), req, "destination")
    assert prev["name"] == "Internet" and prev["exists"] is True


# --- Section-aware floor placement (provisioned section, not inside the cleanup section) ----------
_SECT_OD = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
            "drp": {"uid": "drp", "name": "Drop"}, "acc": {"uid": "acc", "name": "Accept"},
            "h": {"uid": "h", "type": "host", "name": "web", "ipv4-address": "10.0.0.9"}}
_SECT = "Provisioned (automation)"   # the aa_rule_section default


def _cleanup_rule(uid="r14", num=14):
    return {"uid": uid, "type": "access-rule", "rule-number": num, "name": "Cleanup rule",
            "enabled": True, "action": "drp", "source": ["any"], "destination": ["any"], "service": ["any"]}


def _normal_rule():
    return {"uid": "r1", "type": "access-rule", "rule-number": 1, "name": "web", "enabled": True,
            "action": "acc", "source": ["h"], "destination": ["h"], "service": ["any"]}


class _SectSess:
    """A fake session that serves one rulebase page + records add-access-section / add-access-rule calls."""
    def __init__(self, items):
        self._items, self.calls = items, []

    def call(self, cmd, payload=None):
        self.calls.append((cmd, payload or {}))
        if cmd == "show-access-rulebase":
            return {"rulebase": self._items, "objects-dictionary": list(_SECT_OD.values()),
                    "total": 1, "to": 1}                          # to >= total -> single page, stop
        if cmd == "add-access-section":
            return {"uid": "sec-new"}
        return {}

    def _addsecs(self):
        return [c[1] for c in self.calls if c[0] == "add-access-section"]


def test_floor_position_creates_provisioned_section_above_cleanup_section():
    sess = _SectSess([_normal_rule(),
                      {"type": "access-section", "uid": "sC", "name": "Clean up rule",
                       "rulebase": [_cleanup_rule()]}])
    out = {"ops": []}
    pos = aa._floor_position(sess, "Network", None, out)
    assert pos == {"bottom": _SECT}                               # rule lands at the bottom of the section
    sec = sess._addsecs()
    # anchored on the cleanup section's UID (unambiguous), not its name
    assert sec and sec[0] == {"layer": "Network", "name": _SECT, "position": {"above": "sC"}}
    assert any(o.startswith("add-access-section") for o in out["ops"])


def test_floor_position_reuses_existing_provisioned_section():
    sess = _SectSess([{"type": "access-section", "uid": "sP", "name": _SECT, "rulebase": []},
                      {"type": "access-section", "uid": "sC", "name": "Clean up rule",
                       "rulebase": [_cleanup_rule()]}])
    pos = aa._floor_position(sess, "Network", None, {"ops": []})
    assert pos == {"bottom": _SECT} and not sess._addsecs()        # reused, never recreated


def test_floor_position_bare_cleanup_rule_sits_above_it_no_section():
    sess = _SectSess([_normal_rule(), _cleanup_rule("r99", 99)])
    pos = aa._floor_position(sess, "Network", None, {"ops": []})
    assert pos == {"above": "r99"} and not sess._addsecs()         # no wrapping section -> just above it


def test_floor_position_disabled_falls_back_to_bottom(monkeypatch):
    monkeypatch.setattr("app.services.naming.rule_section", lambda: "")
    sess = _SectSess([_normal_rule(), _cleanup_rule()])
    assert aa._floor_position(sess, "Network", None, {"ops": []}) == "bottom"
    assert not sess.calls                                          # short-circuits before any read


def test_floor_position_degrades_to_bottom_when_no_cleanup_found():
    sess = _SectSess([_normal_rule()])                             # no recognizable catch-all cleanup
    assert aa._floor_position(sess, "Network", None, {"ops": []}) == "bottom"


def test_floor_position_degrades_above_section_when_creation_rejected():
    items = [_normal_rule(), {"type": "access-section", "uid": "sC", "name": "Clean up rule",
                              "rulebase": [_cleanup_rule()]}]

    class _Reject(_SectSess):
        def call(self, cmd, payload=None):
            if cmd == "add-access-section":
                self.calls.append((cmd, payload or {}))
                raise aa.MgmtError("a section named that already exists")
            return super().call(cmd, payload)

    pos = aa._floor_position(_Reject(items), "Network", None, {"ops": []})
    assert pos == {"above": "sC"}                                  # degrade: above the cleanup SECTION (uid)


def test_floor_position_relocated_section_degrades_to_above_cleanup():
    # an admin moved the provisioned section ABOVE a business rule (not bottom-adjacent). Reusing it for a
    # floored allow could leap the allow above the rule that forced the floor (e.g. the Stealth rule), so
    # anchor relative to the cleanup instead — never trust a relocated section's height.
    items = [{"type": "access-section", "uid": "sP", "name": _SECT, "rulebase": []},
             _normal_rule(),
             {"type": "access-section", "uid": "sC", "name": "Clean up rule", "rulebase": [_cleanup_rule()]}]
    sess = _SectSess(items)
    pos = aa._floor_position(sess, "Network", None, {"ops": []})
    assert pos == {"above": "sC"} and not sess._addsecs()          # not recreated; safe bottom, not the section


# --- MEDIUM-1: creating above an overridden deny flags a SHADOWED more-specific deny below ----------
def test_create_above_partial_deny_flags_shadowed_specific_deny_below():
    A = _rule("rA", 1, "Drop", _net("10.0.0.0/16"), _net("10.2.0.0/24"), _tcp(443))   # partial deny
    B = _rule("rB", 2, "Drop", _host("10.5.5.5"), _net("10.2.0.0/24"), _tcp(443))      # more-specific deny
    req = AccessRequest(["10.0.0.0/8"], ["10.2.0.0/24"], "tcp", "443")                 # ⊋ A (src) and ⊋ B
    d = aa.decide(req, [A, B, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "rA", "_anomaly": True}
    assert any("rB" in n for n in (d.notes or []))                 # advisory names the shadowed deny


def test_create_above_partial_deny_no_flag_when_nothing_specific_below():
    A = _rule("rA", 1, "Drop", _net("10.0.0.0/16"), _net("10.2.0.0/24"), _tcp(443))
    req = AccessRequest(["10.0.0.0/8"], ["10.2.0.0/24"], "tcp", "443")
    d = aa.decide(req, [A, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "rA"}   # no _anomaly, no shadow note


def test_app_carveout_flags_shadowed_app_deny_below():
    drop = _rule("rD", 1, "Drop", _net("10.0.0.0/8"), _net("172.16.0.0/16"), _tcp(443))    # L4 drop -> carve
    fbdrop = _rule("rS", 2, "Drop", _host("10.5.5.5"), _net("172.16.0.0/16"), _app(["Facebook"]))  # app deny
    req = AccessRequest(["10.0.0.0/8"], ["172.16.0.0/16"], application="Facebook")
    d = aa.decide(req, [drop, fbdrop, CLEANUP])
    assert d.outcome is Outcome.CREATE and (d.position or {}).get("_anomaly") is True
    assert any("rS" in n for n in (d.notes or []))


# --- removal symmetry for the Internet object (it routes through the shared primitives) -----------
def test_decide_removal_internet_exact_rule_disables():
    r = _inet_rule("rI", 13, "acc", ["ws"], ["inet"], ["fb"])          # win_server -> Internet -> Facebook
    cleanup = _inet_rule("rC", 99, "drp", ["any"], ["any"], ["any"])
    d = aa.decide_removal(_req_fb_internet(), [r, cleanup])
    assert d.outcome is aa.RemovalOutcome.DISABLE and d.target_rule.uid == "rI"


def test_decide_removal_internet_deny_above_broader_any_dest_rule():
    r = _inet_rule("rA", 5, "acc", ["ws"], ["any"], ["fb"])            # Any dest is broader than Internet
    cleanup = _inet_rule("rC", 99, "drp", ["any"], ["any"], ["any"])
    d = aa.decide_removal(_req_fb_internet(), [r, cleanup])
    assert d.outcome is aa.RemovalOutcome.DENY and d.position == {"above": "rA"}   # no over-removal


def test_decide_removal_internet_regranted_below_is_deny_not_disable():
    exact = _inet_rule("rI", 13, "acc", ["ws"], ["inet"], ["fb"])
    broad = _inet_rule("rA", 20, "acc", ["ws"], ["any"], ["fb"])       # below: still grants it
    cleanup = _inet_rule("rC", 99, "drp", ["any"], ["any"], ["any"])
    d = aa.decide_removal(_req_fb_internet(), [exact, broad, cleanup])
    assert d.outcome is aa.RemovalOutcome.DENY                          # disabling rI alone wouldn't stop it


# --- application CATEGORY as a first-class service kind (NO_OP/WIDEN vs an identical-category rule) ----
_CAT_OD = {
    "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "ws": {"uid": "ws", "type": "host", "name": "win_server", "ipv4-address": "10.1.2.250"},
    "srv": {"uid": "srv", "type": "host", "name": "intranet", "ipv4-address": "172.16.5.10"},
    "sn": {"uid": "sn", "type": "application-site-category", "name": "Social Networking"},
    "grp": {"uid": "grp", "type": "application-site-group", "name": "Social Networking"},  # SAME name, a GROUP
    "drp": {"uid": "drp", "name": "Drop"},
}


def _cat_rule(uid, num, svc_refs, action="acc"):
    od = dict(_CAT_OD, acc={"uid": "acc", "name": "Accept"})
    return aa._parse_rule({"uid": uid, "rule-number": num, "name": uid, "enabled": True, "action": action,
                           "source": ["ws"], "destination": ["srv"], "service": svc_refs}, od)


def _cat_cleanup():
    return aa._parse_rule({"uid": "rC", "rule-number": 99, "name": "cleanup", "enabled": True,
                           "action": "drp", "source": ["any"], "destination": ["any"],
                           "service": ["any"]}, _CAT_OD)


def _req_category(cat="Social Networking"):
    return AccessRequest(["10.1.2.250/32"], ["172.16.5.10/32"], application=cat,
                         application_kind="application-site-category")


def test_parse_svc_category_captured_by_name():
    s = aa._parse_svc(["sn"], _CAT_OD)
    assert s.categories == {"Social Networking"} and s.opaque and not s.apps and not s.app_group


def test_parse_svc_app_group_is_opaque_not_a_category():
    s = aa._parse_svc(["grp"], _CAT_OD)
    assert s.app_group and s.opaque and not s.categories          # a group is NOT captured as a category


def test_category_request_svc_is_categories():
    assert _req_category().svc().categories == {"Social Networking"} and not _req_category().svc().apps


def test_category_request_reuses_matching_category_rule():
    d = aa.decide(_req_category(), [_cat_rule("rCat", 5, ["sn"]), _cat_cleanup()])
    assert d.outcome is Outcome.NO_OP and d.target_rule.uid == "rCat"   # category == category -> reuse


def test_category_request_not_matched_by_same_named_app_group():
    d = aa.decide(_req_category(), [_cat_rule("rGrp", 5, ["grp"]), _cat_cleanup()])
    assert d.outcome is Outcome.CREATE        # a same-named app-GROUP can't be proven to cover the category


def test_single_app_request_not_reused_by_category_rule():
    req = AccessRequest(["10.1.2.250/32"], ["172.16.5.10/32"], application="Facebook",
                        application_kind="application-site")
    d = aa.decide(req, [_cat_rule("rCat", 5, ["sn"]), _cat_cleanup()])
    assert d.outcome is Outcome.CREATE        # can't prove a single app is a member of the category


def test_category_with_app_group_is_subset_not_equal():
    # a cell holding the category AND an app-group is broader than the category alone -> SUBSET, never EQUAL
    rule = aa._parse_svc(["sn", "grp"], _CAT_OD)
    assert aa.svc_relation(ServiceSet(categories={"Social Networking"}), rule) == Relation.SUBSET


# --- the live-lab case: an Internet-dest rule must be WIDENable, not read as opaque -> redundant CREATE ----
def test_internet_rule_recognized_from_live_representation_and_widens_source():
    # The real lab representation: the predefined "Internet" object (uid f99b1488-…, type "Internet") lives
    # in the "Check Point Data" domain and is NOT returned in the rulebase's objects-dictionary — so rule
    # 13's destination is a BARE UID the engine can't dereference to a name. It must still be recognized
    # (by that fixed uid), or it reads as opaque -> complex_eff disqualifies the widen -> redundant CREATE.
    UID = aa._INTERNET_UID
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
          "ws": {"uid": "ws", "type": "host", "name": "win_server", "ipv4-address": "10.1.2.250"},
          "fb": {"uid": "fb", "type": "application-site", "name": "Facebook"},
          "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"}}
    # NOTE: the Internet uid is deliberately ABSENT from od (mirrors the live objdict gap).

    def _r(u, n, a, s, d, v):
        return aa._parse_rule({"uid": u, "rule-number": n, "name": u, "enabled": True, "action": a,
                               "source": s, "destination": d, "service": v}, od)

    assert aa._parse_net([UID], {})[4].internet == {"Internet"}                 # bare uid -> recognized
    assert aa._parse_net([{"uid": "x", "name": "Internet", "type": "Internet"}], {})[4].internet == {"Internet"}
    assert aa._parse_net([od["any"]], {})[0] == aa.ANY_IP                       # real Any stays Any, not internet
    req = AccessRequest(["10.1.1.222/32"], [], application="Facebook",
                        dst_kind="internet", dst_value="Internet")
    d = aa.decide(req, [_r("r13", 13, "acc", ["ws"], [UID], ["fb"]),
                        _r("rC", 99, "drp", ["any"], ["any"], ["any"])])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source" and d.target_rule.uid == "r13"


# --- rollback panel: "disabled" is a non-terminal, actionable state (re-enable OR delete) -----------
def _chg_ns(**kw):
    base = dict(id=1, created_at=None, created_by="u", layer="L", action="apply", outcome="create",
                summary="allow x -> y", ticket_id="", objects_json=[], reverted_at=None, reverted_by="",
                revert_error="", resolution="",
                inverse_json=[{"op": "delete-access-rule", "uid": "x", "layer": "L"}])
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_revert_state_machine():
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    assert aar._revert_state(_chg_ns(outcome="create")) == "active"
    assert aar._revert_state(_chg_ns(outcome="widen")) == "active"
    # a created rule rolled back BY disabling it -> "disabled" (NOT terminal), reverted_at stays NULL
    assert aar._revert_state(_chg_ns(outcome="create", resolution="disabled")) == "disabled"
    # a removal that DISABLEd a rule (not yet finalized) -> "disabled"
    assert aar._revert_state(_chg_ns(outcome="disable")) == "disabled"
    # terminal states
    assert aar._revert_state(_chg_ns(reverted_at=now, resolution="deleted")) == "resolved"
    assert aar._revert_state(_chg_ns(reverted_at=now, resolution="reverted")) == "resolved"


def test_change_row_disabled_added_rule_stays_deletable():
    # THE BUG: a created rule rolled back via Disable must remain re-enable/delete-able, not look resolved.
    row = aar._change_row(_chg_ns(outcome="create", resolution="disabled"))
    assert row["state"] == "disabled" and row["deletable_disabled"] is True and row["revertable"] is True
    assert row["reverted"] is False                          # reverted_at NULL -> not terminal
    assert aar._change_row(_chg_ns(outcome="create"))["state"] == "active"
    import datetime as _dt
    term = aar._change_row(_chg_ns(reverted_at=_dt.datetime.now(_dt.timezone.utc), resolution="deleted"))
    assert term["state"] == "resolved" and term["revertable"] is False


def test_disabled_rule_near_match_is_noted_on_create():
    # a DISABLED accept that already matches the access -> CREATE (disabled rules are correctly skipped),
    # but the operator is advised to re-enable it instead of adding a duplicate.
    r = _inet_rule("rD", 13, "acc", ["ws"], ["inet"], ["fb"]); r.enabled = False
    cleanup = _inet_rule("rC", 99, "drp", ["any"], ["any"], ["any"])
    d = aa.decide(_req_fb_internet(), [r, cleanup])
    assert d.outcome is Outcome.CREATE
    assert any("DISABLED" in n and "re-enable" in n.lower() for n in (d.notes or []))


# --- QA matrix findings: regression guards --------------------------------------------------------
def test_multikind_service_overlap_creates_not_widens():
    # QA BUG-1 (HIGH): a multi-kind service request {tcp/443 + icmp} where a rule covers only the tcp/443
    # leg -> svc_relation=OVERLAP. A single-object widen would silently DROP the icmp leg (under-grant), so
    # the engine must CREATE, not WIDEN, when the request service can't be added as one object.
    rule = _rule("r1", 1, "Accept", _host("10.1.1.5"), _host("172.16.5.10"), _tcp(443))
    req = AccessRequest(["10.1.1.5/32"], ["172.16.5.10/32"], "tcp", "443")
    req.svc_set = ServiceSet(by_proto={"tcp": aa._ports_to_iv("443")}, named={("icmp", "echo-request")})
    d = aa.decide(req, [rule, CLEANUP])
    assert d.outcome is Outcome.CREATE                      # was a silent-under-grant WIDEN before the fix
    # control: a single-kind clean diff still widens; a full-cover rule still NO_OPs
    d2 = aa.decide(AccessRequest(["10.1.1.5/32"], ["172.16.5.10/32"], "tcp", "8080"),
                   [_rule("r2", 1, "Accept", _host("10.1.1.5"), _host("172.16.5.10"), _tcp(443)), CLEANUP])
    assert d2.outcome is Outcome.WIDEN and d2.widen_field == "service"
    full = _rule("rf", 1, "Accept", _host("10.1.1.5"), _host("172.16.5.10"),
                 ServiceSet(by_proto={"tcp": aa._ports_to_iv("443")}, named={("icmp", "echo-request")}))
    assert aa.decide(req, [full, CLEANUP]).outcome is Outcome.NO_OP


def test_exact_covering_deny_override_flags_shadowed_deny_below():
    # QA BUG-2: overriding an EXACT-covering deny (create the allow above it) must flag a more-specific deny
    # BELOW it — same anomaly the partial-deny branch already raised (advisory parity).
    A = _rule("rA", 1, "Drop", _net("10.1.1.0/24"), _net("10.2.0.0/24"), _tcp(443))   # exact-covering deny
    B = _rule("rB", 2, "Drop", _host("10.1.1.5"), _net("10.2.0.0/24"), _tcp(443))       # more-specific, below
    req = AccessRequest(["10.1.1.0/24"], ["10.2.0.0/24"], "tcp", "443")                 # EQUAL to A's scope
    d = aa.decide(req, [A, B, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "rA", "_anomaly": True}
    assert any("rB" in n for n in (d.notes or []))


def test_allowed_summary_separates_ok_from_currently_allowed():
    # The agent-facing yes/no: ok (the check ran) must never be confused with currently_allowed (access
    # exists). no_op -> True; create/widen -> False (a change is required); review/unknown -> None.
    ok_yes, ans = aa._allowed_summary("no_op", {"number": 2, "name": "Public DNS Servers"})
    assert ok_yes is True and ans.lower().startswith("yes") and "rule 2" in ans
    no_create, ans = aa._allowed_summary("create", None)
    assert no_create is False and ans.lower().startswith("no")
    no_widen, ans = aa._allowed_summary("widen", {"number": 10, "name": "Mail"})
    assert no_widen is False and "widen" in ans.lower() and "Mail" in ans
    unk, ans = aa._allowed_summary("review", None)
    assert unk is None and "review" in ans.lower()


def test_allow_to_gateway_carves_above_stealth_not_below():
    # A Stealth rule (Any -> Gateway, Drop) resolves the gateway as an APPROX infra IP. A request TO the
    # gateway is provably covered by that drop, so an allow placed BELOW it would be shadowed (dead). It
    # MUST be carved ABOVE the Stealth rule (CP best practice). Regression for the live bug where the
    # approx-infra drop wrongly floored the allow below itself.
    gw = {"uid": "gw1", "type": "simple-gateway", "name": "GW", "ipv4-address": "10.1.1.111"}
    ANY_C = [{"uid": "any", "type": "CpmiAnyObject", "name": "Any"}]
    objs = {gw["uid"]: gw}

    def raw(uid, n, name, act, src, dst, svc):
        return {"uid": uid, "name": name, "rule-number": n, "action": act, "enabled": True,
                "source": src, "destination": dst, "service": svc}

    stealth = aa._parse_rule(raw("r6", 6, "Stealth Rule", "Drop", ANY_C, [gw], ANY_C), objs)
    cleanup = aa._parse_rule(raw("r13", 13, "Cleanup rule", "Drop", ANY_C, ANY_C, ANY_C), objs)

    # TO the gateway -> carve ABOVE the Stealth rule
    to_gw = AccessRequest(["10.1.1.50/32"], ["10.1.1.111/32"], "tcp", "8081")
    d = aa.decide(to_gw, [stealth, cleanup])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "r6"}, (d.outcome, d.position)

    # the same request with override_blocking_deny OFF -> honestly placed below + flagged (won't take effect)
    d_off = aa.decide(to_gw, [stealth, cleanup], aa.DecideOptions(override_blocking_deny=False))
    assert d_off.outcome is Outcome.CREATE and d_off.position == {"below": "r6"}

    # a /24 that only OVERLAPS the gateway (not fully covered) -> stay conservative, floored below the drop
    overlap = AccessRequest(["10.1.1.50/32"], ["10.1.1.0/24"], "tcp", "8081")
    d2 = aa.decide(overlap, [stealth, cleanup])
    assert d2.outcome is Outcome.CREATE and d2.position != {"above": "r6"}
    assert any("Stealth" in n for n in (d2.notes or []))


# --- amend_access_rule: edit an existing rule's METADATA (name / comment / tags) -----------------
def test_amend_execute_renames_rule_via_new_name_and_records_inverse(monkeypatch):
    calls = []
    rule = {"uid": "R1", "name": "old name", "comments": "", "tags": [{"name": "t-old"}]}
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, rule=rule))
    monkeypatch.setattr(aa, "invalidate_cache", lambda *a, **k: None)
    res = aa.amend_execute(object(), "secret", uid="R1", layer="Network",
                           name="Allow win_client -> Facebook", publish=True)
    assert res["ok"] and res["applied"] and res["published"] and res["outcome"] == "amend"
    # rename is sent via web_api 'new-name' (NOT 'name', which set-access-rule rejects), and ONLY metadata
    setc = next(p for c, p in calls if c == "set-access-rule")
    assert setc["uid"] == "R1" and setc["layer"] == "Network"
    assert setc["new-name"] == "Allow win_client -> Facebook" and "name" not in setc
    assert "source" not in setc and "destination" not in setc and "service" not in setc and "action" not in setc
    assert ("publish", {}) in calls
    # the recorded inverse restores the OLD name (read back as 'name', written as 'new-name') -> reversible
    inv = res["inverse"][0]
    assert inv["op"] == "set-access-rule" and inv["uid"] == "R1" and inv["set"]["new-name"] == "old name"
    assert res["changed"] == {"name": "Allow win_client -> Facebook"}


def test_amend_naming_a_nameless_rule_records_no_blank_inverse(monkeypatch):
    # HIGH: adding a name to a rule that had none must NOT record an inverse that would BLANK the name on
    # revert (the SMS rejects an empty name) — the name leg yields an empty inverse (recorded non-revertable).
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, rule={"uid": "R1"}))  # no 'name'
    monkeypatch.setattr(aa, "invalidate_cache", lambda *a, **k: None)
    res = aa.amend_execute(object(), "secret", uid="R1", layer="Network", name="Now Named", publish=True)
    assert res["ok"] and next(p for c, p in calls if c == "set-access-rule")["new-name"] == "Now Named"
    assert res["inverse"] == []                          # nothing safe to restore -> no blank-name revert op


def test_amend_execute_sets_track_and_records_inverse(monkeypatch):
    # track (logging) is written as the Track Settings object {"type": "<name>"}; the inverse restores the
    # prior track type read back from show-access-rule's track.type {name} object.
    calls = []
    rule = {"uid": "R1", "name": "r", "track": {"type": {"name": "None", "uid": "t-none"}}}
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, rule=rule))
    monkeypatch.setattr(aa, "invalidate_cache", lambda *a, **k: None)
    res = aa.amend_execute(object(), "secret", uid="R1", layer="Network", track="Log", publish=True)
    assert res["ok"] and res["changed"] == {"track": "Log"}
    setc = next(p for c, p in calls if c == "set-access-rule")
    assert setc["track"] == {"type": "Log"}
    assert res["inverse"][0]["set"]["track"] == {"type": "None"}     # restores the prior track type


def test_amend_execute_dry_run_discards(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, rule={"uid": "R1", "name": "x"}))
    res = aa.amend_execute(object(), "secret", uid="R1", layer="Network", comment="set during PoV", publish=False)
    assert res["ok"] and res["applied"] and not res["published"] and res["validated"]
    assert ("discard", {}) in calls and ("publish", {}) not in calls
    setc = next(p for c, p in calls if c == "set-access-rule")
    assert setc["comments"] == "set during PoV"          # request 'comment' maps to web_api 'comments'


def test_amend_execute_missing_rule_is_clean_error(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, rule=None))   # show-access-rule 404s
    res = aa.amend_execute(object(), "secret", uid="gone", layer="Network", name="x", publish=True)
    assert not res["ok"] and "nothing to edit" in res["error"]
    assert not any(c == "set-access-rule" for c, _ in calls)   # never wrote anything


def test_amend_execute_rejects_empty_and_no_fields():
    assert not aa.amend_execute(object(), "s", uid="R1", layer="L")["ok"]            # nothing to change
    assert not aa.amend_execute(object(), "s", uid="R1", layer="L", name="  ")["ok"]  # empty name


def test_amend_revert_restores_metadata_only(monkeypatch):
    # _apply_inverse_op must accept a metadata 'set' inverse (new-name/comments/tags) ...
    calls = []
    sess = _fake_session_factory(calls, rule={"uid": "R1"})(object(), "s")
    note = aa._apply_inverse_op(sess, {"op": "set-access-rule", "uid": "R1", "layer": "Network",
                                       "set": {"new-name": "old name", "comments": "c", "tags": ["t-old"],
                                               "track": {"type": "None"}}})
    setc = next(p for c, p in calls if c == "set-access-rule")
    assert setc["new-name"] == "old name" and setc["comments"] == "c" and setc["tags"] == ["t-old"]
    assert setc["track"] == {"type": "None"}
    assert "R1" in note
    # ... NEVER a match column: a 'set' that smuggles a source is rejected, not executed.
    with pytest.raises(aa.MgmtError):
        aa._apply_inverse_op(sess, {"op": "set-access-rule", "uid": "R1", "layer": "Network",
                                    "set": {"source": "Any"}})
    # ... and NEVER replays a blank name/track (empty values screened; here only comments survive).
    calls.clear()
    aa._apply_inverse_op(sess, {"op": "set-access-rule", "uid": "R1", "layer": "Network",
                                "set": {"new-name": "", "track": {"type": ""}, "comments": "keep"}})
    setc2 = next(p for c, p in calls if c == "set-access-rule")
    assert "new-name" not in setc2 and "track" not in setc2 and setc2["comments"] == "keep"


def test_amend_target_from_change_only_resolves_a_CREATED_rule():
    from app.services import mcp_tools as mt

    class _Create:                                       # create/deny inverse DELETES the rule it added
        layer = "Network"
        inverse_json = [{"op": "delete-access-rule", "uid": "rule-561", "layer": "Network"}]
    assert mt._amend_target_from_change(_Create()) == ("rule-561", "Network")

    class _Widen:                                        # widen/disable inverse set-access-rule's a PRE-EXISTING rule
        layer = "DNS_Layer"
        inverse_json = [{"op": "set-access-rule", "uid": "prod-rule-9", "layer": "DNS_Layer",
                         "source": {"remove": "h-x"}}]
    assert mt._amend_target_from_change(_Widen()) == (None, "DNS_Layer")   # refused -> won't relabel prod rule

    class _Empty:
        layer = "X"
        inverse_json = []
    assert mt._amend_target_from_change(_Empty()) == (None, "X")


# --- remove an APPLICATION when a broad L4 accept above can carry it (block ABOVE the enabler) -------
def _app_req(src="10.1.1.222/32"):
    return AccessRequest(src_cidrs=[src], dst_cidrs=["Any"], application="Facebook")


def test_remove_app_blocks_above_enabling_l4_accept_with_explicit_grant():
    # The lab case: Outbound (net -> Any, http/https) sits ABOVE an explicit "Allow Facebook" rule whose
    # source has two hosts. Blocking 10.1.1.222 -> Facebook must drop ABOVE Outbound (first-match), not next
    # to the app rule (which Outbound's https would bypass). Used to bail to REVIEW.
    web = _rule("web", 9, "Accept", _net("10.1.1.0/24"), ANY, _tcp("80,443"))
    fb = _rule("fb", 13, "Accept", _host("10.1.1.222") + _host("10.1.2.250"), ANY, _app({"Facebook"}))
    d = aa.decide_removal(_app_req(), [web, fb, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DENY
    assert d.target_rule.uid == "web" and d.position == {"above": "web"}          # ABOVE the L4 enabler
    assert any("narrow" in n.lower() for n in d.notes)                            # flags the explicit grant


def test_remove_app_only_web_accept_denies_above_it():
    # No explicit app rule — just the L4 Outbound that can carry the app. Block above it (post-loop), not REVIEW.
    web = _rule("web", 9, "Accept", _net("10.1.1.0/24"), ANY, _tcp("80,443"))
    d = aa.decide_removal(_app_req(), [web, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DENY and d.target_rule.uid == "web" and d.position == {"above": "web"}


def test_remove_app_explicit_only_still_disables():
    # No broad L4 accept above -> the explicit app rule grants EXACTLY this -> clean DISABLE (no regression).
    fb = _rule("fb", 13, "Accept", _host("10.1.1.222"), ANY, _app({"Facebook"}))
    d = aa.decide_removal(_app_req(), [fb, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.DISABLE and d.target_rule.uid == "fb"


def test_remove_port_request_vs_app_rule_still_reviews():
    # A PORT removal (not an app) facing an indeterminate app rule stays conservative -> REVIEW (unchanged).
    appr = _rule("ar", 9, "Accept", _net("10.1.1.0/24"), ANY, _app({"Facebook"}))
    d = aa.decide_removal(_req("10.1.1.222/32", "172.16.5.10/32"), [appr, CLEANUP])
    assert d.outcome is aa.RemovalOutcome.REVIEW


# --- auto-narrow: remove the blocked host from the explicit grant's source (apply-time proof) --------
def _deny_with_narrow():
    enabler = _rule("web", 9, "Accept", _net("10.1.1.0/24"), ANY, _tcp("80,443"))
    fb = _rule("fb", 13, "Accept", _host("10.1.1.222") + _host("10.1.2.250"), ANY, _app({"Facebook"}))
    return aa.RemovalDecision(aa.RemovalOutcome.DENY, "block above enabler", target_rule=enabler,
                              position={"above": "web"}, narrow_rule=fb)


def test_apply_removal_narrows_explicit_grant_and_records_source_add_inverse(monkeypatch):
    calls = []
    # the explicit grant has TWO direct host members; the request host is one of them -> narrowable
    rule = {"uid": "fb", "source": [{"name": "win_client", "ipv4-address": "10.1.1.222"},
                                     {"name": "win_server", "ipv4-address": "10.1.2.250"}]}
    sess = _fake_session_factory(calls, hosts={"10.1.1.222": "win_client"}, rule=rule)(object(), "s")
    req = AccessRequest(src_cidrs=["10.1.1.222/32"], dst_cidrs=["Any"], application="Facebook")
    out = aa._apply_removal(sess, _deny_with_narrow(), req, "Network", "")
    # the Drop was added AND the explicit grant's source was narrowed (remove the blocked host)
    setc = next(p for c, p in calls if c == "set-access-rule")
    assert setc["uid"] == "fb" and setc["source"] == {"remove": "win_client"}
    assert out["narrowed"] == {"rule_uid": "fb", "member": "win_client"}
    # compound inverse: delete the Drop AND re-add the member (source.add) -> full rollback
    ops = out["inverse"]
    assert ops[0]["op"] == "delete-access-rule"
    assert ops[1] == {"op": "set-access-rule", "uid": "fb", "layer": "Network", "field": "source", "add": "win_client"}


def test_narrow_member_name_guards(monkeypatch):
    req = AccessRequest(src_cidrs=["10.1.1.222/32"], dst_cidrs=["Any"], application="Facebook")
    # (a) sole member -> never empties the cell -> None
    s1 = _fake_session_factory([], rule={"uid": "r", "source": [{"name": "win_client", "ipv4-address": "10.1.1.222"}]})(object(), "s")
    assert aa._narrow_member_name(s1, "r", "L", req) is None
    # (b) host only INSIDE a group (no direct member matches the /32) -> None
    s2 = _fake_session_factory([], rule={"uid": "r", "source": [{"name": "g", "type": "group"},
                                                                {"name": "other", "ipv4-address": "10.9.9.9"}]})(object(), "s")
    assert aa._narrow_member_name(s2, "r", "L", req) is None
    # (c) exactly one direct match among >=2 members -> the member name
    s3 = _fake_session_factory([], rule={"uid": "r", "source": [{"name": "win_client", "ipv4-address": "10.1.1.222"},
                                                                {"name": "win_server", "ipv4-address": "10.1.2.250"}]})(object(), "s")
    assert aa._narrow_member_name(s3, "r", "L", req) == "win_client"


def test_remove_inverse_whitelist_allows_source_add_only_for_real_fields():
    calls = []
    sess = _fake_session_factory(calls)(object(), "s")
    note = aa._apply_inverse_op(sess, {"op": "set-access-rule", "uid": "fb", "layer": "Network",
                                       "field": "source", "add": "win_client"})
    assert next(p for c, p in calls if c == "set-access-rule")["source"] == {"add": "win_client"} and "fb" in note
    with pytest.raises(aa.MgmtError):          # a non-whitelisted field can't be smuggled via 'add'
        aa._apply_inverse_op(sess, {"op": "set-access-rule", "uid": "fb", "layer": "Network",
                                    "field": "action", "add": "Accept"})


# --- full-column support: ACTION (Drop/Reject/Ask/Inform/Apply Layer) -----------------------------
def _act_req(action, src="10.1.1.50/32", dst="10.1.2.250/32", port="3389", **kw):
    return AccessRequest([src], [dst], protocol="tcp", ports=port, action=action, **kw)


def test_canonical_action_and_build_request_validation():
    assert aa.canonical_action("drop") == "Drop" and aa.canonical_action("APPLY  LAYER") == "Apply Layer"
    assert aa.canonical_action("") == "Accept" and aa.canonical_action("bogus") == ""
    from app.services import ticketing
    assert ticketing.build_request("10.1.1.5", "10.1.2.5", "tcp", "443", action="reject").canon_action == "Reject"
    with pytest.raises(ValueError):                              # garbage/legacy never silently Accepts
        ticketing.build_request("10.1.1.5", "10.1.2.5", "tcp", "443", action="User Auth")
    with pytest.raises(ValueError):                              # Apply Layer needs an inline layer
        ticketing.build_request("10.1.1.5", "10.1.2.5", "tcp", "443", action="Apply Layer")
    with pytest.raises(ValueError):                              # inline layer only valid with Apply Layer
        ticketing.build_request("10.1.1.5", "10.1.2.5", "tcp", "443", action="Accept", inline_layer="X")


def test_decide_action_drop_above_covering_accept():
    a = _rule("a", 1, "Accept", _host("10.1.1.50"), _host("10.1.2.250"), _tcp(3389))
    d = aa.decide(_act_req("Drop"), [a, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "a"} and d.target_rule.uid == "a"


def test_decide_action_reject_like_drop():
    a = _rule("a", 1, "Accept", _host("10.1.1.50"), _host("10.1.2.250"), _tcp(3389))
    assert aa.decide(_act_req("Reject"), [a, CLEANUP]).outcome is Outcome.CREATE


def test_decide_action_drop_already_denied_noop():
    dny = _rule("d", 1, "Drop", _host("10.1.1.50"), _host("10.1.2.250"), _tcp(3389))
    assert aa.decide(_act_req("Drop"), [dny, CLEANUP]).outcome is Outcome.NO_OP


def test_decide_action_drop_nothing_grants_noop():
    # only the Any/Any/Any cleanup drop covers it -> already denied -> NO_OP (nothing to add)
    assert aa.decide(_act_req("Drop", src="10.9.9.9/32", dst="10.8.8.8/32", port="9"), [CLEANUP]).outcome is Outcome.NO_OP


def test_decide_action_ask_always_creates_above():
    a = _rule("a", 1, "Accept", _host("10.1.1.50"), _host("10.1.2.250"), _tcp(3389))
    d = aa.decide(_act_req("Ask"), [a, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "a"}    # Ask takes effect over the accept


def test_decide_action_apply_layer_creates():
    d = aa.decide(_act_req("Apply Layer", inline_layer="DNS_Layer"), [CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_execute_action_drop_writes_drop_rule(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, hosts={"10.1.1.50": "h1", "10.1.2.250": "h2"}))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [
        _rule("a", 1, "Accept", _host("10.1.1.50"), _host("10.1.2.250"), _tcp(3389)), CLEANUP])
    monkeypatch.setattr(aa, "invalidate_cache", lambda *a, **k: None)
    res = aa.execute(object(), "s", _act_req("Drop"), "Network", publish=True)
    assert res["ok"] and res["outcome"] == "create"
    addc = next(p for c, p in calls if c == "add-access-rule")
    assert addc["action"] == "Drop" and "action-settings" not in addc


def test_execute_action_ask_with_captive_portal_writes_action_settings(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, hosts={"10.1.1.50": "h1", "10.1.2.250": "h2"}))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [CLEANUP])
    monkeypatch.setattr(aa, "invalidate_cache", lambda *a, **k: None)
    res = aa.execute(object(), "s", _act_req("Ask", action_settings_captive_portal=True), "Network", publish=True)
    addc = next(p for c, p in calls if c == "add-access-rule")
    assert addc["action"] == "Ask" and addc["action-settings"] == {"enable-identity-captive-portal": True}


def test_execute_apply_layer_validates_and_writes_inline_layer(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(
        calls, hosts={"10.1.1.50": "h1", "10.1.2.250": "h2"}, layers=[{"name": "DNS_Layer", "uid": "l1"}]))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [CLEANUP])
    monkeypatch.setattr(aa, "invalidate_cache", lambda *a, **k: None)
    ok = aa.execute(object(), "s", _act_req("Apply Layer", inline_layer="DNS_Layer"), "Network", publish=True)
    addc = next(p for c, p in calls if c == "add-access-rule")
    assert addc["action"] == "Apply Layer" and addc["inline-layer"] == "DNS_Layer"
    # a non-existent inline layer fails loud (no dangling divert), session discards -> ok False
    calls2 = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(
        calls2, hosts={"10.1.1.50": "h1", "10.1.2.250": "h2"}, layers=[{"name": "DNS_Layer", "uid": "l1"}]))
    bad = aa.execute(object(), "s", _act_req("Apply Layer", inline_layer="Nope"), "Network", publish=True)
    assert not bad["ok"] and "no access layer" in bad["error"].lower()


# --- full-column support: CONTENT / TIME / INSTALL-ON / VPN (write + request + engine guard) --------
# gateway/server classes the dedicated show-gateways-and-servers command enumerates (a subset, for the fake)
_GW_LIST_TYPES = {"simple-gateway", "simple-cluster", "CpmiGatewayCluster", "CpmiClusterMember",
                  "CpmiHostCkp", "CpmiGatewayPlain"}
# dedicated list command -> the object types it enumerates (mirrors the real API: these classes are NOT
# reliably returned by show-objects, so the resolver uses these commands instead)
_LIST_CMD_TYPES = {
    "show-vpn-communities-meshed": {"vpn-community-meshed"},
    "show-vpn-communities-star": {"vpn-community-star"},
    "show-vpn-communities-remote-access": {"vpn-community-remote-access"},
    "show-limits": {"limit"},
}


class _GateSession:
    """Mirrors how the reuse-only resolver looks things up: data-types/time via show-objects (typed), and
    gateways / VPN communities / limit objects via their DEDICATED list commands."""
    def __init__(self, objs):
        self.objs, self.calls = objs, []

    def call(self, cmd, payload=None, **k):
        p = payload or {}
        self.calls.append((cmd, p))
        if cmd == "show-objects":
            f, t = p.get("filter"), p.get("type")            # honor the type filter (the real API does)
            return {"objects": [o for o in self.objs if o.get("name") == f and (not t or o.get("type") == t)]}
        if cmd == "show-gateways-and-servers":
            m = [o for o in self.objs if o.get("type") in _GW_LIST_TYPES]
            return {"objects": m, "total": len(m)}
        if cmd in _LIST_CMD_TYPES:
            m = [o for o in self.objs if o.get("type") in _LIST_CMD_TYPES[cmd]]
            return {"objects": m, "total": len(m)}
        return {}


def test_build_request_gating_normalization():
    from app.services import ticketing as t
    r = t.build_request("10.1.1.5", "Any", "tcp", "443", content="A; B, A", content_direction="UP",
                        time_objects=["X", "X"], install_on="GW1, any, GW2", vpn=["Any"])
    assert r.content == ["A", "B"] and r.content_direction == "up"
    assert r.time_objects == ["X"] and r.install_on == ["GW1", "GW2"] and r.vpn == []   # Any->[], dupes/default dropped
    assert t.build_request("10.1.1.5", "Any", "tcp", "443").vpn is None                 # untouched when omitted


def test_restricted_request_forces_create_not_noop():
    a = _rule("a", 1, "Accept", _host("10.1.1.50"), ANY, _tcp(443))
    plain = AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443")
    assert aa.decide(plain, [a, CLEANUP]).outcome is Outcome.NO_OP                       # control: plain -> reuse
    for kw in ({"install_on": ["GW"]}, {"time_objects": ["X"]}, {"vpn": ["C"]},
               {"content": ["PCI"]}):
        req = AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443", **kw)
        assert aa.decide(req, [a, CLEANUP]).outcome is Outcome.CREATE, kw                # restricted -> never false NO_OP


def test_write_gating_columns_all_four(monkeypatch):
    objs = [{"name": "PCI", "type": "data-type-patterns"}, {"name": "Off-Work", "type": "time"},
            {"name": "GW", "type": "simple-gateway"}, {"name": "MyComm", "type": "vpn-community-star"}]
    s = _GateSession(objs)
    req = AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443",
                        content=["PCI"], content_direction="up", content_negate=True,
                        time_objects=["Off-Work"], install_on=["GW"], vpn=["MyComm"])
    p = {}
    aa._write_gating_columns(s, p, req)
    assert p["content"] == ["PCI"] and p["content-direction"] == "up" and p["content-negate"] is True
    assert p["time"] == ["Off-Work"] and p["install-on"] == ["GW"] and p["vpn"] == ["MyComm"]


def test_write_gating_vpn_any_literals_and_unknown_errors():
    aa._write_gating_columns(_GateSession([]), p := {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp",
                             ports="443", vpn=[]))
    assert "vpn" not in p                                                                # Any -> omit the key
    # All_GwToGw is a whitelisted literal (no object lookup needed)
    aa._write_gating_columns(_GateSession([]), q := {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp",
                             ports="443", vpn=["All_GwToGw"]))
    assert q["vpn"] == ["All_GwToGw"]
    with pytest.raises(aa.MgmtError):                                                    # unknown gateway -> loud
        aa._write_gating_columns(_GateSession([]), {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp",
                                 ports="443", install_on=["NopeGW"]))


def test_write_gating_content_type_prefix_gate():
    # an exact-name object whose type does NOT start with "data-type" is NOT accepted as content
    s = _GateSession([{"name": "X", "type": "host"}])
    with pytest.raises(aa.MgmtError):
        aa._write_gating_columns(s, {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443",
                                 content=["X"]))


# --- full-column validation fixes (round 2) -------------------------------------------------------
def test_restricted_accept_anchored_above_covering_accept():
    # HIGH #19: a restricted Accept must be placed ABOVE the broad covering Accept (or it's a dead rule).
    a = _rule("a", 1, "Accept", _host("10.1.1.50"), ANY, _tcp(443))
    req = AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443", time_objects=["Off-Work"])
    d = aa.decide(req, [a, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "a"}


def test_action_settings_force_create_above_covering_accept():
    # HIGH #5: an Accept asking for captive-portal/limit must not NO_OP a plain covering Accept (control lost).
    a = _rule("a", 1, "Accept", _host("10.1.1.50"), ANY, _tcp(443))
    req = AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443", action_settings_captive_portal=True)
    d = aa.decide(req, [a, CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "a"}


def test_decide_unknown_action_reviews():
    # #17: a directly-built request with a bad/legacy action -> REVIEW (engine self-defends; never writes Accept)
    req = AccessRequest(["10.1.1.50/32"], ["10.1.2.250/32"], protocol="tcp", ports="443", action="User Auth")
    assert aa.decide(req, [CLEANUP]).outcome is Outcome.REVIEW


def test_conditional_above_covering_drop_respects_override():
    # #6/#11: Ask above a covering DROP loosens an admin deny -> with override off, place BELOW + flag.
    d = _rule("d", 1, "Drop", _host("10.1.1.50"), _host("10.1.2.250"), _tcp(3389))
    req = AccessRequest(["10.1.1.50/32"], ["10.1.2.250/32"], protocol="tcp", ports="3389", action="Ask")
    dec = aa.decide(req, [d, CLEANUP], aa.DecideOptions(override_blocking_deny=False))
    assert dec.outcome is Outcome.CREATE and dec.position == {"below": "d"}
    # with override on, it carves above to take effect
    dec2 = aa.decide(req, [d, CLEANUP], aa.DecideOptions(override_blocking_deny=True))
    assert dec2.outcome is Outcome.CREATE and dec2.position == {"above": "d"}


def test_block_with_no_cleanup_creates_not_noop():
    # #16: a Drop request with NOTHING in path (no catch-all) must CREATE the drop (cleanup may be accept).
    a = _rule("a", 1, "Accept", _host("10.9.9.9"), _host("10.8.8.8"), _tcp(22))   # unrelated, out of path
    req = AccessRequest(["10.1.1.50/32"], ["10.1.2.250/32"], protocol="tcp", ports="3389", action="Drop")
    assert aa.decide(req, [a]).outcome is Outcome.CREATE      # no cleanup -> create the drop, not false NO_OP


def test_content_any_is_not_a_restriction():
    # #3: content "Any" == no content restriction -> not written, and not "restricted"
    s = _GateSession([])
    aa._write_gating_columns(s, p := {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443",
                             content=["Any"]))
    assert "content" not in p and not any(c == "show-objects" for c, _ in s.calls)


def test_action_settings_limit_validated_reuse_only(monkeypatch):
    # HIGH #1: a bad limit object name fails the atomic pre-flight, not a live add-access-rule rejection
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, hosts={"10.1.1.50": "h1", "10.1.2.250": "h2"}))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [CLEANUP])
    req = AccessRequest(["10.1.1.50/32"], ["10.1.2.250/32"], protocol="tcp", ports="443",
                        action_settings_limit="Nope_Limit")
    res = aa.execute(object(), "s", req, "Network", publish=True)
    assert not res["ok"] and "limit" in res["error"].lower()
    assert not any(c == "add-access-rule" for c, _ in calls)   # never reached the write


# --- full-column validation fixes (round 3 — re-validation findings) ------------------------------
def test_content_any_normalized_at_engine_boundary():
    # #1/#11/#13/#14/#19: content/vpn ["Any"] (and install-on "Policy Targets") are NOT restrictions, no
    # matter how the request is built — normalized in AccessRequest.__post_init__, so no phantom CREATE.
    r = AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443",
                      content=["Any"], vpn=["any"], install_on=["Policy Targets"])
    assert r.content == [] and r.vpn == [] and r.install_on == [] and not r.is_restricted
    a = _rule("a", 1, "Accept", _host("10.1.1.50"), ANY, _tcp(443))
    assert aa.decide(r, [a, CLEANUP]).outcome is Outcome.NO_OP        # reuses the covering Accept, no duplicate


def test_content_negate_over_only_any_is_dropped():
    # #1/#20: content_negate over ONLY "Any" is meaningless -> dropped at the engine boundary (never a CREATE
    # whose written rule lacks the negate that justified it). build_request rejects it loudly.
    r = AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443",
                      content=["Any"], content_negate=True)
    assert r.content == [] and r.content_negate is False and not r.is_restricted
    from app.services import ticketing as t
    with pytest.raises(ValueError):
        t.build_request("10.1.1.5", "Any", "tcp", "443", content="Any", content_negate=True)


def test_install_on_resolves_via_gateways_command_not_show_objects():
    # HIGH #6: a gateway is resolved via show-gateways-and-servers (CPMI types are invalid show-objects
    # filters), and a gateway GROUP — which that command does NOT enumerate — is confirmed via the typed
    # `group` fallback (an install-on group target is legitimate); a genuine typo is rejected.
    s = _GateSession([{"name": "GW", "type": "CpmiGatewayCluster"}, {"name": "GwGrp", "type": "group"}])
    aa._write_gating_columns(s, p := {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443",
                             install_on=["GW"]))
    assert p["install-on"] == ["GW"]
    assert not any(c == "show-objects" for c, _ in s.calls)           # a gateway hit needs no show-objects probe
    aa._write_gating_columns(s, q := {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443",
                             install_on=["GwGrp"]))
    assert q["install-on"] == ["GwGrp"]                               # a group of gateways: valid via fallback
    with pytest.raises(aa.MgmtError):                                 # a genuine typo (not a gw/server/group)
        aa._write_gating_columns(s, {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443",
                                 install_on=["NopeTypo"]))


def test_reuse_validation_best_effort_when_class_not_enumerable():
    # #2/#6: if the dedicated list command is unavailable on this version (errors), don't FALSE-reject a
    # legitimate object — pass it through (the SMS validates at write; the apply discards atomically on failure).
    class _NoCmd:
        def call(self, cmd, payload=None, **k):
            if cmd in ("show-vpn-communities-meshed", "show-vpn-communities-star",
                       "show-vpn-communities-remote-access", "show-limits", "show-gateways-and-servers"):
                raise aa.MgmtError("command not found on this version")
            return {}
    aa._write_gating_columns(_NoCmd(), p := {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp",
                             ports="443", vpn=["RealComm"], install_on=["RealGW"]))
    assert p["vpn"] == ["RealComm"] and p["install-on"] == ["RealGW"]


def test_conditional_floored_below_opaque_possible_deny():
    # HIGH #10: an Ask/Inform/Apply-Layer verdict must NOT be anchored ABOVE an opaque/partial possible-deny
    # (first-match would leap it). It is floored at the section bottom + flagged instead.
    partial_drop = _rule("d", 1, "Drop", _host("10.1.1.50"), _host("10.1.2.250"), _tcp(3389))  # ⊂ request: partial
    clean_accept = _rule("a", 2, "Accept", ANY, ANY, ServiceSet(any=True))
    req = AccessRequest(["10.1.1.0/24"], ["10.1.2.250/32"], protocol="tcp", ports="3389", action="Ask")
    d = aa.decide(req, [partial_drop, clean_accept])
    assert d.outcome is Outcome.CREATE and not d.position          # floored (no anchor), not above the accept
    assert any("possible-deny" in n for n in (d.notes or [])) or "possible-deny" in d.reason
    # control: with NO opaque deny in path, the Ask anchors ABOVE the clean accept
    d2 = aa.decide(AccessRequest(["10.1.1.50/32"], ["10.1.2.250/32"], protocol="tcp", ports="3389", action="Ask"),
                   [clean_accept])
    assert d2.outcome is Outcome.CREATE and d2.position == {"above": "a"}


def test_apply_widen_rejects_restricted_request():
    # #8: a directly-built WIDEN decision carrying a restriction must fail loud (would silently drop the column).
    tgt = _rule("a", 1, "Accept", _host("10.1.1.50"), ANY, _tcp(443))
    dec = aa.Decision(Outcome.WIDEN, "widen", target_rule=tgt, widen_field="source")
    req = AccessRequest(["10.1.1.51/32"], ["Any"], protocol="tcp", ports="443", time_objects=["X"])
    with pytest.raises(aa.MgmtError):
        aa._apply(_GateSession([]), dec, req, "Network", [tgt, CLEANUP], "T")


def test_validate_inline_layer_transient_error_is_not_not_found():
    # #4/#12/#22: a FAILED show-access-layers must re-raise as transient, not assert "no such layer".
    class _Boom:
        def call(self, cmd, payload=None, **k):
            raise aa.MgmtError("connection reset")
    with pytest.raises(aa.MgmtError) as ei:
        aa._validate_inline_layer(_Boom(), "Web_Layer")
    assert "could not list" in str(ei.value).lower()


def test_build_request_rejects_action_settings_on_block():
    # #16: action-settings (limit/captive portal) on a Drop/Reject/Apply-Layer is rejected, not silently dropped.
    from app.services import ticketing as t
    with pytest.raises(ValueError):
        t.build_request("10.1.1.5", "10.1.2.2", "tcp", "3389", action="Drop", action_settings_captive_portal=True)
    with pytest.raises(ValueError):
        t.build_request("10.1.1.5", "10.1.2.2", "tcp", "3389", action="Reject", action_settings_limit="L1")


def test_resolver_transient_paging_failure_passes_through_not_false_reject():
    # round-4 HIGH: a transient error AFTER progress (a later page / a sibling command) must degrade the
    # whole column to best-effort pass-through, NEVER finalize a truncated set that false-rejects a real object.
    class _FlakyPager:
        def __init__(self):
            self.calls = 0
        def call(self, cmd, payload=None, **k):
            if cmd == "show-gateways-and-servers":
                self.calls += 1
                if (payload or {}).get("offset", 0) == 0:
                    return {"objects": [{"name": f"gw{i}"} for i in range(200)], "total": 500}  # page 1 of 3
                raise aa.MgmtError("connection reset")                # transient on page 2 (offset 200)
            return {}
    aa._write_gating_columns(_FlakyPager(), p := {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp",
                             ports="443", install_on=["gw300"]))      # on page 3 — would be lost in a truncated set
    assert p["install-on"] == ["gw300"]                              # passed through, not false-rejected
    # a UNION partial (one community command errors after another succeeded) also degrades to pass-through
    class _FlakyUnion:
        def call(self, cmd, payload=None, **k):
            if cmd == "show-vpn-communities-meshed":
                return {"objects": [{"name": "MeshA"}], "total": 1}
            if cmd in ("show-vpn-communities-star", "show-vpn-communities-remote-access"):
                raise aa.MgmtError("timeout")
            return {}
    aa._write_gating_columns(_FlakyUnion(), q := {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp",
                             ports="443", vpn=["StarComm"]))
    assert q["vpn"] == ["StarComm"]


def test_vpn_remote_access_community_resolves():
    # round-4 MEDIUM: a remote-access community must validate (show-vpn-communities-remote-access is in the union).
    s = _GateSession([{"name": "RA_Comm", "type": "vpn-community-remote-access"}])
    aa._write_gating_columns(s, p := {}, AccessRequest(["10.1.1.50/32"], ["Any"], protocol="tcp", ports="443",
                             vpn=["RA_Comm"]))
    assert p["vpn"] == ["RA_Comm"]


def test_webhook_bare_action_is_lenient_dedicated_field_strict():
    # #18: a ServiceNow ticket's unrelated `action` field must NOT hard-fail the request (default Accept);
    # a DEDICATED verdict field is taken strictly (a bad value errors).
    from app.services import ticketing as t
    base = {"server_id": 1, "layer": "Network", "source": "10.1.1.5", "destination": "10.1.2.2", "port": "443"}
    tr = t.parse_payload({**base, "action": "close_ticket"})          # unrelated workflow action -> ignored
    assert tr.request.canon_action == "Accept"
    tr2 = t.parse_payload({**base, "action": "Drop"})                 # a real verdict in `action` -> honoured
    assert tr2.request.canon_action == "Drop"
    with pytest.raises(ValueError):                                   # a dedicated verdict field is strict
        t.parse_payload({**base, "verdict": "NotAVerdict"})
