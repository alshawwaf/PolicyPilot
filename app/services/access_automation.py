"""Ticket-driven access automation engine.

Turns an access request (source, destination, service) into the *minimal correct*
change on a Check Point access layer, via the Management web_api. Mirrors the
four-outcome model that FireMon / Tufin Designer / AlgoSec FireFlow converge on,
grounded in the Al-Shaer & Hamed five-relation algebra (IEEE JSAC 2005):

    NO_OP  - the flow is already permitted              -> change nothing
    WIDEN  - a rule already covers dst+svc, src differs -> extend its source
             (prefer a group the rule already references)
    CREATE - nothing permits it (or a deny blocks it)   -> add a least-privilege
             rule; placed ABOVE a blocking deny so the access takes effect, below
             any more-specific rule, else above the cleanup

The engine is built for AUTOMATION: it never hard-stops the flow for a policy
"review". A rule it can't fully resolve (an updatable feed, a negated/unparsable
cell, a conditional or inline-layer rule) is NOTED as a "possible match — review
later" and the walk CONTINUES; the new allow is then placed BELOW that rule so it
can't leap over a possible block. (Outcome.REVIEW survives only as a defensive
signal for an INCOMPLETE request — no concrete service, or an endpoint that names
no object — and for an ambiguous application/service NAME that matches no single
Check Point object, where the caller returns "did you mean …" suggestions.)

Design
------
* ``decide()`` is PURE (no I/O). It runs on already-parsed rules, so it is unit
  testable and drives the dry-run preview. Run this module directly
  (``python -m app.services.access_automation``) for an offline smoke test.
* The rulebase is pulled the same way ``mgmt_api.pull_for_export`` does it:
  ``show-access-rulebase`` with ``use-object-dictionary`` + ``details-level full``,
  then cells are resolved through the object dictionary to effective IP / port
  intervals. Comparisons are on values, never on object names.
* ``preview()`` is read-only. ``execute()`` writes inside ONE session and then
  publishes (commit) or discards (validate-only / on error) — same transactional
  shape as ``mgmt_api.apply_changes``.

VERIFY markers
--------------
Tokens tagged ``# VERIFY`` are exact web_api parameter spellings (e.g.
``members.add``, ``source.add``, ``position {above: uid}``). The *capability* is
confirmed by research; the precise spelling should be checked against a live
R82.10 management server (the SBT lab) before production use. IPv4 + IPv6 are both
modeled (a dual-band integer space, see _V6_BASE); port-based tcp/udp/sctp and
named services are handled, while truly unparsable cells fall through to REVIEW.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("policypilot.access_automation")

try:  # keep the engine import-safe outside the app runtime (offline smoke test)
    from .mgmt_api import (MgmtError, MgmtSession, _is_lock_error, cached_raw, invalidate_cache,
                           locking_sessions, read_session, write_session, write_session_timeout)
except Exception:  # pragma: no cover
    MgmtSession = object  # type: ignore
    read_session = cached_raw = invalidate_cache = locking_sessions = None  # type: ignore
    write_session = None                  # type: ignore
    write_session_timeout = lambda: 300  # type: ignore  # noqa: E731
    _is_lock_error = lambda m: False     # type: ignore  # noqa: E731

    class MgmtError(Exception):
        pass


# IPv4 and IPv6 share ONE integer line, in two non-overlapping BANDS: v4 in [0, 2^32) and v6 mapped to
# [_V6_BASE, _V6_BASE + 2^128). A point/interval lives in exactly one band, so the existing interval math
# (relation/_covers/_overlaps) treats v4 vs v6 as automatically DISJOINT (different bands) while same-
# family ranges compare normally — and "Any" (which in Check Point covers BOTH families) spans both bands.
# This is what lets the engine reason about v6 instead of guarding it out: a v6 request is no longer
# "disjoint from everything" (which used to make the Any/Any cleanup invisible -> silent CREATE).
_V4_MAX = (1 << 32) - 1
# v6 is offset into a band that starts ABOVE a deliberate gap (2^33, not 2^32) so the v4 and v6 bands are
# never ADJACENT — otherwise _merge (which fuses intervals touching at +1) would coalesce an all-v4 +
# all-v6 set into one interval. That fusion is provably lossless (no integer exists between 2^32-1 and
# 2^32), but the gap makes the separation structural so a v4-all + v6-all GROUP stays two intervals that
# mirror ANY_IP exactly, and no future change to _merge can ever leak coverage across the families.
_V6_BASE = 1 << 33
_V6_MAX = (1 << 128) - 1
ANY_IP: list[tuple[int, int]] = [(0, _V4_MAX), (_V6_BASE, _V6_BASE + _V6_MAX)]

# The predefined topology-based "Internet" object. It is a global object in the "Check Point Data" domain
# with the FIXED uid below and type "Internet" — and it is NOT returned in a per-rulebase
# objects-dictionary, so a destination reference to it frequently can't be dereferenced to a name (only the
# bare uid is available). Recognize it by this uid (definitive across deployments — predefined uids are
# fixed) or by type, so an Internet-dest rule isn't read as opaque and disqualified from reuse/widen.
_INTERNET_UID = "f99b1488-7510-11e2-8668-87656188709b"


def _addr_point(addr: str) -> int:
    """An IP (v4 or v6) -> its point on the shared integer line (v6 offset into its band)."""
    ip = ipaddress.ip_address(addr)
    return int(ip) if ip.version == 4 else _V6_BASE + int(ip)


def _net_interval(net) -> tuple[int, int]:
    """An ip_network (v4 or v6) -> its (lo, hi) interval on the shared line (v6 offset into its band)."""
    base = 0 if net.version == 4 else _V6_BASE
    return (base + int(net.network_address), base + int(net.broadcast_address))


# --------------------------------------------------------------------------- #
# Interval math -- the Al-Shaer relation primitive (compare per field, by value)
# --------------------------------------------------------------------------- #
def _merge(iv):
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(iv):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _subtract(base, exclude):
    """Interval-set difference base ∖ exclude (both lists of (lo,hi)). Exact: used to resolve a
    group-with-exclusion (include minus except) to its real extent."""
    result = []
    for lo, hi in _merge(base):
        segs = [(lo, hi)]
        for elo, ehi in _merge(exclude):
            nxt = []
            for slo, shi in segs:
                if ehi < slo or elo > shi:        # no overlap -> keep the segment
                    nxt.append((slo, shi))
                    continue
                if slo < elo:                     # piece left of the exclusion
                    nxt.append((slo, elo - 1))
                if ehi < shi:                     # piece right of the exclusion
                    nxt.append((ehi + 1, shi))
            segs = nxt
        result.extend(segs)
    return _merge(result)


_WILDCARD_CAP = 256        # max intervals a wildcard may expand to before we keep it opaque (REVIEW)


def _wildcard_to_intervals(addr: str, mask: str, base: int, bits: int):
    """Expand a Check Point wildcard (address + WILDCARD mask, where a 1-bit means 'don't care') into the
    EXACT set of (lo,hi) intervals it matches, mapped into the given band. The low contiguous run of
    don't-care bits is one range; each combination of the higher scattered don't-care bits is a separate
    range. Returns None if it would explode past the cap (-> caller keeps it opaque, REVIEW) or on a parse
    error — never an over-approximation."""
    a, m = int(ipaddress.ip_address(addr)), int(ipaddress.ip_address(mask))
    fixed = a & ~m & ((1 << bits) - 1)            # base with every don't-care bit zeroed
    low = 0
    while low < bits and (m >> low) & 1:          # contiguous low don't-care run -> a 2^low block
        low += 1
    block = 1 << low
    scattered = [i for i in range(low, bits) if (m >> i) & 1]
    if len(scattered) > 16 or (1 << len(scattered)) > _WILDCARD_CAP:
        return None                               # too many disjoint ranges -> opaque
    intervals = []
    for combo in range(1 << len(scattered)):
        off = 0
        for j, pos in enumerate(scattered):
            if (combo >> j) & 1:
                off |= (1 << pos)
        intervals.append((base + fixed + off, base + fixed + off + block - 1))
    return _merge(intervals)


def _covers(big, small) -> bool:
    """True if every interval in ``small`` is fully contained in ``big``."""
    for lo, hi in small:
        if not any(blo <= lo and hi <= bhi for blo, bhi in big):
            return False
    return True


def _overlaps(a, b) -> bool:
    return any(alo <= bhi and blo <= ahi for alo, ahi in a for blo, bhi in b)


class Relation(str, Enum):
    DISJOINT = "disjoint"
    EQUAL = "equal"
    SUBSET = "subset"      # request is contained by rule  (request <= rule)
    SUPERSET = "superset"  # request contains rule         (request >= rule)
    OVERLAP = "overlap"    # partial / correlated


def relation(req, rule) -> Relation:
    if not _overlaps(req, rule):
        return Relation.DISJOINT
    req_in_rule = _covers(rule, req)
    rule_in_req = _covers(req, rule)
    if req_in_rule and rule_in_req:
        return Relation.EQUAL
    if req_in_rule:
        return Relation.SUBSET
    if rule_in_req:
        return Relation.SUPERSET
    return Relation.OVERLAP


@dataclass
class ServiceSet:
    """The 'Services & Applications' cell: port services (proto -> port intervals), application-site
    names, an 'Any' flag, an 'opaque' flag (an app category/group we can't enumerate), the truly
    unparsable flag, and the service-group uids it references (for widening)."""
    any: bool = False
    by_proto: dict = field(default_factory=dict)
    apps: set = field(default_factory=set)        # exact application-site names (e.g. {"Facebook"})
    categories: set = field(default_factory=set)  # application-site-CATEGORY names (e.g. {"Social Networking"})
    named: set = field(default_factory=set)       # non-port service objects by name (icmp, GRE, sctp, …)
    opaque: bool = False                          # an app category/group, or a service whose protocol
                                                  # reach we can't bound vs a port request (other/rpc/gtp…)
    app_group: bool = False                       # holds an application-site-GROUP (an opaque app container
                                                  # that is NOT one of the captured `categories`)
    complex: bool = False                         # held a service we could not parse (named, >, < ...)
    group_uids: list = field(default_factory=list)  # service-group uids referenced (widen target)

    def covers(self, other: "ServiceSet") -> bool:
        if self.any:
            return True
        if other.any:
            return False
        for proto, iv in other.by_proto.items():
            mine = self.by_proto.get(proto)
            if not mine or not _covers(mine, iv):
                return False
        return True

    def overlaps(self, other: "ServiceSet") -> bool:
        if self.any or other.any:
            return True
        for proto, iv in other.by_proto.items():
            mine = self.by_proto.get(proto)
            if mine and _overlaps(mine, iv):
                return True
        return False


# --------------------------------------------------------------------------- #
# Typed (non-IP) source/destination objects
# --------------------------------------------------------------------------- #
# A source/destination cell can hold objects that do NOT live in IPv4/IPv6 space — they match by a
# different identity entirely: a dns-domain matches by FQDN/DNS, an access-role by identity, a
# security-zone by interface, a dynamic-object by gateway-resolved name, an updatable-object by a
# Check Point-curated feed. The engine reasons about these the SAME way svc_relation reasons about
# apps-vs-ports: each kind is its own space, so two different kinds are provably DISJOINT (an IP
# object can never equal a domain object), with a small set of "opaque" cross-kind cases where one
# kind's container could plausibly include another (an updatable feed can contain FQDNs).
#
# CP object type (lower-cased) -> the TypedExtent field that holds its names.
_TYPED_KIND = {
    "dns-domain": "domains",
    "access-role": "roles",
    "dynamic-object": "dynamic",
    "updatable-object": "updatable",
    "security-zone": "zones",
}
# A request's source/destination "kind" -> the TypedExtent field it matches against. "ip" is the
# default (IPv4/IPv6 interval space) and is handled by the existing relation() path, not here.
_KIND_FIELD = {
    "domain": "domains",
    "access-role": "roles",
    "dynamic-object": "dynamic",
    "updatable-object": "updatable",
    "security-zone": "zones",
    # Check Point's predefined, topology-based "Internet" object — the canonical destination for an
    # Application Control / URL Filtering rule (it matches traffic egressing an External/DMZ interface,
    # i.e. everything the gateway does not know as internal). Its own identity space: a request to
    # Internet is EQUAL to a cell holding Internet, SUBSET of Any, and DISJOINT from any IP cell (a
    # gateway/host IP is not the Internet object) — which is why an Internet-dest request steps cleanly
    # past a Stealth rule (Any -> gateway, drop) instead of being floored below it.
    "internet": "internet",
}
TYPED_KINDS = tuple(k for k in _KIND_FIELD if k != "internet")  # user-pickable typed kinds (both sides)
DEST_ONLY_KINDS = ("internet",)    # selectable only as a destination (App Control / URL Filtering)


@dataclass
class TypedExtent:
    """The non-IP objects a source/destination cell references, grouped by identity space. Parallel to
    the IPv4/IPv6 interval list — a cell can hold both (e.g. a host AND a dns-domain)."""
    domains: set = field(default_factory=set)     # dns-domain object names, e.g. {".example.com"}
    roles: set = field(default_factory=set)        # access-role names
    dynamic: set = field(default_factory=set)      # dynamic-object names
    updatable: set = field(default_factory=set)    # updatable-object names (CP-curated feeds)
    zones: set = field(default_factory=set)        # security-zone names
    internet: set = field(default_factory=set)     # the predefined Internet object (held as {"Internet"})

    def add(self, kind: str, name: str) -> None:
        getattr(self, kind).add(name)

    def any_members(self) -> bool:
        return bool(self.domains or self.roles or self.dynamic or self.updatable or self.zones
                    or self.internet)

    def merge(self, o: "TypedExtent") -> None:
        self.domains |= o.domains
        self.roles |= o.roles
        self.dynamic |= o.dynamic
        self.updatable |= o.updatable
        self.zones |= o.zones
        self.internet |= o.internet


def _domain_norm(name: str) -> tuple[str, bool]:
    """Normalize a dns-domain name to ``(base_fqdn, includes_subdomains)``. Check Point writes a leading
    dot (``.example.com``) to mean 'this domain AND every sub-domain'; no dot means the exact FQDN."""
    n = (name or "").strip().lower().rstrip(".")
    sub = n.startswith(".")
    return n.lstrip("."), sub


def _domain_covers(cell_name: str, req_fqdn: str) -> bool:
    """Does a rule cell's dns-domain object grant a requested domain? A sub-domain object (``.x.com``)
    covers the apex and any sub-domain; an exact object (``x.com``) covers only that FQDN. The REQUEST
    also carries sub-domain semantics (a leading-dot value asks for the domain *and* its sub-domains),
    so an EXACT cell can never cover a sub-domain request — only the same exact FQDN."""
    base, sub = _domain_norm(cell_name)
    req, req_sub = _domain_norm(req_fqdn)
    if not base or not req:
        return False
    if req == base:
        return sub or not req_sub      # an exact cell can't cover a "domain + sub-domains" request
    return bool(sub and req.endswith("." + base))


def _domain_equal(cell_name: str, req_fqdn: str) -> bool:
    """The cell's domain object is EXACTLY the requested domain (same FQDN, same sub-domain semantics)."""
    cb, cs = _domain_norm(cell_name)
    rb, rs = _domain_norm(req_fqdn)
    return cb == rb and cs == rs


def _portset_covers(big: dict, small: dict) -> bool:
    for proto, iv in small.items():
        mine = big.get(proto)
        if not mine or not _covers(mine, iv):
            return False
    return True


def _portset_overlaps(a: dict, b: dict) -> bool:
    return any(proto in b and _overlaps(b[proto], iv) for proto, iv in a.items())


def _svc_single(req: ServiceSet, rule: ServiceSet) -> Relation:
    """Relation for a SINGLE-kind request service (apps XOR named XOR ports) against the rule's cell.
    An opaque app container in the rule yields OVERLAP for a non-matching app request (uncertain)."""
    if req.categories:                    # APPLICATION-CATEGORY request, e.g. {"Social Networking"}
        if req.categories & rule.categories:
            # EXACT only when the cell holds JUST this category and nothing that broadens it. The category
            # itself sets the rule's `opaque` flag (expected), but ANY other content — apps, ports, named
            # services, a service-group, or an application-site-GROUP (app_group) — makes the cell broader,
            # so it's a SUBSET (still a valid reuse), never an over-claiming EQUAL.
            exact = (rule.categories == req.categories and not rule.apps and not rule.by_proto
                     and not rule.named and not rule.group_uids and not rule.app_group)
            return Relation.EQUAL if exact else Relation.SUBSET
        return Relation.OVERLAP if rule.opaque else Relation.DISJOINT
    if req.apps:                          # APPLICATION request, e.g. {"Facebook"}
        if req.apps & rule.apps:
            exact = (rule.apps == req.apps and not rule.by_proto and not rule.named and not rule.opaque)
            return Relation.EQUAL if exact else Relation.SUBSET
        return Relation.OVERLAP if rule.opaque else Relation.DISJOINT
    if req.named:                         # NAMED service request (icmp / GRE / sctp / …) — match by name
        if req.named & rule.named:
            exact = (rule.named == req.named and not rule.by_proto and not rule.apps and not rule.opaque)
            return Relation.EQUAL if exact else Relation.SUBSET
        return Relation.OVERLAP if rule.opaque else Relation.DISJOINT
    if not rule.by_proto:                 # PORT request vs a non-port rule. Disjoint UNLESS the rule holds
        return Relation.OVERLAP if rule.opaque else Relation.DISJOINT   # a protocol-ambiguous service.
    a_in_b = _portset_covers(rule.by_proto, req.by_proto)
    b_in_a = _portset_covers(req.by_proto, rule.by_proto)
    # If the rule cell ALSO holds applications / named services / an opaque member, it grants strictly
    # more than the ports, so a pure-port request can never be EXACTLY EQUAL to it -- only a SUBSET (still
    # 'covered', so a genuine no-op stays a no-op). Returning EQUAL would let a widen treat the service as
    # an exact match and drag the rule's extra apps/services onto the new source/destination.
    rule_port_only = not (rule.apps or rule.named or rule.opaque or rule.complex)
    if a_in_b and b_in_a:
        return Relation.EQUAL if rule_port_only else Relation.SUBSET
    if a_in_b:
        return Relation.SUBSET
    if b_in_a:
        return Relation.SUPERSET
    return Relation.OVERLAP if _portset_overlaps(req.by_proto, rule.by_proto) else Relation.DISJOINT


def _svc_sets_equal(a: ServiceSet, b: ServiceSet) -> bool:
    """True iff two service sets denote the SAME service — identical apps / categories / named / opaque, and
    mutually-covering (i.e. identical) port intervals. Used to promote a MULTI-kind request to EQUAL (which
    unlocks a safe WIDEN) ONLY when the rule is EXACTLY the request. Must never be loose: a rule that is
    BROADER than the request read as EQUAL would let a widen on another dimension grant that broader service
    to the added object (an over-grant)."""
    if a.any or b.any:
        return bool(a.any) and bool(b.any)
    return (a.apps == b.apps and a.categories == b.categories and a.named == b.named
            and bool(a.opaque) == bool(b.opaque)
            and _portset_covers(a.by_proto, b.by_proto) and _portset_covers(b.by_proto, a.by_proto))


def svc_relation(req: ServiceSet, rule: ServiceSet) -> Relation:
    """Relate a request's service to a rule's 'Services & Applications' cell. A request may be port-based
    (by_proto), application-based (apps), or named (icmp/GRE/…) — and a real Check Point service-GROUP can
    bundle MORE THAN ONE kind at once (e.g. tcp/443 + icmp, or an app-site + a port). The kinds are distinct
    spaces, so a multi-kind request is covered ONLY when EVERY kind it spans is covered: we combine the
    per-kind relations by MEET. This stops a rule that grants only one leg of a group from reading EQUAL/
    SUBSET (a false NO_OP / under-grant) or DISJOINT (a false step-over). A single-kind request keeps the
    exact prior behavior."""
    if rule.any and req.any:
        return Relation.EQUAL
    if rule.any:
        return Relation.SUBSET            # a specific request is a subset of Any
    if req.any:
        return Relation.SUPERSET
    present = [k for k, v in (("apps", req.apps), ("categories", req.categories),
                              ("named", req.named), ("ports", req.by_proto)) if v]
    if len(present) <= 1:
        return _svc_single(req, rule)
    rels = []
    for k in present:
        leg = ServiceSet(apps=req.apps if k == "apps" else set(),
                         categories=req.categories if k == "categories" else set(),
                         named=req.named if k == "named" else set(),
                         by_proto=req.by_proto if k == "ports" else {})
        rels.append(_svc_single(leg, rule))
    covered = (Relation.SUBSET, Relation.EQUAL)
    if all(r in covered for r in rels):
        # EQUAL only when the rule denotes EXACTLY the request (structural equality) — never merely because
        # each leg is covered (per-leg comparison against the whole multi-kind rule can't yield EQUAL, so the
        # old all-EQUAL test never fired and a genuine reuse downgraded to a redundant CREATE). A broader rule
        # stays SUBSET (still a valid no-op, never an over-claim, and never a widen that could over-grant).
        if _svc_sets_equal(req, rule):
            return Relation.EQUAL
        return Relation.SUBSET
    if all(r == Relation.DISJOINT for r in rels):
        return Relation.DISJOINT
    return Relation.OVERLAP               # some legs covered, some not -> not a no-op, not a clean step-over


def _typed_other(typed: TypedExtent, keep_field: str) -> bool:
    """True if the cell holds typed objects of a kind OTHER than ``keep_field`` -- so the cell can't be
    EXACTLY EQUAL to a single-kind request."""
    return any(getattr(typed, f) for f in _KIND_FIELD.values() if f != keep_field)


def typed_relation(kind: str, value: str, is_any: bool, has_ip: bool,
                   typed: TypedExtent, cell_complex: bool, negate: bool) -> tuple[Relation, bool]:
    """Relate a TYPED (non-IP) request — a domain / access-role / dynamic-object / updatable-object /
    security-zone identity — to ONE rule source/destination cell.

    Returns ``(relation, unknown)``. ``unknown`` is True when the cell's reach for this kind can't be
    proven (a negated cell, a truly-unresolvable member, or an opaque cross-kind container) -> the rule
    stays in the path and routes to REVIEW, never silently stepped over.

    Each identity kind is its OWN space (mirroring svc_relation's apps-vs-ports disjointness): a domain
    request is provably DISJOINT from a cell holding only IP / role / zone / dynamic objects, EQUAL or
    SUBSET to a cell naming the same (or a parent) domain, and OVERLAP (uncertain) only against an
    opaque container that could itself include the identity (an updatable feed can contain FQDNs)."""
    unknown = bool(cell_complex or negate)
    if is_any:
        return Relation.SUBSET, unknown            # a specific identity is contained by an Any cell
    field = _KIND_FIELD[kind]
    names = getattr(typed, field)
    if kind == "domain":
        if any(_domain_covers(c, value) for c in names):
            exact = any(_domain_equal(c, value) for c in names)
            cell_only = exact and not has_ip and not _typed_other(typed, field) and len(names) == 1
            return (Relation.EQUAL if cell_only else Relation.SUBSET), unknown
        if typed.updatable:                        # an updatable feed could contain this FQDN -> uncertain
            return Relation.OVERLAP, True
        return Relation.DISJOINT, unknown
    # access-role / dynamic-object / updatable-object / security-zone: matched by EXACT object identity.
    if value in names:
        cell_only = not has_ip and not _typed_other(typed, field) and len(names) == 1
        return (Relation.EQUAL if cell_only else Relation.SUBSET), unknown
    return Relation.DISJOINT, unknown


# --------------------------------------------------------------------------- #
# Request / rule / decision models
# --------------------------------------------------------------------------- #
# Wildcard tokens that mean "no restriction" on a match-gating column — stripped so a content/vpn/install-on
# list of ONLY these is identical to an unset column (never a phantom restriction / forced CREATE / duplicate).
_GATING_WILDCARDS = {"any", "all", "*"}


def _strip_gating_wildcards(value, extra=()):
    """Drop blanks + Any/All wildcards (case-insensitive) from a match-gating name list. Keeps None as None
    (means "column not touched"); a list collapses to the real names ([] when only wildcards were given)."""
    if value is None:
        return None
    drop = _GATING_WILDCARDS | {str(e).strip().lower() for e in extra}
    return [s for s in (str(x).strip() for x in value) if s and s.lower() not in drop]


@dataclass
class AccessRequest:
    src_cidrs: list[str]      # e.g. ["192.168.9.9/32"] — used only when src_kind == "ip"
    dst_cidrs: list[str]
    protocol: str = "tcp"     # "tcp" | "udp" (ignored when `application`/`service` is set)
    ports: str = ""           # "443" or "8000-8100" (ignored when `application`/`service` is set)
    application: Optional[str] = None   # an application-site OR category name (e.g. "Facebook") — overrides all
    application_kind: Optional[str] = None  # "application-site-category" (a category) else a single app — set
                                            # by resolve() so a category compares as a category, not an app
    service: Optional[str] = None       # a named non-port service (e.g. "echo-request", "GRE") by name
    service_kind: Optional[str] = None  # its protocol family (icmp/icmp6/sctp/other/…) — set by resolve()
    action: str = "Accept"
    # A TYPED (non-IP) source/destination: kind is "ip" (default — reasons over *_cidrs) or one of
    # TYPED_KINDS (domain / access-role / dynamic-object / updatable-object / security-zone), in which
    # case *_value holds the object's identity (a FQDN for domain, the object name otherwise).
    src_kind: str = "ip"
    src_value: str = ""
    dst_kind: str = "ip"
    dst_value: str = ""
    # The request's service EXPANDED to the same ServiceSet shape the rule side uses (a services-group or a
    # tcp/udp/sctp service resolved to its member ports), set by correlation so a group/named-port request
    # compares against rule cells (which dereference groups to ports) instead of reading DISJOINT. None ->
    # fall back to the coarse representation below. (Apply still writes req.service — the group's name.)
    svc_set: Optional[ServiceSet] = None
    # ACTION companions (full-column support). action is canonicalized via canonical_action(). Apply Layer
    # requires inline_layer (the layer name to divert into); action-settings carries the optional UserCheck
    # limit / captive-portal for an allowing action.
    inline_layer: str = ""                     # required iff action == "Apply Layer"
    action_settings_limit: str = ""            # a QoS/bandwidth "limit" object name (Accept/Ask/Inform)
    action_settings_captive_portal: bool = False  # enable-identity-captive-portal (Accept/Ask/Inform)
    # UserCheck (the top-level ``user-check`` rule object — sibling of action/action-settings, NOT nested).
    # Ask/Inform carry an interaction message + frequency + confirm; Drop/Reject carry a block-message
    # interaction only. Reuse-only — the interaction object must already exist (validated at publish).
    user_check: str = ""                       # UserCheck interaction object NAME (e.g. "Access Notification")
    user_check_frequency: str = ""             # once a day | once a week | once a month | custom frequency...
    user_check_confirm: str = ""               # per rule | per category | per application/site | per data type
    user_check_custom_every: int = 0           # custom-frequency {every} (only when frequency == custom)
    user_check_custom_unit: str = ""           # custom-frequency {unit}: hours | days | weeks | months
    # MATCH-GATING columns (full-column support, all REUSE-ONLY object refs). A request that carries any of
    # these is "restricted" -> the engine forces CREATE (never a false NO_OP/widen against an unrestricted
    # rule). Apply writes each via the shared validate-by-name resolver.
    content: Optional[list] = None             # Content Awareness data-type NAMES (OR-matched)
    content_direction: str = "any"             # any | up | down
    content_negate: bool = False
    time_objects: list = field(default_factory=list)   # time / time-group NAMES (union)
    install_on: list = field(default_factory=list)     # gateway/cluster/group NAMES ([] = Policy Targets/Any)
    vpn: Optional[list] = None                 # VPN community NAMES + Any/All_GwToGw (None = don't touch)

    def __post_init__(self):
        # Normalize the Any/All wildcard out of the match-gating object lists at the ENGINE boundary, so the
        # decision surface (has_content / is_restricted / forces_create) is identical no matter how the request
        # was built (webhook, MCP, portal, or direct construction). Without this, content=["Any"] / vpn=["Any"]
        # / install-on=["Policy Targets"] would read as a restriction the apply layer then strips — a phantom
        # CREATE whose written rule lacks the very condition that justified it. "All_GwToGw" is a real community
        # (a restriction) so it is NOT a wildcard; only literal Any/All/* collapse.
        self.content = _strip_gating_wildcards(self.content)
        self.vpn = _strip_gating_wildcards(self.vpn)
        self.install_on = _strip_gating_wildcards(self.install_on, extra=("Policy Targets",)) or []
        self.time_objects = _strip_gating_wildcards(self.time_objects) or []
        # A negate with no real data-type left is meaningless (negating "any") — drop it so it can't force a
        # CREATE the apply layer would then write empty.
        if self.content_negate and not self.content:
            self.content_negate = False

    @property
    def has_content(self) -> bool:
        return bool(self.content) or self.content_negate

    @property
    def has_action_settings(self) -> bool:
        return bool(self.action_settings_limit or self.action_settings_captive_portal)

    @property
    def is_restricted(self) -> bool:
        """True when the request carries a match-gating column (content/time/install-on/vpn) the engine does
        not fully model — force CREATE rather than risk a false NO_OP/widen against a rule lacking it."""
        return bool(self.has_content or self.time_objects or self.install_on
                    or (self.vpn is not None and self.vpn != []))

    @property
    def forces_create(self) -> bool:
        """The request carries a per-rule restriction or setting (content/time/install-on/vpn OR an
        action-settings limit / captive portal) a plain covering Accept may lack — so it must never reuse or
        widen that Accept; CREATE instead (ABOVE the covering Accept so the new condition takes effect)."""
        return self.is_restricted or self.has_action_settings

    def src_iv(self):
        return _cidrs_to_iv(self.src_cidrs)

    def dst_iv(self):
        return _cidrs_to_iv(self.dst_cidrs)

    @property
    def canon_action(self) -> str:
        """The request's action in exact Check Point casing (Accept/Drop/Reject/Ask/Inform/Apply Layer)."""
        return canonical_action(self.action)

    def svc(self) -> ServiceSet:
        if self.svc_set is not None:
            return self.svc_set         # correlation expanded the named service/group to real ports
        if self.application:
            if self.application_kind == "application-site-category":
                return ServiceSet(categories={self.application})   # a category matches a category cell
            return ServiceSet(apps={self.application})
        if self.service:
            if self.service.strip().lower() in ("any", "all", "*"):
                return ServiceSet(any=True)   # Service=Any — the "all services/ports" wildcard (block/allow all)
            # (family, name): family-less (unresolved) fails safe — it won't alias a real family object
            return ServiceSet(named={(self.service_kind or "", self.service)})
        return ServiceSet(by_proto={self.protocol.lower(): _ports_to_iv(self.ports)})


# Canonical Check Point access-rule actions (exact casing the web_api expects). User Auth / Client Auth are
# legacy/read-only — a request may never ask for them. "Apply Layer" diverts into an inline layer.
_CANON_ACTIONS = {
    "accept": "Accept", "allow": "Accept", "permit": "Accept",
    "drop": "Drop", "deny": "Drop", "block": "Drop",
    "reject": "Reject",
    "ask": "Ask", "inform": "Inform",
    "apply layer": "Apply Layer", "apply-layer": "Apply Layer", "applylayer": "Apply Layer",
    "layer": "Apply Layer",
}
WRITABLE_ACTIONS = ("Accept", "Drop", "Reject", "Ask", "Inform", "Apply Layer")


def canonical_action(s) -> str:
    """Normalise a requested action to exact CP casing, collapsing internal whitespace ('Apply  Layer'); '' ->
    'Accept' (the default verdict). Unknown/legacy -> '' so the caller (build_request) rejects it loudly —
    never a silent Accept."""
    key = " ".join(str(s or "Accept").strip().lower().split())
    if not key:
        return "Accept"
    return _CANON_ACTIONS.get(key, "")


@dataclass
class ParsedRule:
    uid: str
    number: int
    name: str
    enabled: bool
    action: str
    src: list                                   # ip intervals
    dst: list
    svc: ServiceSet
    source_group_uids: list = field(default_factory=list)
    dest_group_uids: list = field(default_factory=list)
    # Human object NAMES in each cell (preserved verbatim from the rulebase) — used only for messages,
    # e.g. the near-miss "already permitted for these sources: win_client, GW, …" reporting. Never used
    # for matching (that's done on the resolved extents above); empty for cells we couldn't name.
    src_names: list = field(default_factory=list)
    dst_names: list = field(default_factory=list)
    svc_names: list = field(default_factory=list)
    complex: bool = False                       # negation / unresolved -> excluded from reuse
    # Per-cell "extent unknown" FOR AN IP REQUEST: the cell was negated, held a truly-unresolvable
    # object, OR held a typed (non-IP) object (a domain/role/zone/dynamic/updatable that could resolve
    # to IPs we can't see). Such a cell is never "provably disjoint" for an IP request -> the rule stays
    # in the path. (A TYPED request reasons in its own identity space via src_typed/src_cx/src_negate.)
    src_unknown: bool = False
    dst_unknown: bool = False
    svc_unknown: bool = False
    # The typed (non-IP) objects each cell references + the raw flags a TYPED request reasons over:
    # src_cx/dst_cx = a TRULY-unresolvable member (over-cap wildcard, unenumerable group, malformed,
    # unknown type); src_negate/dst_negate = the cell was negated. (src_unknown folds these + typed +
    # IP-opacity together for the IP path; the typed path uses them separately.)
    src_typed: TypedExtent = field(default_factory=TypedExtent)
    dst_typed: TypedExtent = field(default_factory=TypedExtent)
    src_cx: bool = False
    dst_cx: bool = False
    src_negate: bool = False
    dst_negate: bool = False
    # An infra object (gateway/cluster/mgmt) resolved to its main ipv4-address — an UNDER-approximation
    # of its possibly-multi-homed reach. Trusted to drop an ACCEPT out of the path; never treated as
    # provably-disjoint, so an overlapping/uncertain DROP with such a cell still routes to REVIEW.
    src_approx: bool = False
    dst_approx: bool = False
    # Match-gating columns the engine does NOT model (VPN community, time window, content/data type,
    # install-on gateway subset, service-resource). When set, the rule only matches UNDER that extra
    # condition -> it is not an always-on Accept/Drop and must never be reused/widened/NO_OP'd.
    conditional: bool = False
    conditions: tuple = ()
    # Inline layer ("Apply Layer"): the parent rule diverts matching traffic into a sub-rulebase. The
    # loader pulls + attaches that rulebase so decide() can recurse purely. inline_rules is None for a
    # normal rule, a (possibly empty) list for an inline-layer rule; inline_cleanup is the inline layer's
    # own implicit cleanup action ("drop" | "accept" | "" unknown) -- what happens when traffic enters
    # the layer but matches no rule there.
    inline_uid: str = ""                        # uid of the referenced inline layer (set by _parse_rule)
    inline_layer_name: str = ""                 # its name (for the apply 'layer' param + messages)
    inline_rules: Optional[list] = None
    inline_cleanup: str = ""
    dynamic_layer: bool = False                 # the referenced layer is a Dynamic Layer (sk182252) —
                                                # managed out-of-band by other admins -> EXCLUDED from
                                                # decide() entirely (not descended, not flagged)

    @property
    def is_accept(self) -> bool:
        return self.action.lower() in ("accept", "allow")

    @property
    def is_drop(self) -> bool:
        return self.action.lower() in ("drop", "reject")

    @property
    def is_resolved_action(self) -> bool:
        """True only for a plain Accept/Drop we can reason about. An inline-layer rule's action resolves
        to the sub-layer name, and Ask/Inform/Client-Auth delegate elsewhere -- we can't evaluate those,
        so a rule with such an action that lies in the path must route to REVIEW."""
        return self.is_accept or self.is_drop


class Note(str):
    """A decision advisory that IS a plain string (so every existing consumer — substring checks, joins,
    json serialization, the MCP/REST passthrough — keeps working unchanged) while carrying a machine-
    readable ``kind`` for consumers that render severity. Kinds:

      * ``review``    (default) — a possible match the walk continued past; benign, review later.
      * ``shadow``    — DENY-NEUTRALIZATION warning: the created allow is placed above a more-specific
                        deny below it, which will no longer match its overlapping scope. NOT benign —
                        the UI must render this as a warning, never under "review later".
      * ``redundant`` — the new allow is likely already permitted by a higher web-port accept (may
                        never match / 0 hits).
      * ``disabled``  — a disabled rule already matches this access (re-enable instead of duplicating).
      * ``prereq``    — an environmental prerequisite (e.g. the predefined Internet object needs
                        topology + the App Control blade) without which the rule matches nothing.

    Plain ``str`` notes are still fine everywhere — consumers read ``getattr(note, "kind", "review")``.
    """
    kind: str = "review"

    def __new__(cls, text: str, kind: str = "review"):
        n = super().__new__(cls, text)
        n.kind = kind
        return n


def notes_payload(notes: list) -> dict:
    """Serialize a Decision/RemovalDecision notes list for a JSON boundary: the backward-compatible
    ``notes`` (plain strings, exactly as before) plus ``notes_detail`` ({text, kind}) so the UI and
    agents can style/weight each advisory by severity."""
    return {"notes": [str(n) for n in notes],
            "notes_detail": [{"text": str(n), "kind": getattr(n, "kind", "review")} for n in notes]}


class Outcome(str, Enum):
    NO_OP = "no_op"
    WIDEN = "widen"
    CREATE = "create"
    REVIEW = "review"


@dataclass
class Decision:
    outcome: Outcome
    reason: str
    target_rule: Optional[ParsedRule] = None    # rule we reuse / widen / anchor on
    position: Optional[dict] = None             # internal placement hint (resolved at apply)
    widen_group_uid: Optional[str] = None       # group to add the object to, if that cell uses one
    widen_field: Optional[str] = None           # "source" | "destination" — the dimension to extend
    layer: Optional[str] = None                 # target layer for the change — set to an INLINE layer's
                                                # name when the decision lands inside it (else the caller's
                                                # top-level layer is used)
    notes: list = field(default_factory=list)   # advisory "possible match — review later" warnings for
                                                # opaque rules the walk continued PAST (an updatable feed,
                                                # an unresolvable cell): never block the automated flow,
                                                # just flag them. The outcome is still acted on.
    partial: Optional["ParsedRule"] = None      # a reachable, unconditional ACCEPT that already permits the
                                                # request EXCEPT it is NARROWER on exactly one dimension (the
                                                # request is broader there) — i.e. "already permitted for a
                                                # narrower {source|destination|service}". Display-only: it
                                                # makes a CREATE answer say "permitted for these sources, just
                                                # not the one asked" instead of a misleading flat "No".
    partial_field: Optional[str] = None         # which dimension the partial accept is narrower on


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #
def _ip_int(addr: str) -> int:
    return int(ipaddress.IPv4Address(addr))


def _is_any(cidr) -> bool:
    return str(cidr).strip().lower() == "any"


def _cidrs_to_iv(cidrs):
    iv = []
    for c in cidrs:
        if _is_any(c):
            return ANY_IP
        iv.append(_net_interval(ipaddress.ip_network(c, strict=False)))   # v4 or v6 -> its band
    return _merge(iv)


def _ports_to_iv(spec: str):
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                if lo > hi:
                    continue   # inverted range (e.g. "443-1") is malformed -> drop it, never an interval that
                    #            reads 'covered-by-everything / overlaps-nothing' (a false SUBSET/NO_OP)
                out.append((lo, hi))
            elif part:
                out.append((int(part), int(part)))
        except ValueError:
            continue   # unparsable token -> drop it; an all-empty result hits decide()'s guard 2 -> REVIEW
    return _merge(out)


def _deref(ref, objdict: dict) -> dict:
    """A rule cell holds object UIDs (use-object-dictionary) or inline dicts; resolve to the full obj."""
    if isinstance(ref, str):
        return objdict.get(ref) or {"uid": ref, "name": ref}
    if isinstance(ref, dict):
        return objdict.get(ref.get("uid")) or ref
    return {}


def _cell_names(cell, objdict: dict) -> list:
    """The human object names in a rule cell (deduped, order-preserving). Display-only — used to name the
    objects in a near-miss explanation (e.g. "permitted for these sources: …"); never used for matching."""
    out: list = []
    for ref in (cell or []):
        nm = (_deref(ref, objdict) or {}).get("name")
        if nm and nm not in out:
            out.append(nm)
    return out


def _parse_net(cell, objdict: dict):
    """Resolve a source/destination cell to IPv4/IPv6 intervals AND its typed (non-IP) objects.

    -> (ip intervals, complex?, [group uids], approx?, TypedExtent).
    Resolution is by FIELD, not just type, so any object that exposes a concrete IPv4 extent resolves
    (hosts AND infrastructure objects — gateways, clusters, management/checkpoint-hosts, interoperable
    devices — which carry an ``ipv4-address`` but are not type ``host``).
    Wildcard objects expand to their EXACT interval set (capped — a pathological mask stays opaque), and a
    group-with-exclusion resolves to include∖except when both are exact.
    - ``TypedExtent`` = the non-IP objects the cell references, grouped by identity space (dns-domain,
      access-role, dynamic-object, updatable-object, security-zone). These are captured (not lumped into
      ``complex``) so a TYPED request can be reasoned about; an IP request still treats them as opaque
      (see _parse_rule's src_unknown), preserving the never-step-past-unknown-reach invariant.
    - ``complex`` = the cell held something with NO computable extent of ANY known kind (an over-cap
      wildcard, a group-with-exclusion whose 'except' isn't provably exact, an unenumerable group, a
      malformed address, or an object of an unrecognised type) -> the rule's reach is unknown -> REVIEW.
    - ``approx`` = we resolved an object to its main ``ipv4-address`` but its TRUE reach may exceed that
      single IP (a gateway/cluster can be multi-homed). It is an under-approximation, never an over-
      approximation, so it's safe to drop an ACCEPT out of the path; but decide() never treats an approx
      cell as 'provably disjoint', so an overlapping/uncertain DROP stays in the path -> REVIEW (we must
      never under-approximate a deny)."""
    iv, groups, cx, approx, typed = [], [], False, False, TypedExtent()
    for ref in cell or []:
        o = _deref(ref, objdict)
        t = (o.get("type") or "").lower()
        name = (o.get("name") or "").lower()
        raw_name = o.get("name") or ""
        # Check Point's predefined topology-based "Internet" object — captured in its own identity space.
        # Recognize it ONLY by its FIXED predefined uid (it lives in the "Check Point Data" domain and is NOT
        # in a rulebase's objects-dictionary, so a destination reference is typically the bare uid — caught
        # here) or its explicit type "Internet". The name "internet" is deliberately NOT a trigger: it is not
        # reserved, so a customer object literally named "Internet" — a group / access-role / dynamic-object /
        # zone / dns-domain, or a host/network — must resolve by its own kind below. (The old name fallback
        # silently dropped a customer group's member IPs and could mis-match a DROP whose cell was so named.)
        if o.get("uid") == _INTERNET_UID or t == "internet":
            typed.internet.add("Internet")
            continue
        if t == "cpmianyobject" or name == "any":
            return ANY_IP, False, groups, False, typed
        if t == "group":
            groups.append(o.get("uid", ""))
            mem = o.get("members")
            if mem is None:
                # Membership not in the dictionary (a nested group not inlined, a paging/details-level
                # gap, a thin object copy). We CANNOT enumerate the extent, so it is unknown -> REVIEW.
                # An explicitly-empty group (members: []) is different: a real empty set, kept disjoint.
                cx = True
                continue
            sub_iv, sub_cx, _, sub_ap, sub_typed = _parse_net(mem, objdict)
            iv.extend(sub_iv)
            cx = cx or sub_cx
            approx = approx or sub_ap
            typed.merge(sub_typed)
            if mem and not sub_iv and not sub_cx and not sub_typed.any_members():
                cx = True   # a non-empty member list that resolved to nothing (all unresolvable) -> unknown
            continue
        if t == "group-with-exclusion":
            groups.append(o.get("uid", ""))
            inc, exc = o.get("include"), o.get("except")
            if not inc or not exc:
                cx = True                            # can't see both halves -> unknown extent -> REVIEW
                continue
            b_iv, b_cx, _, b_ap, b_typed = _parse_net([inc], objdict)   # the included set
            e_iv, e_cx, _, e_ap, e_typed = _parse_net([exc], objdict)   # the excluded set (typed too!)
            # IP reach: subtract EXACTLY only when the excluded IP set is provably exact — an under-stated
            # 'except' (approx/unknown) would OVER-state include∖except -> over-grant. The base may be approx
            # (an under-approximation stays an under-approximation after subtraction -> safe).
            if b_cx or e_cx or e_ap:
                cx = True
            else:
                iv.extend(_subtract(b_iv, e_iv))
                approx = approx or b_ap
            # TYPED reach: there is NO typed-set subtraction, so if the 'except' half carries TYPED members
            # (a dns-domain / access-role / zone / dynamic exclusion), the included half's typed reach is NOT
            # provably exact — an EXCLUDED identity must never read as covered. Fail closed: mark the cell
            # unknown (-> typed_relation returns unknown=True -> never a false NO_OP / never provably-disjoint,
            # so a covering DROP still floors placement) and DO NOT surface the included typed objects. Only a
            # pure-IP exclusion leaves the included typed reach intact.
            if e_typed.any_members():
                cx = True
            else:
                typed.merge(b_typed)                 # surface typed objects from the included half
            continue
        # A typed (non-IP) object — a domain / access-role / dynamic-object / updatable-object /
        # security-zone. Capture its name in its identity space rather than discarding it as 'complex'.
        # Most carry no IP extent, so we record and move on; an updatable-object MAY also expose resolved
        # IP ranges, so it falls through to the IP extraction below as well (its IPs are an extra, safe
        # under-approximation, never replacing the feed semantics).
        kind = _TYPED_KIND.get(t)
        if kind:
            typed.add(kind, raw_name or o.get("uid", ""))
            if kind != "updatable":
                continue
        # Resolve every IPv4 AND IPv6 extent the object exposes (a dual-stack host carries both) -> each
        # maps to its own band via _net_interval / _addr_point, so v4 and v6 never collide.
        matched = False
        try:
            w4m, w6m = o.get("ipv4-mask-wildcard"), o.get("ipv6-mask-wildcard")
            if w4m or w6m:               # a wildcard object — expand its (non-contiguous) mask EXACTLY, capped
                matched = True           # (wildcard fields are exclusive of subnet/range/host fields)
                for waddr, wmask, base, bits in ((o.get("ipv4-address"), w4m, 0, 32),
                                                 (o.get("ipv6-address"), w6m, _V6_BASE, 128)):
                    if not wmask:
                        continue
                    exp = _wildcard_to_intervals(waddr, wmask, base, bits) if waddr else None
                    if exp is None:
                        cx = True        # no address, or too many disjoint ranges -> keep opaque (REVIEW)
                    else:
                        iv.extend(exp)
            else:
                sub4, ml4 = o.get("subnet4") or o.get("subnet"), o.get("mask-length4", o.get("mask-length"))
                if sub4 and ml4 is not None:         # network (and anything carrying subnet4 + mask)
                    iv.append(_net_interval(ipaddress.ip_network(f"{sub4}/{ml4}", strict=False))); matched = True
                sub6, ml6 = o.get("subnet6"), o.get("mask-length6")
                if sub6 and ml6 is not None:         # IPv6 network
                    iv.append(_net_interval(ipaddress.ip_network(f"{sub6}/{ml6}", strict=False))); matched = True
                f4, l4 = o.get("ipv4-address-first"), o.get("ipv4-address-last")
                if f4 and l4:                        # address-range / multicast-address-range (v4)
                    iv.append((_addr_point(f4), _addr_point(l4))); matched = True
                f6, l6 = o.get("ipv6-address-first"), o.get("ipv6-address-last")
                if f6 and l6:                        # IPv6 address-range
                    iv.append((_addr_point(f6), _addr_point(l6))); matched = True
                a4, a6 = o.get("ipv4-address"), o.get("ipv6-address")
                if a4:                               # host OR an infra object (gateway/cluster/mgmt/...)
                    iv.append((_addr_point(a4), _addr_point(a4))); matched = True
                    if t != "host":                  # main IP only; full reach may be larger -> approx
                        approx = True
                if a6:
                    iv.append((_addr_point(a6), _addr_point(a6))); matched = True
                    if t != "host":
                        approx = True
        except ValueError:
            # A malformed address/subnet in the object dictionary degrades THIS cell to extent-unknown
            # (-> REVIEW) instead of crashing the whole layer pull. Mirrors _ports_to_iv / lookup_host
            # tolerance; fail closed (the rule stays in the path), never silently disjoint.
            cx = matched = True
        if not matched and not kind:                 # an unrecognised object type with no computable
            cx = True                                # extent of any known kind -> unknown -> REVIEW
    return _merge(iv), cx, groups, approx, typed


def _parse_port(spec):
    spec = str(spec).strip()
    try:
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                return None   # inverted/degenerate range (e.g. "443-1") -> unparsable -> mark svc complex
                #               -> the rule stays in path -> REVIEW (fail closed; mirrors _ports_to_iv)
            return [(lo, hi)]
        if spec.isdigit():
            return [(int(spec), int(spec))]
    except ValueError:
        return None
    return None  # ">1024", named, etc -> unparsable


def _parse_svc(cell, objdict: dict) -> ServiceSet:
    s = ServiceSet()
    for ref in cell or []:
        o = _deref(ref, objdict)
        t = o.get("type", "")
        name = o.get("name") or ""
        if t == "CpmiAnyObject" or name.lower() == "any":
            return ServiceSet(any=True)
        if t in ("service-tcp", "service-udp", "service-sctp"):
            # Port-based protocols. SCTP (like TCP/UDP) carries a real destination port, so it is keyed by
            # value in `by_proto` under its OWN protocol -- which never overlaps tcp/udp (distinct keys),
            # so cross-protocol disjointness is automatic while same-protocol port ranges still widen/cover.
            proto = t.replace("service-", "")     # tcp | udp | sctp
            iv = _parse_port(o.get("port", ""))
            if iv is None:
                s.complex = True
            elif (o.get("enable-tcp-resource") or o.get("match-by-protocol-signature")
                  or str(o.get("source-port") or "").strip()):
                # The service matches MORE NARROWLY than its destination port alone -- a URI/CIFS/FTP
                # resource, an L7 protocol signature, or a specific client source-port. Treating it as a
                # plain port would let the engine NO_OP / widen / reuse a rule that does not actually
                # permit all of that port -> silent over-grant. Mark it complex (extent-unknown) so the
                # rule stays in the path and routes to REVIEW instead.
                s.complex = True
            else:
                s.by_proto[proto] = _merge(s.by_proto.get(proto, []) + iv)
        elif t == "application-site":
            s.apps.add(name)
        elif t == "application-site-category":
            # A category is captured by NAME so an identical-category request matches it (NO_OP/WIDEN), AND
            # kept opaque so a SINGLE-app request can't claim membership (we can't enumerate the category).
            s.categories.add(name)
            s.opaque = True
        elif t == "application-site-group":
            s.opaque = True                 # a group: can't enumerate which apps/categories it contains
            s.app_group = True              # an opaque app container distinct from the captured categories
        elif t in ("service-icmp", "service-icmp6"):
            # PORTLESS protocols (icmp 1 / icmp6 58) matched by type/code, never a port — can NEVER overlap
            # a tcp/udp/sctp port request, so match by name. Key on (family, name): the SAME predefined
            # name exists across families (echo-request is both service-icmp AND service-icmp6) -> no alias.
            s.named.add((t.replace("service-", ""), name))
        elif t in ("service-other", "service-dce-rpc", "service-rpc", "service-gtp",
                   "service-citrix-tcp", "service-compound-tcp"):
            # Match by (family, name), but their protocol/port reach can't be bounded (service-other is
            # an arbitrary IP protocol; rpc/gtp/citrix/compound match dynamically) -> opaque so a PORT
            # request can't assume it's disjoint (stays in the path -> REVIEW for a deny).
            s.named.add((t.replace("service-", ""), name))
            s.opaque = True
        elif t == "service-group":
            s.group_uids.append(o.get("uid", ""))
            mem = o.get("members")
            if mem is None:                     # membership not enumerable -> unknown extent -> REVIEW
                s.complex = True
                continue
            sub = _parse_svc(mem, objdict)
            if sub.any:
                return ServiceSet(any=True)
            for proto, iv in sub.by_proto.items():
                s.by_proto[proto] = _merge(s.by_proto.get(proto, []) + iv)
            s.apps |= sub.apps
            s.named |= sub.named
            s.opaque = s.opaque or sub.opaque
            s.complex = s.complex or sub.complex
        else:
            s.complex = True
    return s


def _cell_is_any(cell, objdict: dict, *defaults: str) -> bool:
    """A match column (vpn/time/content/install-on) imposes NO restriction when it is empty or holds
    ONLY its default object(s) (e.g. 'Any', 'Policy Targets'). Any other named object -- or an unnamed
    structured entry such as a directional-VPN {from,to} pair -- is a real restriction."""
    items = cell or []
    if not items:
        return True
    for ref in items:
        name = (_deref(ref, objdict).get("name") or "").strip().lower()
        if name not in defaults:
            return False
    return True


def _rule_conditions(e: dict, objdict: dict) -> tuple:
    """The match-gating columns the engine does not model. A rule using any of them only matches under
    that extra condition (a VPN community/direction, a time window, a data/content type, a subset of
    gateways, or a service resource) -> it is not an always-on Accept/Drop."""
    conds = []
    if not _cell_is_any(e.get("vpn"), objdict, "any"):
        conds.append("VPN")
    if not _cell_is_any(e.get("time"), objdict, "any"):
        conds.append("time")
    if e.get("content-negate") or not _cell_is_any(e.get("content"), objdict, "any"):
        conds.append("data")
    if not _cell_is_any(e.get("install-on"), objdict, "any", "policy targets"):
        conds.append("install-on")
    if e.get("service-resource"):
        conds.append("service-resource")
    return tuple(conds)


def _parse_rule(e, objdict: dict) -> ParsedRule:
    src, src_cx, src_groups, src_ap, src_typed = _parse_net(e.get("source", []), objdict)
    dst, dst_cx, dst_groups, dst_ap, dst_typed = _parse_net(e.get("destination", []), objdict)
    svc = _parse_svc(e.get("service", []), objdict)
    action = e.get("action")
    if isinstance(action, str):
        action = (objdict.get(action) or {}).get("name", action)
    elif isinstance(action, dict):
        action = action.get("name", "")
    src_negate = bool(e.get("source-negate"))
    dst_negate = bool(e.get("destination-negate"))
    # For an IP request a cell's extent is "unknown" if it was negated, held a truly-unresolvable object,
    # OR held a typed (non-IP) object — a domain/role/zone/dynamic/updatable could resolve to IPs we
    # can't see, so an IP request must never step past it (preserves the pre-typed behaviour exactly).
    src_unknown = bool(src_cx or src_negate or src_typed.any_members())
    dst_unknown = bool(dst_cx or dst_negate or dst_typed.any_members())
    svc_unknown = bool(svc.complex or e.get("service-negate"))
    conditions = _rule_conditions(e, objdict)
    # Inline layer: action "Apply Layer" + an `inline-layer` reference (uid or inline dict). Record the
    # uid + name now; the loader attaches the sub-rulebase. The layer's implicit-cleanup action is read
    # from the object dictionary here when present (no extra call); the loader falls back to a lookup.
    inline_ref = e.get("inline-layer")
    inline_uid = inline_ref if isinstance(inline_ref, str) else (
        (inline_ref or {}).get("uid", "") if isinstance(inline_ref, dict) else "")
    inline_obj = objdict.get(inline_uid) if inline_uid else None
    inline_name = (inline_obj or {}).get("name", "") if isinstance(inline_obj, dict) else ""
    inline_cleanup = ((inline_obj or {}).get("implicit-cleanup-action", "") or "").lower()
    inline_dynamic = bool((inline_obj or {}).get("dynamic-layer")) if isinstance(inline_obj, dict) else False
    return ParsedRule(
        uid=e.get("uid", ""),
        number=e.get("rule-number", e.get("number", 0)),
        name=e.get("name", ""),
        enabled=e.get("enabled", True),
        action=action or "",
        src=src, dst=dst, svc=svc,
        source_group_uids=src_groups, dest_group_uids=dst_groups,
        src_names=_cell_names(e.get("source", []), objdict),
        dst_names=_cell_names(e.get("destination", []), objdict),
        svc_names=_cell_names(e.get("service", []), objdict),
        complex=bool(src_unknown or dst_unknown or svc_unknown),
        src_unknown=src_unknown, dst_unknown=dst_unknown, svc_unknown=svc_unknown,
        src_approx=src_ap, dst_approx=dst_ap,
        src_typed=src_typed, dst_typed=dst_typed,
        src_cx=bool(src_cx), dst_cx=bool(dst_cx), src_negate=src_negate, dst_negate=dst_negate,
        conditional=bool(conditions), conditions=conditions,
        inline_uid=inline_uid, inline_layer_name=inline_name, inline_cleanup=inline_cleanup,
        dynamic_layer=inline_dynamic,
    )


def _flatten(items):
    for it in items or []:
        if it.get("type") == "access-section":
            yield from _flatten(it.get("rulebase", []))
        else:
            yield it


# --------------------------------------------------------------------------- #
# The pure decision engine
# --------------------------------------------------------------------------- #
def _is_subset(rel_src, rel_dst, rel_svc) -> bool:
    sub = (Relation.SUBSET, Relation.EQUAL)
    return rel_src in sub and rel_dst in sub and rel_svc in sub


def _dim_covered(rel: Relation) -> bool:
    """One request dimension is covered by a rule cell when the request is a subset of (or equals) it."""
    return rel in (Relation.SUBSET, Relation.EQUAL)


def _svc_uncertain(req_svc: ServiceSet, rule_svc: ServiceSet) -> bool:
    """We can't tell whether a rule's opaque app container (category/group) covers an APPLICATION
    request that isn't an exact match -> treat that rule as unresolved (route to REVIEW) for this
    request. Port requests are unaffected (an app container doesn't grant ports)."""
    if rule_svc.any:
        return False
    if req_svc.apps and not (req_svc.apps & rule_svc.apps):
        return rule_svc.opaque
    if req_svc.categories and not (req_svc.categories & rule_svc.categories):
        return rule_svc.opaque         # a category request vs an opaque cell that doesn't name it -> uncertain
    if req_svc.named and not (req_svc.named & rule_svc.named):
        return rule_svc.opaque         # a named-service request vs an opaque rule cell -> uncertain
    return False


_WEB_APP_PORTS = (80, 443)   # where Check Point App Control identifies a web application: HTTP / HTTPS (/QUIC)


def _rule_may_bear_web_app(rule_svc: ServiceSet) -> bool:
    """Could a rule whose service cell resolves to concrete L4 ports carry an App-Control web application
    (Facebook, YouTube, Office365, …)? Those apps are identified over HTTP/HTTPS, so a rule scoped to ports
    that don't include 80/443 — NetBIOS, DHCP/bootp, SSH, SMTP, … — can NEVER match one (provably disjoint).
    Only a rule whose ports cover 80 or 443 (incl. a broad range that does) keeps the app-vs-L4 uncertainty
    the carve-out / removal logic must respect. PROTOCOL-AWARE: web is TCP 80/443 (+ UDP 443 for QUIC); a
    udp/80 or sctp/443 leg is NOT web-bearing, so it stays provably disjoint."""
    by = rule_svc.by_proto or {}
    tcp = by.get("tcp") or []
    udp = by.get("udp") or []
    return (any(lo <= p <= hi for lo, hi in tcp for p in (80, 443))
            or any(lo <= 443 <= hi for lo, hi in udp))


def _svc_indeterminate(req_svc: ServiceSet, rule_svc: ServiceSet) -> bool:
    """Can we PROVE the service dimension does NOT match? Not when a PORT request meets a rule whose
    service carries an application (concrete or category) that its port leg doesn't already cover --
    App Control identifies L7 over ports, so the rule MIGHT match this port's traffic. Keeping such a
    rule 'in the path' lets a DROP route to REVIEW (don't override a possible block); an ACCEPT is
    harmless to create around. Subsumes the application-request uncertainty (_svc_uncertain)."""
    if _svc_uncertain(req_svc, rule_svc):
        return True
    if (req_svc.by_proto and (rule_svc.apps or rule_svc.opaque)
            and not _portset_covers(rule_svc.by_proto, req_svc.by_proto)):
        return True
    # SYMMETRIC case: an APPLICATION request meeting a rule that carries L4 ports — App Control identifies a
    # (web) app over HTTP/HTTPS, so a rule whose ports COULD carry that traffic (cover 80/443, or a broad
    # range that does) might match the app -> indeterminate (a tcp/443 DROP must stay in the path, else a
    # false NO_OP claims the app is allowed when the gateway is dropping it). But a rule scoped to ports that
    # can NEVER carry a web app — NetBIOS, DHCP/bootp, SSH, a "Silent Drop" — is provably disjoint from the
    # app: don't let it falsely block a carve-out (apply) or a removal (REVIEW). This is the screenshot case.
    if (req_svc.apps or req_svc.categories) and rule_svc.by_proto and not rule_svc.any:
        return _rule_may_bear_web_app(rule_svc)
    return False


def _is_proper_superset(rel_src, rel_dst, rel_svc) -> bool:
    sup = (Relation.SUPERSET, Relation.EQUAL)
    all_equal = rel_src == rel_dst == rel_svc == Relation.EQUAL
    return rel_src in sup and rel_dst in sup and rel_svc in sup and not all_equal


def _is_catchall(r: ParsedRule) -> bool:
    return _covers(r.src, ANY_IP) and _covers(r.dst, ANY_IP) and r.svc.any


def _provably_disjoint(rel: Relation, unknown: bool) -> bool:
    """A dimension proves the rule is out of the request's path only if the cell was fully resolved
    AND is disjoint. An unknown (negated / unresolved) cell can never prove disjointness."""
    return (not unknown) and rel == Relation.DISJOINT


def _out_of_path(rel_src, src_unknown, rel_dst, dst_unknown, rel_svc, svc_unknown, svc_indeterminate) -> bool:
    """Is a rule PROVABLY out of the request's path (disjoint on some dimension)? The ONE definition shared by
    decide(), decide_removal(), and _still_granted_below() so they can't drift (that drift was the root cause
    of the QA-found over/under-conservatism). The IP legs are judged on RESOLVED extents only — an APPROX
    cell (a gateway/SMS resolved to its main IP) that is resolved-disjoint is treated as unrelated, NOT
    dragged into the path by the under-approximation caveat (an approx cell that OVERLAPS is not DISJOINT, so
    it still stays in path). The SERVICE leg folds svc_indeterminate (App Control can carry an app over a
    rule's L4 ports, so an http/https rule is never 'disjoint' from an app request)."""
    return (_provably_disjoint(rel_src, src_unknown)
            or _provably_disjoint(rel_dst, dst_unknown)
            or _provably_disjoint(rel_svc, svc_unknown or svc_indeterminate))


def _cant_cover_dim(rel: Relation, req_any: bool, cell_any: bool, unresolved: bool) -> bool:
    """PROVE that this rule cell cannot be a superset-or-equal of the request on one dimension — i.e. the
    rule cannot COVER (already permit) the request. Two provable cases:
      * the request is ANY on this dimension but the cell is NOT Any — a specific cell (even an opaque one)
        is a strict subset of Any, so it can never cover an Any request (this is the "rule has a specific
        destination, so it can't allow a request to Any" case);
      * the dimension is fully resolved and the request is broader than / not contained in the cell
        (SUPERSET / OVERLAP / DISJOINT — anything but SUBSET/EQUAL).
    An UNRESOLVED non-Any dimension proves nothing (the cell might contain the request), so returns False."""
    if req_any and not cell_any:
        return True
    if not unresolved:
        return rel in (Relation.SUPERSET, Relation.OVERLAP, Relation.DISJOINT)
    return False


def _dim_relation(kind: str, value: str, req_iv, r: ParsedRule, which: str) -> tuple[Relation, bool, bool]:
    """Relate ONE request dimension (source or destination) to rule ``r``'s cell on that side, dispatching
    on the request's kind. Returns ``(relation, unknown, approx)`` — the same shape for IP and typed
    requests so decide() reasons uniformly.

    - IP request: the established IPv4/IPv6 interval relation; ``unknown``/``approx`` are the cell's
      precomputed IP-path flags (a typed object in the cell already made src_unknown True -> the rule
      stays in the path, exactly as before typing).
    - Typed request (domain / role / zone / dynamic / updatable): reasoned in that identity space via
      typed_relation(); ``approx`` is always False (an identity is exact, not an under-approximation)."""
    cell_ip = r.src if which == "source" else r.dst
    if kind == "ip":
        unknown = r.src_unknown if which == "source" else r.dst_unknown
        approx = r.src_approx if which == "source" else r.dst_approx
        return relation(req_iv, cell_ip), unknown, approx
    typed = r.src_typed if which == "source" else r.dst_typed
    cell_cx = r.src_cx if which == "source" else r.dst_cx
    negate = r.src_negate if which == "source" else r.dst_negate
    is_any = _covers(cell_ip, ANY_IP)
    has_ip = bool(cell_ip) and not is_any
    rel, unknown = typed_relation(kind, value, is_any, has_ip, typed, cell_cx, negate)
    return rel, unknown, False


def _widen_mixes_internet(field: str, req: "AccessRequest", r: ParsedRule) -> bool:
    """A DESTINATION widen must not combine the topology-based predefined "Internet" object with IP /
    other-typed destinations in one cell: mixing match semantics that way is not an endorsed Check Point
    pattern (Internet is resolved by gateway topology, an IP/object by address/identity). When a widen
    would create such a mixed cell, the engine prefers a clean separate rule (CREATE) instead."""
    if field != "destination":
        return False
    req_inet = req.dst_kind == "internet"
    rule_inet = bool(r.dst_typed.internet)
    rule_other = bool(r.dst) or any(getattr(r.dst_typed, f)
                                    for f in _KIND_FIELD.values() if f != "internet")
    return (req_inet and rule_other) or (not req_inet and rule_inet)


def _more_specific_deny_below(req: "AccessRequest", req_src, req_dst, req_svc,
                              rules: list, i: int) -> Optional["ParsedRule"]:
    """Scan rules BELOW index ``i`` for an enabled, fully-resolved DROP that PROVABLY INTERSECTS the request
    (not disjoint on any dimension — so it is narrower than, equal to, or overlaps the request's scope). When
    we CREATE an allow ABOVE an overridden/partial deny, first-match makes that allow win for the request's
    scope, so any lower deny sharing that scope is (fully or partially) SHADOWED — it no longer matches the
    overlap. The placement is by design; the gap this closes is the missing ADVISORY. Returns the first such
    rule, else None. The catch-all cleanup is excluded (it's the floor); approx / unresolved denies are
    skipped (their true reach isn't provable, so not provably shadowed)."""
    for r2 in rules[i + 1:]:
        if not r2.enabled or not r2.is_drop or _is_catchall(r2):
            continue
        rel_s, su, sa = _dim_relation(req.src_kind, req.src_value, req_src, r2, "source")
        rel_d, du, da = _dim_relation(req.dst_kind, req.dst_value, req_dst, r2, "destination")
        if su or du or sa or da or r2.svc_unknown:
            continue
        # Provably intersects iff no dimension is disjoint (covers EQUAL, SUBSET, SUPERSET and OVERLAP) —
        # broader than the old "strictly more specific (request ⊋ rule)", which missed an EQUAL / overlapping
        # lower deny that is equally shadowed by the allow placed above.
        rel_svc = svc_relation(req_svc, r2.svc)
        if rel_s != Relation.DISJOINT and rel_d != Relation.DISJOINT and rel_svc != Relation.DISJOINT:
            return r2
    return None


def _service_widenable(req: "AccessRequest") -> bool:
    """A SERVICE widen adds exactly ONE object to the rule's cell — the object the apply materializer builds:
    ``req.application`` (a single app/category), ``req.service`` (a named service OR a services-group whose
    NAME was kept), or the single port-service it creates for a plain protocol+port request. That object
    fully covers the request's service ONLY in those cases. A MULTI-kind ``svc_set`` built with no backing
    object name (e.g. {tcp/443 + icmp} passed directly) can't be added as one object — the other legs would
    be SILENTLY DROPPED — so it must NOT widen; fall through to CREATE instead."""
    return bool(req.application or req.service) or req.svc_set is None


def _shadow_note(shadowed: "ParsedRule") -> Note:
    # kind="shadow": this is a DENY-NEUTRALIZATION warning, not a benign "review later" advisory — the UI
    # renders it as a danger box so an operator can't publish past it thinking it's informational.
    return Note(f"this allow is placed above the more-specific deny rule {shadowed.number} "
                f"({shadowed.name}) below it, which overlaps this request — that deny will no longer match "
                f"its scope. Review the intent.", kind="shadow")


@dataclass(frozen=True)
class DecideOptions:
    """Admin-tunable decision/placement behaviour (built from Settings by the caller; decide() stays pure).

    These are the knobs that let an operator TUNE the engine from the portal without touching code — every
    judgment call in decide() that has a defensible alternative is one of these. Each default is the
    current, recommended behaviour, so an unset/blank config decides exactly as before. ``_decide_options()``
    builds this from app_settings (the 'Access automation logic' group)."""
    ignore_conditions: bool = False        # treat VPN/time/data/install-on-scoped rules as unconditional
                                           # (a conditional ACCEPT can then cover; a conditional DROP blocks)
    app_carveout: bool = True              # an APPLICATION request blocked by an in-path rule -> CREATE the
                                           # app-Accept ABOVE it (CP carves out just that app); off -> note +
                                           # place below (conservative, but the new rule may be shadowed)
    override_blocking_deny: bool = True    # a resolved covering/partial DENY -> CREATE the allow ABOVE it so
                                           # the access works; off -> note it + place the new rule BELOW
                                           # (never override an admin's deny; may not achieve the request)
    prefer_widen: bool = True              # reuse by widening an existing rule's cell when possible; off ->
                                           # always CREATE a fresh least-privilege rule (never widen)
    emit_notes: bool = True                # attach advisory 'possible match — review later' notes; off ->
                                           # quiet mode (placement safety is unchanged, only the notes drop)


def _widen_above_block(widen_target: ParsedRule, widen_field: str, blocker: ParsedRule) -> "Decision":
    """A WIDEN preferred over creating a NEW rule above an in-path block: ``widen_target`` is a clean
    reachable ACCEPT (EQUAL to the request in two dimensions) that ALREADY sits above ``blocker`` in the
    top-down walk, so extending its third dimension grants the request there by first-match and the block
    is moot — the same effect as a create-above carve-out, with one fewer rule. Only chosen when widening
    is safe (prefer_widen on, a target found, no opaque possible-deny passed, and — for a real deny — the
    operator allows overriding denies)."""
    others = {"source": "destination + service", "destination": "source + service",
              "service": "source + destination"}[widen_field]
    return Decision(
        Outcome.WIDEN,
        f"rule {widen_target.number} ({widen_target.name}) already matches the request's {others} and sits "
        f"above the blocking rule {blocker.number} ({blocker.name}); widening it grants the access there "
        f"(first-match) — no new rule needed",
        target_rule=widen_target, widen_field=widen_field,
    )


def decide(req: AccessRequest, rules: list[ParsedRule], options: "DecideOptions" = None) -> Decision:
    """Pure: pick the minimal correct change for ``req`` against ``rules``.

    Walks the rulebase top-down, honouring Check Point first-match semantics. The result is always an
    actionable outcome — reuse (NO_OP), widen, or CREATE (placed above a blocking deny when needed) — never
    a policy "review" stop; anything it can't fully resolve is NOTED and the walk continues.

    Thin wrapper around ``_decide``: it owns the ``notes`` list (advisory 'possible match — review later'
    warnings the walk raises when it CONTINUES past an opaque rule instead of hard-stopping) and tags
    them onto whatever single outcome the walk returns — so the automated flow is never halted just
    because some rule in the path holds an object we can't fully resolve.
    """
    options = options or DecideOptions()
    notes: list[str] = []
    decision = _decide(req, rules, options, notes)
    # The predefined Internet object is TOPOLOGY- and BLADE-dependent (it matches only internet/DMZ-bound
    # traffic via the gateway's External interface, and only inside an App Control / URL Filtering layer).
    # Surface that prerequisite whenever we build a rule against it, so a PoV doesn't install a green policy
    # whose app rule silently matches nothing.
    if req.dst_kind == "internet" and decision.outcome in (Outcome.CREATE, Outcome.WIDEN):
        notes.append(Note(
            "destination is the predefined Internet object (Application Control / URL Filtering "
            "best practice for app rules) — it matches only internet/DMZ-bound traffic, so it needs "
            "the gateway topology defined (an External interface) and the Application Control / URL "
            "Filtering blade enabled, or the rule will match nothing.", kind="prereq"))
    # ``emit_notes`` off = quiet mode: drop the advisory notes (placement/uncertain_deny safety is decided
    # inside _decide and is unaffected — only the human-facing advisories are suppressed).
    if options.emit_notes and notes:
        decision.notes = list(notes) + [n for n in (decision.notes or []) if n not in notes]
    return decision


def _decide_nonaccept(req: AccessRequest, rules: list[ParsedRule], options: "DecideOptions", notes: list,
                      req_src, req_dst, req_svc) -> Decision:
    """Decide a NON-Accept request (Drop / Reject / Ask / Inform / Apply Layer). The Accept reuse/widen
    logic does not apply — it answers "is this already granted?", which is meaningless for a block / a
    conditional verdict / a divert. Here we place a rule with the REQUESTED verdict for first-match
    correctness and NEVER reuse or widen:

      * DROP / REJECT (block): if the FIRST rule in this request's path is a fully-resolved covering DROP, the
        flow is already denied -> NO_OP. Otherwise place the block ABOVE the first in-path rule (whatever
        could match this flow first) so first-match denies exactly this request; the existing rule still
        serves everyone else. Nothing in the path -> already denied by the cleanup -> NO_OP.
      * ASK / INFORM (conditional allow) / APPLY LAYER (divert): always CREATE. Placed ABOVE the first in-path
        rule whose deny we can PROVE we are safe to leap — but never ABOVE an opaque/partial possible-deny
        (first-match would let our conditional silently override an unmodeled block). When such a possible-deny
        sits in the path, the conditional is floored at the section bottom + flagged, mirroring the Accept
        path's ``uncertain_deny`` placement floor. Nothing in path -> at the section floor. Always flagged for
        review (the engine doesn't model UserCheck/divert matching).
    """
    act = req.canon_action
    is_block = act in ("Drop", "Reject")
    conditional = act in ("Ask", "Inform", "Apply Layer")
    cnote = ([f"“{act}” is a conditional / divert verdict the engine does not model for matching — review "
              f"the new rule's placement and settings after creation"] if conditional else [])
    # uncertain_deny: a conditional walk stepped PAST an opaque/partial rule that COULD block this flow. Like
    # the Accept path, that forbids anchoring our rule ABOVE a later rule (first-match would leap the possible
    # deny) -> floor the conditional at the bottom instead.
    uncertain_deny = False
    for r in rules:
        if not r.enabled or r.dynamic_layer:
            continue
        rel_src, src_unknown, _sa = _dim_relation(req.src_kind, req.src_value, req_src, r, "source")
        rel_dst, dst_unknown, _da = _dim_relation(req.dst_kind, req.dst_value, req_dst, r, "destination")
        rel_svc = svc_relation(req_svc, r.svc)
        svc_ind = _svc_indeterminate(req_svc, r.svc)
        if _out_of_path(rel_src, src_unknown, rel_dst, dst_unknown, rel_svc, r.svc_unknown, svc_ind):
            continue
        all_ip = req.src_kind == "ip" and req.dst_kind == "ip"
        complex_eff = bool(src_unknown or dst_unknown or r.svc_unknown or (all_ip and r.complex))
        covers = (not complex_eff and r.is_resolved_action and not r.conditional and not svc_ind
                  and r.inline_rules is None and _is_subset(rel_src, rel_dst, rel_svc))
        if is_block:
            if r.is_drop and covers:
                return Decision(Outcome.NO_OP,
                                f"already denied by rule {r.number} ({r.name}) — nothing to add", target_rule=r)
            # A block above ANY in-path rule guarantees first-match denies this flow (safe-or-redundant), so
            # place it above the first in-path rule.
            return Decision(Outcome.CREATE,
                            f"creating a {act} rule ABOVE rule {r.number} ({r.name}) so first-match applies it "
                            f"to this flow", target_rule=r, position={"above": r.uid}, notes=cnote)
        # ---- conditional (Ask / Inform / Apply Layer) ----
        if r.is_drop and covers:
            # A covering DROP. Placing the conditional ABOVE it LOOSENS an admin deny by first-match — honor
            # override_blocking_deny: off -> place BELOW the deny + flag (won't take effect until it changes).
            if not options.override_blocking_deny:
                return Decision(Outcome.CREATE,
                                f"rule {r.number} ({r.name}) denies this; per policy the deny is NOT overridden "
                                f"— the {act} rule is placed BELOW it and will not take effect until that rule "
                                f"changes (review)", target_rule=r, position={"below": r.uid}, notes=cnote)
            return Decision(Outcome.CREATE,
                            f"rule {r.number} ({r.name}) denies this; per policy the deny IS overridden — "
                            f"creating the {act} rule ABOVE it (review)",
                            target_rule=r, position={"above": r.uid}, notes=cnote)
        # An in-path rule we CANNOT prove is safe to leap with a conditional: a drop we don't fully cover
        # (partial), or any rule whose extent/action we couldn't resolve (could itself be a deny). Don't
        # anchor above it — record the uncertainty and continue; the conditional will be floored.
        if r.is_drop or not r.is_resolved_action:
            uncertain_deny = True
            continue
        # A clean, resolved, non-deny in-path rule (e.g. an Accept). Safe to anchor the conditional ABOVE it —
        # UNLESS we already stepped past an opaque possible-deny (placing above would leap it) -> floor instead.
        if uncertain_deny:
            break
        return Decision(Outcome.CREATE,
                        f"creating a {act} rule ABOVE rule {r.number} ({r.name}) so first-match applies it "
                        f"to this flow", target_rule=r, position={"above": r.uid}, notes=cnote)
    # Fell through. A BLOCK with nothing in path can't be assumed already-denied — the layer's implicit
    # cleanup may be ACCEPT (configurable), so create the Drop at the floor to guarantee the deny.
    if conditional and uncertain_deny:
        return Decision(Outcome.CREATE,
                        f"an opaque/partial possible-deny in this request's path could not be proven; the "
                        f"{act} rule is placed at the section floor (NOT above it) so it cannot silently "
                        f"override an unmodeled deny — review placement", notes=cnote)
    return Decision(Outcome.CREATE,
                    f"no rule covers this request; creating the {act} rule at the section floor", notes=cnote)


def _decide(req: AccessRequest, rules: list[ParsedRule], options: "DecideOptions", notes: list) -> Decision:
    """The walk itself. Appends advisory warnings to ``notes`` (shared with ``decide``); returns the
    single chosen Decision. Recurses through ``decide`` (the wrapper) for inline layers, so a sub-layer's
    own notes come back tagged and get merged."""
    # IPv6 is now modeled (the dual-band integer space, see _V6_BASE). v4 and v6 occupy disjoint bands and
    # the predefined "Any" spans both, so a v6 request relates correctly to v6 cells, is disjoint from
    # v4-only cells, and is still covered by the Any/Any cleanup -- which is what makes it safe to reason
    # about rather than guard out. (A v4-only "0.0.0.0/0" network object covers only the v4 band, as it
    # should.)
    req_src, req_dst, req_svc = req.src_iv(), req.dst_iv(), req.svc()

    # Guard 2 -- a request that resolves to no concrete service (empty/garbage port, no application) has
    # an empty interval set, which would read as "covered by anything" -> a false NO_OP. Fail loud so the
    # pure surface is self-defending (build_request guards this too, as defense in depth).
    if not req_svc.any and not req_svc.apps and not req_svc.categories and not req_svc.named and not (
            req_svc.by_proto and any(iv for iv in req_svc.by_proto.values())):
        return Decision(
            Outcome.REVIEW,
            "the request specifies no concrete service, port, or application -- it is incomplete, so "
            "there is nothing to evaluate or create",
        )

    # Guard 3 -- a typed (non-IP) source/destination must name a concrete identity, and an IP source/
    # destination must resolve to a concrete extent. An empty value on either side can't be reasoned
    # about (a typed cell with no name, or an IP cell that resolved to nothing) -> fail loud, not NO_OP.
    for label, kind, value, iv in (("source", req.src_kind, req.src_value, req_src),
                                   ("destination", req.dst_kind, req.dst_value, req_dst)):
        if kind != "ip" and not (value or "").strip():
            return Decision(
                Outcome.REVIEW,
                f"the {label} is typed as a {kind} but names no object -- the request is incomplete, so "
                f"there is nothing to evaluate or create",
            )
        if kind == "ip" and not iv:
            return Decision(
                Outcome.REVIEW,
                f"the {label} resolves to no concrete IP extent -- the request is incomplete, so there "
                f"is nothing to evaluate or create",
            )

    # Guard 4 -- self-defend the PURE engine against an unknown action on a directly-constructed request
    # (build_request rejects these, but tests/aa_qa build AccessRequest directly). canonical_action() returns
    # "" for garbage/legacy -> REVIEW, never let decide() say one verdict while apply writes another.
    if req.canon_action not in WRITABLE_ACTIONS:
        return Decision(Outcome.REVIEW, f"unsupported action “{req.action}” — cannot evaluate this request")

    # NON-ACCEPT verdicts (Drop / Reject / Ask / Inform / Apply Layer) are routed to their own branch — the
    # reuse/widen logic below is ALLOW-semantics (it answers "is this access already granted?") and must NOT
    # run for a block / conditional / divert request. The Accept path stays exactly as it was.
    if req.canon_action != "Accept":
        return _decide_nonaccept(req, rules, options, notes, req_src, req_dst, req_svc)

    covering_drop: Optional[ParsedRule] = None   # the catch-all cleanup that floors placement
    widen_target: Optional[ParsedRule] = None    # reachable accept EQUAL in 2 dims, differing in the 3rd
    widen_field: Optional[str] = None            # the dimension to extend: source | destination | service
    widen_below_uncertain = False                # was the widen target found BELOW an opaque possible-deny?
    lower_anchor: Optional[ParsedRule] = None     # last rule strictly more specific than req
    conditional_skip: Optional[ParsedRule] = None  # a conditional ACCEPT we skipped (for the CREATE note)
    # A reachable, unconditional ACCEPT that covers the request on two dimensions and is NARROWER on the
    # third (the request is strictly BROADER there) — e.g. the request source is Any but the rule grants a
    # specific host set. It does NOT grant the request as asked (so the outcome is still CREATE), but the
    # access IS already permitted for that narrower scope. Recorded for the answer ONLY (it turns a
    # misleading "No — not permitted" into "permitted for these sources, just not the one you asked").
    partial_rule: Optional[ParsedRule] = None
    partial_field: Optional[str] = None
    # A reachable, unconditional ACCEPT whose L4 ports could already carry this APPLICATION over HTTP/HTTPS
    # (App Control identifies web apps on 80/443) and that already covers the request's source + destination.
    # We can't PROVE it grants the app (an app has no fixed transport — see _svc_indeterminate), so the
    # outcome stays CREATE; but the new app rule will most likely match this rule FIRST (at L4) and see no
    # hits — so we flag it (CP best practice: don't add redundant 0-hit rules). Display/advisory only.
    likely_covered_rule: Optional[ParsedRule] = None
    last_enabled = max((i for i, r in enumerate(rules) if r.enabled), default=-1)

    # ``uncertain_deny`` records that the walk continued past an opaque rule that COULD block (a drop /
    # divert). It only constrains PLACEMENT: a new allow must never be inserted ABOVE such a rule (first-
    # match would let it leap over a possible block) -> we force bottom placement when it's set. (The
    # advisory text lives in ``notes``, which the decide() wrapper tags onto the returned outcome.)
    uncertain_deny = False
    disabled_match: Optional[ParsedRule] = None   # a DISABLED accept that would cover/extend the request

    for i, r in enumerate(rules):
        if not r.enabled:
            # A disabled rule grants nothing, so it's correctly skipped from matching — but if it's an
            # ACCEPT that (were it on) would already cover or be widenable for this exact access, remember
            # it: at a CREATE we advise re-enabling it rather than silently adding a duplicate.
            if disabled_match is None and r.is_accept and not r.svc_unknown:
                # resolve FOR THIS REQUEST (r.complex is the IP-path flag — a typed/Internet dst sets it,
                # yet the rule is perfectly resolvable for a typed request): dst covered + svc covered.
                d_rel, d_unk, _ = _dim_relation(req.dst_kind, req.dst_value, req_dst, r, "destination")
                if not d_unk and _dim_covered(d_rel) and _dim_covered(svc_relation(req_svc, r.svc)):
                    disabled_match = r
            continue

        # Relate each dimension to the rule cell, dispatching on the request's kind (IP vs typed). The
        # effective *_unknown / *_approx come back per-request so the rest of decide() reads uniformly;
        # complex_eff is this rule's "extent unknown for THIS request" (replaces the IP-only r.complex).
        rel_src, src_unknown, src_approx = _dim_relation(req.src_kind, req.src_value, req_src, r, "source")
        rel_dst, dst_unknown, dst_approx = _dim_relation(req.dst_kind, req.dst_value, req_dst, r, "destination")
        rel_svc = svc_relation(req_svc, r.svc)
        # The rule's "extent unknown for THIS request" (replaces the IP-only r.complex). For a fully-IP
        # request this equals the stored r.complex (so the never-reason-past-an-unresolved-rule safety
        # net is unchanged); a TYPED request instead trusts the per-dimension unknowns, so a cell whose
        # only "complexity" was a typed object of the matching kind is now reasoned about, not REVIEW'd.
        all_ip = req.src_kind == "ip" and req.dst_kind == "ip"
        complex_eff = bool(src_unknown or dst_unknown or r.svc_unknown or (all_ip and r.complex))

        # A rule is out of the request's path only if it is PROVABLY disjoint on some dimension. A cell
        # whose extent we could not resolve (zone, dynamic-object, negation, unknown service) is never
        # provably disjoint -- so a rule with such a cell stays in the path and routes to REVIEW below.
        # (This is the safety invariant: never reason past a rule whose real reach is unknown.)
        svc_uncertain = _svc_uncertain(req_svc, r.svc)
        svc_indeterminate = _svc_indeterminate(req_svc, r.svc)
        # In the request's path unless PROVABLY disjoint on some dimension (the ONE shared rule — see
        # _out_of_path). IP legs judged on resolved extents: a resolved-disjoint APPROX rule (a gateway
        # resolved to its main IP, unrelated to the request) is stepped over rather than dragged in by the
        # under-approximation caveat; an approx rule that OVERLAPS is not DISJOINT, so it still stays in path
        # (a DROP whose approx extent overlaps is still floored below). Service leg folds svc_indeterminate.
        interferes = not _out_of_path(rel_src, src_unknown, rel_dst, dst_unknown,
                                      rel_svc, r.svc_unknown, svc_indeterminate)

        # A Dynamic Layer (sk182252) is managed OUT-OF-BAND by other admins -> EXCLUDED from our logic: we
        # never descend into it, reason about its sub-rules, or flag it (no note — the user asked for it to
        # be out of the picture). BUT safety still binds: if its parent columns INTERFERE with the request,
        # the rule diverts that traffic into the out-of-band layer, so we must NOT place the new allow
        # ABOVE it (first-match would bypass the out-of-band segmentation). It therefore still acts as a
        # silent placement FLOOR (uncertain_deny -> WIDEN suppressed + bottom placement, guaranteed below
        # the divert). A provably-disjoint dynamic rule can't affect the request -> skipped entirely.
        if r.dynamic_layer:
            if interferes:
                # A clean widen target already found ABOVE this divert grants the app by first-match BEFORE the
                # divert is consulted — widening it is first-match-equivalent to a carve-out above the divert
                # (it grants no scope the target's existing position didn't already imply), so prefer it over
                # flooring the new rule below the divert (AW-13). Honors prefer_widen + the opaque-deny guard.
                if options.prefer_widen and widen_target is not None and not uncertain_deny:
                    return _widen_above_block(widen_target, widen_field, r)
                uncertain_deny = True   # else the divert is a placement floor -> the new rule goes BELOW it
            continue

        # L7 (application) CARVE-OUT — the precise way to ACHIEVE an application allow-request that an
        # in-path rule would block. Per CP column-based matching, a broad L4 (port) DROP, or an opaque
        # app-category/group DROP, that lies in the request's path matches on the SYN and DROPS the app
        # today; a Facebook-Accept placed BELOW it is shadowed (a dead rule). Creating the app-Accept
        # ABOVE the blocking rule is correct AND safe: CP holds the connection, identifies the app and
        # accepts it, while every OTHER connection on that scope still falls through to the rule — a single
        # application carved out, never an over-grant. (Tunable: app_carveout off -> fall through to the
        # conservative note + place-below path instead.) Only a real application request qualifies; a port
        # request above a port-drop would grant the whole port -> not a carve-out, so it is excluded.
        # Only a FULLY-RESOLVED, UNCONDITIONAL drop qualifies for the carve-out. A conditional (VPN/time/
        # data-gated) drop, a negated/unresolvable cell (complex_eff), or an approx (gateway-main-IP) drop is
        # a POSSIBLE block whose true reach/applicability we can't prove — leaping the app-Accept above it
        # would silently override an unmodeled deny. Those cases FALL THROUGH to the conservative
        # note-and-place-below handlers below (the uncertain_deny floor), exactly like the port path — so the
        # operator always sees a review note and the grant lands below the possible block.
        carveable = ((req_svc.apps or req_svc.categories) and r.is_drop and interferes and covering_drop is None
                     and not (_is_catchall(r) and i == last_enabled)
                     and not (r.conditional and not options.ignore_conditions)
                     and not complex_eff and not src_approx and not dst_approx)
        if carveable:
            # Carving an allow ABOVE a resolved deny IS overriding that deny, so it honors override_blocking_deny
            # too (consistent with the port path) — both app_carveout AND override_blocking_deny must allow it.
            if options.app_carveout and options.override_blocking_deny:
                # Prefer WIDENING a clean accept already ABOVE this drop over a new carve-out rule (same effect,
                # one fewer rule; the widened rule sits above the drop so first-match grants the app).
                if options.prefer_widen and widen_target is not None and not uncertain_deny:
                    return _widen_above_block(widen_target, widen_field, r)
                pos = {"above": r.uid}
                shadowed = _more_specific_deny_below(req, req_src, req_dst, req_svc, rules, i)
                if shadowed is not None:        # carving above this drop also shadows a more-specific deny below
                    pos["_anomaly"] = True
                    notes.append(_shadow_note(shadowed))
                return Decision(
                    Outcome.CREATE,
                    f"rule {r.number} ({r.name}) blocks the requested application; creating the allow ABOVE "
                    f"it so Check Point carves out just that application — the rule still drops all of its "
                    f"other traffic",
                    target_rule=r, position=pos,
                )
            # app_carveout OFF, or the operator disallows overriding denies: place BELOW + flag, and STOP.
            # Returning (not continuing) avoids a lower Accept being read as a false NO_OP — per CP this drop
            # matches the app on the blocked port, so first-match, the drop wins until the deny is changed.
            return Decision(
                Outcome.CREATE,
                f"rule {r.number} ({r.name}) blocks the requested application; per policy the deny is NOT "
                f"overridden — the new rule is placed below it and will not take effect for traffic that rule "
                f"blocks (review)",
                target_rule=r, position={"below": r.uid},
            )

        # Inline layer ("Apply Layer"): the parent rule's columns gate entry into a sub-rulebase that the
        # loader has attached as r.inline_rules. Honour Check Point first-match: if ALL of the request is
        # contained in the parent's match (and the parent is a plain, unconditional rule), every packet
        # descends into the inline layer and never returns to this layer -> recurse and let the sub-rules
        # plus the inline layer's OWN implicit cleanup decide. If the request only partially matches, it
        # splits across the inline layer and the parent layer (a multi-rule interaction we won't
        # second-guess) -> REVIEW. This converts the old blanket "non-Accept/Drop action" REVIEW into an
        # automatic decision whenever the request lives wholly inside one inline layer.
        if r.inline_rules is not None and interferes and covering_drop is None:
            name = r.inline_layer_name or r.name
            if r.conditional and not options.ignore_conditions:
                # The "Apply Layer" only kicks in under a condition we can't model -> we can't follow that
                # branch. Don't stop: NOTE it and keep walking (a new rule is placed below it, so it can't
                # leap over whatever the inline layer would have done under the condition).
                notes.append(
                    f"rule {r.number} ({r.name}) applies inline layer “{name}” only under "
                    f"{', '.join(r.conditions)} (a dimension the engine doesn't model) — it may divert or "
                    f"block this traffic; the new rule is placed below it. Review it later.")
                uncertain_deny = True
                continue
            if complex_eff or not _is_subset(rel_src, rel_dst, rel_svc):
                # Only PART of the request enters the inline layer; the rest stays in this layer. We can't
                # cleanly reason across the split -> NOTE and keep walking (placement stays below it).
                notes.append(
                    f"the request only partially matches rule {r.number} ({r.name}); its traffic splits "
                    f"across inline layer “{name}” and the parent layer — the new rule is placed below it. "
                    f"Review it later.")
                uncertain_deny = True
                continue
            sub = decide(req, r.inline_rules, options)
            if sub.outcome is Outcome.REVIEW:
                return sub
            if sub.outcome is Outcome.CREATE:
                # A CREATE from the recursion is overloaded: it either anchored on an EXPLICIT covering
                # DROP inside the layer (target_rule.is_drop -> a real block, first-match consults it
                # BEFORE the implicit cleanup) or it fell through with no covering rule (target_rule is a
                # non-drop anchor or None -> the implicit cleanup decides). Discriminate, so an explicit
                # bottom Any/Any/Drop in the layer is never silently converted to a NO_OP by an
                # implicit-cleanup=accept (that would step over a covering deny).
                if sub.target_rule is not None and sub.target_rule.is_drop:
                    sub.reason = (f"inline layer “{name}” (rule {r.number}) blocks the request with an "
                                  f"explicit rule {sub.target_rule.number}; create a least-privilege rule "
                                  f"above it, inside the layer")
                    sub.layer = sub.layer or name
                    return sub
                # No explicit rule in the inline layer covers it -> its implicit cleanup is the verdict.
                if r.inline_cleanup == "accept" and not req.forces_create:
                    return Decision(
                        Outcome.NO_OP,
                        f"already permitted by the implicit cleanup (accept) of inline layer “{name}” "
                        f"(applied by rule {r.number})",
                        target_rule=r,
                    )
                # No explicit rule there covers it and the layer's cleanup is drop OR unknown: either way
                # the safe, actionable move is to CREATE an explicit allow INSIDE the inline layer (above
                # its cleanup). An explicit allow grants the request regardless of what the implicit
                # cleanup would do, so we don't need to resolve the cleanup to act -- no review stop.
                sub.reason = (f"no rule in inline layer “{name}” (applied by rule {r.number}) covers the "
                              f"request; create a least-privilege rule inside it, above its cleanup")
            elif sub.outcome is Outcome.NO_OP:
                sub.reason = f"already permitted inside inline layer “{name}”: {sub.reason}"
            # WIDEN / CREATE land INSIDE the inline layer (keep a deeper layer a nested recursion set).
            if sub.outcome is not Outcome.NO_OP:
                sub.layer = sub.layer or name
            return sub

        if (complex_eff or svc_uncertain or not r.is_resolved_action) and interferes:
            # This rule lies in the path but holds something we can't fully resolve — an updatable feed
            # (which may itself contain the requested object), an unresolvable/negated cell, or a non-
            # Accept/Drop action. We do NOT hard-stop the whole request on it (that would defeat the
            # automated flow); instead we NOTE it as a possible match to review later and CONTINUE the
            # walk. This is SAFE because nothing we go on to do can weaken the firewall: a NO_OP writes
            # nothing, a WIDEN/CREATE never overrides this rule (a new allow is placed BELOW any opaque
            # possible-deny — see uncertain_deny + placement — so first-match keeps that rule's effect).
            # (A *resolved*, provable covering/partial deny is different — it gets an explicit allow created
            # ABOVE it below; this branch is only the UN-resolvable case, which stays below the rule.)
            # If this rule provably CANNOT cover the request (e.g. the request destination is Any but the
            # rule's destination is a specific object, or a resolved dimension shows the request is
            # broader), then an ACCEPT here can't be the rule that "already permits" it — there is nothing
            # to flag, so skip it silently. (A DROP that can't fully cover may still block a SUBSET, so it
            # is still noted + placed-below below; an opaque ACCEPT that COULD cover is still flagged.)
            cant_cover = (
                _cant_cover_dim(rel_src, req.src_kind == "ip" and _covers(req_src, ANY_IP),
                                _covers(r.src, ANY_IP), src_unknown or src_approx)
                or _cant_cover_dim(rel_dst, req.dst_kind == "ip" and _covers(req_dst, ANY_IP),
                                   _covers(r.dst, ANY_IP), dst_unknown or dst_approx)
                or _cant_cover_dim(rel_svc, req_svc.any, r.svc.any, r.svc_unknown or svc_indeterminate))
            if r.is_accept and cant_cover:
                continue

            why = []
            if src_unknown:
                why.append("a negated or unresolvable source")
            if dst_unknown:
                why.append("a negated or unresolvable destination")
            if svc_uncertain or r.svc_unknown:
                why.append("a negated or unresolvable service/application")
            if not r.is_resolved_action:
                why.append(f"a non-Accept/Drop action (“{r.action or 'unknown'}”)")
            detail = "; ".join(why) or "an unresolvable match condition"
            could_block = r.is_drop or not r.is_resolved_action     # might deny/divert -> placement floor
            effect = ("may already permit it" if r.is_accept else
                      ("may block or divert it — the new rule is placed below it, so it can't override it"
                       if could_block else "may also match it"))
            notes.append(f"rule {r.number} ({r.name}) lies in the path with {detail} — it {effect}; "
                         f"review it later.")
            if could_block:
                uncertain_deny = True
            continue

        # A rule whose match ALSO depends on a column the engine doesn't model -- a VPN community/
        # direction, a time window, a content/data type, an install-on gateway subset, or a service-
        # resource -- is not an always-on Accept/Drop. We can't verify the extra condition, so a
        # conditional DENY/divert in the path is NOTED and the walk CONTINUES (don't hard-stop; the new
        # allow is placed below it so it can't leap over a possible block), and a conditional ACCEPT is
        # excluded from NO_OP / reuse / widen (its grant only holds under that condition) and skipped -- a
        # clean rule decides, or we CREATE a precise rule for the requested (unconditional) traffic, noting
        # why the matching-but-conditional rule doesn't grant it.
        if r.conditional and interferes and not options.ignore_conditions:
            if not r.is_accept:
                # A conditional DENY/divert (VPN / time / data / install-on) only blocks under a column we
                # can't model. Don't stop the flow: NOTE it and keep walking. It MIGHT block under its
                # condition, so we treat it as a possible-deny -> the new allow is placed below it (first-
                # match keeps that rule's effect for the traffic it does match).
                notes.append(
                    f"rule {r.number} ({r.name}) lies in the path but its match is restricted by "
                    f"{', '.join(r.conditions)} (a dimension the engine doesn't model) and it denies or "
                    f"diverts the traffic — it may block this under that condition; the new rule is placed "
                    f"below it. Review it later.")
                uncertain_deny = True
                continue
            conditional_skip = r
            continue

        # A DROP that interferes but whose true extent we CANNOT resolve for this request -- an approx
        # infra object (a gateway/cluster/mgmt resolved to its main IP; its real reach may be WIDER) or an
        # indeterminate/opaque service (an app category, service-other, a port we can't pin to the request)
        # -- is a POSSIBLE block we can't prove. We must NOT override it with a create-ABOVE (that could
        # leap over a real deny we simply couldn't see). NOTE it and CONTINUE, forcing the new allow BELOW
        # it (uncertain_deny). Only a FULLY-RESOLVED covering/partial deny is overridden with a create-
        # above (the branches below) -- there we can prove exactly what it blocks, which is the access the
        # caller asked us to make work.
        if r.is_drop and interferes and (svc_indeterminate or src_approx or dst_approx):
            # BUT if — despite the approx — the request is provably WITHIN this drop's RESOLVED extent (every
            # dimension SUBSET/EQUAL and no truly-unknown cell), the drop DEFINITELY blocks this exact request.
            # Approx is an UNDER-approximation (an infra object resolved to its main IP; true reach ⊇ resolved),
            # so a wider real extent only blocks MORE — it can't make this request escape. Placing the allow
            # BELOW such a drop would shadow it ENTIRELY (first-match hits the drop, the allow is dead). So the
            # allow MUST be carved ABOVE it to take effect — this is the Stealth-rule case (Any→Gateway Drop,
            # request to the gateway IP): an allow to the gateway belongs ABOVE the Stealth rule (CP best
            # practice). Gated by override_blocking_deny, identical to the resolved covering-drop branch below.
            provably_covered = (not svc_indeterminate and not r.svc_unknown and not src_unknown
                                and not dst_unknown and _is_subset(rel_src, rel_dst, rel_svc)
                                and not (_is_catchall(r) and i == last_enabled))
            if provably_covered and covering_drop is None:
                if not options.override_blocking_deny:
                    return Decision(
                        Outcome.CREATE,
                        f"traffic is denied by rule {r.number} ({r.name}); per policy the deny is NOT "
                        f"overridden — the new rule is placed below it and will not take effect until that "
                        f"rule is changed (review)",
                        target_rule=r, position={"below": r.uid},
                    )
                if options.prefer_widen and widen_target is not None and not uncertain_deny:
                    return _widen_above_block(widen_target, widen_field, r)
                pos = {"above": r.uid}
                shadowed = _more_specific_deny_below(req, req_src, req_dst, req_svc, rules, i)
                if shadowed is not None:
                    pos["_anomaly"] = True
                    notes.append(_shadow_note(shadowed))
                return Decision(
                    Outcome.CREATE,
                    f"traffic is currently denied by rule {r.number} ({r.name}); creating the allow ABOVE it "
                    f"so the requested access takes effect — placed below, first-match would let that drop "
                    f"shadow it (an allow to the gateway must sit above the Stealth rule)",
                    target_rule=r, position=pos,
                )
            # Otherwise the drop only POSSIBLY / partially covers (its approx extent may be wider than the
            # request, or its service is indeterminate) — we can't prove it blocks THIS exact request, so stay
            # conservative: NOTE it and place the new allow BELOW it (never leap a deny we can't pin down).
            dim = "service" if svc_indeterminate else "source / destination"
            notes.append(f"rule {r.number} ({r.name}) may block this request — its {dim} extent can't be "
                         f"fully resolved, so the new rule is placed below it. Review it later.")
            uncertain_deny = True
            continue

        # Past here, any rule we reuse / widen / anchor on is fully resolved (rules we couldn't resolve
        # were already NOTED and skipped above; complex+provably-disjoint rules are excluded below).
        fully_covers = not complex_eff and _is_subset(rel_src, rel_dst, rel_svc)

        # (1) already permitted? first covering ACCEPT before any covering DROP wins. The verdict is scoped
        # to THIS access layer — Check Point Ordered Layers chain (an Accept here only advances evaluation to
        # the next layer), so a downstream layer could still restrict the flow. A RESTRICTED request (it
        # carries a content/time/install-on/vpn match-gating column we don't fully model) is NEVER a NO_OP
        # against a rule that may lack that restriction -> fall through to CREATE.
        if fully_covers and r.is_accept and covering_drop is None:
            if req.forces_create:
                # the new rule adds a restriction/setting (content/time/install-on/vpn/action-settings) this
                # broad Accept lacks — it MUST sit ABOVE the Accept (first-match) or the new condition never
                # takes effect. (Placing it at the floor below would be a dead rule.)
                return Decision(
                    Outcome.CREATE,
                    f"rule {r.number} ({r.name}) broadly permits this; creating the more-specific rule ABOVE "
                    f"it so the new condition takes effect (the broad rule still serves its other traffic)",
                    target_rule=r, position={"above": r.uid})
            return Decision(
                Outcome.NO_OP,
                f"already permitted by rule {r.number} ({r.name}) within this access layer",
                target_rule=r,
            )

        # A covering DROP. The catch-all cleanup is a placement floor; a *specific* deny is an
        # intentional block -- never silently insert an allow above it.
        if fully_covers and r.is_drop and covering_drop is None:
            if _is_catchall(r) and i == last_enabled:
                covering_drop = r        # the real bottom cleanup -> placement floor
            elif not options.override_blocking_deny:
                # Tunable: the operator chose NOT to override an admin's deny. Place the new rule BELOW it
                # and STOP (returning here avoids a lower Accept being read as a NO_OP — first-match, the
                # deny wins). The rule won't take effect until the deny is changed; the reason says so.
                return Decision(
                    Outcome.CREATE,
                    f"traffic is denied by rule {r.number} ({r.name}); per policy the deny is NOT "
                    f"overridden — the new rule is placed below it and will not take effect until that rule "
                    f"is changed (review)",
                    target_rule=r, position={"below": r.uid},
                )
            else:
                # Prefer widening a clean accept already above this deny over a new rule (overriding denies
                # is allowed here, and the widened rule sits above the deny -> first-match grants it).
                if options.prefer_widen and widen_target is not None and not uncertain_deny:
                    return _widen_above_block(widen_target, widen_field, r)
                # A *specific* covering deny currently blocks the request. This tool's job is to make the
                # requested access work, so we CREATE the least-privilege allow directly ABOVE that deny
                # (first-match then hits the allow). The reason names the deny so the operator sees exactly
                # what the new rule takes precedence over.
                pos = {"above": r.uid}
                shadowed = _more_specific_deny_below(req, req_src, req_dst, req_svc, rules, i)
                if shadowed is not None:        # the allow above this deny also shadows a narrower deny below
                    pos["_anomaly"] = True
                    notes.append(_shadow_note(shadowed))
                return Decision(
                    Outcome.CREATE,
                    f"traffic is currently denied by rule {r.number} ({r.name}); creating the allow ABOVE "
                    f"it so the requested access takes effect",
                    target_rule=r, position=pos,
                )

        # A reachable DROP that overlaps the request but does NOT fully cover it partially blocks the
        # flow (e.g. a /32 deny inside a /24 request, or an overlapping range). To make the full request
        # work we create the allow ABOVE it. (A fully-covering deny is handled above; the catch-all
        # cleanup is excluded.)
        if (r.is_drop and not complex_eff and covering_drop is None
                and interferes and not fully_covers and not _is_catchall(r)):
            if not options.override_blocking_deny:
                # Tunable: don't override the deny. Place below it — first-match still drops the part this
                # rule covers, and the new rule grants the rest. STOP (return) so a lower Accept isn't read
                # as a NO_OP.
                return Decision(
                    Outcome.CREATE,
                    f"rule {r.number} ({r.name}) partially denies the requested scope; per policy the deny "
                    f"is NOT overridden — the new rule is placed below it (grants only the part the deny "
                    f"doesn't block)",
                    target_rule=r, position={"below": r.uid},
                )
            # Prefer widening a clean accept already above this partial deny over a new rule.
            if options.prefer_widen and widen_target is not None and not uncertain_deny:
                return _widen_above_block(widen_target, widen_field, r)
            # An overlapping deny blocks PART of the requested scope. Create the allow ABOVE it so the full
            # request takes effect (first-match hits the allow before this partial deny).
            pos = {"above": r.uid}
            shadowed = _more_specific_deny_below(req, req_src, req_dst, req_svc, rules, i)
            if shadowed is not None:            # placing above this partial deny also shadows a narrower deny below
                pos["_anomaly"] = True
                notes.append(_shadow_note(shadowed))
            return Decision(
                Outcome.CREATE,
                f"rule {r.number} ({r.name}) partially denies the requested scope; creating the allow "
                f"ABOVE it so the requested access takes effect",
                target_rule=r, position=pos,
            )

        # (2) widen candidate: a reachable ACCEPT that is EXACTLY EQUAL to the request in two of the
        # three dimensions {source, destination, service} and differs in the third -> add the request's
        # value for that third dimension to the rule's CELL. The other two MUST be equal, not merely a
        # superset: a cell holds a set, and adding a value grants it combined with EVERY member of the
        # other cells. If a rule's source is {win_client, win_server} and only win_server was requested,
        # widening its destination would also grant win_client -> over-grant. Requiring equality (and
        # adding to the cell, never to a shared group) means we grant precisely src x dst x svc.
        if (options.prefer_widen and widen_target is None and r.is_accept and not complex_eff
                and not svc_indeterminate and not r.conditional and covering_drop is None
                and not req.forces_create):   # a restricted/settinged request carries a column the rule may lack -> CREATE, don't widen
            # A non-differing dimension may serve as the "must be EQUAL" guard ONLY if it is a real,
            # exact extent. An approx cell (an infra object resolved to its main IP — true reach may be
            # wider) that reads EQUAL is an UNDER-approximation: widening the third dimension would grant
            # it combined with the cell's unseen extra addresses -> over-grant. Exclude approx from eq so
            # such a rule falls through to CREATE instead of widening.
            eq = {"source": rel_src == Relation.EQUAL and not src_approx,
                  "destination": rel_dst == Relation.EQUAL and not dst_approx,
                  "service": rel_svc == Relation.EQUAL}
            cov = {"source": _dim_covered(rel_src), "destination": _dim_covered(rel_dst),
                   "service": _dim_covered(rel_svc)}
            not_covered = [d for d in ("source", "destination", "service") if not cov[d]]
            if len(not_covered) == 1:
                field = not_covered[0]
                if (all(eq[d] for d in ("source", "destination", "service") if d != field)
                        and not _widen_mixes_internet(field, req, r)
                        and not (field == "service" and not _service_widenable(req))):
                    # If an opaque possible-deny was ALREADY passed, this widen target sits BELOW it — so
                    # widening it can't leap the request over that block (first-match still hits the block
                    # first). Record that, so the suppression below applies only to ABOVE-the-block widens.
                    widen_target, widen_field = r, field
                    widen_below_uncertain = uncertain_deny

        # NEAR-MISS for the ANSWER (display-only — never changes the outcome): a reachable, unconditional
        # ACCEPT that already permits the request on two dimensions and is NARROWER on exactly the third
        # (the request is strictly BROADER there — e.g. the request source is Any, but this rule grants a
        # specific host set). The access is genuinely NOT granted as asked (so we still CREATE), but it IS
        # permitted for that narrower scope — so the answer can say "already permitted for these sources,
        # just not the one you asked about" instead of a flat, misleading "No". Recorded only while the
        # accept is still reachable (no covering drop / opaque possible-deny passed above, which would
        # shadow the claim); the first (topmost) such rule wins. A fully-covering accept already returned
        # NO_OP above, so anything reaching here genuinely fails to cover the request as asked.
        if (partial_rule is None and r.is_accept and not complex_eff and not svc_indeterminate
                and not r.conditional and covering_drop is None and not uncertain_deny
                and not src_approx and not dst_approx):
            # An approx cell on ANY dimension (an infra object — gateway/cluster/mgmt — resolved to its main
            # IP) is an UNDER-approximation: its true reach may be wider than the resolved extent. Excluding
            # it on every dimension (not just the gap) keeps the "already permitted for these {names}" claim
            # provable — we assert it only when each dimension's extent is exactly known.
            _rel = {"source": rel_src, "destination": rel_dst, "service": rel_svc}
            _ncov = [d for d in ("source", "destination", "service") if not _dim_covered(_rel[d])]
            if len(_ncov) == 1 and _rel[_ncov[0]] == Relation.SUPERSET:
                partial_rule, partial_field = r, _ncov[0]

        # LIKELY-REDUNDANT flag (advisory only — never changes the outcome). This APPLICATION request meets a
        # reachable, unconditional ACCEPT whose L4 ports already carry web apps (cover TCP 80/443) and that
        # already covers the request's source + destination. App Control identifies the app over those ports,
        # so first-match will most likely hit THIS rule and the new app-Accept below it will be a dead 0-hit
        # rule. It's not a NO_OP (we can't prove the app is granted — its transport isn't fixed), so we still
        # CREATE, but we surface the likely redundancy. The topmost such rule wins.
        if (likely_covered_rule is None and r.is_accept and not complex_eff and not r.conditional
                and covering_drop is None and not uncertain_deny
                and (req_svc.apps or req_svc.categories)
                and _rule_may_bear_web_app(r.svc)
                and _dim_covered(rel_src) and _dim_covered(rel_dst)):
            likely_covered_rule = r

        # Placement lower bound: a fully-resolved rule strictly MORE specific than req (don't shadow it).
        if not complex_eff and _is_proper_superset(rel_src, rel_dst, rel_svc):
            lower_anchor = r

    # WIDEN is suppressed only when widening would let the request LEAP an opaque possible-deny: i.e. the
    # widen target sits ABOVE such a deny (widening it pulls the request's traffic over the block — a
    # first-match under-deny). A target found BELOW the deny (``widen_below_uncertain``) is safe — first-
    # match still hits the block first — so it widens normally. (This was the live bug: a Dynamic Layer
    # high in the rulebase set uncertain_deny and wrongly suppressed a widen of a rule far below it.)
    if widen_target is not None and (not uncertain_deny or widen_below_uncertain):
        others = {"source": "destination + service", "destination": "source + service",
                  "service": "source + destination"}[widen_field]
        # When the widen was allowed only because its target sits BELOW an opaque possible-deny
        # (widen_below_uncertain under uncertain_deny), the cell edit itself is exact — but a rule above whose
        # reach we couldn't resolve may still block this traffic. Say so on the widen line so the reason isn't
        # read as an unconditional grant (the possible-deny note is already attached separately).
        caveat = ("" if not uncertain_deny else
                  " — note: an unresolved rule above this one may still block the traffic (see the review "
                  "note); the widen edits the cell exactly but does not override that rule")
        return Decision(
            Outcome.WIDEN,
            f"rule {widen_target.number} ({widen_target.name}) matches the request's {others} exactly; "
            f"add the {widen_field} to that rule{caveat}",
            target_rule=widen_target, widen_field=widen_field,
        )

    reason = "no rule covers the request; create a least-privilege rule"
    if conditional_skip is not None:
        reason += (f" (rule {conditional_skip.number} ({conditional_skip.name}) overlaps this request "
                   f"but only applies under {', '.join(conditional_skip.conditions)}, so it does not "
                   f"grant this traffic)")
    if disabled_match is not None:
        notes.append(Note(f"rule {disabled_match.number} ({disabled_match.name}) already matches this access "
                          f"but is DISABLED — re-enable it (and the engine will extend it) instead of creating "
                          f"a duplicate, if that rule is what you intended.", kind="disabled"))
    # If an opaque rule that COULD deny was passed over, never anchor the new allow on a more-specific
    # rule above it (that could place the allow ABOVE the possible-deny -> a first-match leap over it).
    # Drop lower_anchor so placement falls to the cleanup floor / bottom — guaranteed below any such rule.
    anchor = None if uncertain_deny else lower_anchor
    if likely_covered_rule is not None:
        lc = likely_covered_rule
        notes.append(Note(
            f"likely redundant: rule {lc.number} ({lc.name}) already accepts this source → destination on "
            f"web ports (HTTP/HTTPS), and Check Point App Control identifies the requested application over "
            f"80/443 — so this traffic will most likely match rule {lc.number} first and the new rule may "
            f"see no hits. If the application only rides HTTP/HTTPS the access is already permitted (consider "
            f"not adding the rule, or enforcing app control in a dedicated Application layer); if it also uses "
            f"other ports, the new rule is still needed for those. To RESTRICT it instead, a Drop must be "
            f"placed ABOVE rule {lc.number}.", kind="redundant"))
    return Decision(
        Outcome.CREATE,
        reason,
        target_rule=covering_drop or anchor,
        position=_placement(covering_drop, anchor),
        partial=partial_rule, partial_field=partial_field,
    )


def _placement(covering_drop, lower_anchor) -> dict:
    """Internal placement hint, resolved to a web_api 'position' at apply time."""
    if (covering_drop is not None and lower_anchor is not None
            and lower_anchor.number > covering_drop.number):
        # the more-specific rule sits BELOW the cleanup -> existing anomaly worth flagging.
        return {"above": covering_drop.uid, "_anomaly": True}
    if covering_drop is not None:
        return {"above": covering_drop.uid}
    if lower_anchor is not None:
        return {"below": lower_anchor.uid}
    return {"_above_cleanup": True}


def _section_index(items: list, name: str) -> int:
    """Index of the top-level access-section with this name (case-insensitive), or -1 if absent."""
    low = (name or "").strip().lower()
    for idx, it in enumerate(items or []):
        if it.get("type") == "access-section" and (it.get("name") or "").strip().lower() == low:
            return idx
    return -1


def _cleanup_anchor(items: list, objdict: dict):
    """Where to insert the provisioned section so it sits ABOVE the cleanup. The cleanup is the catch-all
    DROP at the layer tail: either a trailing SECTION that ends in one or a bare trailing catch-all RULE.
    Returns ``("section"|"rule", uid, index)`` (anchored on the UID — unambiguous, unlike a name that could
    collide), or None (can't locate it -> caller degrades to bare bottom)."""
    def _is_catchall_item(e: dict) -> bool:
        return e.get("type") == "access-rule" and _is_catchall(_parse_rule(e, objdict))

    if not items:
        return None
    idx = len(items) - 1
    last = items[idx]
    if last.get("type") == "access-section":
        if any(_is_catchall_item(m) for m in (last.get("rulebase") or [])):
            return "section", last.get("uid"), idx
        return None
    if _is_catchall_item(last):
        return "rule", last.get("uid"), idx
    return None


def _floor_position(session, layer: str, package: Optional[str], out: dict):
    """Resolve the floor (above-cleanup) placement to a SECTION-aware web_api 'position', so a created
    rule lands in the configured 'provisioned' section ABOVE the cleanup section — never inside it. The
    rule's first-match HEIGHT is unchanged (still above the cleanup); only its grouping is tidied.

    Falls back to bare ``"bottom"`` whenever a section isn't configured, the layer can't be read, or its
    cleanup can't be located — so placement never breaks, it just isn't tidied. The web_api position forms
    here are marked VERIFY: dry-run them on the live SMS before publishing."""
    from . import naming
    section = naming.rule_section()
    if not section:
        return "bottom"
    try:
        items, objdict = _pull_items(session, layer, package)
    except Exception:  # noqa: BLE001 — discovery must never break the apply; degrade to bottom
        return "bottom"
    anchor = _cleanup_anchor(items, objdict)
    sec_idx = _section_index(items, section)
    if sec_idx >= 0:
        # The section already exists. Reuse it ONLY when it is bottom-adjacent to the cleanup (sits directly
        # above it). If an admin RELOCATED the section higher up (above some blocking rule, e.g. the Stealth
        # rule), placing a floored allow into it could leap the allow above the very rule that forced the
        # floor -> first-match exposes that traffic. In that case anchor relative to the cleanup instead, so
        # the rule stays at the safe bottom height. (decide() floors only below the cleanup or a possible
        # block; the cleanup is always below such a block, so above-the-cleanup is always a safe floor.)
        if anchor is not None and sec_idx == anchor[2] - 1:
            return {"bottom": section}           # VERIFY: bottom of the existing, bottom-adjacent section
        if anchor is not None:
            return {"above": anchor[1]}          # relocated section -> safe bottom, not the relocated group
        return "bottom"
    if anchor is None:
        return "bottom"                          # can't locate the cleanup -> safe degrade
    kind, ref, _ = anchor
    if kind == "rule":
        # a BARE cleanup rule (no wrapping section): just sit above it. Creating a section here would risk
        # the section absorbing the cleanup rule beneath its header -> the allow shadowed below the drop.
        return {"above": ref}                    # VERIFY (above a rule uid — the always-supported form)
    try:
        session.call("add-access-section",       # VERIFY: position forms mirror add-access-rule
                     {"layer": layer, "name": section, "position": {"above": ref}})
        out.setdefault("ops", []).append("add-access-section " + section)
    except MgmtError:
        return {"above": ref}                    # creation rejected -> still place above the cleanup SECTION
    return {"bottom": section}                    # VERIFY: rule -> bottom of the new provisioned section


# --------------------------------------------------------------------------- #
# REMOVE-access engine  (the inverse of decide(): revoke a granted access)
# --------------------------------------------------------------------------- #
class RemovalOutcome(str, Enum):
    NO_OP = "no_op"      # the access isn't permitted today -> nothing to remove
    DISABLE = "disable"  # one rule grants EXACTLY this access -> disable that rule (reversible)
    DENY = "deny"        # a BROADER rule grants it -> insert a least-privilege Drop ABOVE that rule
    REVIEW = "review"    # granted via an opaque / inline / conditional / partial / multi-rule path -> don't guess


@dataclass
class RemovalDecision:
    outcome: RemovalOutcome
    reason: str
    target_rule: Optional[ParsedRule] = None
    position: Optional[dict] = None
    notes: list = field(default_factory=list)
    # An explicit ACCEPT (BELOW the enabling L4 accept) that ALSO grants this app and whose source is broader
    # than the request -> a secondary cleanup: narrow its source (remove the now-blocked host) so the rulebase
    # isn't left with a shadowed grant. Only set for an app block where a Drop is placed above the enabler;
    # the actual removal is proven SAFE (direct host member, >=2 members) at APPLY time -> else just a note.
    narrow_rule: Optional[ParsedRule] = None


def _still_granted_below(req: AccessRequest, req_src, req_dst, req_svc,
                         rules_below: list[ParsedRule], options: "DecideOptions") -> bool:
    """If the first exact-match ACCEPT were disabled, would first-match STILL permit the request? Walks the
    rules BELOW it with the SAME relation logic as decide_removal: an interfering reachable ACCEPT — or any
    rule whose effect we cannot fully resolve (inline / conditional / opaque / non-Accept-Drop) — means the
    flow could survive -> True (so disabling alone is unsafe; the caller uses a Drop-above instead). A
    fully-covering resolved DROP denies it -> False. Reaching the end with neither -> the implicit cleanup
    denies it -> False. Partial drops and provably-disjoint rules are stepped over."""
    for r in rules_below:
        if not r.enabled:
            continue
        rel_src, src_unknown, src_approx = _dim_relation(req.src_kind, req.src_value, req_src, r, "source")
        rel_dst, dst_unknown, dst_approx = _dim_relation(req.dst_kind, req.dst_value, req_dst, r, "destination")
        rel_svc = svc_relation(req_svc, r.svc)
        all_ip = req.src_kind == "ip" and req.dst_kind == "ip"
        complex_eff = bool(src_unknown or dst_unknown or r.svc_unknown or (all_ip and r.complex))
        svc_indeterminate = _svc_indeterminate(req_svc, r.svc)
        # DISABLE-vs-DENY safety: only a PROVABLE re-grant below should block the clean disable. Judge the
        # IP legs on their RESOLVED extents (src_unknown / dst_unknown) — NOT folding in the approx (gateway
        # main-IP) CAVEAT — so an unrelated rule whose only "interference" is an approx source (e.g. a
        # CP-Updates accept "GW/SMS -> http/https", source-disjoint from the host) is correctly stepped over
        # and the one rule that grants is simply disabled. The SERVICE leg KEEPS svc_indeterminate: a same-
        # src+dst rule on http/https (tcp 80/443) DOES re-grant a web APP request via App Control, so it must
        # NOT be read as disjoint (that was a silent under-removal). A genuinely-unknown cell (negated /
        # opaque) is never resolved-disjoint, so it still falls through to the conservative "survives" below.
        if _out_of_path(rel_src, src_unknown, rel_dst, dst_unknown, rel_svc, r.svc_unknown, svc_indeterminate):
            continue                                      # provably out of this request's path -> not a re-granter
        # An interfering Dynamic Layer (sk182252, "Apply Layer") is managed out-of-band: its sub-rulebase is
        # invisible to us (inline_rules is None) and MAY grant the flow once the exact ACCEPT above it is
        # disabled. So it can't be proven harmless -> the flow could survive -> force the safe Drop-above.
        if r.dynamic_layer:
            return True
        if (r.inline_rules is not None or (r.conditional and not options.ignore_conditions)
                or (r.conditional and r.is_drop)   # a conditional DROP only blocks UNDER its condition; in a
                #                                    REMOVAL it must NEVER assert a full deny (which would mask a
                #                                    re-granting ACCEPT below), even under ignore_conditions.
                or complex_eff or svc_indeterminate or not r.is_resolved_action):
            return True                                   # can't prove the flow is denied below -> assume it survives
        if r.is_drop:
            if _is_subset(rel_src, rel_dst, rel_svc):
                return False                              # a covering DROP denies the whole request
            continue                                      # partial drop: the rest may flow on
        return True                                       # a reachable ACCEPT still grants (part of) the request
    return False                                          # nothing below grants it -> implicit cleanup denies it


def decide_removal(req: AccessRequest, rules: list[ParsedRule], options: "DecideOptions" = None) -> RemovalDecision:
    """The INVERSE of decide(): find what GRANTS src->dst:svc and remove it with the least-disruptive SAFE
    move, honouring Check Point first-match. Walk top-down to the FIRST fully-covering, fully-resolved ACCEPT
    (before any covering Drop): grants EXACTLY the request -> DISABLE that rule; grants something BROADER ->
    insert a least-privilege Drop ABOVE it (first-match then denies just this flow; the broad rule still
    serves everyone else, never an over-removal). Already denied / nothing grants it -> NO_OP. An opaque /
    inline / conditional rule in the path, a partial drop, or access granted across multiple rules -> REVIEW
    (removal is destructive — never guess). NARROW (removing a discrete source member) is intentionally NOT
    attempted here: it can't be proven safe from intervals alone (group vs cell member, embedded-in-network),
    so the safe universal primitive is the precise Drop-above."""
    options = options or DecideOptions()
    req_src, req_dst, req_svc = req.src_iv(), req.dst_iv(), req.svc()
    if not req_svc.any and not req_svc.apps and not req_svc.categories and not req_svc.named and not (
            req_svc.by_proto and any(iv for iv in req_svc.by_proto.values())):
        return RemovalDecision(RemovalOutcome.REVIEW, "the request specifies no concrete service, port, or application")
    for label, kind, value, iv in (("source", req.src_kind, req.src_value, req_src),
                                    ("destination", req.dst_kind, req.dst_value, req_dst)):
        if kind != "ip" and not (value or "").strip():
            return RemovalDecision(RemovalOutcome.REVIEW, f"the {label} is typed {kind} but names no object")
        if kind == "ip" and not iv:
            return RemovalDecision(RemovalOutcome.REVIEW, f"the {label} resolves to no concrete IP extent")

    is_app_req = bool(req_svc.apps or req_svc.categories)   # an APPLICATION/category block (vs IP/port)
    enabling_accept = None                                   # highest in-path L4 ACCEPT that may CARRY the app
    for idx, r in enumerate(rules):
        if not r.enabled:
            continue
        rel_src, src_unknown, src_approx = _dim_relation(req.src_kind, req.src_value, req_src, r, "source")
        rel_dst, dst_unknown, dst_approx = _dim_relation(req.dst_kind, req.dst_value, req_dst, r, "destination")
        rel_svc = svc_relation(req_svc, r.svc)
        all_ip = req.src_kind == "ip" and req.dst_kind == "ip"
        complex_eff = bool(src_unknown or dst_unknown or r.svc_unknown or (all_ip and r.complex))
        svc_indeterminate = _svc_indeterminate(req_svc, r.svc)
        # In the path unless PROVABLY out of it (the ONE shared rule — see _out_of_path). An unrelated rule
        # whose only link is an approx (gateway main-IP) source/dest — e.g. a "CP Updates" accept GW/SMS ->
        # http/https sitting ABOVE the real grant — is resolved-disjoint and STEPPED OVER, so the walk reaches
        # the rule that actually grants rather than bailing to REVIEW (was the reported failure).
        interferes = not _out_of_path(rel_src, src_unknown, rel_dst, dst_unknown,
                                      rel_svc, r.svc_unknown, svc_indeterminate)
        # GOLDEN RULE: a DYNAMIC layer (sk182252) is managed out-of-band (Gaia pushes its content straight to
        # the GW) — invisible to us, so it is SKIPPED from matching. Look PAST it for the real, management-
        # visible rule that grants the flow rather than bailing to REVIEW. (The DISABLE-vs-DENY safety for a
        # dynamic layer sitting BELOW the grant is kept in _still_granted_below — there we prefer an explicit
        # Drop-above over a reversible-looking disable that would leave the divert reachable.)
        if r.dynamic_layer:
            continue
        if not interferes:
            continue
        # an unresolved / inline / conditional / opaque rule sits in the path before any clean grant -> a
        # destructive change can't be reasoned past it safely.
        if (r.inline_rules is not None or (r.conditional and not options.ignore_conditions)
                or (r.conditional and r.is_drop)   # a conditional DROP only blocks UNDER its condition; in a
                #                                    REMOVAL it must NEVER assert a full deny (which would mask a
                #                                    re-granting ACCEPT below), even under ignore_conditions.
                or complex_eff or not r.is_resolved_action):
            return RemovalDecision(RemovalOutcome.REVIEW,
                                   f"rule {r.number} ({r.name}) lies in the path but can't be fully resolved "
                                   f"(inline layer / conditional / opaque cell / non-Accept-Drop action) — "
                                   f"review the removal manually")
        # APP-vs-L4 ambiguity. An otherwise-resolved ACCEPT whose only in-path reason is svc_indeterminate may
        # CARRY an application over its L4 ports (e.g. an Outbound http/https accept carrying Facebook). For an
        # APPLICATION removal it is an ENABLER: the block must be placed ABOVE it (first-match), so record the
        # FIRST (highest) one and keep walking to also find an explicit app rule below. Any other indeterminate
        # case (a port request vs an app rule, or an indeterminate DROP) stays conservative -> REVIEW.
        if svc_indeterminate:
            if is_app_req and r.is_accept:
                if enabling_accept is None:
                    enabling_accept = r
                continue
            if is_app_req and r.is_drop and enabling_accept is not None:
                # A web-bearing (indeterminate) DROP sitting BELOW an enabling ACCEPT is shadowed for this
                # app — first-match hits the accept above, so the drop is not the effective verdict. Step
                # past it (mirroring the resolved shadowed-drop path below); the block we create lands ABOVE
                # the enabling accept. Without this the removal bailed to REVIEW even though a clean DENY is
                # provable.
                continue
            return RemovalDecision(RemovalOutcome.REVIEW,
                                   f"rule {r.number} ({r.name}) lies in the path with an indeterminate "
                                   f"service/application match — review the removal manually", target_rule=r)
        fully_covers = _is_subset(rel_src, rel_dst, rel_svc)
        if r.is_drop:
            # An enabling ACCEPT already found ABOVE carries the app, so this drop is shadowed for it (not the
            # effective verdict) — keep walking; the block lands above the enabling accept.
            if enabling_accept is None:
                if fully_covers:
                    return RemovalDecision(RemovalOutcome.NO_OP,
                                           f"already denied by rule {r.number} ({r.name}) — the access is not "
                                           f"permitted; nothing to remove", target_rule=r)
                return RemovalDecision(RemovalOutcome.REVIEW,
                                       f"rule {r.number} ({r.name}) partially denies the request; the removal "
                                       f"interacts with it — review manually", target_rule=r)
            continue
        # a reachable ACCEPT
        if fully_covers:
            if enabling_accept is not None:
                # A higher L4 accept can carry the app, so the ONLY first-match-correct block is a Drop ABOVE
                # that accept. This rule ALSO explicitly grants it; if its source is broader than the request
                # (it has other members), recommend narrowing its source rather than leaving a shadowed grant.
                narrowable = rel_src == Relation.SUBSET     # the rule has OTHER sources -> remove just this host
                note = (f"rule {r.number} ({r.name}) also explicitly grants this — narrowing its source to drop "
                        f"just this host (it has other sources), so the rulebase isn't left with a shadowed "
                        f"grant" if narrowable else
                        f"rule {r.number} ({r.name}) also explicitly grants this and is now shadowed by the "
                        f"Drop — review whether it is still needed")
                return RemovalDecision(
                    RemovalOutcome.DENY,
                    f"rule {enabling_accept.number} ({enabling_accept.name}) can carry this application over "
                    f"its L4 ports, so a least-privilege Drop is placed ABOVE it — first-match then blocks "
                    f"just this flow while that rule still serves its other traffic",
                    target_rule=enabling_accept, position={"above": enabling_accept.uid}, notes=[note],
                    narrow_rule=r if narrowable else None)
            # DISABLE only when the rule grants EXACTLY this and NOTHING ELSE relies on it. Two proofs are
            # required, both safety-critical: (1) no approx cell — an infra object resolved to its main IP
            # reads EQUAL but its true reach may be WIDER, so disabling the rule would revoke access for
            # those unseen addresses too (over-removal); (2) no rule BELOW re-grants the flow — otherwise
            # first-match would fall through to it and the access would survive (under-removal: we'd report
            # it removed when it isn't). Either proof failing -> the always-safe Drop-above primitive.
            exact = (rel_src == Relation.EQUAL and rel_dst == Relation.EQUAL and rel_svc == Relation.EQUAL
                     and not src_approx and not dst_approx)
            if exact and not _still_granted_below(req, req_src, req_dst, req_svc, rules[idx + 1:], options):
                return RemovalDecision(RemovalOutcome.DISABLE,
                                       f"rule {r.number} ({r.name}) grants EXACTLY this access and no rule "
                                       f"below re-grants it — disable it (reversible; nothing else relies on "
                                       f"this rule)", target_rule=r)
            why = ("grants this access but is broader" if not exact else
                   "grants exactly this access, but a rule below also grants it (disabling alone would not "
                   "remove it)")
            return RemovalDecision(RemovalOutcome.DENY,
                                   f"rule {r.number} ({r.name}) {why}; inserting a least-privilege Drop ABOVE "
                                   f"it removes exactly this request by first-match while the rule still "
                                   f"serves its other traffic", target_rule=r,
                                   position={"above": r.uid})
        # accept overlaps but is narrower than the request -> granted piecemeal. With an enabling accept above,
        # the Drop-above-it covers the whole flow, so the piecemeal grant is moot; otherwise -> REVIEW.
        if enabling_accept is None:
            return RemovalDecision(RemovalOutcome.REVIEW,
                                   f"rule {r.number} ({r.name}) grants only part of the requested scope; the "
                                   f"access spans multiple rules — review the removal manually")

    if enabling_accept is not None:
        # An L4 accept carries the app but no explicit app rule was found below it -> Drop above that accept.
        return RemovalDecision(
            RemovalOutcome.DENY,
            f"rule {enabling_accept.number} ({enabling_accept.name}) can carry this application over its L4 "
            f"ports; a least-privilege Drop is placed ABOVE it so first-match blocks just this flow",
            target_rule=enabling_accept, position={"above": enabling_accept.uid})
    return RemovalDecision(RemovalOutcome.NO_OP,
                           "no rule grants this access — it is already not permitted; nothing to remove")


# --------------------------------------------------------------------------- #
# I/O layer  (uses the existing MgmtSession client)
# --------------------------------------------------------------------------- #
_INLINE_MAX_DEPTH = 4     # inline layers can nest; cap the recursion (a cycle guard backs this up)


def _pull_items(session, layer_name: str, package: Optional[str], max_rules: int = 50000) -> tuple:
    """One layer's raw rulebase items + object dictionary (paged), the pull pattern decide() relies on."""
    items: list[dict] = []
    objdict: dict = {}
    total, offset = 0, 0
    while offset < max_rules:
        payload = {"name": layer_name, "limit": 500, "offset": offset,
                   "use-object-dictionary": True, "details-level": "full",
                   "dereference-group-members": True}   # resolve group cells to member IPs (see decide())
        if package:
            payload["package"] = package
        page = session.call("show-access-rulebase", payload)
        for o in page.get("objects-dictionary", []):
            if o.get("uid"):
                objdict[o["uid"]] = o
        batch = page.get("rulebase", [])
        items.extend(batch)
        total = page.get("total", total)
        to = page.get("to", 0)
        if not batch or to >= total or to <= offset:
            break
        offset = to
    # FAIL LOUD on truncation: a partial rulebase (cleanup + denies past the cap missing) would make
    # decide() under-deny (step over a covering DROP it never loaded). Never decide on a truncated view.
    # Compare total to the CAP, not len(items): `total` is the rule count, `items` is the TOP-LEVEL
    # rulebase (sections wrap rules), so `total > len(items)` falsely tripped on any sectioned layer.
    if total and total > max_rules:
        raise MgmtError(f"access layer “{layer_name}” has {total} rules, over the {max_rules} cap; "
                        f"refusing to decide on a truncated rulebase — raise the cap or split the layer")
    return items, objdict


def _layer_meta(session, layer_ref: str, *, by: str = "uid") -> tuple[str, bool]:
    """An access layer's ``(implicit-cleanup-action, is-dynamic-layer)``. The cleanup is usually already in
    the rule's object dictionary (no extra call); this is the lookup fallback. ``dynamic-layer`` (sk182252)
    marks a layer managed out-of-band -> the caller EXCLUDES it from the engine entirely."""
    if not layer_ref:
        return "", False
    try:
        r = session.call("show-access-layer", {by: layer_ref})          # VERIFY (accepts name or uid)
        return (r.get("implicit-cleanup-action", "") or "").lower(), bool(r.get("dynamic-layer"))
    except Exception:  # noqa: BLE001 — best-effort; on error we just don't learn the cleanup / dynamic flag
        return "", False


def _attach_inline_layers(session, rules, package, pull, depth: int, visited: set) -> None:
    """For every "Apply Layer" rule, pull + parse its inline layer's rulebase (recursively) and attach it
    as r.inline_rules so decide() can recurse purely. ``pull(layer_name) -> list[ParsedRule]`` does the
    fetch (fresh or cached). Guards: a depth cap and a visited-uid set (an inline layer referencing one of
    its ancestors would otherwise loop). On any error the rule is left as a normal unresolved action,
    which decide() routes to REVIEW -- never a silent grant."""
    if depth <= 0:
        return
    for r in rules:
        if not r.inline_uid:
            continue
        # Learn whether this is a Dynamic Layer (sk182252) via show-access-layer. CRITICAL: the
        # ``dynamic-layer`` flag is returned ONLY by show-access-layer — it is NOT in the object dictionary
        # that show-access-rulebase feeds _parse_rule — so we MUST consult the layer here (the objdict's
        # cleanup is no substitute, and gating this on inline_cleanup-absence would miss a dynamic layer
        # whose cleanup happened to be in the dict). One best-effort call per inline rule; it also fills the
        # cleanup if the object dictionary didn't carry it.
        if not r.dynamic_layer:
            cleanup, dyn = _layer_meta(session, r.inline_uid)
            if cleanup and not r.inline_cleanup:
                r.inline_cleanup = cleanup
            if dyn:
                r.dynamic_layer = True
        # A Dynamic Layer is managed out-of-band by other admins -> EXCLUDE it: never pull or descend, and
        # leave inline_rules None + dynamic_layer set so decide() skips the rule entirely.
        if r.dynamic_layer:
            r.inline_rules = None
            continue
        if r.inline_uid in visited:
            r.inline_rules = []                  # cycle -> treat as an empty inline layer (cleanup decides)
            continue
        try:
            sub = pull(r.inline_layer_name or r.inline_uid)
            _attach_inline_layers(session, sub, package, pull, depth - 1, visited | {r.inline_uid})
            r.inline_rules = sub
        except Exception:  # noqa: BLE001 — leave inline_rules None, never assume a grant
            r.inline_rules = None


def load_layer(session, layer_name: str, package: Optional[str] = None,
               max_rules: int = 50000) -> list[ParsedRule]:
    """Pull a layer with full object details (same pattern as mgmt_api.pull_for_export) and parse
    every rule into value-resolved intervals, attaching any inline-layer sub-rulebases."""
    def _pull(name: str) -> list[ParsedRule]:
        items, objdict = _pull_items(session, name, package, max_rules)
        return [_parse_rule(e, objdict) for e in _flatten(items) if e.get("type") == "access-rule"]

    try:
        rules = _pull(layer_name)
    except MgmtError as exc:
        # Turn the SMS's opaque "Requested object [X] not found" into a clear, actionable message that names
        # it as an ACCESS LAYER and lists the real layer names — so a wrong/guessed layer self-corrects
        # (e.g. "Network Layer" -> "did you mean Network?") instead of dead-ending.
        if _is_not_found_error(str(exc)):
            try:
                names = [L.get("name") for L in session.list_access_layers() if L.get("name")]
            except Exception:  # noqa: BLE001 — best-effort enrichment; fall back to the raw error
                names = []
            avail = ", ".join(names) if names else "none found on this server"
            raise MgmtError(f"access layer '{layer_name}' was not found on this server. "
                            f"Available access layers: {avail}. Re-run with the exact layer name.") from exc
        raise
    _attach_inline_layers(session, rules, package, _pull, _INLINE_MAX_DEPTH, set())
    return rules


def _norm_layer(s: str) -> str:
    """Normalize a layer name for matching: lowercase, trimmed, with a trailing noise word the user/agent
    often appends ('Network Layer' / 'Network policy') dropped — so 'Network Layer' resolves to 'Network'."""
    out = " ".join((s or "").strip().lower().split())
    for w in (" access layer", " layer", " policy", " rulebase", " access"):
        if out.endswith(w):
            out = out[: -len(w)].strip()
            break
    return out


def resolve_layer_name(session, requested: str) -> tuple[str, str]:
    """Map a user/agent-supplied layer name to the EXACT name on the server. Returns (canonical, note).

    A case-insensitive exact match wins; otherwise a normalized match that ignores a trailing 'layer'/
    'policy' noise word ('Network Layer' -> 'Network'). A normalized match must be UNIQUE — so we never
    silently target the wrong layer. With no confident match, raise MgmtError listing the real layer names
    (the caller surfaces it), so a wrong name self-corrects or fails clearly instead of dead-ending on the
    SMS's opaque 'Requested object [...] not found'. Falls back to the requested name if layers can't be
    listed (the load attempt then surfaces the true error)."""
    req = (requested or "").strip()
    try:
        names = [L.get("name") for L in session.list_access_layers() if L.get("name")]
    except Exception:  # noqa: BLE001 — can't list -> let the subsequent load surface the real error
        return req, ""
    if not names or not req:
        return req, ""
    for n in names:                                   # exact, case-insensitive
        if n.lower() == req.lower():
            return n, ""
    rn = _norm_layer(req)
    matches = [n for n in names if _norm_layer(n) == rn] if rn else []
    if len(matches) == 1:
        return matches[0], f"resolved access layer “{requested}” to “{matches[0]}”"
    raise MgmtError(f"access layer '{requested}' was not found on this server. "
                    f"Available access layers: {', '.join(names)}. Re-run with the exact layer name.")


def lookup_host(session, ip: str) -> Optional[str]:
    """Existing host object name for this exact IP (v4 or v6), or None. Read-only (dedup by value;
    compared numerically so a differently-formatted v6 literal still matches)."""
    found = session.call("show-objects",
                         {"filter": ip, "ip-only": True, "type": "host", "limit": 5})  # VERIFY
    try:
        want = ipaddress.ip_address(ip)
    except ValueError:
        want = None
    for o in found.get("objects", []):
        for v in (o.get("ipv4-address"), o.get("ipv6-address")):
            if not v:
                continue
            try:
                if want is not None and ipaddress.ip_address(v) == want:
                    return o["name"]
            except ValueError:
                if v == ip:
                    return o["name"]
    return None


def _object_ip_span(o: dict) -> Optional[tuple]:
    """The (lo, hi, version) integer IP interval an object spans, or None if it carries no FIXED address
    scope (a group / Any / identity object / unresolved cell). Covers every address-bearing Check Point
    object kind uniformly — a host or any single-address infra object (gateway / cluster / cluster-member /
    Check Point host / interop ...) via ipv4/ipv6-address; a network via subnet+mask; an address-range (incl.
    multicast) via first/last. This lets endpoint reuse match by EXACT scope across ALL types, not a per-type
    allowlist."""
    a = o.get("ipv4-address") or o.get("ipv6-address")
    if a:
        try:
            ip = ipaddress.ip_address(a)
            return (int(ip), int(ip), ip.version)
        except ValueError:
            return None
    try:
        if o.get("subnet4") is not None and o.get("mask-length4") is not None:
            n = ipaddress.ip_network(f"{o['subnet4']}/{int(o['mask-length4'])}", strict=False)
            return (int(n.network_address), int(n.broadcast_address), 4)
        if o.get("subnet6") is not None and o.get("mask-length6") is not None:
            n = ipaddress.ip_network(f"{o['subnet6']}/{int(o['mask-length6'])}", strict=False)
            return (int(n.network_address), int(n.broadcast_address), 6)
        f = o.get("ipv4-address-first") or o.get("ipv6-address-first")
        l = o.get("ipv4-address-last") or o.get("ipv6-address-last")
        if f and l:
            lo, hi = ipaddress.ip_address(f), ipaddress.ip_address(l)
            return (int(lo), int(hi), lo.version)
    except ValueError:
        return None
    return None


# Reuse precedence among objects that EXACTLY match the requested scope: the canonical address objects
# first (host for a single IP, network for a CIDR, then address-range), any other matching type (a gateway /
# cluster / Check Point host / interop) last — so a duplicate is never created, but the most natural object
# wins a tie. Unknown types sort after these.
_ENDPOINT_TYPE_RANK = {"host": 0, "network": 1, "address-range": 2, "multicast-address-range": 2}


def lookup_address_object(session, cidr_or_ip: str) -> Optional[str]:
    """The existing object whose address scope EXACTLY equals the requested IP/CIDR, across ALL supported
    address-bearing types (host / network / address-range / gateway / cluster / cluster-member / Check Point
    host / interop / ...), or None. ``ip-only`` returns everything whose scope CONTAINS the address (covering
    ranges/groups/networks too) and only ``details-level=full`` echoes the address fields — so we ask for full
    and keep only an object whose own span is IDENTICAL to the request (never a broader container, which would
    over-grant). Read-only dedup so a request reuses the right object instead of fabricating a duplicate."""
    net = ipaddress.ip_network(cidr_or_ip, strict=False)
    want = (int(net.network_address), int(net.broadcast_address), net.version)
    found = session.call("show-objects",
                         {"filter": str(net.network_address), "ip-only": True,
                          "details-level": "full", "limit": 50})  # VERIFY
    matches = [o for o in found.get("objects", [])
               if o.get("name") and _object_ip_span(o) == want]
    if not matches:
        return None
    matches.sort(key=lambda o: _ENDPOINT_TYPE_RANK.get((o.get("type") or "").lower(), 9))
    return matches[0]["name"]


def resolve_host(session, ip: str, name_hint: Optional[str] = None) -> str:
    """Reuse an existing host by exact IP, else create one."""
    existing = lookup_host(session, ip)
    if existing:
        return existing
    from . import naming
    name = name_hint or naming.host_name(ip)
    session.call("add-host", {"name": name, "ip-address": ip})            # VERIFY
    return name


def _endpoint_name(net) -> str:
    from . import naming                       # admin-customisable templates (defaults = the h-/n- scheme)
    addr = str(net.network_address)
    if net.prefixlen == net.max_prefixlen:
        return naming.host_name(addr)
    return naming.network_name(addr, net.prefixlen)


def lookup_network(session, net) -> Optional[str]:
    """Existing network object name matching this subnet + prefix, or None (dedup by value)."""
    sub_key = "subnet6" if net.version == 6 else "subnet4"
    mask_key = "mask-length6" if net.version == 6 else "mask-length4"
    found = session.call("show-objects",
                         {"filter": str(net.network_address), "type": "network", "limit": 25})  # VERIFY
    for o in found.get("objects", []):
        if str(o.get(sub_key)) == str(net.network_address) and int(o.get(mask_key, -1)) == net.prefixlen:
            return o["name"]
    return None


def lookup_endpoint(session, cidr: str) -> Optional[str]:
    """Existing object for a request endpoint — the predefined Any, else ANY supported address-bearing
    object whose scope EXACTLY equals the request (host / network / address-range / gateway / cluster /
    Check Point host / interop / ...), or None. Matching by exact IP span (not a per-type allowlist) means a
    /32 to a gateway reuses the gateway, a CIDR reuses a matching network OR an equivalent address-range,
    etc. — never a duplicate, never a broader container."""
    if _is_any(cidr):
        return "Any"
    return lookup_address_object(session, cidr)


def resolve_endpoint(session, cidr: str) -> str:
    """Reuse-or-create the object that represents a request endpoint. Critically, a CIDR wider than a
    single address materializes as a NETWORK object (not a /32 host), so the committed rule covers the
    full requested scope that decide() reasoned over — never silently narrowed to one IP. The literal
    Any references Check Point's predefined Any object and is never created."""
    if _is_any(cidr):
        return "Any"
    net = ipaddress.ip_network(cidr, strict=False)
    # Reuse before create, with the SAME precedence the preview reported (host > gateway/cluster/CP-host >
    # network) — so what decide() showed as "exists" is exactly what apply references, no duplicate h-<ip>.
    existing = lookup_endpoint(session, cidr)
    if existing:
        return existing
    if net.prefixlen == net.max_prefixlen:
        return resolve_host(session, str(net.network_address), name_hint=_endpoint_name(net))
    name = _endpoint_name(net)
    addr = str(net.network_address)
    if net.version == 6:
        session.call("add-network", {"name": name, "subnet6": addr, "mask-length6": net.prefixlen})  # VERIFY
    else:
        session.call("add-network", {"name": name, "subnet4": addr, "mask-length4": net.prefixlen})  # VERIFY
    return name


# CP object type per typed request kind (for show-objects lookup) + whether it may be CREATED from an
# access request. Identity objects that must be defined elsewhere — an access-role (Identity Awareness),
# a security-zone (gateway topology), a CP-curated updatable-object — are REUSE-ONLY: a clear error if
# missing, never silently fabricated (an empty one would grant nothing and mislead the user).
_TYPED_OBJ = {
    "domain":           {"type": "dns-domain",       "creatable": True},
    "dynamic-object":   {"type": "dynamic-object",   "creatable": True},
    "access-role":      {"type": "access-role",      "creatable": False},
    "security-zone":    {"type": "security-zone",    "creatable": False},
    "updatable-object": {"type": "updatable-object", "creatable": False},
}


def _find_dns_domain(session, value: str) -> tuple[Optional[str], bool]:
    """Look for a dns-domain object matching a domain request -> ``(reusable_name, name_clash)``.

    A CP dns-domain object name ALWAYS starts with a dot for BOTH kinds; ``is-sub-domain`` (a boolean) is
    what distinguishes "the domain + its sub-domains" (a leading-dot request value) from "the exact FQDN".
    So we may reuse an existing object ONLY when its name AND its is-sub-domain flag match the request's
    intent — reusing a sub-domain object for an exact request would silently grant ``*.fqdn`` (over-grant).
    Because names are unique, a same-name object with the OPPOSITE flag is a ``name_clash``: the intended
    object can be neither reused nor created -> resolve() fails loud rather than over/under-granting."""
    want = ("." + value.lstrip(".")).lower()
    req_sub = value.startswith(".")
    found = session.call("show-objects", {"filter": value.lstrip("."), "type": "dns-domain",
                                          "limit": 25})  # VERIFY
    clash = False
    for o in found.get("objects", []):
        if (o.get("name") or "").lower() != want:
            continue
        if bool(o.get("is-sub-domain")) == req_sub:
            return o["name"], False
        clash = True
    return None, clash


def lookup_typed_object(session, kind: str, value: str) -> Optional[str]:
    """Existing object name for a typed (non-IP) request endpoint, or None. A domain matches by its
    canonical dotted name AND its is-sub-domain semantics (see _find_dns_domain); the others by exact name."""
    if kind == "domain":
        name, _ = _find_dns_domain(session, value)
        return name
    found = session.call("show-objects", {"filter": value, "type": _TYPED_OBJ[kind]["type"],
                                          "limit": 25})  # VERIFY
    for o in found.get("objects", []):
        if (o.get("name") or "") == value:
            return o["name"]
    return None


def resolve_typed_object(session, kind: str, value: str) -> str:
    """Reuse-or-create the object for a typed request endpoint. Domains and dynamic-objects are created
    when missing; access-roles / security-zones / updatable-objects are REUSE-ONLY (a clear error if
    absent). A dns-domain is reused only when its is-sub-domain semantics match the request (else a
    same-name/opposite-flag clash is reported, never silently widened to ``*.fqdn``)."""
    if kind == "domain":
        reuse, clash = _find_dns_domain(session, value)
        if reuse:
            return reuse
        name = "." + value.lstrip(".")                 # CP dns-domain names always start with a dot
        req_sub = value.startswith(".")
        if clash:
            raise MgmtError(
                f"a dns-domain object named {name} already exists with the opposite is-sub-domain "
                f"setting; this request needs is-sub-domain={str(req_sub).lower()} — resolve the naming "
                f"conflict on the server first.")
        session.call("add-dns-domain", {"name": name, "is-sub-domain": req_sub})  # VERIFY
        return name
    existing = lookup_typed_object(session, kind, value)
    if existing:
        return existing
    if not _TYPED_OBJ[kind]["creatable"]:
        # Match the Preview's helpfulness on the apply/dry-run path too: surface the closest existing
        # objects ("did you mean …") so a typo like "Finanance" points straight at "Finance" instead of a
        # dead end. Best-effort — a suggest failure just omits the hint.
        hint = ""
        try:
            from . import typed_objects
            near = [c["name"] for c in typed_objects.suggest(session, kind, value)][:5]
            if near:
                hint = f" Did you mean: {', '.join(near)}?"
        except Exception:  # noqa: BLE001
            pass
        raise MgmtError(
            f"{kind} '{value}' was not found on this server.{hint} It can't be created from an access "
            f"request — define it first (an access-role in Identity Awareness, a security-zone in the "
            f"gateway topology, or an updatable-object from Check Point's repository), then re-run.")
    session.call("add-dynamic-object", {"name": value})  # VERIFY
    return value


def typed_object_preview(session, kind: str, value: str) -> dict:
    """Read-only: the object execute() would place for a typed endpoint + whether it already exists. When
    a REUSE-ONLY object (access-role / security-zone / updatable-object) is missing — it can't be created
    from a request — attach the closest existing objects as ``candidates`` so the form can recommend a
    'did you mean' (a creatable domain/dynamic-object just gets made, so it needs no suggestions)."""
    try:
        ex = lookup_typed_object(session, kind, value)
    except MgmtError:
        ex = None
    creatable = _TYPED_OBJ[kind]["creatable"]
    name = ex or (("." + value.lstrip(".")) if kind == "domain" else value)
    out = {"name": name, "exists": bool(ex), "kind": kind, "creatable": creatable}
    if not ex and not creatable:
        try:
            from . import typed_objects
            out["candidates"] = typed_objects.suggest(session, kind, value)
        except Exception:  # noqa: BLE001 — recommendations are best-effort; never break the preview
            out["candidates"] = []
    return out


def _resolve_endpoint_object(session, req: "AccessRequest", side: str) -> str:
    """Reuse-or-create the object for one request endpoint (source/destination), dispatching on its kind."""
    kind = req.src_kind if side == "source" else req.dst_kind
    if kind == "ip":
        cidrs = req.src_cidrs if side == "source" else req.dst_cidrs
        return resolve_endpoint(session, cidrs[0])
    if kind == "internet":
        return "Internet"          # predefined topology object — referenced by name, never created
    value = req.src_value if side == "source" else req.dst_value
    return resolve_typed_object(session, kind, value)


def _endpoint_object_preview(session, req: "AccessRequest", side: str) -> dict:
    kind = req.src_kind if side == "source" else req.dst_kind
    if kind == "ip":
        cidr = (req.src_cidrs if side == "source" else req.dst_cidrs)[0]
        ex = lookup_endpoint(session, cidr)
        return {"ip": cidr, "exists": bool(ex),
                "name": ex or _endpoint_name(ipaddress.ip_network(cidr, strict=False))}
    if kind == "internet":
        return {"name": "Internet", "exists": True, "kind": "internet"}
    return typed_object_preview(session, kind, req.src_value if side == "source" else req.dst_value)


def lookup_service(session, protocol: str, port: str) -> Optional[str]:
    """Existing service object name for this exact port/proto (incl. predefined), or None."""
    proto = protocol.lower()
    found = session.call(f"show-services-{proto}", {"filter": str(port), "limit": 25})  # VERIFY
    for o in found.get("objects", []):
        if str(o.get("port")) == str(port):
            return o["name"]
    return None


def resolve_service(session, protocol: str, port: str, name_hint: Optional[str] = None) -> str:
    proto = protocol.lower()
    existing = lookup_service(session, proto, port)
    if existing:
        return existing
    from . import naming
    name = name_hint or naming.service_name(proto, port)
    session.call(f"add-service-{proto}", {"name": name, "port": str(port)})  # VERIFY
    return name


def lookup_application(session, name: str) -> bool:
    """Whether a predefined/custom application-site OR application-site-category by this exact name exists
    (best-effort) — so the preview's 'reuse vs create' flag is correct for a CATEGORY too, not just an app."""
    for typ in ("application-site", "application-site-category"):
        try:
            found = session.call("show-objects", {"filter": name, "type": typ, "limit": 5})  # VERIFY
        except MgmtError:
            continue
        if any((o.get("name") or "") == name for o in found.get("objects", [])):
            return True
    return False


_ANY_SVC_ALIASES = ("any", "all", "*")


def _svc_write_name(service: str) -> str:
    """The service NAME to write: the predefined "Any" for an all-services request (block/allow all), else
    the given (already-canonical) service name verbatim."""
    return "Any" if (service or "").strip().lower() in _ANY_SVC_ALIASES else service


def _resolve_svc_object(session, req: AccessRequest) -> str:
    """The object to put in the rule's 'Services & Applications' cell: an application-site or a named
    service referenced by name (predefined / already correlated to the canonical Check Point name), the
    predefined "Any" (all services), or a reused/created tcp/udp port service."""
    if req.application:
        return req.application
    if req.service:
        return _svc_write_name(req.service)      # "any"/"all"/"*" -> the predefined Any object
    return resolve_service(session, req.protocol, req.ports)


def _svc_object_preview(session, req: AccessRequest) -> dict:
    if req.application:
        return {"name": req.application, "exists": lookup_application(session, req.application),
                "kind": "application"}
    if req.service:                       # already correlated to a real service by services.resolve()
        return {"name": _svc_write_name(req.service), "exists": True, "kind": "service"}
    ex = lookup_service(session, req.protocol, req.ports)
    from . import naming
    return {"name": ex or naming.service_name(req.protocol, req.ports), "exists": bool(ex), "kind": "service"}


def _brief(rule: Optional[ParsedRule]) -> Optional[dict]:
    if not rule:
        return None
    return {"number": rule.number, "name": rule.name, "uid": rule.uid}


def _position_payload(hint: dict):
    """Internal hint -> the web_api add-access-rule 'position' value."""
    if hint.get("above"):
        return {"above": hint["above"]}   # VERIFY (accepts rule name / uid / number)
    if hint.get("below"):
        return {"below": hint["below"]}   # VERIFY
    return "bottom"                       # no explicit cleanup -> bottom (above the implicit drop)


def _rules_for_layer(decision: Decision, rules: list[ParsedRule]) -> list[ParsedRule]:
    """The rulebase the decision's position uids belong to: when the change lands inside an inline layer
    (decision.layer set), that layer's sub-rules (so the anchor rule renders), else the top-level rules."""
    if decision.layer:
        for r in rules:
            if r.inline_rules is not None and (r.inline_layer_name or r.name) == decision.layer:
                return r.inline_rules
    return rules


def _position_human(hint: Optional[dict], rules: list[ParsedRule]) -> str:
    hint = hint or {}
    if hint.get("_above_cleanup") or (not hint.get("above") and not hint.get("below")):
        from . import naming
        section = naming.rule_section()
        return (f"in the “{section}” section, above the cleanup" if section
                else "bottom (above the implicit cleanup)")
    by_uid = {r.uid: r for r in rules}
    if hint.get("above"):
        r = by_uid.get(hint["above"])
        return f"above rule {r.number} ({r.name})" if r else "above the cleanup / blocking rule"
    r = by_uid.get(hint["below"])
    return f"below rule {r.number} ({r.name})" if r else "below the more-specific rule"


def _allowed_summary(outcome: str, target_rule: Optional[dict]) -> tuple[Optional[bool], str]:
    """A framing-independent answer to the question behind every preview — "is this access permitted as the
    policy stands RIGHT NOW?" — so a caller (esp. an LLM agent) reports a faithful yes/no instead of
    mistaking ``ok: true`` (the CHECK ran successfully) for "access is allowed". Returns
    (currently_allowed, one-line answer):
      * NO_OP  -> True  ("already permitted by rule N")           — answer a "can X reach Y?" as YES
      * CREATE -> False (a brand-new rule would be needed)        — answer NO; state the change
      * WIDEN  -> False (an existing rule would need to be widened)— answer NO; state the change
      * REVIEW -> None  (opaque/unresolved -> can't be sure)      — answer "needs review", never YES."""
    if outcome == Outcome.NO_OP.value:
        via = f" by rule {target_rule['number']} ({target_rule['name']})" if target_rule else ""
        return True, f"Yes — already permitted{via}. No change is needed."
    if outcome == Outcome.CREATE.value:
        return False, "No — not currently permitted. A new least-privilege rule would have to be created."
    if outcome == Outcome.WIDEN.value:
        via = (f"rule {target_rule['number']} ({target_rule['name']})" if target_rule else "an existing rule")
        return False, f"No — not currently permitted. {via} would have to be widened to cover it."
    return None, "Can't confirm automatically — this needs manual review (see reason)."


def _partial_fields(decision: "Decision", asked_name: str) -> dict:
    """Build the near-miss overlay fields (``partially_allowed`` + ``allowed_by`` + a restated ``answer``,
    and ``assumed_any_field`` for the Any case) for a CREATE whose access IS already permitted for a NARROWER
    scope — the request was simply broader on one dimension (e.g. asked from "Any", granted from a specific
    host set). ``asked_name`` is the request's value on the gap dimension, supplied by the caller (the preview
    path reads it from the object preview; the apply path derives it from the request) — so the SAME wording
    is produced no matter which surface assembles the result. Returns {} when there is no near-miss."""
    pr = decision.partial
    if pr is None:
        return {}
    gap = decision.partial_field or "source"
    names = {"source": pr.src_names, "destination": pr.dst_names, "service": pr.svc_names}.get(gap) or []
    shown = names[:12]
    listed = ", ".join(shown) + (f" (+{len(names) - len(shown)} more)" if len(names) > len(shown) else "")
    scope = f"these {gap}s: {listed}" if shown else f"a narrower {gap}"
    asked = (asked_name or gap).strip()
    fields = {"partially_allowed": True,
              "allowed_by": {"rule": {"number": pr.number, "name": pr.name}, "field": gap, "values": names}}
    if asked.lower() == "any":
        # The broad "Any" on the gap dimension is what made the request "not permitted" — but it IS already
        # permitted for SPECIFIC values. Make that assumption explicit and invite the user to narrow it, so
        # they get a definite yes/no instead of a verdict against a field they may not have meant to leave open.
        fields["assumed_any_field"] = gap
        fields["answer"] = (
            f"Partially — checked with {gap} = Any (the broadest case). It is already permitted by rule "
            f"{pr.number} ({pr.name}) for {scope}, but not for every {gap}. Specify a {gap} and I'll give a "
            f"definite yes/no for that one.")
    else:
        fields["answer"] = (
            f"Partially — already permitted by rule {pr.number} ({pr.name}) for {scope}. That rule does not "
            f"cover the requested {gap} ({asked}), so the access is NOT permitted as asked; a new "
            f"least-privilege rule would grant it.")
    return fields


def _partial_overlay(decision: "Decision", out: dict) -> None:
    """Apply the near-miss overlay onto a preview ``out`` dict. ``currently_allowed`` deliberately stays False
    (the request AS ASKED is not permitted), but the ``answer`` no longer reads as a flat "No" that hides the
    rule already granting the destination/service. Reads the gap's requested value from the object preview."""
    if decision.partial is None:
        return
    gap = decision.partial_field or "source"
    asked = ((out.get(gap) or {}).get("name")) or gap
    out.update(_partial_fields(decision, asked))


def _req_gap_label(req: "AccessRequest", gap: str) -> str:
    """The request's value on the gap dimension, as a display name — derived from the request alone (no
    session reads), so the apply path can produce the same near-miss wording as the preview path. Mirrors how
    the preview names each endpoint: a typed value by its identity, an IP request by "Any" or its CIDR(s)."""
    if gap == "service":
        return (req.service or req.application
                or (f"{(req.protocol or 'tcp').lower()}/{req.ports}" if req.ports else "service"))
    kind = req.src_kind if gap == "source" else req.dst_kind
    value = req.src_value if gap == "source" else req.dst_value
    cidrs = req.src_cidrs if gap == "source" else req.dst_cidrs
    if kind != "ip" and (value or "").strip():
        return value
    if any(_is_any(c) for c in (cidrs or [])):
        return "Any"
    return ", ".join(cidrs or []) or "Any"


def _cell_items(names: list, is_any: bool) -> list:
    """Display cells for a rule column: the real object names, else ['Any'] for an Any cell, else []."""
    if names:
        return list(names)
    return ["Any"] if is_any else []


def _req_columns(req: "AccessRequest") -> list:
    """The restriction/setting columns THIS request sets (for the new rule's chips) — order matches SmartConsole."""
    cols = []
    if req.time_objects:
        cols.append("time")
    if req.has_content:
        cols.append("content")
    if req.install_on:
        cols.append("install-on")
    if req.vpn:
        cols.append("vpn")
    if req.action_settings_limit:
        cols.append("limit")
    if req.action_settings_captive_portal:
        cols.append("captive portal")
    return cols


def _rule_preview(decision: "Decision", req: "AccessRequest", out: dict) -> Optional[dict]:
    """A faithful rule-ROW render of the decision so the UI can show exactly how the rule will look:
      * no_op → the EXISTING rule that already permits it (real number + cells), unchanged.
      * widen → the EXISTING rule (real number + cells) with the object being ADDED highlighted in its cell.
      * create → the NEW rule (cells from the request, action, where it'll be placed; no number yet).
    Display-only — every value is already computed above; this just shapes it for a rule-row widget."""
    tr = decision.target_rule
    if decision.outcome == Outcome.NO_OP and tr is not None:
        return {"mode": "existing", "number": tr.number, "name": tr.name, "action": tr.action or "Accept",
                "cells": {"source": {"items": _cell_items(tr.src_names, _covers(tr.src, ANY_IP))},
                          "destination": {"items": _cell_items(tr.dst_names, _covers(tr.dst, ANY_IP))},
                          "service": {"items": _cell_items(tr.svc_names, tr.svc.any)}},
                "columns": list(tr.conditions or [])}
    if decision.outcome == Outcome.WIDEN and tr is not None:
        field = decision.widen_field or "source"
        added = ((out.get("widen") or {}).get("object") or {}).get("name")
        cells = {"source": {"items": _cell_items(tr.src_names, _covers(tr.src, ANY_IP))},
                 "destination": {"items": _cell_items(tr.dst_names, _covers(tr.dst, ANY_IP))},
                 "service": {"items": _cell_items(tr.svc_names, tr.svc.any)}}
        if added and field in cells:
            cells[field]["added"] = [added]
        return {"mode": "widen", "number": tr.number, "name": tr.name, "action": tr.action or "Accept",
                "cells": cells, "widen_field": field, "columns": list(tr.conditions or [])}
    if decision.outcome == Outcome.CREATE:
        def _nm(k):
            return ((out.get(k) or {}).get("name")) or "Any"
        return {"mode": "new", "number": None, "name": None, "action": req.canon_action,
                "cells": {"source": {"items": [_nm("source")]},
                          "destination": {"items": [_nm("destination")]},
                          "service": {"items": [_nm("service")]}},
                "position": out.get("position"), "columns": _req_columns(req)}
    return None


def build_preview(session, decision: Decision, req: AccessRequest, rules: list[ParsedRule]) -> dict:
    """Read-only: report exactly what execute() would do, without writing anything."""
    out: dict = {"outcome": decision.outcome.value, "reason": decision.reason,
                 "target_rule": _brief(decision.target_rule)}
    # An explicit yes/no the caller can trust: ``ok`` means the check RAN; ``currently_allowed`` means the
    # access EXISTS. Conflating the two is the classic agent error ("ok:true" -> wrongly answers "yes").
    out["currently_allowed"], out["answer"] = _allowed_summary(out["outcome"], out["target_rule"])
    if decision.notes:                       # advisories: notes (compat strings) + notes_detail ({text, kind})
        out.update(notes_payload(decision.notes))
    if decision.layer:                       # the change lands inside an inline layer, not the top layer
        out["layer"] = decision.layer
    if decision.outcome is Outcome.NO_OP:
        out["rule_preview"] = _rule_preview(decision, req, out)   # the existing rule that already permits it
        return out
    if decision.outcome is Outcome.REVIEW:
        return out

    if decision.outcome == Outcome.WIDEN:
        field = decision.widen_field or "source"
        obj = (_svc_object_preview(session, req) if field == "service"
               else _endpoint_object_preview(session, req, field))
        out["widen"] = {"field": field, "object": obj, "via": f"rule {field} cell"}
    elif decision.outcome == Outcome.CREATE:
        out["source"] = _endpoint_object_preview(session, req, "source")
        out["destination"] = _endpoint_object_preview(session, req, "destination")
        out["service"] = _svc_object_preview(session, req)
        out["position"] = _position_human(decision.position, _rules_for_layer(decision, rules))
        if (decision.position or {}).get("_anomaly"):
            out["anomaly"] = True
        _partial_overlay(decision, out)   # "already permitted for these sources, just not the one asked"
    out["rule_preview"] = _rule_preview(decision, req, out)   # the new (create) / updated (widen) rule row
    return out


def _naming_ctx(req: AccessRequest, ticket_id: str, src_name: str, dst_name: str,
                layer: str, action: str) -> dict:
    """Template context for the customer rule naming / comment / tag conventions. IDENTICAL field set for an
    Accept (apply) and a Drop (removal), so a customized template using {proto}/{port}/{src}/{destination}/…
    renders the same on both surfaces (the removal ctx previously omitted proto/port/src and read truncated)."""
    return {"ticket": (ticket_id or "").strip(), "app": req.application or "",
            "service": req.service or req.application or
                       (f"{(req.protocol or '').lower()}/{req.ports}" if req.ports else ""),
            "source": src_name, "src": src_name, "dest": dst_name, "destination": dst_name,
            "layer": layer, "action": action,
            "proto": (req.protocol or "").lower(), "port": req.ports or ""}


def _validate_inline_layer(session, name: str) -> str:
    """Resolve an Apply-Layer rule's inline-layer NAME against the real access layers and return it. The layer
    must exist (ordered OR dynamic — per directive we create the divert either way); a missing/blank name fails
    loud so we never write a dangling divert. Reuse-only — never creates a layer."""
    want = (name or "").strip()
    if not want:
        raise MgmtError("an Apply Layer rule needs an inline-layer name (the layer to divert into)")
    try:
        res = session.call("show-access-layers", {"limit": 500, "details-level": "standard"})  # VERIFY
    except MgmtError as e:
        # A failed listing is NOT proof the layer is absent — re-raise as a transient error so the apply
        # aborts cleanly (session discarded), rather than asserting "no such layer" and writing nothing.
        raise MgmtError(f"could not list access layers to validate the Apply Layer divert target “{want}” "
                        f"({e}); try again") from e
    layers = res.get("access-layers") or res.get("layers") or []
    for lyr in layers:
        if (lyr.get("name") or "") == want or (lyr.get("uid") or "") == want:
            return lyr.get("name") or want
    avail = ", ".join(sorted({l.get("name") for l in layers if l.get("name")})[:12]) or "none found"
    raise MgmtError(f"no access layer named “{want}” to divert into (Apply Layer) — available: {avail}")


# Object types eligible per match-gating column resolved via TYPED show-objects (data-types + time objects
# ARE part of the generic object index). Gateways/clusters, VPN communities and limit objects are NOT
# reliably returned by show-objects (their CPMI classes are not valid `type` filters, and communities/limits
# have dedicated show commands) — those use the LISTING path below, not these type tuples.
_CONTENT_DT_TYPES = ("data-type-patterns", "data-type-keywords", "data-type-file-attributes",
                     "data-type-group", "data-type-compound-group", "data-type-traditional-group",
                     "data-type-weighted-keywords", "data-type-file-group")
_TIME_TYPES = ("time", "time-group")
# Dedicated list commands per class (the reliable way to enumerate classes show-objects does not index). A
# tuple is unioned (e.g. both VPN community kinds). If NONE of a column's commands exist on this version the
# resolver degrades to best-effort pass-through (the SMS validates at write, atomically discarded on failure)
# rather than falsely rejecting a legitimate object.
_LIST_CMDS_INSTALL_ON = ("show-gateways-and-servers",)
# install-on may also name a GROUP of gateways — show-gateways-and-servers does NOT enumerate groups, so a
# group target is validated via a typed show-objects fallback (a group object IS in the generic index).
_INSTALL_ON_FALLBACK_TYPES = ("group",)
_LIST_CMDS_VPN = ("show-vpn-communities-meshed", "show-vpn-communities-star", "show-vpn-communities-remote-access")
_LIST_CMDS_LIMIT = ("show-limits",)


def _known_object_names(session, commands, *, keys=("objects",), page=200):
    """Page through one or more dedicated list commands and return the UNION set of object NAMES they know.
    Returns None to signal "could not build a COMPLETE set — fall back to best-effort pass-through" in two
    cases: (a) EVERY command is unavailable on this version (the very first call errors), or (b) a TRANSIENT
    error strikes AFTER progress (a later page of a command, or a sibling command once another already
    succeeded). Only case (b)'s distinction prevents a transient SMS hiccup from finalizing a TRUNCATED set
    that would false-reject a legitimate object and discard the atomic session. A complete enumeration (every
    command fully paged with no errors) returns the full name set, which the caller may match strictly."""
    names: set = set()
    any_ok = False
    for command in commands:
        offset = 0
        while True:
            try:
                res = session.call(command, {"limit": page, "offset": offset, "details-level": "standard"})
            except MgmtError:
                # A failure on the FIRST page of the FIRST command = "command unavailable on this version" ->
                # skip to the next command (best-effort). A failure AFTER progress (mid-paging, offset>0, OR a
                # later command once one already succeeded) is TRANSIENT — we cannot prove the object absent,
                # so degrade the WHOLE column to pass-through rather than returning a truncated set.
                if offset > 0 or any_ok:
                    return None
                break
            any_ok = True
            objs = None
            for k in keys:
                objs = res.get(k)
                if objs:
                    break
            objs = objs or []
            for o in objs:
                if isinstance(o, dict) and o.get("name"):
                    names.add(o["name"])
            total = res.get("total") or 0
            offset += len(objs)
            if not objs or offset >= total:
                break
    return names if any_ok else None


def _typed_lookup(session, nm, types):
    """Look up an exact NAME across one or more show-objects ``type`` classes. Returns True if found, False if
    every query SUCCEEDED but none contained it (a real miss), or None if the class could not be queried at
    all (every typed query errored — caller treats as best-effort pass-through). 200 keeps an exact name from
    being lost behind a crowded substring page (the name is a high-relevance hit for its own filter)."""
    any_query_ok = False
    for t in types:
        try:
            res = session.call("show-objects", {"filter": nm, "type": t, "limit": 200})
        except MgmtError:
            continue
        any_query_ok = True
        if any((o.get("name") or "") == nm for o in res.get("objects", [])):
            return True
    return False if any_query_ok else None


def _resolve_named_objects(session, names, label, *, commands=(), allow_types=(),
                           fallback_types=(), literals=()) -> list:
    """Validate each NAME exists (REUSE-ONLY — never creates) and return the confirmed names. A whitelisted
    literal (e.g. "Policy Targets", "All_GwToGw") passes through.

    Two resolution strategies, chosen by the column:
      * ``commands`` — enumerate the class via its dedicated list command(s) and exact-name match. Used for
        gateways/clusters (install-on), VPN communities and limit objects, which show-objects does not index
        reliably (CPMI type filters are invalid; communities/limits have their own show commands). When a name
        is NOT in the enumerated set, ``fallback_types`` (if given) is probed via show-objects before rejecting
        — e.g. a GROUP of gateways for install-on, which the gateways list command cannot enumerate.
      * ``allow_types`` — query show-objects with each TYPE and exact-name match. Used for data-types
        (content) and time objects, which ARE part of the generic object index.

    BEST-EFFORT, never a false reject: if the class is not queryable on this version (the list enumeration is
    incomplete, or every typed query errors), the name passes through and the SMS validates it at write time —
    the apply is an atomic pre-flight, so a genuinely bad name still discards the whole session (no partial
    rule). A name a fully-enumerable class does not contain (and no fallback class confirms) is a clear
    MgmtError (a real typo/missing object)."""
    lits = {l.lower() for l in literals}
    out: list = []
    known = _known_object_names(session, commands) if commands else None
    for raw in names:
        nm = str(raw).strip()
        if not nm:
            continue
        if nm.lower() in lits:
            out.append(nm)
            continue
        if commands:
            if known is None or nm in known:             # incomplete enumeration -> trust; or an exact hit
                out.append(nm)
                continue
            fb = _typed_lookup(session, nm, fallback_types) if fallback_types else False
            if fb is None or fb:                         # confirmed via a fallback class, or class not queryable
                out.append(nm)
            else:
                raise MgmtError(f"no {label} named “{nm}” found (reuse-only — create it first, or fix the name)")
            continue
        res = _typed_lookup(session, nm, allow_types)
        if res is None or res:                           # confirmed, or class not queryable here -> pass through
            out.append(nm)
        else:
            raise MgmtError(f"no {label} named “{nm}” found (reuse-only — create it first, or fix the name)")
    return out


def _write_gating_columns(session, payload: dict, req: AccessRequest) -> None:
    """Write the match-gating columns (content / time / install-on / vpn) onto an add-access-rule payload —
    each behind a non-default guard so a request that sets none yields a byte-identical payload. Every object
    reference is validated reuse-only. The CREATE delete-rule inverse already covers all."""
    # req.content is already wildcard-normalized in AccessRequest.__post_init__ ("Any" -> no restriction).
    if req.content:
        payload["content"] = _resolve_named_objects(session, req.content, "data type", allow_types=_CONTENT_DT_TYPES)
        payload["content-direction"] = req.content_direction or "any"
        if req.content_negate:
            payload["content-negate"] = True
    elif req.content_negate:
        # A negate with no real data-type would write nothing yet the request reads as restricted (forced a
        # CREATE) — never let the applied rule silently contradict the decision. (Normally unreachable: the
        # request normalizer drops a negate-only content, and build_request rejects it.)
        raise MgmtError("content-negate requires at least one content (data-type) name, not Any")
    if req.time_objects:
        payload["time"] = _resolve_named_objects(session, req.time_objects, "time object", allow_types=_TIME_TYPES)
    if req.install_on:
        payload["install-on"] = _resolve_named_objects(session, req.install_on, "gateway/target",
                                                       commands=_LIST_CMDS_INSTALL_ON,
                                                       fallback_types=_INSTALL_ON_FALLBACK_TYPES,
                                                       literals=("Policy Targets",))
    if req.vpn:
        payload["vpn"] = _resolve_named_objects(session, req.vpn, "VPN community",
                                                commands=_LIST_CMDS_VPN, literals=("All_GwToGw",))


def _action_settings_payload(action: str, req: AccessRequest) -> Optional[dict]:
    """The action-settings object for an ALLOWING action (Accept/Ask/Inform) when the request set a limit or
    captive portal — else None (omit, so a no-settings rule's payload is unchanged). Stripped from a Drop/
    Reject/Apply-Layer (settings are meaningless there)."""
    if action not in ("Accept", "Ask", "Inform"):
        return None
    out: dict = {}
    if req.action_settings_limit:
        out["limit"] = req.action_settings_limit
    if req.action_settings_captive_portal:
        out["enable-identity-captive-portal"] = True
    return out or None


# R82 web_api enum values for the top-level ``user-check`` object (verified against the CheckPointSW Ansible
# collection schema + a live mgmt_cli example). Exact wire strings — lowercase, the literal "…" ellipsis on
# custom, and the slash in "per application/site". A request supplies these (the UI selects them by value).
_UC_FREQUENCY = ("once a day", "once a week", "once a month", "custom frequency...")
_UC_CONFIRM = ("per rule", "per category", "per application/site", "per data type")
_UC_UNITS = ("hours", "days", "weeks", "months")
_UC_ACTIONS = ("Ask", "Inform", "Drop", "Reject")   # actions that can carry a UserCheck interaction


def _user_check_payload(action: str, req: AccessRequest) -> Optional[dict]:
    """The top-level ``user-check`` object for a UserCheck-capable action, or None.

    Ask / Inform → an interaction (message) + frequency + confirm (+ custom-frequency when 'custom …').
    Drop / Reject → the interaction alone (the blocked-message page); frequency/confirm aren't meaningful.
    The interaction object is REUSE-ONLY (must already exist) and validated at publish by the atomic apply —
    there is no reliable list command to pre-validate it against, so a bad name discards the whole session
    with the SMS's own error. Enum values are validated here (fail loud) so we never write a bad payload."""
    interaction = (req.user_check or "").strip()
    if action not in _UC_ACTIONS or not interaction:
        return None
    uc: dict = {"interaction": interaction}
    if action in ("Ask", "Inform"):
        freq = (req.user_check_frequency or "once a day").strip().lower()
        if freq not in _UC_FREQUENCY:
            raise MgmtError(f"UserCheck frequency “{req.user_check_frequency}” is not one of: "
                            f"{', '.join(_UC_FREQUENCY)}")
        conf = (req.user_check_confirm or "per rule").strip().lower()
        if conf not in _UC_CONFIRM:
            raise MgmtError(f"UserCheck confirm “{req.user_check_confirm}” is not one of: "
                            f"{', '.join(_UC_CONFIRM)}")
        uc["frequency"] = freq
        uc["confirm"] = conf
        if freq == "custom frequency...":
            unit = (req.user_check_custom_unit or "days").strip().lower()
            if unit not in _UC_UNITS:
                raise MgmtError(f"UserCheck custom-frequency unit “{req.user_check_custom_unit}” is not one "
                                f"of: {', '.join(_UC_UNITS)}")
            try:
                every = max(1, int(req.user_check_custom_every or 1))
            except (TypeError, ValueError):
                raise MgmtError("UserCheck custom-frequency ‘every’ must be a positive integer")
            uc["custom-frequency"] = {"every": every, "unit": unit}
    return uc


def _apply(session, decision: Decision, req: AccessRequest, layer: str,
           rules: list[ParsedRule], ticket_id: str, package: Optional[str] = None) -> dict:
    out: dict = {"ops": []}
    # decide() reasons over the FULL request (all of src_cidrs/dst_cidrs, merged), but the materialization
    # below writes one object per endpoint. The public build_request() always yields single-element lists;
    # a directly-built multi-CIDR request would otherwise silently apply LESS than was reasoned (only the
    # first CIDR). Fail loud instead — split into one request per CIDR. (Caught as a clean error.) A typed
    # endpoint carries no CIDR (one named object), so the guard only applies to IP endpoints.
    if (req.src_kind == "ip" and len(req.src_cidrs) != 1) or (req.dst_kind == "ip" and len(req.dst_cidrs) != 1):
        raise MgmtError("multi-CIDR source/destination is not supported on apply — "
                        "submit one request per source and destination CIDR")
    # The change targets the inline layer when the decision landed inside one (decision.layer); otherwise
    # the caller's top-level layer. The position uids in decision.position belong to that same layer.
    target_layer = decision.layer or layer
    if decision.layer:
        out["layer"] = decision.layer

    if decision.outcome == Outcome.WIDEN:
        # Self-defense (symmetric with the decide() guards): a request carrying a per-rule restriction or
        # action-setting must NEVER be materialized as a widen — widening adds only an object to one cell and
        # would silently drop content/time/install-on/vpn/action-settings. decide() already routes these to
        # CREATE; a directly-built WIDEN that slipped through fails loud rather than under-applying.
        if req.forces_create:
            raise MgmtError("a restricted/settinged request cannot be applied as a widen "
                            "(content/time/install-on/vpn/action-settings would be dropped) — create instead")
        field = decision.widen_field or "source"
        obj_name = (_resolve_svc_object(session, req) if field == "service"
                    else _resolve_endpoint_object(session, req, field))
        out.update(widen_field=field, widen_object=obj_name)
        # Add to the rule's CELL, never to a shared group — modifying a group widens EVERY rule that
        # references it. decide() guarantees the other two cells equal the request exactly, so this
        # grants precisely the requested source x destination x service and nothing more.
        session.call("set-access-rule",
                     {"uid": decision.target_rule.uid, "layer": target_layer,
                      field: {"add": obj_name}})  # VERIFY
        out["ops"].append(f"set-access-rule {decision.target_rule.uid} {field}.add {obj_name}")
        # the exact inverse: drop the object back out of the same cell (rollback/undo).
        out["inverse"] = [{"op": "set-access-rule", "uid": decision.target_rule.uid,
                           "layer": target_layer, "field": field, "remove": obj_name}]
        return out

    # CREATE
    src_name = _resolve_endpoint_object(session, req, "source")
    dst_name = _resolve_endpoint_object(session, req, "destination")
    svc_name = _resolve_svc_object(session, req)
    from . import naming
    # Customer naming/track/tag conventions (Settings → "Access automation"; data-driven templates). The
    # PLACEMENT (position) is NOT a convention — the engine computes it for first-match correctness.
    # The requested verdict (full-column support): grant defaults to Accept; a ticket may ask for any of
    # Drop / Reject / Ask / Inform / Apply Layer. The decision engine already routed non-Accept through its
    # own branch — here we just WRITE exactly what was asked.
    action = req.canon_action                            # decide() already REVIEW-guarded an unknown action
    nctx = _naming_ctx(req, ticket_id, src_name, dst_name, target_layer, action)
    # An anchored placement ({above/below: rule uid}) is first-match-critical — keep it exactly. A FLOOR
    # placement (above the cleanup) is instead routed into the configured 'provisioned' section so the new
    # rule doesn't land INSIDE the cleanup section; same height, tidier grouping (may create the section).
    pos_hint = decision.position or {}
    position = (_position_payload(pos_hint) if (pos_hint.get("above") or pos_hint.get("below"))
                else _floor_position(session, target_layer, package, out))
    payload = {
        "layer": target_layer,
        "position": position,
        "name": naming.rule_name(ticket_id, nctx),
        "source": src_name,
        "destination": dst_name,
        "service": svc_name,
        "action": action,
        "track": naming.rule_track(),
        "comments": naming.rule_comment(nctx),
    }
    if action == "Apply Layer":
        # divert into an inline layer — the layer must exist (ordered OR dynamic; per directive we create the
        # divert either way). Resolve the name to a real layer; a missing layer fails loud, not a bad write.
        payload["inline-layer"] = _validate_inline_layer(session, req.inline_layer)
    asettings = _action_settings_payload(action, req)        # limit / captive-portal, allowing actions only
    if asettings:
        if asettings.get("limit"):                           # validate the limit object reuse-only (like the other refs)
            _resolve_named_objects(session, [asettings["limit"]], "QoS/bandwidth limit", commands=_LIST_CMDS_LIMIT)
        payload["action-settings"] = asettings
    ucheck = _user_check_payload(action, req)                # top-level user-check (Ask/Inform message+freq+confirm; Drop/Reject block page)
    if ucheck:
        payload["user-check"] = ucheck                       # interaction is reuse-only — the atomic publish validates it
    _write_gating_columns(session, payload, req)             # content / time / install-on / vpn (reuse-only)
    tags = naming.rule_tags()
    if tags:
        payload["tags"] = tags
    created = session.call("add-access-rule", {k: v for k, v in payload.items() if v is not None})  # VERIFY
    created_uid = (created or {}).get("uid")
    out.update(source_object=src_name, destination_object=dst_name, service_object=svc_name,
               position=_position_human(decision.position, _rules_for_layer(decision, rules)),
               created_uid=created_uid)
    if (decision.position or {}).get("_anomaly"):       # mirror build_preview: a placement anomaly (this
        out["anomaly"] = True                           # allow neutralizes/shadows a deny) survives to apply
    out["ops"].append("add-access-rule")
    # the exact inverse: delete the rule we just added (rollback/undo). Reused/created objects are left
    # in place — they may now be referenced elsewhere, and deleting them is a separate, riskier action.
    # NOTE (by design): if placement auto-created the provisioned grouping SECTION (_floor_position), it is
    # deliberately NOT in the inverse — the section is a persistent, REUSED container (every later floored
    # rule lands in it), so deleting it on a single rule's revert could orphan other rules. A revert may
    # therefore leave an empty provisioned section; that is intended tidiness, not a leak.
    if created_uid:
        out["inverse"] = [{"op": "delete-access-rule", "uid": created_uid, "layer": target_layer}]
    return out


# --------------------------------------------------------------------------- #
# Top-level entry points the router / webhook call
# --------------------------------------------------------------------------- #
def load_layer_cached(session, server, layer: str, package: Optional[str] = None):
    """Parsed rules for ``layer`` via the revision-based policy cache, with inline-layer sub-rulebases
    attached (each pulled through the same cache, keyed by its own name). Returns (rules, cached)."""
    def _pull(name: str) -> list[ParsedRule]:
        raw = cached_raw(session, server, name, package=package)
        return [_parse_rule(e, raw["objdict"]) for e in _flatten(raw["items"])
                if e.get("type") == "access-rule"]

    raw = cached_raw(session, server, layer, package=package)
    rules = [_parse_rule(e, raw["objdict"]) for e in _flatten(raw["items"])
             if e.get("type") == "access-rule"]
    _attach_inline_layers(session, rules, package, _pull, _INLINE_MAX_DEPTH, set())
    return rules, bool(raw.get("cached"))


# --------------------------------------------------------------------------- #
# Read-only policy analysis (the MCP "analyze / insights" tools). PURE over parsed rules.
# --------------------------------------------------------------------------- #
def _svc_definitely_covers(big: ServiceSet, small: ServiceSet) -> bool:
    """Conservative: True only when we can PROVE ``big`` covers ``small`` on the service dimension. Any
    app/named/opaque/complex member on either side -> we don't claim coverage (avoids false shadows)."""
    if big.any:
        return True
    if small.any:
        return False
    if (big.apps or big.named or big.opaque or big.complex
            or small.apps or small.named or small.opaque or small.complex):
        return False
    return _portset_covers(big.by_proto, small.by_proto)


def summarize_rules(rules: list[ParsedRule]) -> dict:
    """High-level shape of a rulebase (for an agent's natural-language overview)."""
    enabled = [r for r in rules if r.enabled]
    def _any(r):  # noqa: ANN001
        return _covers(r.src, ANY_IP), _covers(r.dst, ANY_IP), r.svc.any
    return {
        "total_rules": len(rules),
        "enabled": len(enabled),
        "disabled": sum(1 for r in rules if not r.enabled),
        "accept": sum(1 for r in enabled if r.is_accept),
        "drop_or_reject": sum(1 for r in enabled if r.is_drop),
        "inline_layers": sum(1 for r in enabled if r.inline_rules is not None),
        "conditional": sum(1 for r in enabled if r.conditional),
        "any_source": sum(1 for r in enabled if _any(r)[0]),
        "any_destination": sum(1 for r in enabled if _any(r)[1]),
        "any_service": sum(1 for r in enabled if _any(r)[2]),
        "has_cleanup_drop": any(_is_catchall(r) and r.is_drop for r in enabled),
    }


def find_shadowed(rules: list[ParsedRule]) -> list[dict]:
    """Rules that can NEVER match because an earlier, fully-resolved, unconditional Accept/Drop already
    covers them on all three dimensions (first-match shadowing). Conservative — only provable cases."""
    out: list[dict] = []
    enabled = [r for r in rules if r.enabled]
    for j, rj in enumerate(enabled):
        if rj.complex:
            continue
        for ri in enabled[:j]:
            if ri.complex or ri.conditional or ri.inline_rules is not None or not (ri.is_accept or ri.is_drop):
                continue
            if (relation(rj.src, ri.src) in (Relation.SUBSET, Relation.EQUAL)
                    and relation(rj.dst, ri.dst) in (Relation.SUBSET, Relation.EQUAL)
                    and _svc_definitely_covers(ri.svc, rj.svc)):
                out.append({"rule": rj.number, "name": rj.name, "shadowed_by": ri.number,
                            "shadowed_by_name": ri.name, "covering_action": ri.action})
                break
    return out


def find_permissive(rules: list[ParsedRule]) -> list[dict]:
    """Enabled ACCEPT rules that are broad on a whole dimension (Any source / destination / service) —
    candidates to tighten. The bottom catch-all cleanup (usually a Drop) is naturally excluded."""
    out: list[dict] = []
    for r in rules:
        if not r.enabled or not r.is_accept or r.inline_rules is not None:
            continue
        wide = [d for d, on in (("source", _covers(r.src, ANY_IP)),
                                ("destination", _covers(r.dst, ANY_IP)),
                                ("service", r.svc.any)) if on]
        if wide:
            out.append({"rule": r.number, "name": r.name, "any_dimensions": wide})
    return out


def _resolve_app(session, req: AccessRequest):
    """If the request is application-based, correlate its name to a real Check Point application. On a
    confident (unique exact / normalized-exact) hit, rewrite req.application to CP's canonical name so
    BOTH the rulebase match and any new rule use it. Returns the resolution dict (or None if not an app
    request); the caller turns a no-confident-match into REVIEW with candidates."""
    if not req.application:
        return None
    from . import applications
    # Autonomous-only typo auto-correct: pass a confidence floor ONLY when the Autopilot gate is on and the
    # admin set a threshold (Automation logic → aa_app_autocorrect_min). Supervised/Read-only pass None, so
    # a misspelled app surfaces a "did you mean" candidate and routes to review instead of being guessed.
    autocorrect_min = None
    try:
        from . import app_settings
        if app_settings.get("aa_autopilot"):
            pct = int(app_settings.get("aa_app_autocorrect_min") or 0)
            if pct > 0:
                autocorrect_min = max(0.0, min(1.0, pct / 100.0))
    except Exception:  # noqa: BLE001 — settings best-effort; default = no auto-correct (safe)
        autocorrect_min = None
    res = applications.resolve(session, req.application, autocorrect_min=autocorrect_min)
    if res.get("match"):
        req.application = res["match"]
        # remember whether it resolved to a CATEGORY (vs a single application-site) so the engine reasons
        # about it in the right space — a category matches a category rule cell, not a single-app cell.
        req.application_kind = ("application-site-category" if res.get("match_kind") == "category"
                                else "application-site")
    return res


def _resolve_svc(session, req: AccessRequest):
    """Correlate a named (non-port) service to its canonical Check Point service object. A confident,
    unique match rewrites req.service; otherwise the caller routes to REVIEW with candidates."""
    if not req.service:
        return None
    from . import services
    res = services.resolve(session, req.service)
    if res.get("match"):
        req.service = res["match"]
        req.service_kind = res.get("match_kind") or ""   # tag the family so the engine can't alias it
        # Expand a services-GROUP or a tcp/udp/sctp service to the SAME ServiceSet the rule side parses
        # (groups dereference to member ports), so the request compares correctly against rule cells.
        # Without this a 'dns' group request read DISJOINT from rule cells holding the same group's ports
        # -> the engine skipped a DNS inline layer and created a shadowed top-level rule. Portless families
        # (icmp/other/rpc/…) keep their named token (the rule side keys them by name too) -> no expansion.
        expanded = _expand_request_service(session, req.service, req.service_kind)
        if expanded is not None:
            req.svc_set = expanded
    return res


def _expand_request_service(session, name: str, kind: str) -> "Optional[ServiceSet]":
    """The request's resolved service as the rule side would parse it. A services-GROUP is dereferenced to
    its members' ports/apps/named; a tcp/udp/sctp service to its port. Returns None for a portless family
    (icmp/other/rpc/gtp/…) — those already match by name — or on any error (best-effort; the coarse named
    fallback is safe: a named-vs-port mismatch reads DISJOINT, never a false grant)."""
    k = (kind or "").lower()
    try:
        if k == "group":
            o = session.call("show-service-group", {"name": name, "details-level": "full"})  # VERIFY
            members = [m for m in (o.get("members") or []) if isinstance(m, dict)]
            sset = _parse_svc(members, {})                       # _deref returns an inline member dict as-is
            guid = o.get("uid")
            if guid and guid not in sset.group_uids:
                sset.group_uids.append(guid)                     # remember the group for widen/reuse
            return sset
        if k in ("tcp", "udp", "sctp"):
            o = session.call(f"show-service-{k}", {"name": name})                              # VERIFY
            return _parse_svc([dict(o, type=f"service-{k}")], {})
    except MgmtError:
        return None
    return None


def _correlate(session, req: AccessRequest):
    """Resolve the request's application and/or named service to canonical Check Point objects. Returns
    (resolutions, unresolved, kind): ``resolutions`` is the dict to attach to the result; ``unresolved``
    is the resolution that lacked a confident match (-> REVIEW with candidates), or None."""
    res: dict = {}
    app_res = _resolve_app(session, req)
    if app_res is not None:
        res["app_resolution"] = app_res
    svc_res = _resolve_svc(session, req)
    if svc_res is not None:
        res["svc_resolution"] = svc_res
    for r, kind in ((app_res, "application"), (svc_res, "service")):
        if r is not None and not r.get("match"):
            return res, r, kind
    return res, None, ""


# Behavior PROFILES — one-click bundles of the decision knobs (data, not code; org policy forbids user
# scripting). "balanced" == the recommended defaults; "custom" is NOT here (it falls through to the
# individual toggles). Each must set every DecideOptions field. Surfaced as the `aa_profile` choice Setting.
_PROFILES: dict[str, dict] = {
    # Never touch existing rules and never override a deny: always create a fresh rule, place it BELOW any
    # block (so it may be shadowed) and flag it. The least-disruptive, most hands-off posture.
    "conservative": dict(app_carveout=False, override_blocking_deny=False, prefer_widen=False,
                         emit_notes=True, ignore_conditions=False),
    # The recommended engine defaults: reuse/widen where exact, carve apps + override denies by placement so
    # the access actually works, conditions respected, advisories on.
    "balanced": dict(app_carveout=True, override_blocking_deny=True, prefer_widen=True,
                     emit_notes=True, ignore_conditions=False),
    # Make it work in the fewest rules with the least friction: also treat conditional rules (time / VPN /
    # content / install-on) as unconditional, so a conditional Accept can cover and a conditional Drop can
    # block. Notes stay ON so the engine (and the agent, in the lab-demo flow) can narrate what it did.
    "aggressive": dict(app_carveout=True, override_blocking_deny=True, prefer_widen=True,
                       emit_notes=True, ignore_conditions=True),
}
# NOTE: the "Autopilot" lab demo is NOT a behavior profile — it's the Aggressive engine posture PLUS the
# agent's one-turn apply+publish blessing (the separate ``aa_autopilot`` toggle + ``mcp_allow_publish``).
# Keeping it out of _PROFILES is deliberate: a profile is a DECISION posture; auto-publish is an agent
# permission. See Settings → MCP / agent and mcp_tools._autopilot().


def _scoped_profile(app_settings, server, layer) -> Optional[str]:
    """A per-scope profile override (Settings → ``aa_scope_overrides``) matching this server/layer, or None.
    Lines are ``scope = profile``; scope = server(name|id) | ``server:layer`` | ``*:layer``. Most-specific
    wins (exact server+layer ▸ ``*:layer`` ▸ server). Only the named profile bundles are honored; blank /
    ``#`` / malformed / unknown-profile lines are ignored (fail safe → falls back to the global profile)."""
    raw = str(app_settings.get("aa_scope_overrides") or "").strip()
    if not raw:
        return None
    sid = str(getattr(server, "id", "") or "").lower()
    sname = (getattr(server, "name", "") or "").strip().lower()
    lname = (layer or "").strip().lower()
    best, best_score = None, -1
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        scope, prof = (p.strip() for p in line.split("=", 1))
        prof = prof.lower()
        if prof not in _PROFILES:                      # named bundles only ('custom' isn't a per-scope value)
            continue
        if ":" in scope:
            sp, lp = (p.strip().lower() for p in scope.split(":", 1))
        else:
            sp, lp = scope.strip().lower(), "*"
        srv_ok = sp in ("", "*") or sp == sname or (sid and sp == sid)
        lyr_ok = lp in ("", "*") or lp == lname
        if srv_ok and lyr_ok:
            # Layer-specificity outranks server-specificity, matching the documented order
            # exact(server+layer)=3 ▸ *:layer=2 ▸ server=1 ▸ *:*=0.
            score = (1 if sp not in ("", "*") else 0) + (2 if lp not in ("", "*") else 0)
            if score > best_score:
                best, best_score = prof, score
    return best


def _decide_options(server=None, layer=None) -> "DecideOptions":
    """Build the engine's decision/placement knobs from the admin's Settings (best-effort). Resolution order:
    a per-scope override (``aa_scope_overrides``) matching this server/layer wins; else the global
    ``aa_profile`` bundle (Conservative/Balanced/Aggressive); else (``custom``/unknown) the
    individual ``aa_*`` toggles. Each Setting/profile carries the same default as DecideOptions, so an
    unconfigured portal decides exactly as before."""
    try:
        from . import app_settings
        profile = _scoped_profile(app_settings, server, layer) or str(app_settings.get("aa_profile") or "custom")
        if profile in _PROFILES:
            return DecideOptions(**_PROFILES[profile])
        return DecideOptions(
            ignore_conditions=bool(app_settings.get("aa_ignore_conditions")),
            app_carveout=bool(app_settings.get("aa_app_carveout")),
            override_blocking_deny=bool(app_settings.get("aa_override_blocking_deny")),
            prefer_widen=bool(app_settings.get("aa_prefer_widen")),
            emit_notes=bool(app_settings.get("aa_emit_notes")),
        )
    except Exception:  # noqa: BLE001
        return DecideOptions()


def _obj_review(res: dict, unresolved: dict, kind: str, base: dict) -> dict:
    """An application/service name that didn't resolve to a single Check Point object -> REVIEW, BEFORE any
    write reaches the SMS (so a wrong/typo'd name never produces a failing add-access-rule). The candidate
    matches are surfaced TWO ways: nested (``{kind}_resolution.candidates`` — drives the portal's pick
    chips) AND as a top-level ``suggestions`` list + a 'did you mean …' reason, so a programmatic webhook
    caller gets an actionable correction without digging into the nested dict."""
    names = [c.get("name") for c in (unresolved.get("candidates") or []) if c.get("name")]
    if names:
        hint = f"did you mean: {', '.join(names[:6])}?"
    elif unresolved.get("note"):
        hint = unresolved["note"]
    else:
        hint = f"no close Check Point {kind} matched — check the exact object name"
    return {"ok": True, "outcome": "review", "target_rule": None, "unresolved": kind,
            "currently_allowed": None,
            "answer": f"Can't confirm — “{unresolved['term']}” isn't a recognized {kind}; correct the name "
                      "and re-check.",
            "reason": f"“{unresolved['term']}” did not match a single Check Point {kind} — {hint}",
            "suggestions": names, **res, **base}


def _dynamic_layer_block(session, layer: str) -> Optional[dict]:
    """If ``layer`` is itself a Dynamic Layer (sk182252) — managed out-of-band by other admins — return a
    refusal dict so the caller stops; otherwise None. Best-effort (a lookup failure just proceeds)."""
    _, dyn = _layer_meta(session, layer, by="name")
    if dyn:
        return {"ok": False, "error": f"“{layer}” is a Dynamic Layer (sk182252) — managed out-of-band by "
                f"another process, so access automation is disabled for it. Choose a standard layer."}
    return None


def _enrich_reputation(req: AccessRequest, result: dict) -> None:
    """Attach a destination-reputation advisory to a decision result when the reputation_enrich setting is
    on (see services.reputation). Best-effort + fail-open — an import or lookup failure must never affect
    the decision. Only enriches an ALLOW-shaped request (a Drop/Reject block is not 'allowing traffic to a
    bad destination', so it carries no reputation risk to warn about)."""
    try:
        if canonical_action(getattr(req, "action", "Accept")) not in ("Accept", "Ask", "Inform", "Apply Layer"):
            return
        from . import reputation
        reputation.attach(req, result)
    except Exception:  # noqa: BLE001
        logger.debug("reputation enrichment skipped", exc_info=True)


def preview(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None) -> dict:
    """Read-only: correlate app -> load (cached) -> decide -> describe."""
    try:
        with read_session(server, secret) as s:          # read-only, pooled — no login per preview
            layer, layer_note = resolve_layer_name(s, layer)   # "Network Layer" -> "Network"; clear error if unknown
            block = _dynamic_layer_block(s, layer)
            if block is not None:                         # the chosen layer is managed out-of-band
                return {**block, "trace": s.trace}
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:
                return _obj_review(res, unresolved, kind, {"cached": False, "trace": s.trace})
            rules, cached = load_layer_cached(s, server, layer, package)
            decision = decide(req, rules, _decide_options(server, layer))
            out = build_preview(s, decision, req, rules)
            extra = {"layer_note": layer_note} if layer_note else {}
            result = {"ok": True, **out, "cached": cached, "trace": s.trace, **res, **extra}
            _enrich_reputation(req, result)   # opt-in destination-reputation advisory (fail-open)
            return result
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — never let a non-MgmtError (connection/TLS reset, a degraded
        # SDK import leaving read_session=None, an engine bug) propagate to an API/MCP/webhook caller as an
        # opaque "Internal error". Log the stack server-side; hand the caller the real one-line reason.
        logger.exception("access preview failed (layer=%r)", layer)
        return {"ok": False, "error": f"preview failed: {type(exc).__name__}: {exc}"}


def execute(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None,
            ticket_id: str = "", publish: bool = False) -> dict:
    """Load -> decide -> apply in ONE session. ``publish`` commits; otherwise the change is made
    then DISCARDED (validates against the SMS with zero commit). Discards on any error."""
    try:
        # WRITE path: an isolated read-write session (NOT the shared read pool) that loads the live
        # policy, decides, applies, and publishes/discards in one transaction -> always decided on
        # fresh rules, locks held only for this commit.
        with write_session(server, secret) as s:
            layer, layer_note = resolve_layer_name(s, layer)   # "Network Layer" -> "Network"; clear error if unknown
            block = _dynamic_layer_block(s, layer)
            if block is not None:             # the chosen layer is a Dynamic Layer (managed out-of-band)
                return {**block, "applied": False, "published": False, "trace": s.trace}
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:        # never apply an unresolved / ambiguous application or service
                return {"ok": True, "applied": False, "published": False,
                        **_obj_review(res, unresolved, kind, {"trace": s.trace})}
            rules = load_layer(s, layer, package)
            decision = decide(req, rules, _decide_options(server, layer))
            base = {"outcome": decision.outcome.value, "reason": decision.reason,
                    "target_rule": _brief(decision.target_rule), **res}
            if layer_note:
                base["layer_note"] = layer_note
            if decision.notes:
                base.update(notes_payload(decision.notes))
            # Surface the same near-miss overlay the preview path shows ("already permitted for these
            # sources, just not the one asked") so a dry-run apply / REST /access/apply / MCP apply_access
            # don't diverge from decide_access for the same request. Derived from the request (no extra
            # reads on the write path); only present when the walk recorded a near-miss.
            if decision.outcome is Outcome.CREATE and decision.partial is not None:
                base.update(_partial_fields(decision, _req_gap_label(req, decision.partial_field or "source")))
            if decision.outcome in (Outcome.NO_OP, Outcome.REVIEW):
                return {"ok": True, "applied": False, "published": False, **base, "trace": s.trace}
            try:
                applied = _apply(s, decision, req, layer, rules, ticket_id, package)
                if publish:
                    s.publish()
                    invalidate_cache(server)   # our change advanced the revision -> drop the read cache
                else:
                    s.discard()
            except Exception as exc:   # noqa: BLE001 — ANY failure mid-apply (incl. a non-MgmtError from
                # resolve_endpoint / naming) must release the write session's pending changes + locks. The
                # session's __exit__ only logs out, and on Check Point a read-WRITE logout does NOT discard
                # — so without this the half-applied object + its locks linger until the session times out.
                try:
                    s.discard()
                except MgmtError:
                    sessions = []
                    try:
                        sessions = locking_sessions(server, secret)
                    except Exception:  # noqa: BLE001
                        pass
                    return {"ok": False, "lock_conflict": True, "sessions": sessions, "trace": s.trace,
                            "error": f"the change could not be discarded after a failed apply: {exc}"}
                if isinstance(exc, MgmtError):
                    raise                      # let the outer handler classify (lock vs generic)
                return {"ok": False, "error": f"apply failed: {exc}", "trace": s.trace}
            result = {"ok": True, "applied": True, "published": publish,
                      "validated": not publish, **base, **applied, "trace": s.trace}
            _enrich_reputation(req, result)   # opt-in destination-reputation advisory (fail-open)
            return result
    except MgmtError as exc:
        msg = str(exc)
        out = {"ok": False, "error": msg}
        if _is_lock_error(msg):       # name the session holding the lock + let the UI offer a take-over
            out["lock_conflict"] = True
            out["sessions"] = locking_sessions(server, secret)
        return out
    except Exception as exc:  # noqa: BLE001 — a non-MgmtError before/around the session (unreachable SMS,
        # TLS/cert failure, MgmtSession=None from a degraded import, an engine bug) must come back as a
        # structured error, not an uncaught exception the MCP/webhook layer renders as "Internal error".
        logger.exception("access execute failed (layer=%r, publish=%s)", layer, publish)
        return {"ok": False, "error": f"apply failed: {type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
# REMOVE-access I/O  (preview / execute the revoke, mirroring preview()/execute())
# --------------------------------------------------------------------------- #
def _build_removal_preview(decision: RemovalDecision, req: AccessRequest, rules: list[ParsedRule]) -> dict:
    out = {"action": "remove", "outcome": decision.outcome.value, "reason": decision.reason,
           "target_rule": _brief(decision.target_rule)}
    if decision.position:
        out["position"] = _position_human(decision.position, rules)
    if decision.notes:
        out.update(notes_payload(decision.notes))
    return out


def _narrow_member_name(session, rule_uid: str, layer: str, req: AccessRequest) -> Optional[str]:
    """The DIRECT source member of ``rule_uid`` to SAFELY remove when an app block shadows an explicit grant —
    or None (don't narrow). PROVES safety at apply time against the live rule: the request source is a single
    IP/CIDR; the rule's source has >= 2 direct members (so removing one leaves the rule meaningful); and
    EXACTLY ONE direct member's address span equals the request source's. A host hidden INSIDE a group member
    never matches (a group has no single span), so a group is never silently edited — the conservative reason
    NARROW was avoided in the pure engine, now discharged with live data."""
    if req.src_kind != "ip" or not req.src_cidrs:
        return None
    try:
        net = ipaddress.ip_network(req.src_cidrs[0], strict=False)
    except ValueError:
        return None
    want = (int(net.network_address), int(net.broadcast_address), net.version)
    try:
        cur = session.call("show-access-rule", {"uid": rule_uid, "layer": layer, "details-level": "full"})  # VERIFY
    except MgmtError:
        return None
    members = cur.get("source") or []
    if len(members) < 2:                              # removing the sole member would empty the cell -> not a narrow
        return None
    matches = [m.get("name") for m in members if m.get("name") and _object_ip_span(m) == want]
    return matches[0] if len(matches) == 1 else None   # exactly one direct member equals the request source


def _apply_removal(session, decision: RemovalDecision, req: AccessRequest, layer: str, ticket_id: str) -> dict:
    """Materialise a removal: DISABLE = turn the granting rule off; DENY = add a least-privilege Drop ABOVE
    it for exactly src->dst:svc (and, for an app block that shadows an explicit grant, optionally NARROW that
    grant's source — proven safe at apply time). NO_OP / REVIEW write nothing (handled by the caller)."""
    out: dict = {"ops": []}
    # DENY materializes one object per endpoint, so (like _apply) a multi-CIDR IP endpoint would write less
    # than was reasoned — fail loud. build_request() always yields single-element lists; this guards a
    # directly-built request. (DISABLE writes no object, but the guard is cheap and keeps the two symmetric.)
    if (req.src_kind == "ip" and len(req.src_cidrs) != 1) or (req.dst_kind == "ip" and len(req.dst_cidrs) != 1):
        raise MgmtError("multi-CIDR source/destination is not supported on remove — "
                        "submit one request per source and destination CIDR")
    r = decision.target_rule
    if decision.outcome == RemovalOutcome.DISABLE:
        session.call("set-access-rule", {"uid": r.uid, "layer": layer, "enabled": False})  # VERIFY
        out["ops"].append(f"set-access-rule {r.uid} enabled=false")
        out["disabled_uid"] = r.uid
        # the exact inverse: re-enable the rule we disabled (rollback/undo).
        out["inverse"] = [{"op": "set-access-rule", "uid": r.uid, "layer": layer, "enabled": True}]
        return out
    if decision.outcome == RemovalOutcome.DENY:
        src_name = _resolve_endpoint_object(session, req, "source")
        dst_name = _resolve_endpoint_object(session, req, "destination")
        svc_name = _resolve_svc_object(session, req)
        from . import naming
        ctx = _naming_ctx(req, ticket_id, src_name, dst_name, layer, "Drop")
        payload = {"layer": layer, "position": _position_payload(decision.position or {}),
                   "name": naming.rule_name(ticket_id, ctx), "source": src_name, "destination": dst_name,
                   "service": svc_name, "action": "Drop", "track": naming.rule_track(),
                   "comments": naming.rule_comment(ctx)}
        tags = naming.rule_tags()
        if tags:
            payload["tags"] = tags
        created = session.call("add-access-rule", {k: v for k, v in payload.items() if v is not None})  # VERIFY
        created_uid = (created or {}).get("uid")
        out.update(source_object=src_name, destination_object=dst_name, service_object=svc_name,
                   created_uid=created_uid)
        out["ops"].append("add-access-rule (Drop)")
        # Build the inverse INCREMENTALLY so every committed sub-op is revertable independently. Start with
        # the Drop delete (when the SMS returned its uid). The narrow's re-add is appended below even if the
        # Drop's uid is missing — otherwise a committed source-narrowing would be silently un-revertable.
        inverse: list = []
        if created_uid:
            inverse.append({"op": "delete-access-rule", "uid": created_uid, "layer": layer})
        # SECONDARY (app block best practice): the Drop above the enabler shadows an explicit grant that also
        # lists this host. If that host is a SAFELY-removable direct source member, narrow the grant's source
        # so the rulebase isn't left with a redundant shadowed entry. Proven at apply time; else just noted.
        if decision.narrow_rule is not None:
            member = _narrow_member_name(session, decision.narrow_rule.uid, layer, req)
            if member:
                session.call("set-access-rule",                                       # VERIFY
                             {"uid": decision.narrow_rule.uid, "layer": layer, "source": {"remove": member}})
                out["ops"].append(f"set-access-rule {decision.narrow_rule.uid} source.remove {member}")
                out["narrowed"] = {"rule_uid": decision.narrow_rule.uid, "member": member}
                # Always record the re-add inverse for the member we removed — independent of the Drop's uid.
                inverse.append({"op": "set-access-rule", "uid": decision.narrow_rule.uid,
                                "layer": layer, "field": "source", "add": member})
                if not created_uid:
                    out.setdefault("notes", []).append(
                        "the new Drop rule's uid was not returned by the SMS, so a revert can re-add the "
                        "narrowed source member but cannot auto-delete the Drop — remove it manually if you "
                        "roll back")
            else:
                out.setdefault("notes", []).append(
                    f"left rule {decision.narrow_rule.number} ({decision.narrow_rule.name}) unchanged — this "
                    f"host isn't a safely-removable direct source member (it may be inside a group, or the "
                    f"rule's only source); narrow it manually if needed")
        if inverse:
            out["inverse"] = inverse
        return out
    return out


def remove_preview(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None) -> dict:
    """Read-only: what PolicyPilot would do to REVOKE src->dst:svc (no_op / disable / deny / review)."""
    try:
        with read_session(server, secret) as s:
            layer, layer_note = resolve_layer_name(s, layer)
            block = _dynamic_layer_block(s, layer)
            if block is not None:
                return {**block, "trace": s.trace}
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:
                return _obj_review(res, unresolved, kind, {"cached": False, "trace": s.trace})
            rules, cached = load_layer_cached(s, server, layer, package)
            decision = decide_removal(req, rules, _decide_options(server, layer))
            extra = {"layer_note": layer_note} if layer_note else {}
            return {"ok": True, **_build_removal_preview(decision, req, rules), "cached": cached,
                    "trace": s.trace, **res, **extra}
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.exception("removal preview failed (layer=%r)", layer)
        return {"ok": False, "error": f"removal preview failed: {type(exc).__name__}: {exc}"}


def remove_execute(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None,
                   ticket_id: str = "", publish: bool = False) -> dict:
    """Load -> decide_removal -> apply the revoke in ONE write session. publish commits; else discard
    (validate with zero commit). NO_OP / REVIEW change nothing. Discards on any error (mirrors execute())."""
    try:
        with write_session(server, secret) as s:
            layer, layer_note = resolve_layer_name(s, layer)
            block = _dynamic_layer_block(s, layer)
            if block is not None:
                return {**block, "applied": False, "published": False, "trace": s.trace}
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:
                return {"ok": True, "applied": False, "published": False,
                        **_obj_review(res, unresolved, kind, {"trace": s.trace})}
            rules = load_layer(s, layer, package)
            decision = decide_removal(req, rules, _decide_options(server, layer))
            base = {"action": "remove", "outcome": decision.outcome.value, "reason": decision.reason,
                    "target_rule": _brief(decision.target_rule), **res}
            if layer_note:
                base["layer_note"] = layer_note
            if decision.notes:
                base.update(notes_payload(decision.notes))
            if decision.outcome in (RemovalOutcome.NO_OP, RemovalOutcome.REVIEW):
                return {"ok": True, "applied": False, "published": False, **base, "trace": s.trace}
            try:
                applied = _apply_removal(s, decision, req, layer, ticket_id)
                if publish:
                    s.publish()
                    invalidate_cache(server)
                else:
                    s.discard()
            except Exception as exc:  # noqa: BLE001 — release pending changes + locks on any mid-apply failure
                try:
                    s.discard()
                except MgmtError:
                    sessions = []
                    try:
                        sessions = locking_sessions(server, secret)
                    except Exception:  # noqa: BLE001
                        pass
                    return {"ok": False, "lock_conflict": True, "sessions": sessions, "trace": s.trace,
                            "error": f"the change could not be discarded after a failed removal: {exc}"}
                if isinstance(exc, MgmtError):
                    raise
                return {"ok": False, "error": f"removal failed: {exc}", "trace": s.trace}
            return {"ok": True, "applied": True, "published": publish,
                    "validated": not publish, **base, **applied, "trace": s.trace}
    except MgmtError as exc:
        msg = str(exc)
        out = {"ok": False, "error": msg}
        if _is_lock_error(msg):
            out["lock_conflict"] = True
            out["sessions"] = locking_sessions(server, secret)
        return out
    except Exception as exc:  # noqa: BLE001
        logger.exception("access remove failed (layer=%r, publish=%s)", layer, publish)
        return {"ok": False, "error": f"removal failed: {type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
# AMEND  (edit an existing rule's METADATA — name / comment / tags — never its match columns)
# --------------------------------------------------------------------------- #
# Request-key -> web_api set-access-rule WRITE field. METADATA ONLY: a change to source / destination /
# service / action alters what the rule MATCHES (a security decision) and must go through apply/remove with
# full reasoning + placement — it is deliberately NOT amendable here, so this tool can only relabel a rule.
# NOTE: set-access-rule renames via "new-name" (there is NO "name" write field; show-access-rule READS it
# back as "name") — mirror the existing layer editor (mgmt_api.set_access_rule).
_AMEND_API_FIELD = {"name": "new-name", "comment": "comments", "tags": "tags", "track": "track"}


def _rule_tag_names(cur: dict) -> list:
    """The existing rule's tag NAMES (set-access-rule takes names; show returns names or {name} objects)."""
    out = []
    for t in (cur.get("tags") or []):
        n = t.get("name") if isinstance(t, dict) else t
        if n:
            out.append(n)
    return out


def _rule_track_type(cur: dict) -> str:
    """The rule's current track-type NAME ("Log" / "None" / "Detailed Log" / ...). show-access-rule returns
    track.type as a {name,uid} object (details-level full), a bare name, or a uid — handle all three so the
    inverse restores the prior track. set-access-rule WRITES track as {"type": "<name>"} (mirrors mgmt_api)."""
    t = (cur.get("track") or {}).get("type")
    if isinstance(t, dict):
        return t.get("name") or t.get("uid") or ""
    return str(t or "")


def amend_execute(server, secret, *, uid: str, layer: str, name=None, comment=None, tags=None,
                  track=None, publish: bool = False) -> dict:
    """Edit the METADATA of one existing access rule — its name, comment, tags, and/or track (logging) — in
    ONE write session: read the current values (to build the inverse), set the new ones, then publish (commit)
    or discard (validate-only dry-run). NEVER touches the match columns (source/destination/service/action).
    Records an inverse that restores the OLD metadata, so the edit is itself rollback-able. Discards on any
    error. ``track`` is a track-type name, e.g. "Log" / "None" / "Detailed Log" / "Extended Log"."""
    if not uid or not layer:
        return {"ok": False, "error": "uid and layer are required to identify the rule to edit"}
    fields: dict = {}
    if name is not None:
        if not str(name).strip():
            return {"ok": False, "error": "a rule name can't be empty"}
        fields["name"] = str(name)
    if comment is not None:
        fields["comment"] = str(comment)
    if tags is not None:
        fields["tags"] = [str(t) for t in (tags if isinstance(tags, (list, tuple)) else [tags]) if str(t).strip()]
    if track is not None:
        if not str(track).strip():
            return {"ok": False, "error": "a track type can't be empty (use \"None\" to turn logging off)"}
        fields["track"] = str(track).strip()
    if not fields:
        return {"ok": False, "error": "nothing to change — provide a name, comment, tags, and/or track"}
    try:
        with write_session(server, secret) as s:
            try:                                              # details-level full -> track.type / tags resolve to names
                cur = s.call("show-access-rule", {"uid": uid, "layer": layer, "details-level": "full"})  # VERIFY
            except MgmtError as exc:
                if _is_not_found_error(str(exc)):
                    return {"ok": False, "error": f"no rule {uid} in layer “{layer}” (it may have been "
                            f"deleted) — nothing to edit", "trace": s.trace}
                raise
            payload: dict = {"uid": uid, "layer": layer}
            inverse_set: dict = {}
            ops: list = []
            changed: dict = {}
            for key, val in fields.items():
                api = _AMEND_API_FIELD[key]                   # WRITE field (name -> new-name)
                if key == "tags":
                    payload["tags"] = val                    # set-access-rule REPLACES the tag list
                    inverse_set["tags"] = _rule_tag_names(cur)
                elif key == "track":
                    payload["track"] = {"type": val}         # Track Settings object — {"type":"Log"} etc.
                    old = _rule_track_type(cur)
                    if old:                                   # restore the prior track type on revert
                        inverse_set["track"] = {"type": old}
                elif key == "name":
                    payload["new-name"] = val                 # rename via new-name; show READS it back as "name"
                    old = str(cur.get("name") or "")
                    if old:                                   # never restore an EMPTY name (the SMS rejects a
                        inverse_set["new-name"] = old         # blank name) — mirror mgmt_api.set_access_rule
                else:                                         # comment
                    payload["comments"] = val
                    inverse_set["comments"] = cur.get("comments", "")
                changed[key] = val
                ops.append(f"set-access-rule {uid} {api}")
            try:
                s.call("set-access-rule", payload)            # VERIFY
                if publish:
                    s.publish()
                    invalidate_cache(server)
                else:
                    s.discard()
            except Exception as exc:  # noqa: BLE001 — release the write session's pending changes + locks
                try:
                    s.discard()
                except Exception:  # noqa: BLE001 — a discard that ALSO fails (e.g. a dropped connection) must
                    sessions = []  # still surface the structured lock result, not escape to the opaque handler
                    try:
                        sessions = locking_sessions(server, secret)
                    except Exception:  # noqa: BLE001
                        pass
                    return {"ok": False, "lock_conflict": True, "sessions": sessions, "trace": s.trace,
                            "error": f"the edit could not be discarded after a failure: {exc}"}
                if isinstance(exc, MgmtError):
                    raise
                return {"ok": False, "error": f"edit failed: {exc}", "trace": s.trace}
            # An amend that only ADDED a name to a previously-nameless rule has no metadata to restore -> empty
            # inverse (recorded non-revertable) rather than an op that would blank the name on revert.
            inverse = [{"op": "set-access-rule", "uid": uid, "layer": layer, "set": inverse_set}] if inverse_set else []
            return {"ok": True, "action": "amend", "outcome": "amend", "applied": True,
                    "published": publish, "validated": not publish, "uid": uid, "layer": layer,
                    "changed": changed, "ops": ops, "inverse": inverse, "trace": s.trace}
    except MgmtError as exc:
        msg = str(exc)
        out = {"ok": False, "error": msg}
        if _is_lock_error(msg):
            out["lock_conflict"] = True
            out["sessions"] = locking_sessions(server, secret)
        return out
    except Exception as exc:  # noqa: BLE001
        logger.exception("access amend failed (uid=%s, layer=%r, publish=%s)", uid, layer, publish)
        return {"ok": False, "error": f"edit failed: {type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
# ROLLBACK / undo  (replay an AppliedChange's recorded inverse op-list)
# --------------------------------------------------------------------------- #
_REVERT_FIELDS = {"source", "destination", "service"}
_AMEND_REVERT_FIELDS = {"new-name", "comments", "tags", "track", "custom-fields"}   # metadata a revert may restore


def _amend_meta_ok(k, v) -> bool:
    """A recorded revert metadata field is replayable iff it's whitelisted AND non-blank for the
    fields the SMS rejects empty (a rule name, a track type) — so a stranded blank can never fail a rollback.
    ``custom-fields`` (the field-1/2/3 threshold-override/stamp fields Policy Cleanup restores) must be a
    flat dict of scalars — still metadata, never a match column."""
    if k not in _AMEND_REVERT_FIELDS:
        return False
    if k == "new-name":
        return bool(str(v).strip())
    if k == "track":
        return isinstance(v, dict) and bool(str(v.get("type") or "").strip())
    if k == "custom-fields":
        return isinstance(v, dict) and all(isinstance(x, (str, int, float, bool)) for x in v.values())
    return True


def _is_not_found_error(msg: str) -> bool:
    """The SMS reports a missing object ('Requested object [...] not found' / '... can not be found'). For a
    ROLLBACK that means the rule this op targets was already removed OUT-OF-BAND — the change is effectively
    already undone, so the op is a successful no-op, not a failure that strands the change as un-reverted."""
    m = (msg or "").lower()
    return ("not found" in m or "can not be found" in m or "cannot be found" in m or "does not exist" in m)


def _revert_call(session, command: str, payload: dict, note: str) -> str:
    """Run one rollback web_api call IDEMPOTENTLY: if the target rule is already gone (deleted out-of-band in
    SmartConsole), the rollback's intent is already satisfied -> swallow the not-found as a successful no-op
    rather than failing the whole revert and leaving the audit entry stuck (the reported case)."""
    try:
        session.call(command, payload)  # VERIFY
        return note
    except MgmtError as exc:
        if _is_not_found_error(str(exc)):
            return note + " — rule already absent (removed out-of-band)"
        raise


def _apply_inverse_op(session, op: dict) -> str:
    """Translate ONE recorded inverse op (a flat, validated dict) into its web_api call. STRICTLY
    whitelisted — only the three rule edits the engine itself ever emits are accepted (delete a rule,
    re-enable a rule, remove an object from a cell); any other shape is rejected, never executed. The
    op-list comes from our own DB, but validating the shape here keeps a tampered/garbled row from turning
    into an arbitrary management call."""
    kind, uid, layer = op.get("op"), op.get("uid"), op.get("layer")
    if kind == "add-access-rule":
        # Recreate a rule the cleanup DELETED, from its recorded pre-delete snapshot. STRICTLY whitelisted
        # fields only (match columns included — this is a faithful restore of a rule WE removed, not an
        # edit of a live one), and two safety invariants enforced here regardless of the stored row:
        # the rule comes back DISABLED, and at the recorded anchor (falling back to bottom if the anchor
        # rule has since moved/gone).
        if not layer:
            raise MgmtError(f"malformed rollback op (missing layer): {op!r}")
        allowed = {"name", "comments", "source", "destination", "service", "action", "track",
                   "custom-fields", "source-negate", "destination-negate", "service-negate",
                   "vpn", "time", "content", "content-negate", "content-direction", "install-on",
                   "action-settings", "user-check", "inline-layer"}
        rule = op.get("rule") or {}
        payload = {k: v for k, v in rule.items() if k in allowed and v not in (None, [], {}, "")}
        payload["layer"] = layer
        payload["enabled"] = False                      # a rollback never silently re-opens traffic
        anchor = op.get("position") or "bottom"
        try:
            session.call("add-access-rule", {**payload, "position": anchor})
            return f"add-access-rule (recreate, position {anchor})"
        except MgmtError:
            if anchor == "bottom":
                raise
            session.call("add-access-rule", {**payload, "position": "bottom"})   # anchor rule moved/gone
            return "add-access-rule (recreate, anchor gone — placed at bottom)"
    if not uid or not layer:
        raise MgmtError(f"malformed rollback op (missing uid/layer): {op!r}")
    if kind == "delete-access-rule":
        return _revert_call(session, "delete-access-rule", {"uid": uid, "layer": layer},
                            f"delete-access-rule {uid}")
    if kind == "set-access-rule":
        if "enabled" in op:
            # An enable/disable op may carry a whitelisted metadata restore alongside (Policy Cleanup's
            # disable-inverse re-enables AND puts back the prior comments/custom-fields in one atomic call).
            meta = {k: v for k, v in (op.get("set") or {}).items() if _amend_meta_ok(k, v)} \
                if isinstance(op.get("set"), dict) else {}
            return _revert_call(session, "set-access-rule",
                                {"uid": uid, "layer": layer, "enabled": bool(op["enabled"]), **meta},
                                f"set-access-rule {uid} enabled={bool(op['enabled'])}"
                                + ("," + ",".join(sorted(meta)) if meta else ""))
        # Metadata restore (undo an amend): set the OLD name / comments / tags back. STRICTLY limited to
        # those three fields — never a match column — so reverting an edit can only relabel, never re-open
        # or alter what the rule matches.
        if isinstance(op.get("set"), dict):
            # Restore only whitelisted metadata (new-name / comments / tags / track), never a match column,
            # and never a blank name/track (the SMS rejects those — a stranded blank can't fail the rollback).
            meta = {k: v for k, v in op["set"].items() if _amend_meta_ok(k, v)}
            if meta:
                return _revert_call(session, "set-access-rule", {"uid": uid, "layer": layer, **meta},
                                    f"set-access-rule {uid} " + ",".join(sorted(meta)))
        field, obj = op.get("field"), op.get("remove")
        if field in _REVERT_FIELDS and obj:
            return _revert_call(session, "set-access-rule", {"uid": uid, "layer": layer, field: {"remove": obj}},
                                f"set-access-rule {uid} {field}.remove {obj}")
        add = op.get("add")                          # re-add a source member removed by a narrow (undo)
        if field in _REVERT_FIELDS and add:
            return _revert_call(session, "set-access-rule", {"uid": uid, "layer": layer, field: {"add": add}},
                                f"set-access-rule {uid} {field}.add {add}")
    raise MgmtError(f"unsupported rollback op: {op!r}")


def _effective_revert_ops(inverse_ops: list[dict], disable_added_rules: bool) -> list[dict]:
    """Resolve the delete-vs-disable choice for an added-rule rollback. Check Point lets a rule be disabled
    rather than deleted, which is the gentler, reversible, auditable undo (the rule stays in the rulebase,
    greyed out, easy to re-enable). When ``disable_added_rules`` is set, every ``delete-access-rule`` op is
    rewritten to disable that rule instead; all other ops (re-enable, remove-from-cell) are unaffected."""
    if not disable_added_rules:
        return inverse_ops
    out = []
    for op in inverse_ops:
        if op.get("op") == "delete-access-rule" and op.get("uid") and op.get("layer"):
            out.append({"op": "set-access-rule", "uid": op["uid"], "layer": op["layer"], "enabled": False})
        else:
            out.append(op)
    return out


def revert_execute(server, secret, inverse_ops: list[dict], *, publish: bool = False,
                   disable_added_rules: bool = False) -> dict:
    """Replay precomputed INVERSE op(s) (from a recorded AppliedChange) in ONE write session to roll back a
    published change — surgically (delete the rule we added / re-enable the rule we disabled / remove the
    object we widened in), never a heavy full-DB revision rollback. ``disable_added_rules`` undoes an
    added-rule change by DISABLING the rule instead of deleting it (reversible, leaves it visible). publish
    commits; otherwise validate then discard (zero commit). Discards on any error (mirrors execute())."""
    if not inverse_ops:
        return {"ok": False, "error": "this change has no recorded inverse — it can't be rolled back here"}
    ops = _effective_revert_ops(inverse_ops, disable_added_rules)
    try:
        with write_session(server, secret) as s:
            ops_done: list[str] = []
            try:
                for op in ops:
                    ops_done.append(_apply_inverse_op(s, op))
                if publish:
                    s.publish()
                    invalidate_cache(server)
                else:
                    s.discard()
            except Exception as exc:  # noqa: BLE001 — release pending changes + locks on any failure
                try:
                    s.discard()
                except MgmtError:
                    sessions = []
                    try:
                        sessions = locking_sessions(server, secret)
                    except Exception:  # noqa: BLE001
                        pass
                    return {"ok": False, "lock_conflict": True, "sessions": sessions, "trace": s.trace,
                            "error": f"the rollback could not be discarded after a failure: {exc}"}
                if isinstance(exc, MgmtError):
                    raise
                return {"ok": False, "error": f"rollback failed: {exc}", "trace": s.trace}
            # ``mode`` describes how an ADDED rule was undone — only meaningful when the inverse deletes a rule
            # (create / deny revert). A widen-revert (remove object from a cell) or disable-revert (re-enable)
            # has no rule deletion -> "edit", so it isn't mislabeled "disable"/"delete".
            had_delete = any(op.get("op") == "delete-access-rule" for op in inverse_ops)
            mode = ("disable" if disable_added_rules else "delete") if had_delete else "edit"
            return {"ok": True, "reverted": publish, "validated": not publish, "ops": ops_done,
                    "mode": mode, "trace": s.trace}
    except MgmtError as exc:
        msg = str(exc)
        out = {"ok": False, "error": msg}
        if _is_lock_error(msg):
            out["lock_conflict"] = True
            out["sessions"] = locking_sessions(server, secret)
        return out
    except Exception as exc:  # noqa: BLE001
        logger.exception("access revert failed (publish=%s)", publish)
        return {"ok": False, "error": f"rollback failed: {type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
# Offline smoke test of the pure decision engine (no management server needed)
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    def _host(ip):
        return [(_ip_int(ip), _ip_int(ip))]

    def _net(cidr):
        n = ipaddress.ip_network(cidr)
        return [(int(n.network_address), int(n.broadcast_address))]

    def _tcp(p):
        return ServiceSet(by_proto={"tcp": _ports_to_iv(str(p))})

    web = ParsedRule(uid="r8", number=8, name="web farm", enabled=True, action="Accept",
                     src=_net("10.1.0.0/24"), dst=_host("172.16.5.10"), svc=_tcp(443))
    dns1 = ParsedRule(uid="r3", number=3, name="dns one", enabled=True, action="Accept",
                      src=_host("10.1.2.250"), dst=_host("9.9.9.9"), svc=_tcp(53))
    deny_db = ParsedRule(uid="r9", number=9, name="block db", enabled=True, action="Drop",
                         src=ANY_IP, dst=_host("172.16.5.20"), svc=_tcp(1521))
    cleanup = ParsedRule(uid="rC", number=99, name="Cleanup rule", enabled=True, action="Drop",
                         src=ANY_IP, dst=ANY_IP, svc=ServiceSet(any=True))
    rulebase = [web, dns1, deny_db, cleanup]

    def show(label, req):
        d = decide(req, rulebase)
        print(f"{label:24} -> {d.outcome.value:7} | {d.reason}")

    show("already allowed", AccessRequest(["10.1.0.50/32"], ["172.16.5.10/32"], "tcp", "443"))
    show("widen source", AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"))
    show("widen destination", AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"))
    show("widen service", AccessRequest(["10.1.2.250/32"], ["9.9.9.9/32"], "tcp", "8443"))
    show("over-grant guarded", AccessRequest(["10.1.0.50/32"], ["172.16.9.9/32"], "tcp", "443"))
    show("create (new)", AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"))
    show("explicit deny", AccessRequest(["192.168.9.9/32"], ["172.16.5.20/32"], "tcp", "1521"))
