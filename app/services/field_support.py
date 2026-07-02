"""The authoritative Access-Automation FIELD SUPPORT MATRIX — exactly which Check Point object types the
decision + apply engine handles in each rule column, at what support level, how to discover the object, and
the known gaps. Rendered by the "Field support" page so there is NO guessing about what the engine can and
can't do.

DRIFT-SAFE: the concrete object-TYPE lists are pulled from the real engine constants (TYPED_KINDS,
WRITABLE_ACTIONS, correlate_objects._TIME_TYPES/_CONTENT_TYPES). ``verify_against_engine()`` (exercised by a
test) fails if this table ever diverges from the code it documents.
"""
from __future__ import annotations

from . import access_automation as aa
from . import correlate_objects as co

# Support levels (also drive the badge colour in the template).
FULL = "full"        # created-if-missing OR reused; fully reasoned by the engine
REUSE = "reuse"      # supported, but REUSE-ONLY — the object must already exist (engine never creates it)
PARTIAL = "partial"  # supported with a caveat (opaque reach handled conservatively, or blade-dependent)
GAP = "gap"          # not supported / no such Check Point control / routes to human REVIEW

LEVELS = {
    FULL: ("Full", "Created if missing, or reused. Fully reasoned in decide + apply."),
    REUSE: ("Reuse-only", "Must already exist on the server — the engine references it, never creates it."),
    PARTIAL: ("Partial", "Supported, with the caveat noted — always handled conservatively (never a false allow)."),
    GAP: ("Gap", "Not supported: no such Check Point control, or it routes to human review."),
}

# Service & Application object types the engine parses (from access_automation._parse_svc), split by how it
# reasons about each. Curated text; the type strings are the real CP object types.
_SERVICE_TYPES = [
    ("service-tcp / service-udp / service-sctp", FULL, "Port-based — exact port/range reasoning."),
    ("service-group", FULL, "Expanded to members; a widen can add one object to it."),
    ("service-icmp / service-icmp6", FULL, "Matched by name within the ICMP family (never aliased across families)."),
    ("application-site / application-site-category", FULL, "See the Application field."),
    ("service-other / service-dce-rpc / service-rpc / service-gtp / compound / citrix",
     PARTIAL, "Matched by name, but their protocol/port reach can't be bounded → treated as OPAQUE: kept "
              "in the request's path so it's never a false NO_OP, but coverage can't be proven (the engine "
              "creates around it rather than claim reuse)."),
]


def matrix() -> list[dict]:
    """The full field matrix — each row: {field, column, level, supported[], discovery, gaps[], notes}."""
    typed = ", ".join(aa.TYPED_KINDS)                       # domain, access-role, dynamic-object, …
    return [
        {
            "field": "Source", "column": "Source", "level": FULL, "discovery": None,
            "supported": [
                ("IP / CIDR / Any", FULL, "The default. Ranges + subnets reasoned exactly."),
                ("host / network / address-range / group", FULL, "Resolved to member IP extents (a group expands to its members)."),
                (f"Typed identities: {typed}", FULL, "Set source_kind to reason in that identity space, not by IP. "
                 "Domains + dynamic-objects are created if missing; access-role / security-zone / updatable "
                 "are reused (they live in Identity Awareness / topology / Check Point's repository). "
                 "Resolve an identity NAME with correlate_access_role or correlate_zone — the zero-trust path."),
            ],
            "gaps": [
                "A negated (‘not’) source cell → the rule stays in the path and routes to REVIEW (its true reach is unknown).",
                "A wildcard object that expands past 256 disjoint ranges → kept opaque → REVIEW.",
                "A group whose members aren’t inlined in the fetched objects (a thin/nested copy) → REVIEW.",
                "No discovery tool yet for a dynamic-object / updatable-object name (pass it exactly).",
            ],
            "notes": "No name discovery needed for an IP. Identity sources are the zero-trust primitive: "
                     "correlate_access_role / correlate_zone resolve the name, then pass it with the typed kind.",
        },
        {
            "field": "Destination", "column": "Destination", "level": FULL, "discovery": None,
            "supported": [
                ("Everything Source supports", FULL, "IP/CIDR/Any + host/network/range/group + the typed kinds."),
                ("Internet (predefined)", FULL, "Check Point’s topology-based Internet object — the canonical destination "
                 "for an Application Control / URL-Filtering rule. Its own identity space (recognized by uid/type)."),
            ],
            "gaps": ["Same as Source (negation / over-cap wildcard / un-inlined group → REVIEW)."],
            "notes": "An Application request defaults its destination to Internet (App Control best practice).",
        },
        {
            "field": "Service / Port", "column": "Services & Applications", "level": FULL,
            "discovery": "correlate_service",
            "supported": [(t, lvl, note) for (t, lvl, note) in _SERVICE_TYPES if "application" not in t],
            "gaps": [
                "service-other / rpc / gtp / compound: protocol reach isn’t boundable → opaque (conservative, never a false allow).",
                "A service whose port cell can’t be parsed (e.g. a malformed or inverted range) → REVIEW.",
            ],
            "notes": "Resolve a protocol word (‘icmp’, ‘GRE’, ‘dns’) to the exact object with correlate_service first.",
        },
        {
            "field": "Application / Site", "column": "Services & Applications", "level": FULL,
            "discovery": "correlate_application",
            "supported": [
                ("application-site", FULL, "An exact application/site (Facebook, Office365 …)."),
                ("application-site-category", FULL, "A category (Social Networking …) — matched as a category."),
                ("application-site-group", PARTIAL, "An app GROUP is opaque (members not enumerated) → coverage uncertain, handled conservatively."),
            ],
            "gaps": ["App identification requires the Application Control / URL-Filtering blade enabled on the gateway."],
            "notes": "An application goes in the application field with destination = Internet — never as a domain.",
        },
        {
            "field": "Action", "column": "Action", "level": FULL, "discovery": None,
            "supported": [(a, FULL, "") for a in aa.WRITABLE_ACTIONS],
            "gaps": [],
            "notes": "Drop/Reject place a least-privilege block ABOVE what would allow the flow; Ask/Inform/Apply-Layer always create (flagged for review). Apply Layer needs an inline_layer name.",
        },
        {
            "field": "Content (data types)", "column": "Content", "level": REUSE,
            "discovery": "correlate_content",
            "supported": [(t.replace("data-type-", "data-type-"), REUSE, "") for t in co._CONTENT_TYPES],
            "gaps": ["Data types are REUSE-ONLY (must exist). Content inspection needs the Content Awareness blade."],
            "notes": "Resolve a phrase (‘SQL Queries’) with correlate_content; set content_direction up/down/any. Any content makes the request ‘restricted’ → always a precise CREATE above a broad Accept.",
        },
        {
            "field": "Time", "column": "Time", "level": REUSE, "discovery": "correlate_time",
            "supported": [(t, REUSE, "") for t in co._TIME_TYPES],
            "gaps": ["Time objects are REUSE-ONLY (must exist — create in SmartConsole first if none matches)."],
            "notes": "Resolve ‘work hours’ with correlate_time. A time window makes the request ‘restricted’ → precise CREATE above a broad Accept so the window takes effect (first-match).",
        },
        {
            "field": "Action Settings · Limit", "column": "Action Settings", "level": REUSE,
            "discovery": "correlate_limit",
            "supported": [("limit (QoS/bandwidth RATE object)", REUSE, "e.g. Upload_10Mbps — applies to Accept / Ask / Inform.")],
            "gaps": ["A Limit is a RATE (Mbps/Gbps), NOT a volume/quota — Check Point has NO ‘max N GB total’ control in the Access Policy. A volume request maps to a rate object or is declined."],
            "notes": "Resolve a bandwidth phrase with correlate_limit; pass as action_limit.",
        },
        {
            "field": "Action Settings · Captive Portal", "column": "Action Settings", "level": PARTIAL,
            "discovery": None,
            "supported": [("enable-identity-captive-portal (on/off)", FULL, "A boolean on Accept / Ask / Inform.")],
            "gaps": ["Requires Identity Awareness enabled on the gateway (the SmartConsole checkbox is greyed out without it)."],
            "notes": "Pass captive_portal=true. Stripped from Drop/Reject/Apply-Layer (meaningless there).",
        },
        {
            "field": "Action Settings · UserCheck", "column": "Action Settings", "level": REUSE,
            "discovery": "correlate_user_check",
            "supported": [
                ("interaction (the UserCheck message object)", REUSE, "Ask / Inform prompt, or the Drop / Reject blocked-message page. Reuse-only — resolve the name with correlate_user_check; validated at publish."),
                ("frequency", FULL, "once a day | once a week | once a month | custom frequency… — Ask / Inform only."),
                ("confirm", FULL, "per rule | per category | per application/site | per data type — Ask / Inform only."),
                ("custom-frequency {every, unit}", FULL, "hours | days | weeks | months — only when frequency is 'custom frequency…'."),
            ],
            "gaps": ["A wrong UserCheck name is caught only at publish (atomic — the whole change is discarded); correlate_user_check resolves it first, but a server that doesn't index user-check objects returns no candidates (pass the exact name)."],
            "notes": "Written as the top-level user-check object (sibling of action / action-settings). Defaults match SmartConsole: frequency 'once a day', confirm 'per rule'.",
        },
        {
            "field": "Install On", "column": "Install On", "level": REUSE, "discovery": None,
            "supported": [
                ("Gateway / cluster / server (by name)", REUSE, "Enumerated via show-gateways-and-servers."),
                ("Group of gateways", REUSE, "Validated via a typed fallback."),
                ("Policy Targets / Any", FULL, "The default (no restriction)."),
            ],
            "gaps": ["Reuse-only (targets must exist). No dedicated correlate tool yet — pass the exact gateway/group name."],
            "notes": "Restricting to specific gateways makes the request ‘restricted’ → precise CREATE.",
        },
        {
            "field": "VPN", "column": "VPN", "level": REUSE, "discovery": None,
            "supported": [
                ("VPN community (meshed / star / remote-access)", REUSE, "Enumerated via the show-vpn-communities-* commands."),
                ("All_GwToGw / Any", FULL, "The traffic-agnostic defaults."),
            ],
            "gaps": ["Reuse-only (communities must exist). No dedicated correlate tool yet — pass the exact community name."],
            "notes": "A specific community makes the request ‘restricted’ → precise CREATE.",
        },
        {
            "field": "Track (logging)", "column": "Track", "level": FULL, "discovery": None,
            "supported": [("None / Log / Detailed Log / Extended Log", FULL, "Set on a rule via amend_access_rule.")],
            "gaps": ["Changed only via amend (metadata edit), not as part of a decide/apply request."],
            "notes": "amend_access_rule edits name / comment / tags / track only — never the match columns.",
        },
    ]


# Cross-cutting behaviours that route a rule to human REVIEW rather than an automatic decision (safety-first).
REVIEW_TRIGGERS = [
    "A negated (‘not’) cell on any dimension — its true reach is unknown, so the engine never reasons past it.",
    "A wildcard object that expands beyond 256 disjoint ranges — kept opaque.",
    "A group whose members aren’t present in the fetched objects (nested/thin copy) — can’t enumerate its extent.",
    "An updatable-object (geo/threat feed) as a source/destination — membership is dynamic → treated as uncertain overlap.",
    "An existing rule gated by a column the engine doesn’t model (VPN direction, a data/content match, an install-on subset) — noted, and the new rule is placed BELOW it so it can’t leap the possible block.",
    "An inline-layer rule the request only PARTIALLY matches — the traffic splits across layers → review.",
]


def verify_against_engine() -> list[str]:
    """Return a list of drift problems (empty = the matrix matches the engine). Used by a test so this page
    can never silently diverge from the code it documents."""
    problems: list[str] = []
    rows = {r["field"]: r for r in matrix()}
    # Actions row must list EXACTLY the writable actions.
    act = {name for (name, _l, _n) in rows["Action"]["supported"]}
    if act != set(aa.WRITABLE_ACTIONS):
        problems.append(f"Action row {act} != WRITABLE_ACTIONS {set(aa.WRITABLE_ACTIONS)}")
    # Time / Content rows must cover exactly the correlator (== apply-side) type sets.
    time_listed = {t for (t, _l, _n) in rows["Time"]["supported"]}
    if time_listed != set(co._TIME_TYPES):
        problems.append(f"Time row {time_listed} != {set(co._TIME_TYPES)}")
    content_listed = {t for (t, _l, _n) in rows["Content (data types)"]["supported"]}
    if content_listed != set(co._CONTENT_TYPES):
        problems.append(f"Content row {content_listed} != {set(co._CONTENT_TYPES)}")
    return problems
