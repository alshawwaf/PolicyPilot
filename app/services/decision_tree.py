"""The access-automation decision tree as DATA, plus portable diagram exporters.

ONE source of truth for the visual — the same first-match flow ``access_automation.decide()`` implements,
rendered into the formats a customer's own tools open, so the diagram can never drift from the engine:

  * Mermaid (.mmd)      — GitHub / GitLab / Obsidian / VS Code / mermaid.live, and **draw.io imports it**
  * diagrams.net (.drawio / mxGraph XML) — opens + edits in app.diagrams.net, and exports to
                          **Microsoft Visio (.vsdx)**, PDF, PNG, SVG from there
  * Graphviz (.dot)     — every open-source graph viewer (xdot, Graphviz, VS Code, …)

The on-page view renders this same Mermaid source client-side, so editing the tree means editing this
one file. Keep the NODES/EDGES below in lock-step with decide()."""
from __future__ import annotations

import json
from dataclasses import dataclass
from xml.sax.saxutils import escape as _xescape


@dataclass(frozen=True)
class Node:
    id: str
    label: str
    sub: str
    kind: str        # start | process | decision | review | noop | widen | create | note | terminal
    x: int           # layout coords (used by the .drawio exporter; Mermaid/DOT auto-lay-out)
    y: int
    w: int = 250
    h: int = 64
    level: int = 0   # detail TIER for the on-page collapse: 0 = the core flow (always shown), >=1 =
                     # detail (inline-layer recursion, automation modes) collapsed until expanded. NOT a
                     # BFS depth — it's a hand-set "how much detail" tier so the core flow stays whole
                     # when collapsed. The exported .mmd/.drawio/.dot ALWAYS contain every node.
    option: str = ""  # the Settings knob (aa_*) this node's behaviour is governed by — the on-page
                      # diagram turns it into a click-to-toggle pill (interactive editor). "" = not tunable.


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    label: str = ""


# The tree — mirrors decide(). It is REUSE-OR-CREATE: it never hard-stops for a policy "review". CORE flow
# (level 0, always shown): resolve each cell (exact / approx / typed-identity / opaque → note & continue)
# -> already permitted? (no-op) -> resolved deny covering the path? (create the allow ABOVE it) -> two
# columns equal? (widen) -> else create. DETAIL (level 1, collapsed on-page until expanded): (a) HOW each
# source/destination is matched — IP-interval space vs typed-object IDENTITY space (domain / role /
# dynamic / updatable / zone), the cross-kind disjointness and the one opaque case; (b) the inline-layer
# recursion ("Apply Layer" sub-rulebase); (c) the Settings-driven ignore-conditions mode; (d) how the
# chosen objects are materialised on apply (reuse-or-create vs reuse-only). Keep this in lock-step with
# access_automation.decide() + _apply().
# Layout is a TIDY GRID (hand-placed coords; the on-page renderer reads x/y directly). CORE = a clean two-
# column spine: left column (x=40) holds the decision chain req→resolve→perm→deny→create stacked by row;
# the right column (x=430) holds each row's outcome/branch (noteO, noop, widen, doWiden) aligned to its
# decision. deny→create runs straight down the spine (no skip-edge over widen). DETAIL clusters sit in
# their own well-separated regions: identity-matching as a left→right tree (top-right), the inline + opts
# nodes in an x=900 column, and the apply/materialise fan along the bottom. Keep new nodes on this grid.
NODES: list[Node] = [
    # --- CORE spine (left column x=40) + its row-aligned outcomes (right column x=430) ------------
    Node("req", "Access request", "source · destination · service / app / category — each endpoint an IP/CIDR/Any or a typed object; an application request defaults its destination to the predefined Internet object (App Control best practice)",
         "start", 40, 40, 300, 86),
    Node("resolve", "Resolve request + each rule cell (top-down, first match wins)",
         "IP: host / network / range / group (exact) · gateway / cluster / mgmt (approx) · typed object → matched by identity · else opaque → note & continue",
         "process", 40, 200, 320, 104),
    Node("noteO", "Note & keep going", "anything we can’t fully resolve — an OPAQUE rule (updatable feed · negated / unparsable cell · non-Accept/Drop action), a CONDITIONAL rule (VPN / time / data / install-on), or a request that SPLITS across an inline layer — is flagged “review later”, NOT stopped. The walk continues; the new rule is placed BELOW it. A rule that provably CAN’T cover the request (e.g. a specific destination vs an Any request) is NOT flagged as a possible allow.",
         "note", 430, 196, 320, 132, option="aa_emit_notes"),
    Node("review", "Incomplete request — fix & retry",
         "ONLY the REQUEST itself is unusable — an empty / unparsable service (no concrete port or application), a typed endpoint (domain / role / zone …) whose name resolves to NO object, an IP that resolves to nothing, or an unsupported action — so there is nothing to evaluate or create. NOT a POLICY rule we can’t fully resolve (those are noted & passed, never a stop).",
         "review", 780, 40, 330, 120),
    Node("action", "Allow, or block / divert?",
         "Accept → the reuse / widen / create flow below. Drop · Reject · Ask · Inform · Apply-Layer → place the REQUESTED verdict, never reuse an Accept (those answer “is this allowed?”, meaningless for a block / conditional / divert).",
         "decision", 40, 330, 320, 92),
    Node("verdict", "Place the requested verdict",
         "Drop / Reject → no-op if the first in-path rule already denies it, else create the block ABOVE the first in-path rule (first-match denies exactly this flow) · Ask / Inform / Apply-Layer → create, floored BELOW any opaque possible-deny so it can’t silently override an unmodeled block; always flagged for review.",
         "create", 430, 326, 330, 116),
    Node("perm", "Already permitted?", "first reachable Accept covering all 3 columns, before any covering drop",
         "decision", 40, 470, 300, 68),
    Node("noop", "No-op", "already allowed WITHIN this access layer — just attach the rule to the ticket (Check Point Ordered Layers chain, so a downstream layer can still restrict it)", "noop", 430, 396, 250, 84),
    Node("deny", "Resolved deny covering the path?",
         "a covering / partial DROP we can fully resolve → CREATE the allow ABOVE it so the access works (first-match then hits the allow). A conditional / opaque possible-deny is NOT here — it’s noted & passed, above.",
         "decision", 40, 540, 320, 104, option="aa_override_blocking_deny"),
    Node("widen", "Two columns equal the request?", "the third differs → add the request’s value to THAT rule cell (suppressed if an opaque possible-deny was passed)",
         "decision", 430, 552, 300, 84, option="aa_prefer_widen"),
    Node("doWiden", "Widen the rule", "add the differing source / destination / service to the cell (never a shared group)",
         "widen", 430, 760, 260, 72),
    Node("create", "Create least-privilege rule",
         "above a blocking deny, below a more-specific rule, or at the section floor — least-privilege · an APPLICATION or category is carved out ABOVE a rule that blocks it (CP identifies the app; other traffic still hits the rule) · BELOW any opaque possible-deny · else grouped into the provisioned SECTION above the cleanup (never inside it). A more-specific deny SHADOWED below the new allow is flagged; an Internet-object destination is noted topology/blade-dependent. Every choice here is tunable in Settings → Access automation logic.", "create",
         40, 822, 320, 104, option="aa_app_carveout"),

    # --- DETAIL tier 1: HOW each source/destination is matched (IP space vs identity space) -------
    # A self-contained branch off "resolve", laid out left→right: kindq → {ipspace, idspace} →
    # {iddomain, idexact, iddisjoint} → idupd. Each object KIND is its own match space, so cross-kind is
    # provably disjoint (mirrors svc apps-vs-ports). Terminal nodes describe "then continues the normal
    # checks above" rather than drawing an edge back to a core leaf (keeps the subtree self-contained).
    Node("kindq", "How is each source / destination matched?", "by its KIND — an IP/CIDR/Any, or a typed object",
         "decision", 900, 120, 300, 68, level=1),
    Node("ipspace", "IP space", "compare IPv4 / IPv6 intervals · host = exact · gateway / cluster / mgmt = approx (under-count — never proven disjoint)",
         "terminal", 1300, 30, 320, 96, level=1),
    Node("idspace", "Identity space (typed object)", "matched by OBJECT IDENTITY, not by IP — the policy as written, not runtime DNS",
         "process", 1300, 210, 320, 84, level=1),
    Node("iddomain", "Domain request", "covered by Any, or a dns-domain object EQUAL-TO / a PARENT-OF the FQDN (.example.com covers www.example.com; an exact object covers only itself)",
         "decision", 1700, 150, 340, 96, level=1),
    Node("idexact", "Role / dynamic / updatable / zone", "matched by EXACT object name (its own identity)",
         "terminal", 1700, 300, 280, 72, level=1),
    Node("iddisjoint", "Different kinds never collide", "a domain ≠ an IP / role / zone object → provably OUT of the request’s path (can’t satisfy OR block it)",
         "terminal", 1700, 432, 340, 96, level=1),
    Node("idupd", "Note & keep going", "a domain meets an updatable feed (e.g. Office365) — it may contain the FQDN, so it’s flagged “review later” and the walk continues (never a hard stop)",
         "note", 2100, 150, 340, 96, level=1),

    # --- DETAIL tier 1: inline-layer recursion + automation mode (x=900 column, below kindq) ------
    Node("inline", "In-path rule applies an inline layer?", "action “Apply Layer” — a sub-rulebase. A DYNAMIC LAYER (sk182252) is managed out-of-band by other admins → EXCLUDED (not descended, not flagged).",
         "decision", 900, 340, 300, 92, level=1),
    Node("recurse", "Descend into the inline layer",
         "a normal inline layer re-runs this whole flow INSIDE it — its own no-op / widen / create, plus the layer’s implicit cleanup. A request that SPLITS across the inline + parent layers is noted & the new rule placed below.",
         "terminal", 1300, 470, 330, 116, level=1),
    Node("opts", "Automation mode (Settings): ignore-conditions",
         "optionally treat VPN / time / data / install-on rules as unconditional — a conditional Accept then counts as covering and a conditional Drop as a resolved block (create above it), instead of being noted & passed",
         "terminal", 900, 560, 360, 96, level=1, option="aa_ignore_conditions"),

    # --- DETAIL tier 1: object materialisation on apply — a fan along the bottom -------------------
    Node("apply", "On apply: materialise the objects", "reuse an existing object, else create it — then write the rule",
         "process", 430, 940, 300, 72, level=1),
    Node("matIP", "IP endpoint", "reuse a host / network by IP, else add-host / add-network (a CIDR stays a NETWORK — never narrowed to /32)",
         "terminal", 40, 1100, 320, 96, level=1),
    Node("matMk", "Domain / dynamic-object", "reuse, else add-dns-domain (leading dot = sub-domains) / add-dynamic-object",
         "terminal", 430, 1100, 320, 84, level=1),
    Node("matReuse", "Reuse-only object?", "access-role · security-zone · updatable-object", "decision",
         820, 1100, 300, 72, level=1),
    Node("matMissing", "Note: define it first", "a reuse-only object that’s missing can’t be fabricated from a request — create it once (Identity Awareness / topology / CP repository), then re-run",
         "terminal", 820, 1244, 340, 96, level=1),
]

EDGES: list[Edge] = [
    Edge("req", "resolve"),
    Edge("resolve", "review", "empty / unparsable request"),
    Edge("resolve", "noteO", "opaque rule"), Edge("noteO", "action", "continue"),
    Edge("resolve", "action", "resolved"),
    Edge("action", "perm", "Accept"),
    Edge("action", "verdict", "block / conditional / divert"),
    Edge("perm", "noop", "yes"), Edge("perm", "deny", "no"),
    Edge("deny", "create", "yes → create above it"),
    Edge("deny", "doWiden", "clean rule above the deny — widen it"),
    Edge("deny", "widen", "no covering deny — prefer reuse"),
    Edge("widen", "doWiden", "yes"), Edge("widen", "create", "no exact 2-of-3 match"),

    # how each endpoint is matched (detail) — IP-interval space vs typed-object identity space
    Edge("resolve", "kindq", "how each endpoint matches"),
    Edge("kindq", "ipspace", "IP / CIDR / Any"),
    Edge("kindq", "idspace", "typed object"),
    Edge("idspace", "iddomain", "domain"),
    Edge("idspace", "idexact", "role / dynamic / updatable / zone"),
    Edge("idspace", "iddisjoint", "vs a different kind"),
    Edge("iddomain", "idupd", "vs an updatable feed"),

    # inline-layer recursion (detail) — one summarising node off "resolve"
    Edge("resolve", "inline", "applies an inline layer"),
    Edge("inline", "recurse", "descend"),
    # automation mode (detail) — the optional ignore-conditions toggle, off the deny decision
    Edge("deny", "opts", "ignore-conditions"),

    # object materialisation on apply (detail) — off the widen/create outcomes
    Edge("doWiden", "apply", "materialise"),
    Edge("create", "apply", "materialise"),
    Edge("apply", "matIP", "IP endpoint"),
    Edge("apply", "matMk", "domain / dynamic"),
    Edge("apply", "matReuse", "role / zone / updatable"),
    Edge("matReuse", "matMissing", "missing → note"),
]

# The on-page diagram starts collapsed to this tier; deeper nodes expand step-by-step. Downloads/exports
# are never filtered (the whole tree is always in the .mmd/.drawio/.dot).
DEFAULT_LEVEL = 0

# kind -> (fill, stroke, font). LIGHT palette — refined for a WHITE canvas (diagrams.net / Visio /
# Graphviz / GitHub-rendered .mmd): soft tinted fills, a saturated border, dark-tinted text.
PALETTE: dict[str, tuple[str, str, str]] = {
    "start":    ("#f3f6fb", "#cdd7e6", "#334155"),
    "process":  ("#eef2f9", "#cdd7e6", "#334155"),
    "decision": ("#e7eef7", "#9aa8be", "#1e293b"),
    "review":   ("#fde7e7", "#e5484d", "#b01e22"),   # clean crimson
    "noop":     ("#dcf3e4", "#16a34a", "#0c6b34"),   # green
    "widen":    ("#dceffb", "#0ea5e9", "#0b6a96"),   # sky
    "create":   ("#fbeecb", "#f59e0b", "#92610a"),   # amber
    "note":     ("#e6f0fb", "#3b82f6", "#1e497f"),   # advisory blue — "noted, not blocked; keep going"
    "terminal": ("#f1f4fa", "#a9b4c8", "#35435d"),   # muted slate — an informational dead-end leaf
}

# DARK palette — for the on-page render on the portal's dark canvas: nodes sit IN the dark (deep tinted
# fills) with a bright border + light tinted text, so they feel designed rather than pasted on.
PALETTE_DARK: dict[str, tuple[str, str, str]] = {
    "start":    ("#1b2536", "#33415c", "#cdd9ea"),
    "process":  ("#1b2536", "#33415c", "#cdd9ea"),
    "decision": ("#212e46", "#3f5170", "#dbe6f5"),
    "review":   ("#3a1a1d", "#ef5d62", "#ffc7c5"),   # crimson (brighter border for dark)
    "noop":     ("#11302a", "#22c55e", "#a9efca"),   # green
    "widen":    ("#0f2738", "#38bdf8", "#bce3f7"),   # sky
    "create":   ("#33270f", "#fbbf24", "#f7d99a"),   # amber
    "note":     ("#15233b", "#3b82f6", "#bcd7f7"),   # advisory blue — "noted, not blocked; keep going"
    "terminal": ("#202c44", "#4a5a7d", "#aab6cf"),   # muted slate — an informational dead-end leaf
}

# Per-theme Mermaid look (fed via the %%{init}%% directive baked into the source, so the downloaded
# .mmd renders the same in GitHub / mermaid.live). classDef (above) still drives per-node colour.
# NB: we deliberately do NOT override fontFamily/fontSize — Mermaid measures label box widths with one
# font and would render with another, overflowing the box (clipped text). Mermaid's default font sizes
# the boxes correctly; we only theme the lines/labels/defaults (which don't affect text measurement).
_MM_THEME = {
    False: {  # light
        "lineColor": "#94a3b8", "edgeLabelBackground": "#ffffff",
        "primaryColor": "#f1f5f9", "primaryBorderColor": "#cbd5e1", "primaryTextColor": "#334155",
    },
    True: {   # dark
        "lineColor": "#5b6b86", "edgeLabelBackground": "#111a2b",
        "primaryColor": "#1b2536", "primaryBorderColor": "#33415c", "primaryTextColor": "#cdd9ea",
    },
}


# --- Mermaid -------------------------------------------------------------------------------------
# shape delimiters per kind: stadium for start, hexagons for decisions, rounded rects for the rest.
_MM_SHAPE = {"start": ('(["', '"])'), "process": ('["', '"]'), "decision": ('{{"', '"}}'),
             "review": ('("', '")'), "noop": ('("', '")'), "widen": ('("', '")'), "create": ('("', '")'),
             "note": ('>"', '"]'),    # a flag/note shape (asymmetric) — "advisory, keep going"
             "terminal": ('[["', '"]]')}    # a framed subroutine box — an informational dead-end leaf


def _mm_text(n: Node) -> str:
    # Wrap a long subtitle onto its own lines (at the '·' separators) so the node stays narrow and the
    # auto-layout doesn't overlap siblings. On-page Mermaid only — the .drawio/.dot exports keep the
    # single-line sub and wrap via their own canvases.
    sub = n.sub
    if len(sub) > 46 and "·" in sub:
        sub = "<br/>".join(p.strip() for p in sub.split("·"))
    txt = n.label + (f"<br/>{sub}" if sub else "")
    return txt.replace('"', "&quot;")


def _mm_init(dark: bool) -> str:
    cfg = {"theme": "base", "themeVariables": _MM_THEME[dark],
           "flowchart": {"curve": "basis", "nodeSpacing": 46, "rankSpacing": 52, "padding": 12,
                         "htmlLabels": True, "useMaxWidth": True}}
    return "%%{init: " + json.dumps(cfg, separators=(",", ":")) + "}%%"


def _mm_node_decl(n: Node) -> str:
    o, c = _MM_SHAPE[n.kind]
    return f"{n.id}{o}{_mm_text(n)}{c}"


def _mm_edge_decl(e: Edge) -> str:
    arrow = f" -->|{e.label}| " if e.label else " --> "
    return f"{e.src}{arrow}{e.dst}"


def _mm_classdefs(dark: bool) -> list[str]:
    pal = PALETTE_DARK if dark else PALETTE
    return [f"classDef {kind} fill:{fill},stroke:{stroke},color:{font},stroke-width:1.5px;"
            for kind, (fill, stroke, font) in pal.items()]


def to_mermaid(dark: bool = False, visible_ids: "set[str] | None" = None) -> str:
    """Mermaid flowchart with a baked-in %%{init}%% directive (theme + spacing) so it looks the same
    wherever it renders. ``dark`` picks the on-page (dark-canvas) palette; default light is for the .mmd
    download / GitHub / diagrams.net import. ``visible_ids`` (None = the WHOLE tree, used by the downloads
    and golden tests) restricts the emitted nodes — and any edge whose endpoints are both visible — so the
    on-page view can render a collapsed subset in the SAME format the client assembles incrementally."""
    nodes = [n for n in NODES if visible_ids is None or n.id in visible_ids]
    out = [_mm_init(dark), "flowchart TD"]
    out += [f"  {_mm_node_decl(n)}" for n in nodes]
    out.append("")
    for e in EDGES:
        if visible_ids is not None and not (e.src in visible_ids and e.dst in visible_ids):
            continue
        out.append(f"  {_mm_edge_decl(e)}")
    out.append("")
    out += [f"  {c}" for c in _mm_classdefs(dark)]
    grouped: dict[str, list[str]] = {}
    for n in nodes:
        grouped.setdefault(n.kind, []).append(n.id)
    for kind, ids in grouped.items():
        out.append(f"  class {','.join(ids)} {kind};")
    return "\n".join(out)


# The on-page collapse cuts the tree at this BFS depth: depths 0..DEFAULT_DEPTH show, deeper nodes are
# hidden behind a clickable "＋ N more" stub on their parent — expand step-by-step or "Expand all".
DEFAULT_DEPTH = 2


def _bfs_depth() -> dict:
    """Shortest-path depth of every node from the single start node (req=0). Drives the collapse: the
    tree is cut at DEFAULT_DEPTH and continues behind '＋ more' stubs."""
    start = next((n.id for n in NODES if n.kind == "start"), NODES[0].id if NODES else "")
    adj: dict = {}
    for e in EDGES:
        adj.setdefault(e.src, []).append(e.dst)
    depth = {start: 0}
    queue = [start]
    while queue:
        cur = queue.pop(0)
        for child in adj.get(cur, []):
            if child not in depth:
                depth[child] = depth[cur] + 1
                queue.append(child)
    return {n.id: depth.get(n.id, 0) for n in NODES}


def default_visible() -> set:
    """Node ids shown before the user expands anything — the CORE flow (level 0). Collapse is by detail
    TIER (Node.level), not BFS depth: the whole first-match spine (resolve → permitted? → deny? → widen?
    → create, plus the note-&-continue leaf and the outcome leaves) shows at once, and each DETAIL branch
    (identity matching, inline-layer recursion, automation modes, object materialisation) sits behind a
    '＋ N more' stub until expanded."""
    return {n.id for n in NODES if n.level == 0}


def to_graph() -> dict:
    """The tree as data for the on-page collapsible renderer: every node (its detail ``level`` + BFS
    ``depth`` + the pre-formatted Mermaid declaration) and edge, plus the per-theme %%{init}%% directive
    and classDefs. The client shows level 0, puts a '＋ more' stub where a visible node has hidden
    children, and reveals them on click. The Mermaid TEXT is still produced by THIS module's node/edge
    declarations (no format drift). Static engine metadata only (no request-derived data)."""
    depth = _bfs_depth()
    return {
        "start": next((n.id for n in NODES if n.kind == "start"), NODES[0].id if NODES else ""),
        "default_depth": DEFAULT_DEPTH,
        "nodes": [{"id": n.id, "kind": n.kind, "level": n.level, "depth": depth[n.id],
                   "label": n.label, "sub": n.sub, "x": n.x, "y": n.y, "w": n.w, "h": n.h,
                   "option": n.option, "mm": _mm_node_decl(n)} for n in NODES],
        "edges": [{"src": e.src, "dst": e.dst, "label": e.label, "mm": _mm_edge_decl(e)} for e in EDGES],
        "themes": {"dark":  {"init": _mm_init(True),  "classDefs": _mm_classdefs(True)},
                   "light": {"init": _mm_init(False), "classDefs": _mm_classdefs(False)}},
    }


# --- diagrams.net (.drawio / mxGraph XML) --------------------------------------------------------
def _attr(s: str) -> str:
    return _xescape(s, {'"': "&quot;"})


def _drawio_value(n: Node) -> str:
    # html=1 cell value: bold title + a smaller, muted sub-line. Escaped for the XML attribute.
    html = f"<b>{_xescape(n.label)}</b>"
    if n.sub:
        html += f'<br><span style="font-size:10px;color:#5b6573;">{_xescape(n.sub)}</span>'
    return _attr(html)


def to_drawio() -> str:
    cells: list[str] = []
    for n in NODES:
        fill, stroke, font = PALETTE[n.kind]
        shape = "rhombus;" if n.kind == "decision" else "rounded=1;"
        style = (f"{shape}whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};"
                 f"fontColor={font};align=center;verticalAlign=middle;spacing=6;arcSize=12;")
        cells.append(
            f'<mxCell id="{n.id}" value="{_drawio_value(n)}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{n.x}" y="{n.y}" width="{n.w}" height="{n.h}" as="geometry"/></mxCell>')
    for i, e in enumerate(EDGES):
        style = ("edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=block;endFill=1;"
                 "strokeColor=#8893a5;fontColor=#5b6573;fontSize=10;")
        cells.append(
            f'<mxCell id="e{i}" value="{_attr(e.label)}" style="{style}" edge="1" parent="1" '
            f'source="{e.src}" target="{e.dst}"><mxGeometry relative="1" as="geometry"/></mxCell>')
    body = "".join(cells)
    return (
        '<mxfile host="PolicyPilot" type="device">'
        '<diagram id="decision-tree" name="Access automation decision tree">'
        '<mxGraphModel dx="900" dy="900" grid="0" gridSize="10" guides="1" tooltips="1" connect="1" '
        'arrows="1" fold="1" page="1" pageScale="1" pageWidth="850" pageHeight="1169" math="0" shadow="0">'
        f'<root><mxCell id="0"/><mxCell id="1" parent="0"/>{body}</root>'
        '</mxGraphModel></diagram></mxfile>')


# --- Graphviz (.dot) -----------------------------------------------------------------------------
def to_dot() -> str:
    out = ["digraph decision {", "  rankdir=TB;",
           '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, margin="0.14,0.07"];',
           '  edge [fontname="Helvetica", fontsize=9, color="#8893a5", fontcolor="#5b6573"];']
    for n in NODES:
        fill, stroke, font = PALETTE[n.kind]
        shape = "diamond" if n.kind == "decision" else "box"
        label = (n.label + (f"\\n{n.sub}" if n.sub else "")).replace('"', '\\"')
        out.append(f'  {n.id} [label="{label}", shape={shape}, fillcolor="{fill}", color="{stroke}", '
                   f'fontcolor="{font}"];')
    for e in EDGES:
        lbl = f' [label="{e.label}"]' if e.label else ""
        out.append(f"  {e.src} -> {e.dst}{lbl};")
    out.append("}")
    return "\n".join(out)


RENDERERS = {
    "drawio": (to_drawio, "application/xml; charset=utf-8", "drawio"),
    "mmd":    (to_mermaid, "text/plain; charset=utf-8", "mmd"),
    "dot":    (to_dot, "text/vnd.graphviz; charset=utf-8", "dot"),
}
