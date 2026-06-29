"""The decision-tree diagram exporters: structurally complete + valid Mermaid / .drawio / DOT,
and KEPT IN LOCK-STEP with the engine (the sync guards below go red if decide() grows an outcome or
the inline-layer / automation-mode branches lose their visual representation)."""
import xml.etree.ElementTree as ET

from app.services import decision_tree as dt
from app.services.access_automation import Outcome

# Every engine Outcome must map to a tree node KIND. The flow is reuse-or-create — it never stops for a
# POLICY review (a rule it can't reason past is noted & passed). Outcome.REVIEW is the rare case where the
# REQUEST ITSELF can't be resolved (empty/unparsable service, a typed endpoint naming no object); it IS
# depicted as the "review" node so the diagram covers every outcome the engine can return.
_OUTCOME_KIND = {Outcome.NO_OP: "noop", Outcome.WIDEN: "widen", Outcome.CREATE: "create",
                 Outcome.REVIEW: "review"}
_NON_FLOW_OUTCOMES: set = set()


def test_option_bound_nodes_map_to_real_settings():
    # The interactive editor turns option-tagged nodes into click-to-toggle pills. Each option must be a
    # real aa_* knob, and the 5 tunable decisions must stay tagged (so the editor keeps working).
    from app.services import app_settings
    keys = {s.key for s in app_settings.SETTINGS}
    g = dt.to_graph()
    tagged = {n["id"]: n["option"] for n in g["nodes"] if n.get("option")}
    assert tagged == {"noteO": "aa_emit_notes", "deny": "aa_override_blocking_deny",
                      "widen": "aa_prefer_widen", "create": "aa_app_carveout",
                      "opts": "aa_ignore_conditions"}
    for opt in tagged.values():
        assert opt in keys                              # every node option is a real setting


def test_edges_reference_real_nodes_and_outcomes_present():
    ids = {n.id for n in dt.NODES}
    for e in dt.EDGES:
        assert e.src in ids and e.dst in ids, (e.src, e.dst)
    kinds = {n.kind for n in dt.NODES}
    assert {"note", "noop", "widen", "create", "decision", "start", "process"} <= kinds


def test_mermaid_is_well_formed():
    m = dt.to_mermaid()
    assert m.startswith("%%{init:") and "flowchart TD" in m and '"theme":"base"' in m   # self-themed
    assert dt.to_mermaid(dark=True) != m                                       # dark variant differs
    for n in dt.NODES:
        assert f"  {n.id}" in m                      # every node declared
    assert "-->|yes|" in m and "-->|no|" in m         # labelled branches
    assert "classDef review" in m and "class " in m   # styling applied
    # the resolution sub-step is spelled out in the resolve node
    assert "exact" in m and "approx" in m and "identity" in m


def test_drawio_is_valid_xml_with_every_node_and_edge():
    x = dt.to_drawio()
    root = ET.fromstring(x)                            # must parse — malformed XML would raise
    assert root.tag == "mxfile"
    cells = {c.get("id") for c in root.iter("mxCell")}
    for n in dt.NODES:
        assert n.id in cells, n.id
    edge_cells = [c for c in root.iter("mxCell") if c.get("edge") == "1"]
    assert len(edge_cells) == len(dt.EDGES)
    # geometry present on a vertex
    v = next(c for c in root.iter("mxCell") if c.get("id") == "create")
    assert v.find("mxGeometry") is not None


def test_dot_is_well_formed():
    d = dt.to_dot()
    assert d.startswith("digraph decision {") and d.rstrip().endswith("}")
    assert "->" in d
    for n in dt.NODES:
        assert f"  {n.id} [" in d


def test_renderers_registry():
    assert set(dt.RENDERERS) == {"drawio", "mmd", "dot"}
    for fn, ctype, ext in dt.RENDERERS.values():
        assert callable(fn) and ctype and ext


# --- sync guards: the visual can't silently drift from decide() ----------------------------------
def test_every_engine_outcome_maps_to_a_tree_node_kind():
    # a NEW or renamed Outcome forces an update here (and a matching node) -> the suite goes red
    assert set(_OUTCOME_KIND) | _NON_FLOW_OUTCOMES == set(Outcome)
    kinds = {n.kind for n in dt.NODES}
    for outcome, kind in _OUTCOME_KIND.items():
        assert kind in kinds, f"no tree node represents Outcome.{outcome.name}"
    # reverse: no orphan outcome node kind left behind after an outcome is removed
    assert (kinds & {"noop", "widen", "create", "review"}) == set(_OUTCOME_KIND.values())


def test_all_nodes_reachable_from_a_single_start():
    starts = [n.id for n in dt.NODES if n.kind == "start"]
    assert len(starts) == 1, "the collapse BFS + the flow both need exactly one start node"
    adj: dict = {}
    for e in dt.EDGES:
        adj.setdefault(e.src, []).append(e.dst)
    seen, stack = set(), [starts[0]]
    while stack:
        x = stack.pop()
        if x in seen:
            continue
        seen.add(x)
        stack += adj.get(x, [])
    assert seen == {n.id for n in dt.NODES}, "node unreachable from start (orphaned in the diagram)"
    dsts = {e.dst for e in dt.EDGES}
    for n in dt.NODES:                                  # no drawn-but-unwired outcome leaf
        if n.kind in ("noop", "widen", "create", "review"):
            assert n.id in dsts, f"{n.id} is never reached by an edge"


def test_default_collapsed_view_shows_core_hides_detail():
    # collapse is by DETAIL TIER (Node.level): the whole core flow (level 0) shows; detail branches hide
    dv = dt.default_visible()
    allids = {n.id for n in dt.NODES}
    assert dv < allids, "nothing is collapsed — the level cut is missing"
    assert dv == {n.id for n in dt.NODES if n.level == 0}
    assert {"req", "resolve", "perm", "deny", "widen", "create", "noop", "noteO"} <= dv   # core flow shows
    assert not ({"kindq", "inline", "recurse", "opts", "apply", "idupd"} & dv)            # detail behind '+ more'


def test_bfs_depth_root_is_zero_and_all_reachable():
    depth = dt._bfs_depth()
    assert depth["req"] == 0 and all(d >= 0 for d in depth.values())
    assert set(depth) == {n.id for n in dt.NODES}                         # every node got a depth


def test_to_mermaid_visible_subset_filters_nodes_and_edges():
    dv = dt.default_visible()
    sub = dt.to_mermaid(dark=True, visible_ids=dv)
    assert "  inline" not in sub and "  recurse" not in sub              # collapsed nodes absent
    assert "applies an inline layer" not in sub                         # edge with a hidden endpoint dropped
    full = dt.to_mermaid(dark=True)
    assert "  recurse" in full and "applies an inline layer" in full    # the WHOLE tree (download) keeps all
    # subset output is still valid Mermaid in the SAME format
    assert sub.startswith("%%{init:") and "flowchart TD" in sub and "classDef review" in sub


def test_to_graph_is_client_consumable_and_matches_mermaid():
    g = dt.to_graph()
    assert g["start"] == "req" and g["default_depth"] == dt.DEFAULT_DEPTH
    assert {n["id"] for n in g["nodes"]} == {n.id for n in dt.NODES}
    assert all(set(n) >= {"id", "kind", "level", "depth", "mm"} for n in g["nodes"])   # level drives collapse
    assert {(e["src"], e["dst"]) for e in g["edges"]} == {(e.src, e.dst) for e in dt.EDGES}
    for theme in ("dark", "light"):
        assert g["themes"][theme]["init"].startswith("%%{init:") and g["themes"][theme]["classDefs"]
    # the pre-formatted node line is byte-identical to what to_mermaid emits (no JS/Python format drift)
    full = dt.to_mermaid(dark=True)
    for n in g["nodes"]:
        assert ("  " + n["mm"]) in full


def test_inline_layer_recursion_and_automation_mode_are_drawn():
    # guards the engine features that must stay represented in the visual. The inline branch is summarised
    # in ONE node (recurse); a split across layers is noted & continued (no review box). The remaining
    # automation knob (ignore-conditions) hangs off the deny decision.
    ids = {n.id for n in dt.NODES}
    assert {"inline", "recurse", "opts"} <= ids
    assert "odCreate" not in ids                                        # override-deny is gone (deny always creates above)
    edges = {(e.src, e.dst) for e in dt.EDGES}
    assert ("resolve", "inline") in edges                               # inline branch wired off resolve
    assert ("inline", "recurse") in edges                               # the recursion step
    assert ("deny", "opts") in edges                                    # the ignore-conditions automation mode
    assert "ignore-conditions" in (next(n for n in dt.NODES if n.id == "opts").label.lower())
    recurse = next(n for n in dt.NODES if n.id == "recurse")
    assert "inline" in (recurse.label + recurse.sub).lower()


def test_detail_branch_is_self_contained_no_cross_edges():
    # the inline-layer + automation-mode + typed-matching + materialisation detail must terminate in its
    # OWN leaves, never draw an edge back to a CORE (level-0) leaf — those cross-edges tangle the diagram.
    level = {n.id: n.level for n in dt.NODES}
    for e in dt.EDGES:
        if level.get(e.src, 0) >= 1:                  # an edge leaving a detail node...
            assert level.get(e.dst, 0) >= 1, f"detail edge {e.src}->{e.dst} reaches a core node"


# --- sync guards for the typed (non-IP) source/destination framework -----------------------------
def test_typed_object_matching_branch_is_drawn():
    # the identity-space matching detail must stay represented (mirrors the inline-layer guard)
    ids = {n.id for n in dt.NODES}
    assert {"kindq", "ipspace", "idspace", "iddomain", "idexact", "iddisjoint", "idupd"} <= ids
    edges = {(e.src, e.dst) for e in dt.EDGES}
    assert ("resolve", "kindq") in edges                 # branched off the resolve step
    assert ("kindq", "ipspace") in edges and ("kindq", "idspace") in edges   # the IP vs identity fork
    assert ("idspace", "iddomain") in edges and ("idspace", "iddisjoint") in edges
    assert ("iddomain", "idupd") in edges                # domain-vs-updatable -> note & continue (not a stop)
    idupd = next(n for n in dt.NODES if n.id == "idupd")
    assert idupd.kind == "note"


def test_object_materialisation_branch_is_drawn():
    ids = {n.id for n in dt.NODES}
    assert {"apply", "matIP", "matMk", "matReuse", "matMissing"} <= ids
    edges = {(e.src, e.dst) for e in dt.EDGES}
    assert ("create", "apply") in edges and ("doWiden", "apply") in edges   # off both write outcomes
    assert ("apply", "matIP") in edges and ("apply", "matMk") in edges and ("apply", "matReuse") in edges
    assert ("matReuse", "matMissing") in edges           # reuse-only-missing -> a note (define it first)
    assert next(n for n in dt.NODES if n.id == "matMissing").kind == "note"   # not a crimson review


def test_every_typed_request_kind_is_named_in_the_tree():
    # adding a new typed kind to the engine (access_automation.TYPED_KINDS) forces a tree update here:
    # each kind must surface somewhere in the diagram text, so the visual can't silently omit a feature.
    from app.services import access_automation as aa
    text = " ".join((n.label + " " + n.sub) for n in dt.NODES).lower()
    keyword = {"domain": "domain", "access-role": "role", "dynamic-object": "dynamic",
               "updatable-object": "updatable", "security-zone": "zone"}
    assert set(keyword) == set(aa.TYPED_KINDS), "a typed kind has no keyword mapping — update this guard"
    for kind, kw in keyword.items():
        assert kw in text, f"typed kind {kind!r} ({kw!r}) is not represented in the decision tree"


def test_opaque_rules_note_and_continue_is_drawn():
    # the engine NOTES opaque rules and CONTINUES (no hard REVIEW stop). The diagram must show that — a
    # 'note' kind node + the resolve -> note -> perm "continue" path + the domain-vs-updatable case as a
    # note. A regression that re-introduced a hard REVIEW for opaque rules would fail this guard.
    ids = {n.id for n in dt.NODES}
    assert "note" in {n.kind for n in dt.NODES}, "no 'note' node — the note+continue behaviour isn't drawn"
    assert {"noteO", "idupd"} <= ids
    assert all(n.kind == "note" for n in dt.NODES if n.id in ("noteO", "idupd"))
    edges = {(e.src, e.dst) for e in dt.EDGES}
    assert ("resolve", "noteO") in edges and ("noteO", "perm") in edges     # noted, then continues the walk
    resolve = next(n for n in dt.NODES if n.id == "resolve")
    assert "continue" in resolve.sub.lower()                                # advertises continue, not review
    note = next(n for n in dt.NODES if n.id == "noteO")
    assert "note" in (note.label + note.sub).lower() and note.kind == "note"
