"""Editing an existing Dynamic Layer: the builder renders in edit mode, and the content
parser builds + validates the submitted JSON (shared by create and update)."""
import datetime as dt
import json

import pytest

from app.routers.dynamic_layers import (
    DEFAULT_LAYER_CONTENT,
    _BUILDER_CTX,
    _parse_layer_content,
)
from app.routers.ui import templates
from app.schemas.dynamic_layer import (
    build_set_dynamic_content,
    evaluate_dynamic_content,
    referenced_object_names,
)


def _render(name, **ctx):
    ctx.setdefault("request", None)
    return templates.env.get_template(name).render(**ctx)


def _builder(**over):
    ctx = dict(_BUILDER_CTX)
    ctx.update({"action": "/layers/new", "is_edit": False, "cancel_url": "/layers",
                "error": None, "default_content": DEFAULT_LAYER_CONTENT, "gateways": [],
                "selected_gateway_id": "",
                "form": {"name": "L", "layer_name": "dynamic_layer", "description": "",
                         "comments": "", "tags": ""}})
    ctx.update(over)
    return ctx


def test_builder_edit_mode_posts_to_edit_and_returns_to_layer():
    html = _render("dynamic_new.html",
                   **_builder(action="/layers/5/edit", is_edit=True, cancel_url="/layers/5"))
    assert 'action="/layers/5/edit"' in html
    assert "Edit Dynamic Layer" in html and "Save changes" in html
    assert 'href="/layers/5"' in html  # Cancel returns to the layer, not the list


def test_builder_new_mode_unchanged():
    html = _render("dynamic_new.html", **_builder())
    assert 'action="/layers/new"' in html and "Save layer" in html


def test_builder_referenced_section_is_above_rules_and_not_optional():
    html = _render("dynamic_new.html", **_builder())
    assert html.index("Referenced objects") < html.index(">Rules<")  # referenced comes first
    assert "Referenced objects</h2>" in html  # the "(optional)" qualifier is gone


def test_parse_layer_content_builds_validates_and_coerces():
    c = _parse_layer_content(
        objects_json=json.dumps(DEFAULT_LAYER_CONTENT["objects"]),
        rules_json=json.dumps(DEFAULT_LAYER_CONTENT["rulebase"]),
        referenced_json="{}", comments="note", tags="a, b", gateway_id="3")
    assert c["operation"] == "replace"
    assert c["tags"] == ["a", "b"] and c["gateway_id"] == 3
    assert len(c["rulebase"]) == len(DEFAULT_LAYER_CONTENT["rulebase"]) and c["comments"] == "note"


def test_parse_layer_content_rejects_bad_json():
    with pytest.raises(Exception):
        _parse_layer_content(objects_json="{bad", rules_json="[]", referenced_json="{}",
                             comments="", tags="", gateway_id="")


class _DefaultLayer:
    layer_name = "dynamic_layer"
    content = DEFAULT_LAYER_CONTENT


def test_default_policy_ships_referenced_objects_used_by_rules():
    payload = build_set_dynamic_content(_DefaultLayer())
    refs = payload["referenced-objects"]
    assert "ssh" in refs.get("services-tcp", []) and "https" in refs.get("services-tcp", [])
    # at least one rule actually uses a referenced service name
    services = [r.get("service") for r in DEFAULT_LAYER_CONTENT["rulebase"]]
    assert any(isinstance(s, list) and "https" in s for s in services)
    # the default must apply on a plain Firewall layer — no applications/categories, which would
    # require the "Application & URL Filtering" blade to be enabled on the layer.
    assert "application-sites" not in refs and "application-site-categories" not in refs


def test_default_policy_validates_and_all_references_resolve():
    payload = build_set_dynamic_content(_DefaultLayer())
    result = evaluate_dynamic_content(payload)
    assert result["status"] == "succeeded"
    assert result["validation_warnings"] == []  # every name used in a rule resolves


def test_referenced_object_names_excludes_defined_and_builtins():
    objects = {"hosts": [{"name": "client", "ip-address": "10.0.0.5"}],
               "networks": [{"name": "lab_net", "subnet4": "10.0.0.0", "mask-length4": 24}]}
    rulebase = [
        {"name": "allow_web", "source": ["client"], "destination": ["lab_net"], "service": ["https", "ssh"]},
        {"name": "allow_fb", "source": "any", "destination": "any", "service": ["Facebook"]},
        {"name": "cleanup", "source": "any", "destination": "any", "service": "any"},
    ]
    names = referenced_object_names(
        objects, rulebase, {"services-tcp": ["ssh", "https"], "access-layers": ["dynamic_layer"]})
    # defined (client/lab_net), built-ins (any) and access-layers (the layer itself) are excluded
    assert names == ["Facebook", "https", "ssh"]


def test_referenced_object_names_empty_when_all_local_or_builtin():
    objects = {"hosts": [{"name": "h", "ip-address": "1.1.1.1"}]}
    rulebase = [{"name": "r", "source": ["h"], "destination": "any", "service": "any"}]
    assert referenced_object_names(objects, rulebase) == []


def test_layer_detail_renders_referenced_objects_under_rulebase():
    class _L:
        id, name, layer_name, description = 1, "L", "dynamic_layer", ""
        content = {"rulebase": [{"name": "allow_web", "source": ["client"],
                                 "destination": ["lab_net"], "service": ["https", "ssh"]}]}
    html = _render("dynamic_detail.html", layer=_L(), payload_json="{}", tasks=[], task_total=0,
                   latest=None, referenced=["Facebook", "https", "ssh"], gateways=[],
                   layer_gateway_id=None, mock_url="http://x/gaia_api/v1.9")
    assert "Referenced objects" in html
    assert "Facebook" in html and "https" in html and "ssh" in html


def test_gateway_view_macro_renders_referenced_objects():
    tmpl = templates.env.from_string(
        '{% import "_layers_view.html" as lv %}{{ lv.render_layers(layers) }}')
    html = tmpl.render(layers=[{"name": "dynamic_layer", "objects": {},
                                "rulebase": [{"name": "r", "action": "Accept"}],
                                "referenced": ["Facebook", "ssh"]}])
    assert "Referenced objects" in html and "Facebook" in html and "ssh" in html
    assert "2 referenced" in html  # the count badge on the layer card


def _task_obj(**kw):
    return type("T", (), kw)()


def test_layer_detail_merges_last_apply_and_links_to_history():
    class _L:
        id, name, layer_name, description = 5, "Demo", "dynamic_layer", ""
        content = {"objects": {"hosts": [{"name": "client", "ip-address": "10.0.0.5"}]},
                   "rulebase": [{"name": "allow_web", "source": ["client"],
                                 "destination": "any", "service": ["https"]}]}
    latest = {"t": _task_obj(status="succeeded", target="gateway", dry_run=False,
                             task_id="abcdef0123456789xyz", gateway_host="gw.example",
                             at=dt.datetime(2026, 6, 16, 23, 3, 14)),
              "rules_created": 1, "objects_created": ["client"], "layers": [],
              "warnings": [], "errors": [], "trace": []}
    html = _render("dynamic_detail.html", layer=_L(), payload_json="{}", task_total=7,
                   latest=latest, referenced=["https"], gateways=[], layer_gateway_id=None,
                   mock_url="http://x/gaia_api/v1.9")
    assert "last apply: succeeded" in html
    assert "/layers/5/history" in html and "apply history (7)" in html
    assert "client · 10.0.0.5" in html   # defined objects now shown in the merged card
    assert "Rules created" not in html   # the redundant created-list is gone


def test_history_page_lists_records_with_multidelete():
    views = [
        {"t": _task_obj(id=1, status="succeeded", target="gateway", dry_run=False,
                        at=dt.datetime(2026, 6, 16, 23, 3, 14)),
         "rules_created": 3, "objects_created": ["client", "lab_net"], "warnings": [], "errors": [], "trace": []},
        {"t": _task_obj(id=2, status="failed", target="gateway", dry_run=False,
                        at=dt.datetime(2026, 6, 16, 22, 25, 9)),
         "rules_created": 0, "objects_created": [], "warnings": [], "errors": [{"message": "blade not enabled"}], "trace": []},
    ]
    class _L:
        id, name = 5, "Demo"
    html = _render("dynamic_history.html", layer=_L(), tasks=views, flash=None)
    assert 'action="/layers/5/history/delete"' in html
    assert 'name="task_ids" value="1"' in html and 'name="task_ids" value="2"' in html
    assert "Delete selected" in html and "Select all (2)" in html
    assert "blade not enabled" in html   # the failed row surfaces its error


def test_history_page_empty_state_has_no_delete_form():
    class _L:
        id, name = 7, "Empty"
    html = _render("dynamic_history.html", layer=_L(), tasks=[], flash=None)
    assert "No applies recorded yet" in html and "task_ids" not in html
