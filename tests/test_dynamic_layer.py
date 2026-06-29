"""Unit tests for the Dynamic Layer payload builder + apply engine."""
import pytest

from app.schemas.dynamic_layer import (
    OBJECT_TYPES,
    build_set_dynamic_content,
    evaluate_dynamic_content,
    validate_layer_content,
)


class _Layer:
    def __init__(self, content: dict, layer_name: str = "dynamic_layer"):
        self.content = content
        self.layer_name = layer_name


def sample_content() -> dict:
    return {
        "operation": "replace",
        "comments": "demo",
        "objects": {
            "hosts": [{"name": "client", "ip-address": "10.0.0.5"}],
            "networks": [{"name": "random_net", "subnet4": "10.0.0.0", "mask-length4": 24}],
        },
        "rulebase": [
            {"name": "client_rule", "action": "Accept", "source": ["client"], "destination": ["random_net"]},
            {"name": "cleanup_rule", "action": "Accept", "source": "any", "destination": "any", "service": "any"},
        ],
        "referenced_objects": {},
    }


def test_full_object_coverage():
    assert len(OBJECT_TYPES) >= 14


def test_build_payload_structure():
    p = build_set_dynamic_content(_Layer(sample_content()), dry_run=True)
    assert p["dry-run"] is True
    assert p["objects"]["hosts"][0]["name"] == "client"
    layer = p["access-layers-content"][0]
    assert layer["name"] == "dynamic_layer" and layer["operation"] == "replace"
    assert len(layer["rulebase"]) == 2
    assert "dynamic_layer" in p["referenced-objects"]["access-layers"]


def test_evaluate_change_summary():
    r = evaluate_dynamic_content(build_set_dynamic_content(_Layer(sample_content())))
    assert r["status"] == "succeeded"
    layer = r["change_summary"]["layers"][0]
    assert layer["rules"]["create"] == ["client_rule", "cleanup_rule"]
    assert set(r["change_summary"]["objects"]["create"]) == {"client", "random_net"}
    assert r["validation_warnings"] == []
    assert r["validation_errors"] == []


def test_evaluate_warns_on_undefined_object():
    content = sample_content()
    content["rulebase"][0]["destination"] = ["ghost_net"]
    r = evaluate_dynamic_content(build_set_dynamic_content(_Layer(content)))
    assert any(w["object"] == "ghost_net" for w in r["validation_warnings"])


def test_evaluate_no_warning_for_referenced_object():
    content = sample_content()
    content["objects"] = {}
    content["rulebase"] = [{"name": "r", "action": "Accept", "service": ["Facebook"]}]
    content["referenced_objects"] = {"application-sites": ["Facebook"]}
    r = evaluate_dynamic_content(build_set_dynamic_content(_Layer(content)))
    assert r["validation_warnings"] == []


def test_evaluate_error_on_missing_action():
    content = sample_content()
    content["rulebase"][0].pop("action")
    r = evaluate_dynamic_content(build_set_dynamic_content(_Layer(content)))
    assert r["status"] == "failed"
    assert any("missing an action" in e["message"] for e in r["validation_errors"])


def test_validate_rejects_unknown_type():
    with pytest.raises(ValueError):
        validate_layer_content({"objects": {"bogus": [{"name": "x"}]},
                                "rulebase": [{"name": "r", "action": "Accept"}]})


def test_validate_requires_rules():
    with pytest.raises(ValueError):
        validate_layer_content({"objects": {}, "rulebase": []})


def test_validate_requires_action():
    with pytest.raises(ValueError):
        validate_layer_content({"objects": {}, "rulebase": [{"name": "r"}]})
