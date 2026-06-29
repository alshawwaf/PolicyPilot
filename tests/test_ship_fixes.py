"""Regression tests for v1.0.0 ship-hardening fixes."""
import logging

import pytest

import app.main as main
from app.schemas.dynamic_layer import validate_layer_content


def test_setup_logging_tolerates_bad_level(monkeypatch):
    # An invalid DCSIM_LOG_LEVEL must NOT abort boot — fall back to INFO; numeric strings are honored.
    monkeypatch.setenv("DCSIM_LOG_LEVEL", "VERBOSE")
    main._setup_logging()                                  # must not raise
    assert logging.getLogger("dcsim").level == logging.INFO
    monkeypatch.setenv("DCSIM_LOG_LEVEL", "10")
    main._setup_logging()
    assert logging.getLogger("dcsim").level == 10


def test_validate_layer_content_non_list_value_is_friendly():
    # A scalar value for an object type yields a clean ValueError, not a raw TypeError.
    with pytest.raises(ValueError, match="must be a JSON list"):
        validate_layer_content({"objects": {"hosts": 5}, "rulebase": [{"name": "r", "action": "Accept"}]})


def test_validate_layer_content_accepts_normal_shape():
    # control: a well-formed layer validates cleanly.
    validate_layer_content({
        "objects": {"hosts": [{"name": "h1", "ipv4-address": "10.0.0.1"}]},
        "rulebase": [{"name": "allow", "action": "Accept"}],
    })
