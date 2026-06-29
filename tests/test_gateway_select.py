"""Apply/fetch resolve connection details from the selected saved gateway, not from form fields."""
from app.routers.dynamic_layers import _gateway_error


class _GW:
    def __init__(self, name="GW", username="admin"):
        self.name, self.username = name, username


def test_gateway_error_requires_a_selection():
    assert "Select a saved gateway" in _gateway_error(None, "pw")


def test_gateway_error_requires_username_on_the_profile():
    assert "no username" in _gateway_error(_GW(username=""), "pw")


def test_gateway_error_requires_a_password():
    assert "password" in _gateway_error(_GW(), "")


def test_gateway_error_none_when_complete():
    assert _gateway_error(_GW(), "pw") is None
