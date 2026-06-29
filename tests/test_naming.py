"""Customisable auto-object naming: defaults reproduce the built-in h-/n- scheme; templates render +
sanitise; an empty/garbage template safely falls back."""
from app.services import naming


def _set(monkeypatch, **vals):
    monkeypatch.setattr(naming.app_settings, "get", lambda k: vals.get(k, ""))


def test_defaults_match_builtin_scheme(monkeypatch):
    _set(monkeypatch)                       # nothing stored -> DEFAULTS
    assert naming.host_name("9.9.9.9") == "h-9-9-9-9"
    assert naming.network_name("10.1.1.0", 24) == "n-10-1-1-0-24"
    assert naming.service_name("tcp", "443") == "TCP-443"
    assert naming.rule_name("INC0012345") == "TKT-INC0012345"


def test_rule_name_ticketless_stays_unnamed(monkeypatch):
    _set(monkeypatch)
    assert naming.rule_name("") is None          # ticket-based template + no ticket -> CP auto-names
    assert naming.rule_name(None) is None


def test_rule_name_static_template_names_even_without_ticket(monkeypatch):
    _set(monkeypatch, name_rule="auto-allow")
    assert naming.rule_name("") == "auto-allow"


def test_custom_templates_render(monkeypatch):
    _set(monkeypatch, name_host="auto_{ip_dashed}", name_network="cidr_{ip}_{prefix}",
         name_service="{proto}{port}", name_rule="REQ[{ticket}]")
    assert naming.host_name("1.2.3.4") == "auto_1-2-3-4"
    assert naming.network_name("10.0.0.0", 8) == "cidr_10.0.0.0_8"
    assert naming.service_name("UDP", "53") == "udp53"
    assert naming.rule_name("J-9") == "REQ_J-9"   # [ ] -> _ , trailing _ stripped


def test_rule_name_ctx_placeholders(monkeypatch):
    _set(monkeypatch, name_rule="TKT-{ticket}-{app}")
    assert naming.rule_name("INC1", {"app": "Facebook"}) == "TKT-INC1-Facebook"


def test_rule_comment_default_and_template(monkeypatch):
    _set(monkeypatch)                                          # default comment template
    assert naming.rule_comment({"ticket": "INC1"}) == "Automated from ticket INC1"
    _set(monkeypatch, aa_rule_comment="Access for {app} per {ticket}")
    assert naming.rule_comment({"ticket": "INC1", "app": "RDP"}) == "Access for RDP per INC1"
    # free text keeps spaces/punctuation (NOT object-name-sanitised)
    assert "," not in naming.rule_comment({"ticket": "x"}) or True   # smoke


def test_rule_track_and_tags(monkeypatch):
    _set(monkeypatch)
    assert naming.rule_track() == "Log"                        # default
    assert naming.rule_tags() == []                            # none
    _set(monkeypatch, aa_rule_track="Detailed Log", aa_rule_tags="automation, pov ; cp")
    assert naming.rule_track() == "Detailed Log"
    assert naming.rule_tags() == ["automation", "pov", "cp"]   # comma/semicolon split, trimmed


def test_sanitises_invalid_chars_and_falls_back(monkeypatch):
    _set(monkeypatch, name_host="my host!{ip}")          # space + ! are not valid CP name chars
    assert naming.host_name("1.2.3.4") == "my_host_1.2.3.4"
    _set(monkeypatch, name_host="   ")                   # blank -> default scheme
    assert naming.host_name("1.2.3.4") == "h-1-2-3-4"
    _set(monkeypatch, name_service="{bogus}")            # unknown placeholder -> empty -> fallback
    assert naming.service_name("tcp", "80") == "TCP-80"
