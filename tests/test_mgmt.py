"""Management web_api client: rulebase structuring + UID→name resolution (no live SMS needed)."""
import types

from app.services import app_settings, mgmt_api, mgmt_export


class _Resp:
    def __init__(self, code, body):
        self.status_code = code
        self._body = body

    def json(self):
        return self._body


def _settings(**over):
    vals = app_settings.defaults()
    vals.update(over)
    return lambda key: vals[key]


def _srv(**kw):
    base = {"id": 1, "host": "h", "port": 443, "domain": "", "username": "u", "cert_pem": ""}
    base.update(kw)
    return types.SimpleNamespace(**base)


class _RawSess:
    """Fake read session for the policy-cache tests: serves a one-page rulebase + a controllable
    published-revision token, and records the commands it receives."""

    def __init__(self, token="rev-1"):
        self.token = token
        self.calls = []

    def call(self, command, payload=None, **k):
        self.calls.append(command)
        if command == "show-sessions":
            return {"objects": [{"uid": "s1", "publish-time": {"posix": self.token}}]}
        if command == "show-access-rulebase":
            if (payload or {}).get("offset", 0) == 0:
                return {"rulebase": [{"type": "access-rule", "uid": "r1"}],
                        "objects-dictionary": [{"uid": "o1", "name": "x"}], "total": 1, "to": 1}
            return {"rulebase": [], "total": 1, "to": 1}
        return {}

OBJDICT = {
    "u-any": {"uid": "u-any", "name": "Any", "type": "CpmiAnyObject"},
    "u-net": {"uid": "u-net", "name": "dmz-net", "type": "network"},
    "u-web": {"uid": "u-web", "name": "web-srv", "type": "host"},
    "u-https": {"uid": "u-https", "name": "https", "type": "service-tcp"},
    "u-accept": {"uid": "u-accept", "name": "Accept", "type": "RulebaseAction"},
    "u-drop": {"uid": "u-drop", "name": "Drop", "type": "RulebaseAction"},
    "u-log": {"uid": "u-log", "name": "Log", "type": "Track"},
}

ITEMS = [
    {"type": "access-section", "name": "Web", "rulebase": [
        {"type": "access-rule", "rule-number": 1, "name": "Allow web", "enabled": True,
         "source": ["u-net"], "destination": ["u-web"], "service": ["u-https"],
         "action": "u-accept", "track": {"type": "u-log"}},
    ]},
    {"type": "access-rule", "rule-number": 2, "name": "Cleanup", "enabled": False,
     "source": ["u-any"], "destination": ["u-any"], "service": ["u-any"],
     "action": "u-drop", "track": {"type": "u-log"}, "source-negate": True},
    {"type": "place-holder", "name": "weird-thing"},   # unknown type → passthrough, never crash
]


def test_structure_resolves_uids_sections_and_negate():
    rows = mgmt_api._structure_rulebase(ITEMS, OBJDICT)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["section", "rule", "rule", "other"]

    section, allow, cleanup, other = rows
    assert section["name"] == "Web"

    assert allow["name"] == "Allow web" and allow["enabled"] is True
    assert allow["source"] == ["dmz-net"] and allow["destination"] == ["web-srv"]
    assert allow["service"] == ["https"] and allow["action"] == "Accept" and allow["track"] == "Log"
    assert allow["source_negate"] is False

    assert cleanup["enabled"] is False and cleanup["action"] == "Drop"
    assert cleanup["source"] == ["Any"] and cleanup["source_negate"] is True

    assert other["type"] == "place-holder"   # unknown item flagged, not dropped or crashing


def test_obj_names_handles_uids_and_inline_dicts():
    assert mgmt_api._obj_names(["u-web", {"name": "inline-host"}], OBJDICT) == ["web-srv", "inline-host"]
    assert mgmt_api._obj_names(["u-missing"], OBJDICT) == ["u-missing"]   # unresolved UID → shown raw
    assert mgmt_api._one_name("u-accept", OBJDICT) == "Accept"
    assert mgmt_api._one_name({"name": "Reject"}, OBJDICT) == "Reject"


# --- IaC export (mgmt_export.generate) ------------------------------------------------------

EXPORT_BUNDLE = {
    "layer": "Network",
    "objects_by_type": {
        # host carries the full surface: ipv4, color/comments/tags (common), and a NAT nested block
        "host": [{"uid": "u-web", "name": "web-srv", "type": "host", "ipv4-address": "10.0.0.5",
                  "color": "red", "comments": "web tier", "domain": {"domain-type": "domain"},
                  "tags": [{"name": "prod"}, {"name": "dmz"}],
                  "nat-settings": {"auto-rule": True, "method": "static", "ipv4-address": "1.2.3.4"}}],
        "network": [{"uid": "u-net", "name": "dmz-net", "type": "network",
                     "subnet4": "10.0.0.0", "mask-length4": 24, "color": "black"}],
        "group": [{"uid": "u-grp", "name": "web-grp", "type": "group", "members": [{"name": "web-srv"}]}],
        # service-tcp with a bool field + an aggressive-aging nested block
        "service-tcp": [{"uid": "u-svc", "name": "tcp-8443", "type": "service-tcp", "port": "8443",
                         "match-for-any": False,
                         "aggressive-aging": {"enable": True, "timeout": 600, "use-default-timeout": False}}],
        "vpn-community-meshed": [{"uid": "u-vpn", "name": "MyMesh", "type": "vpn-community-meshed"}],  # unsupported
    },
    "rules": [
        {"kind": "section", "name": "Web"},
        {"kind": "rule", "number": 1, "name": "Allow web", "enabled": True,
         "source": ["web-grp"], "destination": ["web-srv"], "service": ["tcp-8443"],
         "vpn": ["MyMesh"], "content": ["Credit Card Numbers"], "content_direction": "any",
         "time": ["WorkHours"], "install_on": ["gw1"], "custom_fields": {"field-1": "ticket-123"},
         "track_full": {"type": "Log", "accounting": True, "per_connection": False,
                        "per_session": False, "enable_firewall_session": False, "alert": ""},
         "action": "Accept", "track": "Log", "comments": "ok",
         "source_negate": False, "destination_negate": False, "service_negate": False},
        {"kind": "rule", "number": 2, "name": "Cleanup", "enabled": False,
         "source": [], "destination": [], "service": [], "vpn": [],
         "action": "Drop", "track": "None", "source_negate": True},
    ],
}


def test_export_stats_count_and_skip_unknown_types():
    art = mgmt_export.generate(EXPORT_BUNDLE)
    s = art["stats"]
    assert s["objects"] == 4 and s["rules"] == 2 and s["sections"] == 1
    assert s["skipped"] == {"vpn-community-meshed": 1}   # unknown type counted, never crashes


def test_export_terraform_resources_refs_and_rule_cells():
    tf = mgmt_export.generate(EXPORT_BUNDLE)["terraform"]
    assert 'resource "checkpoint_management_host" "web_srv"' in tf
    assert 'ipv4_address = "10.0.0.5"' in tf
    assert "mask_length4 = 24" in tf                    # int rendered bare, not quoted
    # group members + rule cells resolve to real resource addresses (dependency wiring)
    assert "members = [checkpoint_management_host.web_srv.name]" in tf
    assert "source = [checkpoint_management_group.web_grp.name]" in tf
    assert 'action = "Accept"' in tf and 'type = "Log"' in tf
    assert 'source = ["Any"]' in tf                     # empty cleanup cell → Any
    assert "enabled = false" in tf and "source_negate = true" in tf
    assert "depends_on = [checkpoint_management_access_section.sec_web]" in tf  # order chain


def test_export_terraform_carries_all_supported_fields():
    """Common fields + nested blocks must round-trip into Terraform."""
    tf = mgmt_export.generate(EXPORT_BUNDLE)["terraform"]
    assert 'color = "red"' in tf and 'comments = "web tier"' in tf
    assert 'tags = ["prod", "dmz"]' in tf
    assert "nat_settings {" in tf and "auto_rule = true" in tf and 'method = "static"' in tf
    assert "aggressive_aging {" in tf and "timeout = 600" in tf and "use_default_timeout = false" in tf
    assert "match_for_any = false" in tf                # a bool that is False is still emitted


def test_export_rule_carries_all_columns():
    """A faithful rulebase backup must carry content / time / install-on / custom-fields / full track
    / vpn across all three targets."""
    art = mgmt_export.generate(EXPORT_BUNDLE)
    tf, ans, cli = art["terraform"], art["ansible"], art["mgmt_cli"]
    # Terraform
    assert 'vpn_communities = ["MyMesh"]' in tf            # TF models a community list as vpn_communities
    assert 'content = ["Credit Card Numbers"]' in tf and 'content_direction = "any"' in tf
    assert 'time = ["WorkHours"]' in tf and 'install_on = ["gw1"]' in tf
    assert "custom_fields {" in tf and 'field_1 = "ticket-123"' in tf
    assert "accounting = true" in tf                       # full track settings, not just type
    # Ansible
    assert 'vpn: ["MyMesh"]' in ans and 'content: ["Credit Card Numbers"]' in ans
    assert 'time: ["WorkHours"]' in ans and "accounting: true" in ans
    assert "custom_fields:" in ans and 'field_1: "ticket-123"' in ans
    # mgmt_cli
    assert "content.1 'Credit Card Numbers'" in cli and "vpn.1 'MyMesh'" in cli
    assert "time.1 'WorkHours'" in cli and "install-on.1 'gw1'" in cli
    assert "custom-fields.field-1 'ticket-123'" in cli and "track-settings.accounting true" in cli


def test_export_new_object_types():
    """The object types added from the OpenAPI spec render across all three targets."""
    bundle = {"layer": "L", "rules": [], "objects_by_type": {
        "service-icmp6": [{"uid": "u1", "name": "icmp6-echo", "type": "service-icmp6",
                           "icmp-type": 128, "icmp-code": 0}],
        "application-site": [{"uid": "u2", "name": "MyApp", "type": "application-site",
                              "primary-category": "Custom", "url-list": ["x.com", "y.com"],
                              "urls-defined-as-regular-expression": False}],
        "time-group": [{"uid": "u3", "name": "WorkTimes", "type": "time-group",
                        "members": [{"name": "WorkHours"}]}],
    }}
    art = mgmt_export.generate(bundle)
    tf, ans, cli = art["terraform"], art["ansible"], art["mgmt_cli"]
    assert 'resource "checkpoint_management_service_icmp6" "icmp6_echo"' in tf and "icmp_type = 128" in tf
    assert 'resource "checkpoint_management_application_site" "myapp"' in tf
    assert 'url_list = ["x.com", "y.com"]' in tf and 'primary_category = "Custom"' in tf
    assert "check_point.mgmt.cp_mgmt_time_group:" in ans and 'mgmt_cli add application-site' in cli
    assert art["stats"]["objects"] == 3 and art["stats"]["skipped"] == {}


def test_export_web_api_ops():
    """The web_api target is a replayable JSON op list (POST /web_api/<command> bodies + publish)."""
    import json as _json
    ops = _json.loads(mgmt_export.generate(EXPORT_BUNDLE)["web_api"])
    cmds = [o["command"] for o in ops]
    assert "add-host" in cmds and "add-access-rule" in cmds and cmds[-1] == "publish"
    host = next(o for o in ops if o["command"] == "add-host")
    assert host["body"]["name"] == "web-srv" and host["body"]["ipv4-address"] == "10.0.0.5"
    assert host["body"]["nat-settings"]["method"] == "static"   # nested body carried through
    rule = next(o for o in ops if o["command"] == "add-access-rule")
    assert rule["body"]["layer"] == "Network" and rule["body"]["action"] == "Accept"
    assert rule["body"]["content"] == ["Credit Card Numbers"]   # full rule columns in the JSON body


def test_export_predefined_objects_are_referenced_not_emitted():
    tf = mgmt_export.generate(EXPORT_BUNDLE)["terraform"]
    assert mgmt_export.is_predefined({"type": "host", "domain": {"domain-type": "data domain"}})
    assert mgmt_export.is_predefined({"name": "Any", "type": "CpmiAnyObject"})
    assert not mgmt_export.is_predefined({"name": "web-srv", "type": "host",
                                          "domain": {"domain-type": "domain"}})


def test_export_ansible_and_mgmt_cli_shape():
    art = mgmt_export.generate(EXPORT_BUNDLE)
    ans, cli = art["ansible"], art["mgmt_cli"]
    assert "check_point.mgmt.cp_mgmt_host:" in ans and "state: present" in ans
    assert "check_point.mgmt.cp_mgmt_access_rule:" in ans and "position: bottom" in ans
    assert "check_point.mgmt.cp_mgmt_publish:" in ans
    # nested NAT renders as a YAML sub-block in Ansible and dotted params in mgmt_cli
    assert "nat_settings:" in ans and "auto_rule: true" in ans
    assert "mgmt_cli add host name 'web-srv' ipv4-address '10.0.0.5'" in cli
    assert "nat-settings.method 'static'" in cli and "tags.1 'prod'" in cli
    assert "mgmt_cli add access-rule layer 'Network' position bottom" in cli
    assert "mgmt_cli publish -s id.txt" in cli


def test_list_access_layers_reads_the_access_layers_key():
    """Regression: show-access-layers returns its list under 'access-layers', not the usual 'objects'.
    The response below has an empty 'objects' (what the old code wrongly read) and the real layers
    under 'access-layers' — the count must come from the latter."""
    s = mgmt_api.MgmtSession.__new__(mgmt_api.MgmtSession)   # skip __init__ → no real httpx client
    seen = {}

    def fake_call(command, payload=None):
        seen["command"] = command
        return {"objects": [], "access-layers": [{"name": "Network", "uid": "u1"},
                                                 {"name": "App Control", "uid": "u2"}],
                "total": 2, "to": 2}

    s.call = fake_call
    layers = s.list_access_layers()
    assert seen["command"] == "show-access-layers"
    assert [l["name"] for l in layers] == ["Network", "App Control"]


def test_export_collect_objects_recurses_groups_and_skips_predefined():
    objdict = {
        "u-grp": {"uid": "u-grp", "name": "g", "type": "group",
                  "members": [{"uid": "u-h", "name": "h", "type": "host", "ipv4-address": "1.1.1.1"}]},
        "u-any": {"uid": "u-any", "name": "Any", "type": "CpmiAnyObject"},
    }
    by_type = mgmt_api._collect_export_objects(objdict)
    assert "host" in by_type and by_type["host"][0]["name"] == "h"   # nested member pulled up
    assert "group" in by_type
    assert "CpmiAnyObject" not in by_type                            # predefined dropped


# --- writes: build_set_rule_op + apply_changes (Phase 4) ------------------------------------

def _fake_session(rec, fail_on=None):
    """A stand-in for MgmtSession that records calls instead of hitting a server."""
    class FS:
        def __init__(self, server, secret, timeout=30.0, **kwargs):
            self.trace = []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def call(self, command, payload=None, **kwargs):
            rec["calls"].append((command, payload))
            if fail_on and command == fail_on:
                raise mgmt_api.MgmtError("server said no")
            return {}

        def publish(self):
            rec["calls"].append(("publish", {}))

        def discard(self):
            rec["calls"].append(("discard", {}))
    return FS


# --- session reuse pool + read-only login + expiry re-login (the login-storm fix) ------------
def _capture_login(**kw):
    s = mgmt_api.MgmtSession(_srv(), "pw", **kw)
    captured = {}

    def fake_post(url, json=None, headers=None):
        captured.update(json or {})
        return _Resp(200, {"sid": "x"})

    s._client = types.SimpleNamespace(post=fake_post, close=lambda: None)
    s.login()
    return captured


def test_login_sends_read_only_and_session_timeout():
    c = _capture_login(read_only=True, session_timeout=3600)
    assert c.get("read-only") is True and c.get("session-timeout") == 3600


def test_login_readonly_omits_session_description():
    # CP rejects session-name/-comments/-description in read-only mode (HTTP 400) -> must NOT be sent
    c = _capture_login(read_only=True, session_timeout=3600, session_description="DC-Sim portal (read-only)")
    assert c.get("read-only") is True and "session-description" not in c


def test_login_readwrite_includes_session_description():
    c = _capture_login(session_description="DC-Sim portal (apply)")
    assert "read-only" not in c and c.get("session-description") == "DC-Sim portal (apply)"


def test_read_session_pools_one_login_across_calls(monkeypatch):
    mgmt_api.close_pool()
    monkeypatch.setattr(app_settings, "get", _settings())
    logins = []

    class FakeSess:
        _client = types.SimpleNamespace(close=lambda: None)

        def __init__(self, server, secret, **kw):
            self.kw = kw
            self.sid = None
            self.trace = []

        def login(self):
            logins.append(self.kw)
            self.sid = "x"

        def keepalive(self):
            self.trace.append("keepalive")

        def call(self, command, payload=None, **k):
            self.trace.append(command)
            return {}

        def logout(self):
            self.sid = None

    monkeypatch.setattr(mgmt_api, "MgmtSession", FakeSess)
    srv = _srv(id=101)
    for _ in range(3):
        with mgmt_api.read_session(srv, "s") as sess:
            sess.call("show-access-layers")
    assert len(logins) == 1                          # logged in ONCE, reused for all 3 reads
    assert logins[0].get("read_only") is True        # and it's a read-only session
    mgmt_api.close_pool()


def test_read_session_reuse_off_logs_in_each_time(monkeypatch):
    mgmt_api.close_pool()
    monkeypatch.setattr(app_settings, "get", _settings(mgmt_session_reuse=False))
    logins = []

    class FakeSess:
        _client = types.SimpleNamespace(close=lambda: None)

        def __init__(self, server, secret, **kw):
            self.sid = None
            self.trace = []

        def login(self):
            logins.append(1)
            self.sid = "x"

        def __enter__(self):
            self.login()
            return self

        def __exit__(self, *a):
            return False

        def call(self, command, payload=None, **k):
            return {}

        def logout(self):
            self.sid = None

    monkeypatch.setattr(mgmt_api, "MgmtSession", FakeSess)
    srv = _srv(id=102)
    for _ in range(2):
        with mgmt_api.read_session(srv, "s") as sess:
            sess.call("x")
    assert len(logins) == 2                           # reuse disabled -> a login per request


def test_call_relogins_once_on_expired_session():
    s = mgmt_api.MgmtSession(_srv(), "pw", auto_relogin=True)
    s.sid = "stale"
    posts = []

    def fake_post(url, json=None, headers=None):
        posts.append(url)
        if url.endswith("/login"):
            return _Resp(200, {"sid": "fresh"})
        if len([p for p in posts if p.endswith("/show-x")]) == 1:
            return _Resp(401, {"message": "session expired"})   # first call: expired
        return _Resp(200, {"ok": 1})                            # after re-login: ok

    s._client = types.SimpleNamespace(post=fake_post, close=lambda: None)
    assert s.call("show-x") == {"ok": 1}
    assert sum(1 for p in posts if p.endswith("/login")) == 1   # re-logged in exactly once
    assert s.sid == "fresh"


def test_call_wraps_transport_error_as_mgmterror():
    # ship-audit HIGH: a mid-session transport drop must surface as a clean MgmtError (not a raw httpx
    # error that escapes to a 500), so the mgmt router / REST tools render an error, not a stack trace.
    import httpx
    s = mgmt_api.MgmtSession(_srv(), "pw")
    s.sid = "live"

    def boom(*a, **k):
        raise httpx.ConnectError("connection reset by peer")

    s._client = types.SimpleNamespace(post=boom, close=lambda: None)
    try:
        s.call("show-access-rulebase")
        assert False, "expected MgmtError"
    except mgmt_api.MgmtError as e:
        assert "lost connection" in str(e).lower()


def test_write_session_does_not_silently_relogin():
    s = mgmt_api.MgmtSession(_srv(), "pw")           # auto_relogin defaults False (write session)
    s.sid = "stale"

    def fake_post(url, json=None, headers=None):
        return _Resp(401, {"message": "session expired"})

    s._client = types.SimpleNamespace(post=fake_post, close=lambda: None)
    try:
        s.call("set-access-rule")
        assert False, "expected MgmtError"
    except mgmt_api.MgmtError:
        pass


# --- write-session pool (amortise the apply login across a burst; fixes the SMS login throttle) -------
class _FakeWrite:
    """A fake read-write MgmtSession for the write-pool tests. ``keepalive`` (the pool's liveness probe)
    goes through ``call`` like the real session. Records its commands; tracks every instance created."""
    instances: list = []

    def __init__(self, server, secret, **kw):
        self.kw = kw
        self.sid = None
        self.trace = []
        self.calls: list = []
        self._client = types.SimpleNamespace(close=lambda: None)
        self.fail_keepalive = False
        _FakeWrite.instances.append(self)

    def login(self):
        self.calls.append("login")
        self.sid = "sid"

    def call(self, command, payload=None, **k):
        self.calls.append(command)
        if command == "keepalive" and self.fail_keepalive:
            raise mgmt_api.MgmtError("session expired")
        return {}

    def discard(self):
        self.calls.append("discard")
        return {}

    def logout(self):
        self.calls.append("logout")
        self.sid = None

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, *a):
        self.logout()
        return False


def test_write_session_pools_one_login_across_applies(monkeypatch):
    mgmt_api.close_write_pool()
    _FakeWrite.instances = []
    monkeypatch.setattr(app_settings, "get", _settings())
    monkeypatch.setattr(mgmt_api, "MgmtSession", _FakeWrite)
    srv = _srv(id=201)
    for _ in range(3):
        with mgmt_api.write_session(srv, "s") as s:
            s.call("add-access-rule")
            s.call("publish")
    assert len(_FakeWrite.instances) == 1                          # ONE session reused for all 3 applies
    inst = _FakeWrite.instances[0]
    assert inst.calls.count("login") == 1                          # logged in once (throttle-safe)
    assert inst.calls.count("keepalive") == 2                      # liveness-probed on reuse (applies 2, 3)
    assert inst.calls.count("discard") == 3                        # defensive clean after each apply
    mgmt_api.close_write_pool()


def test_write_session_reuse_off_logs_in_each_apply(monkeypatch):
    mgmt_api.close_write_pool()
    _FakeWrite.instances = []
    monkeypatch.setattr(app_settings, "get", _settings(mgmt_write_session_reuse=False))
    monkeypatch.setattr(mgmt_api, "MgmtSession", _FakeWrite)
    srv = _srv(id=202)
    for _ in range(2):
        with mgmt_api.write_session(srv, "s") as s:
            s.call("publish")
    assert len(_FakeWrite.instances) == 2                          # reuse off -> a fresh session per apply
    assert all(i.calls.count("logout") == 1 for i in _FakeWrite.instances)  # and each logs out on exit


def test_write_session_evicts_on_error(monkeypatch):
    mgmt_api.close_write_pool()
    _FakeWrite.instances = []
    monkeypatch.setattr(app_settings, "get", _settings())
    monkeypatch.setattr(mgmt_api, "MgmtSession", _FakeWrite)
    srv = _srv(id=203)
    try:
        with mgmt_api.write_session(srv, "s") as s:
            s.call("add-access-rule")
            raise RuntimeError("apply blew up mid-stream")
    except RuntimeError:
        pass
    assert _FakeWrite.instances[0].calls.count("logout") == 1      # errored session was DROPPED (not pooled)
    with mgmt_api.write_session(srv, "s") as s:                    # next apply gets a fresh login
        s.call("publish")
    assert len(_FakeWrite.instances) == 2
    mgmt_api.close_write_pool()


def test_write_session_relogins_when_pooled_session_expired(monkeypatch):
    mgmt_api.close_write_pool()
    _FakeWrite.instances = []
    monkeypatch.setattr(app_settings, "get", _settings())

    class _Expiring(_FakeWrite):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.fail_keepalive = True                             # every reuse liveness-probe fails -> drop+relogin

    monkeypatch.setattr(mgmt_api, "MgmtSession", _Expiring)
    srv = _srv(id=204)
    for _ in range(2):
        with mgmt_api.write_session(srv, "s") as s:
            s.call("publish")
    assert len(_FakeWrite.instances) == 2                          # expired pooled session re-logged in fresh
    mgmt_api.close_write_pool()


def test_login_retries_on_throttle_then_succeeds(monkeypatch):
    monkeypatch.setattr(app_settings, "get", _settings(mgmt_login_retries=2))
    sleeps: list = []
    monkeypatch.setattr(mgmt_api, "_THROTTLE_SLEEP", lambda s: sleeps.append(s))
    s = mgmt_api.MgmtSession(_srv(), "pw")
    posts: list = []

    def fake_post(url, json=None, headers=None):
        posts.append(url)
        if len([p for p in posts if p.endswith("/login")]) < 2:
            return _Resp(429, {"message": "too many requests"})    # throttled on the first attempt
        return _Resp(200, {"sid": "ok"})                           # second attempt succeeds

    s._client = types.SimpleNamespace(post=fake_post, close=lambda: None)
    s.login()
    assert s.sid == "ok" and len(sleeps) == 1                      # waited once, then succeeded


def test_login_throttle_gives_up_after_retries(monkeypatch):
    monkeypatch.setattr(app_settings, "get", _settings(mgmt_login_retries=1))
    monkeypatch.setattr(mgmt_api, "_THROTTLE_SLEEP", lambda s: None)
    s = mgmt_api.MgmtSession(_srv(), "pw")
    s._client = types.SimpleNamespace(post=lambda *a, **k: _Resp(429, {"message": "too many"}),
                                      close=lambda: None)
    try:
        s.login()
        assert False, "expected MgmtError after retries exhausted"
    except mgmt_api.MgmtError as e:
        assert "429" in str(e)


def test_write_session_drops_on_transport_error_probe(monkeypatch):
    # HIGH (review): a dead TCP connection makes the keepalive probe raise a raw httpx error (call() does not
    # wrap transport errors). The probe must still report not-alive so the dead session is DROPPED + re-logged
    # in — not left poisoning the pool.
    import httpx
    mgmt_api.close_write_pool()
    _FakeWrite.instances = []
    monkeypatch.setattr(app_settings, "get", _settings())

    class _ConnDrop(_FakeWrite):
        def call(self, command, payload=None, **k):
            self.calls.append(command)
            if command == "keepalive":
                raise httpx.ConnectError("connection refused")   # transport error, NOT MgmtError
            return {}

    monkeypatch.setattr(mgmt_api, "MgmtSession", _ConnDrop)
    srv = _srv(id=205)
    for _ in range(2):
        with mgmt_api.write_session(srv, "s") as s:
            s.call("publish")
    assert len(_FakeWrite.instances) == 2                         # dead session dropped + fresh re-login
    mgmt_api.close_write_pool()


def test_read_session_login_failure_closes_client_and_skips_pool(monkeypatch):
    # The read login now runs OUTSIDE _POOL_LOCK; a failed login must close its httpx client (no leak) and
    # leave nothing pooled.
    mgmt_api.close_pool()
    monkeypatch.setattr(app_settings, "get", _settings())
    closed = []

    class _BadLogin:
        def __init__(self, *a, **k):
            self._client = types.SimpleNamespace(close=lambda: closed.append(1))
            self.sid = None
            self.trace = []

        def login(self):
            raise mgmt_api.MgmtError("login refused")

    monkeypatch.setattr(mgmt_api, "MgmtSession", _BadLogin)
    srv = _srv(id=301)
    try:
        with mgmt_api.read_session(srv, "s"):
            pass
        assert False, "expected MgmtError"
    except mgmt_api.MgmtError:
        pass
    assert closed == [1]                                          # client closed on login failure (no leak)
    assert mgmt_api._POOL.get(mgmt_api._pool_key(srv)) is None    # nothing poisoned the pool
    mgmt_api.close_pool()


def test_close_write_pool_tears_down_and_clears(monkeypatch):
    mgmt_api.close_write_pool()
    _FakeWrite.instances = []
    monkeypatch.setattr(app_settings, "get", _settings())
    monkeypatch.setattr(mgmt_api, "MgmtSession", _FakeWrite)
    srv = _srv(id=206)
    with mgmt_api.write_session(srv, "s") as s:
        s.call("publish")
    inst = _FakeWrite.instances[0]
    mgmt_api.close_write_pool()
    assert inst.calls.count("logout") >= 1                        # session logged out on shutdown
    assert mgmt_api._WRITE_POOL.get(mgmt_api._pool_key(srv)) is None   # pool cleared


def test_app_settings_validation_and_clamp():
    timeout = app_settings._BY_KEY["mgmt_session_timeout"]
    assert app_settings._coerce(timeout, "999999") == 3600        # clamp to max
    assert app_settings._coerce(timeout, "5") == 60               # clamp to min
    assert app_settings._coerce(timeout, "garbage") == 3600       # bad -> default
    reuse = app_settings._BY_KEY["mgmt_session_reuse"]
    assert app_settings._coerce(reuse, "1") is True and app_settings._coerce(reuse, "0") is False
    assert app_settings._to_text(reuse, True) == "1" and app_settings._to_text(reuse, "no") == "0"
    assert app_settings._to_text(timeout, 99999) == "3600"


def test_settings_spec_is_wellformed():
    keys = [s.key for s in app_settings.SETTINGS]
    assert len(keys) == len(set(keys))                       # unique keys
    for s in app_settings.SETTINGS:
        assert s.kind in ("bool", "int", "str", "secret", "choice", "text") and s.label and s.help
        if s.kind == "int":
            assert s.min <= s.default <= s.max               # default is in range
        if s.kind in ("str", "text"):
            assert isinstance(s.default, str)                # may be "" (e.g. integration config)
        if s.kind == "secret":
            assert s.default == ""                           # secrets never carry a default value
        if s.kind == "choice":
            assert s.choices and s.default in {c[0] for c in s.choices}   # default is a valid choice


# --- revision-based policy cache -------------------------------------------------------------
def test_cached_raw_serves_within_revalidate_window(monkeypatch):
    mgmt_api.invalidate_cache()
    monkeypatch.setattr(app_settings, "get", _settings(mgmt_cache_revalidate=9999))
    sess, srv = _RawSess(), _srv(id=201)
    r1 = mgmt_api.cached_raw(sess, srv, "L")
    after_cold = len(sess.calls)
    r2 = mgmt_api.cached_raw(sess, srv, "L")
    assert r1["cached"] is False and r2["cached"] is True
    assert sess.calls.count("show-access-rulebase") == 1     # second served from cache
    assert len(sess.calls) == after_cold                     # within window: made no calls at all
    mgmt_api.invalidate_cache()


def test_cached_raw_token_unchanged_serves_cache(monkeypatch):
    mgmt_api.invalidate_cache()
    monkeypatch.setattr(app_settings, "get", _settings(mgmt_cache_revalidate=0))   # always check token
    sess, srv = _RawSess(token="rev-1"), _srv(id=202)
    mgmt_api.cached_raw(sess, srv, "L")
    r2 = mgmt_api.cached_raw(sess, srv, "L")
    assert r2["cached"] is True
    assert sess.calls.count("show-access-rulebase") == 1     # unchanged revision -> no re-pull
    assert sess.calls.count("show-sessions") >= 1            # but it did check the token
    mgmt_api.invalidate_cache()


def test_cached_raw_repulls_when_revision_changes(monkeypatch):
    mgmt_api.invalidate_cache()
    monkeypatch.setattr(app_settings, "get", _settings(mgmt_cache_revalidate=0))
    sess, srv = _RawSess(token="rev-1"), _srv(id=203)
    mgmt_api.cached_raw(sess, srv, "L")
    sess.token = "rev-2"                                     # someone published
    r2 = mgmt_api.cached_raw(sess, srv, "L")
    assert r2["cached"] is False
    assert sess.calls.count("show-access-rulebase") == 2     # re-pulled on the new revision
    mgmt_api.invalidate_cache()


def test_cached_raw_disabled_always_pulls(monkeypatch):
    mgmt_api.invalidate_cache()
    monkeypatch.setattr(app_settings, "get", _settings(mgmt_policy_cache=False))
    sess, srv = _RawSess(), _srv(id=204)
    mgmt_api.cached_raw(sess, srv, "L")
    mgmt_api.cached_raw(sess, srv, "L")
    assert sess.calls.count("show-access-rulebase") == 2
    assert "show-sessions" not in sess.calls                 # cache off -> never checks the token


def test_invalidate_cache_forces_repull(monkeypatch):
    mgmt_api.invalidate_cache()
    monkeypatch.setattr(app_settings, "get", _settings(mgmt_cache_revalidate=9999))
    sess, srv = _RawSess(), _srv(id=205)
    mgmt_api.cached_raw(sess, srv, "L")
    mgmt_api.invalidate_cache(srv)                           # e.g. after our own publish
    r2 = mgmt_api.cached_raw(sess, srv, "L")
    assert r2["cached"] is False and sess.calls.count("show-access-rulebase") == 2
    mgmt_api.invalidate_cache()


def test_build_set_rule_op_only_sends_changed_fields():
    op = mgmt_api.build_set_rule_op("Network", "u-1",
                                    {"enabled": False, "action": "Drop", "track": "Log",
                                     "name": "New", "comments": "c"})
    assert op["command"] == "set-access-rule"
    p = op["payload"]
    assert p["uid"] == "u-1" and p["layer"] == "Network"
    assert p["enabled"] is False and p["action"] == "Drop"
    assert p["track"] == {"type": "Log"} and p["new-name"] == "New" and p["comments"] == "c"
    assert "disable" in op["summary"]
    # only the keys present in the change dict are sent — nothing else on the rule is touched
    assert set(mgmt_api.build_set_rule_op("Network", "u-1", {"action": "Accept"})["payload"]) == \
        {"uid", "layer", "action"}


def test_apply_changes_publishes_then_reports(monkeypatch):
    rec = {"calls": []}
    monkeypatch.setattr(mgmt_api, "MgmtSession", _fake_session(rec))
    res = mgmt_api.apply_changes(object(), "secret",
                                 [{"command": "set-access-rule", "payload": {"uid": "u"}, "summary": "e"}],
                                 publish=True)
    assert res["ok"] is True and res["published"] is True
    assert [c for c, _ in rec["calls"]] == ["set-access-rule", "publish"]


def test_apply_changes_dry_run_discards(monkeypatch):
    rec = {"calls": []}
    monkeypatch.setattr(mgmt_api, "MgmtSession", _fake_session(rec))
    res = mgmt_api.apply_changes(object(), "secret",
                                 [{"command": "set-access-rule", "payload": {}, "summary": "e"}],
                                 publish=False)
    assert res["ok"] is True and res["published"] is False
    assert [c for c, _ in rec["calls"]] == ["set-access-rule", "discard"]   # validated, never committed


def test_apply_changes_discards_on_error_never_publishes(monkeypatch):
    rec = {"calls": []}
    monkeypatch.setattr(mgmt_api, "MgmtSession", _fake_session(rec, fail_on="set-access-rule"))
    res = mgmt_api.apply_changes(object(), "secret",
                                 [{"command": "set-access-rule", "payload": {}, "summary": "e"}],
                                 publish=True)
    assert res["ok"] is False and "server said no" in res["error"]
    cmds = [c for c, _ in rec["calls"]]
    assert "publish" not in cmds and "discard" in cmds


def test_export_mgmt_cli_is_shell_safe():
    """Object / comment names pulled from a customer SMS must never execute when the .sh is run."""
    bundle = {"layer": "Net", "objects_by_type": {
        "host": [{"uid": "u", "name": "host_$(id)", "type": "host", "ipv4-address": "10.0.0.5"}]},
        "rules": [{"kind": "rule", "number": 1, "name": "r", "enabled": True, "source": [],
                   "destination": [], "service": [], "action": "Accept", "track": "Log",
                   "comments": "owner `whoami`"}]}
    cli = mgmt_export.generate(bundle)["mgmt_cli"]
    assert "name 'host_$(id)'" in cli              # single-quoted literal — bash cannot expand it
    assert 'name "host_$(id)"' not in cli          # the old, injectable double-quoted form is gone
    assert "comments 'owner `whoami`'" in cli


def test_publish_waits_for_task_and_returns_on_success(monkeypatch):
    """publish is async — it must poll show-task and only return once the task actually succeeded."""
    monkeypatch.setattr(mgmt_api.time, "sleep", lambda *_: None)
    s = mgmt_api.MgmtSession.__new__(mgmt_api.MgmtSession)
    s.server = None                       # publish() invalidates this server's cache on success; None = clear-all
    seq = iter([
        {"task-id": "t1"},                                              # publish
        {"tasks": [{"task-id": "t1", "status": "in progress"}]},        # show-task #1
        {"tasks": [{"task-id": "t1", "status": "succeeded"}]},          # show-task #2
    ])
    cmds = []

    def fake_call(command, payload=None):
        cmds.append(command)
        return next(seq)

    s.call = fake_call
    res = s.publish()
    assert cmds == ["publish", "show-task", "show-task"]   # polled until the task left 'in progress'
    assert res["task"]["status"] == "succeeded"


def test_publish_raises_when_task_fails(monkeypatch):
    monkeypatch.setattr(mgmt_api.time, "sleep", lambda *_: None)
    s = mgmt_api.MgmtSession.__new__(mgmt_api.MgmtSession)
    seq = iter([{"task-id": "t1"}, {"tasks": [{"task-id": "t1", "status": "failed"}]}])
    s.call = lambda command, payload=None: next(seq)
    try:
        s.publish()
        assert False, "expected MgmtError on a failed publish task"
    except mgmt_api.MgmtError as exc:
        assert "not committed" in str(exc).lower()


def test_cp_error_detail_surfaces_validation_messages():
    msg = mgmt_api._cp_error_detail({
        "message": "Publish operation failed with Validation Errors.",
        "blocking-errors": [{"message": "Application & URL Filtering is not enabled on layer DNS_Layer."}]})
    assert "Validation Errors" in msg and "Application & URL Filtering is not enabled" in msg


def test_task_error_text_extracts_and_base64_decodes():
    import base64 as _b64
    enc = _b64.b64encode(b"blade not enabled on layer DNS_Layer").decode()
    task = {"status": "failed",
            "task-details": [{"statusDescription": "rule verification failed", "responseMessage": enc}]}
    txt = mgmt_api._task_error_text(task)
    assert "rule verification failed" in txt and "blade not enabled on layer DNS_Layer" in txt


def test_export_ansible_negate_underscored_and_names_quoted():
    bundle = {"layer": "Net: prod", "objects_by_type": {}, "rules": [
        {"kind": "rule", "number": 1, "name": "allow: web", "enabled": True, "source": [],
         "destination": [], "service": [], "action": "Accept", "track": "Log", "source_negate": True}]}
    ans = mgmt_export.generate(bundle)["ansible"]
    assert "source_negate: true" in ans and "source-negate: true" not in ans   # module-correct key
    assert '- name: "Add rule allow: web"' in ans                              # quoted -> valid YAML
    assert '- name: "Restore Check Point policy - layer Net: prod"' in ans


def test_is_lock_error_detects_locked_for_editing():
    assert mgmt_api._is_lock_error(
        "Requested object with ObjId: [9d44c88b] locked: [Locked for editing by admin]") is True
    assert mgmt_api._is_lock_error("validation failed: bad service") is False
    assert mgmt_api._is_lock_error("") is False


def test_write_session_timeout_is_an_int_in_range():
    t = mgmt_api.write_session_timeout()
    assert isinstance(t, int) and 60 <= t <= 3600


def test_form_tpl_returns_fragment_on_header():
    """The new/edit routes return just the form fragment when loaded into a modal (X-Fragment), else
    the full page — so the modal is a progressive enhancement and the page still works standalone."""
    import types
    from app.routers import mgmt, gateways
    frag = types.SimpleNamespace(headers={"x-fragment": "1"})
    full = types.SimpleNamespace(headers={})
    assert mgmt._form_tpl(frag) == "_management_form.html"
    assert mgmt._form_tpl(full) == "management_form.html"
    assert gateways._form_tpl(frag) == "_gateway_form.html"
    assert gateways._form_tpl(full) == "gateway_form.html"


# CRITICAL regression: the standard "Network" layer groups rules into SECTIONS, so the top-level
# rulebase has far fewer items than the rule `total`. _raw_pull must gate truncation on the CAP, not on
# len(top-level items) — `total > len(items)` falsely refused every sectioned layer ("13 rules over cap").
def test_raw_pull_sectioned_layer_not_falsely_truncated():
    rules = [{"type": "access-rule", "uid": f"r{i}", "rule-number": i} for i in range(1, 14)]   # 13 rules
    section = {"type": "access-section", "uid": "sec", "name": "Section A", "rulebase": rules}

    class _Sectioned:
        def call(self, command, payload=None, **k):
            if command == "show-access-rulebase":
                return {"rulebase": [section], "objects-dictionary": [], "total": 13, "to": 13}
            return {}
    raw = mgmt_api._raw_pull(_Sectioned(), "Network", None, 50000)   # must NOT raise (13 << cap)
    assert raw["total"] == 13 and len(raw["items"]) == 1            # one top-level section, all rules inside

    class _Huge:                                                    # genuinely over-cap → still fails loud
        def call(self, command, payload=None, **k):
            off = (payload or {}).get("offset", 0)
            return {"rulebase": [{"type": "access-rule", "uid": f"r{off}"}],
                    "objects-dictionary": [], "total": 200, "to": off + 1}
    try:
        mgmt_api._raw_pull(_Huge(), "big", None, 5)
        assert False, "expected MgmtError for a genuinely over-cap layer"
    except mgmt_api.MgmtError:
        pass
