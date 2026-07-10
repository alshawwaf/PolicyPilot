"""One-shot ServiceNow onboarding for the PolicyPilot ticketing webhook.

Instead of clicking through *System Web Services -> REST Message* and *Business Rules* by hand, this tool
pushes the whole integration into a ServiceNow instance over its own Table API. It is idempotent (safe to
re-run) and uses only the Python standard library, so it can be handed to a customer as a single file.

What it creates (all upserted by name, never duplicated):
  * system properties  ``policypilot.webhook.url`` / ``.token`` / ``.server_id`` / ``.layer`` / ``.apply``
    -- so the URL/token live in ServiceNow config and the customer can rotate them with no code change.
  * a Business Rule on ``incident`` that POSTs the access request to the PolicyPilot webhook on insert,
    reading those properties (one record -- no separate REST Message needed).
  * (optional, --fields) the full set of custom incident columns (u_source / u_destination / u_port /
    u_protocol / u_service / u_application / u_action / u_vpn / u_time / u_content / u_install_on /
    u_action_limit / typed-kind fields) so a ticket can carry the WHOLE Check Point rule. The rule maps
    whichever are filled; blanks are ignored.
  * (optional, --sample) a test incident (with the fields populated) to trigger the rule end-to-end.

SECURITY
  * No secret is hardcoded. The ServiceNow password comes from ``SNOW_PASSWORD`` or an interactive prompt;
    the PolicyPilot token from ``--pp-token`` or ``PILOT_WEBHOOK_TOKEN``. Nothing is written to disk.
  * TLS certificate verification stays ON (default urllib context). Use an https instance URL.
  * The PolicyPilot token is stored in a ServiceNow system property (admin-readable). That token grants
    policy publish, so scope it (Settings -> Ticketing webhook -> server-id allowlist) and rotate after a POV.

USAGE
  export SNOW_PASSWORD='...'              # the ServiceNow admin password (never pass it on the CLI)
  export PILOT_WEBHOOK_TOKEN='...'        # the PolicyPilot webhook token

  python tools/servicenow_setup.py install \
      --instance https://devXXXXX.service-now.com --user admin \
      --pp-url http://policypilot.example.ca --server-id 1 --layer Network \
      --fields --sample

  python tools/servicenow_setup.py verify  --pp-url http://policypilot.example.ca   # test the webhook only
  python tools/servicenow_setup.py remove  --instance ... --user admin                # tear the config down
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def _ssl_context() -> ssl.SSLContext:
    """A certificate-verifying TLS context. Prefer the ``certifi`` CA bundle when it is installed -- this
    fixes the common macOS error 'unable to get local issuer certificate', where the system/python.org
    Python ships without a usable CA store -- and fall back to the OpenSSL default otherwise. Verification
    is ALWAYS on: there is no skip-verify path (the ServiceNow dev cert is public and valid; a failure here
    is a missing local CA bundle, not a bad cert)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:  # noqa: BLE001 -- certifi absent: use whatever CA store OpenSSL found
        return ssl.create_default_context()


_SSL_CTX = _ssl_context()

# --- The Business Rule body pushed into ServiceNow (runs there, not here) -------------------------------
# Reads the webhook url/token/server/layer/apply from system properties so they can be changed without
# editing the rule. Fires on `after insert` (the incident number + record exist, so PolicyPilot's own
# work-note write-back can find it). Synchronous execute() so the response is visible in the system log.
BUSINESS_RULE_SCRIPT = """(function executeRule(current, previous /*null when async*/) {
  try {
    var url   = gs.getProperty('policypilot.webhook.url');
    var token = gs.getProperty('policypilot.webhook.token');
    if (!url || !token) { gs.error('PolicyPilot: policypilot.webhook.url/token property not set'); return; }

    // Every access-rule column PolicyPilot supports. Blank fields are ignored by the webhook, so unused
    // columns can stay empty; fill only what the ticket needs. Reuse-only objects (VPN / time / content /
    // install-on / limit / access-role / zone) must already exist on the SMS -- PolicyPilot never invents them.
    function v(f) { return (current[f] || '').toString(); }
    var body = {
      ticket_id:         current.number.toString(),
      server_id:         parseInt(gs.getProperty('policypilot.server_id', '1'), 10),
      layer:             gs.getProperty('policypilot.layer', 'Network'),
      package:           v('u_package'),
      source:            v('u_source'),
      source_kind:       v('u_source_kind') || 'ip',        // ip | domain | access-role | dynamic-object | updatable-object | security-zone
      destination:       v('u_destination'),
      destination_kind:  v('u_destination_kind') || 'ip',
      protocol:          v('u_protocol') || 'tcp',
      port:              v('u_port'),
      service:           v('u_service'),                    // named service e.g. icmp / GRE / Any (overrides port)
      application:       v('u_application'),                // app site e.g. Facebook (overrides service)
      verdict:           v('u_action'),                     // Accept | Drop | Reject | Ask | Inform | Apply Layer
      inline_layer:      v('u_inline_layer'),               // required when verdict = Apply Layer
      vpn:               v('u_vpn'),                         // VPN community/-ies e.g. All_GwToGw (comma/semicolon list)
      time:              v('u_time'),                        // time / time-group object names
      content:           v('u_content'),                     // data-type names
      content_direction: v('u_content_direction') || 'any',  // any | up | down
      install_on:        v('u_install_on'),                  // gateway / target names
      action_limit:      v('u_action_limit'),                // QoS rate object e.g. Upload_10Mbps
      apply:             gs.getProperty('policypilot.apply', 'false') === 'true'
    };

    var r = new sn_ws.RESTMessageV2();
    r.setEndpoint(url);
    r.setHttpMethod('POST');
    r.setRequestHeader('X-PolicyPilot-Token', token);
    r.setRequestHeader('Content-Type', 'application/json');
    r.setRequestBody(JSON.stringify(body));
    var resp = r.execute();
    gs.info('PolicyPilot ' + resp.getStatusCode() + ': ' + resp.getBody());
  } catch (ex) {
    gs.error('PolicyPilot call failed: ' + ex.getMessage());
  }
})(current, previous);
"""

BR_NAME = "PolicyPilot - access automation"
PROP_PREFIX = "policypilot."
CUSTOM_FIELDS = [
    # source / destination and how each is interpreted
    ("u_source", "Source", 100),
    ("u_source_kind", "Source kind", 40),          # ip | domain | access-role | dynamic-object | updatable-object | security-zone
    ("u_destination", "Destination", 100),
    ("u_destination_kind", "Destination kind", 40),
    # the service: protocol+port, OR a named service, OR an application (precedence app > service > port)
    ("u_protocol", "Protocol", 20),
    ("u_port", "Port", 40),
    ("u_service", "Service", 60),                  # e.g. icmp / GRE / Any
    ("u_application", "Application", 60),           # e.g. Facebook
    # the verdict + the remaining access-rule columns (all reuse-only objects on the SMS)
    ("u_action", "Action (verdict)", 20),          # Accept | Drop | Reject | Ask | Inform | Apply Layer
    ("u_inline_layer", "Inline layer", 100),       # for Apply Layer
    ("u_vpn", "VPN community", 200),               # e.g. All_GwToGw, or a site-to-site community name
    ("u_time", "Time", 200),                        # time / time-group object names
    ("u_content", "Content (data types)", 200),
    ("u_content_direction", "Content direction", 10),  # any | up | down
    ("u_install_on", "Install on", 200),            # gateway / target names
    ("u_action_limit", "Bandwidth limit", 60),      # QoS rate object e.g. Upload_10Mbps
    ("u_package", "Policy package", 60),
]


class Snow:
    """A thin ServiceNow Table API client (stdlib only, TLS verified). Just enough to upsert config rows."""

    def __init__(self, instance: str, user: str, password: str):
        self.base = instance.rstrip("/")
        if not self.base.startswith(("http://", "https://")):
            self.base = "https://" + self.base
        self._auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self._auth)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:   # TLS verified (certifi/default CA)
                raw = resp.read().decode() or "{}"
            return json.loads(raw)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            raise SystemExit(f"ServiceNow {method} {path} -> HTTP {exc.code}: {detail}")
        except urllib.error.URLError as exc:
            raise SystemExit(f"Could not reach ServiceNow at {self.base} ({exc.reason}). "
                             f"Check the --instance URL and network.")

    def find(self, table: str, query: str, fields: str = "sys_id") -> dict | None:
        path = (f"/api/now/table/{table}?sysparm_query={urllib.parse.quote(query)}"
                f"&sysparm_fields={fields}&sysparm_limit=1")
        rows = self._request("GET", path).get("result") or []
        return rows[0] if rows else None

    def upsert(self, table: str, query: str, payload: dict) -> tuple[str, bool]:
        """Create the row, or PATCH it if one already matches ``query``. Returns (sys_id, created?)."""
        existing = self.find(table, query)
        if existing:
            sys_id = existing["sys_id"]
            self._request("PATCH", f"/api/now/table/{table}/{sys_id}", payload)
            return sys_id, False
        created = self._request("POST", f"/api/now/table/{table}", payload).get("result") or {}
        return created.get("sys_id", ""), True


def _set_property(snow: Snow, name: str, value: str, desc: str) -> None:
    sys_id, created = snow.upsert(
        "sys_properties", f"name={name}",
        {"name": name, "value": value, "type": "string", "description": desc},
    )
    print(f"  property {name:<28} {'created' if created else 'updated'} ({value or '(blank)'})")


def _install(args) -> None:
    password = os.environ.get("SNOW_PASSWORD") or getpass.getpass("ServiceNow password: ")
    if not password:
        raise SystemExit("A ServiceNow password is required (set SNOW_PASSWORD or type it at the prompt).")
    token = args.pp_token or os.environ.get("PILOT_WEBHOOK_TOKEN")
    if not token:
        raise SystemExit("The PolicyPilot webhook token is required (--pp-token or PILOT_WEBHOOK_TOKEN).")

    webhook_url = args.pp_url.rstrip("/")
    if not webhook_url.endswith("/access-automation/webhook"):
        webhook_url += "/access-automation/webhook"

    snow = Snow(args.instance, args.user, password)
    print(f"ServiceNow: {snow.base}")

    print("Storing PolicyPilot config as system properties:")
    _set_property(snow, PROP_PREFIX + "webhook.url", webhook_url, "PolicyPilot access-automation webhook URL")
    _set_property(snow, PROP_PREFIX + "webhook.token", token, "PolicyPilot webhook token (X-PolicyPilot-Token)")
    _set_property(snow, PROP_PREFIX + "server_id", str(args.server_id), "Target PolicyPilot management server id")
    _set_property(snow, PROP_PREFIX + "layer", args.layer, "Check Point access layer to evaluate")
    _set_property(snow, PROP_PREFIX + "apply", "true" if args.apply else "false",
                  "true = apply + publish the rule; false = preview only")

    if args.fields:
        print("Creating custom incident fields:")
        for element, label, length in CUSTOM_FIELDS:
            _sys_id, created = snow.upsert(
                "sys_dictionary", f"name=incident^element={element}",
                {"name": "incident", "element": element, "column_label": label,
                 "internal_type": "string", "max_length": length, "active": "true"},
            )
            print(f"  field incident.{element:<16} {'created' if created else 'exists '} ({label})")

    print("Creating the Business Rule:")
    sys_id, created = snow.upsert(
        "sys_script", f"name={BR_NAME}^collection=incident",
        {"name": BR_NAME, "collection": "incident", "active": "true", "advanced": "true",
         "when": "after", "action_insert": "true", "action_update": "false",
         "order": "100", "script": BUSINESS_RULE_SCRIPT,
         "description": "POSTs the access request to the PolicyPilot webhook on incident creation."},
    )
    print(f"  business rule '{BR_NAME}' {'created' if created else 'updated'} (sys_id {sys_id})")

    if args.sample:
        print("Creating a sample incident to trigger the flow:")
        row = snow._request("POST", "/api/now/table/incident", {
            "short_description": "PolicyPilot demo - allow 192.168.9.9 -> 172.16.5.10:443",
            "u_source": "192.168.9.9", "u_destination": "172.16.5.10",
            "u_port": "443", "u_protocol": "tcp",
        }).get("result") or {}
        print(f"  incident {row.get('number', '?')} created (sys_id {row.get('sys_id', '?')}) — "
              f"check its work notes for the PolicyPilot decision")

    print("\nDone. In ServiceNow, open System Log -> All and filter on 'PolicyPilot' to see each call, "
          "and the incident's work notes for the write-back.")


def _remove(args) -> None:
    password = os.environ.get("SNOW_PASSWORD") or getpass.getpass("ServiceNow password: ")
    snow = Snow(args.instance, args.user, password)
    removed = 0
    for _ in range(50):   # delete ALL matches -- an older build could create duplicate rules on re-run
        br = snow.find("sys_script", f"name={BR_NAME}^collection=incident")
        if not br:
            break
        snow._request("DELETE", f"/api/now/table/sys_script/{br['sys_id']}")
        removed += 1
    print(f"Removed {removed} business rule(s) named '{BR_NAME}'." if removed
          else "No PolicyPilot business rule found.")
    for name in ("webhook.url", "webhook.token", "server_id", "layer", "apply"):
        prop = snow.find("sys_properties", f"name={PROP_PREFIX}{name}")
        if prop:
            snow._request("DELETE", f"/api/now/table/sys_properties/{prop['sys_id']}")
            print(f"Removed property {PROP_PREFIX}{name}.")
    print("Custom fields (if created) are left in place — drop them manually if unwanted.")


def _verify(args) -> None:
    """Sanity-check the PolicyPilot webhook itself (no ServiceNow) with a read-only preview POST."""
    token = args.pp_token or os.environ.get("PILOT_WEBHOOK_TOKEN")
    if not token:
        raise SystemExit("--pp-token or PILOT_WEBHOOK_TOKEN is required to verify the webhook.")
    url = args.pp_url.rstrip("/")
    if not url.endswith("/access-automation/webhook"):
        url += "/access-automation/webhook"
    body = json.dumps({"ticket_id": "VERIFY", "server_id": args.server_id, "layer": args.layer,
                       "source": "192.168.9.9", "destination": "172.16.5.10",
                       "protocol": "tcp", "port": "443", "apply": False}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("X-PolicyPilot-Token", token)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:   # TLS verified (certifi/default CA)
            print(f"HTTP {resp.status}")
            print(resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read().decode(errors='replace')}")
        sys.exit(1)
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach PolicyPilot at {url} ({exc.reason}).")


def main() -> None:
    p = argparse.ArgumentParser(description="Automate the ServiceNow side of the PolicyPilot webhook.")
    sub = p.add_subparsers(dest="cmd", required=True)

    inst = argparse.ArgumentParser(add_help=False)
    inst.add_argument("--instance", required=True, help="ServiceNow instance URL, e.g. https://devXXXXX.service-now.com")
    inst.add_argument("--user", required=True, help="ServiceNow admin username (password via SNOW_PASSWORD env)")

    pp = argparse.ArgumentParser(add_help=False)
    pp.add_argument("--pp-url", required=True, help="PolicyPilot base or full webhook URL")
    pp.add_argument("--pp-token", default=None, help="PolicyPilot webhook token (else PILOT_WEBHOOK_TOKEN env)")
    pp.add_argument("--server-id", type=int, default=1, help="Target management server id (default 1)")
    pp.add_argument("--layer", default="Network", help="Check Point access layer name (default 'Network')")

    ins = sub.add_parser("install", parents=[inst, pp], help="Push the webhook config into ServiceNow.")
    ins.add_argument("--apply", action="store_true", help="Generate apply+publish (default: preview only)")
    ins.add_argument("--fields", action="store_true", help="Also create u_source/u_destination/u_port/u_protocol")
    ins.add_argument("--sample", action="store_true", help="Also create a sample incident to trigger the flow")
    ins.set_defaults(func=_install)

    rm = sub.add_parser("remove", parents=[inst], help="Delete the business rule + properties.")
    rm.set_defaults(func=_remove)

    ver = sub.add_parser("verify", parents=[pp], help="Test the PolicyPilot webhook directly (no ServiceNow).")
    ver.set_defaults(func=_verify)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
