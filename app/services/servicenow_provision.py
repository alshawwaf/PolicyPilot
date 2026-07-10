"""In-portal ServiceNow provisioning for the access-automation webhook.

This is the in-app twin of ``tools/servicenow_setup.py`` (which stays the standalone local testing tool).
It is driven from **Settings -> Ticket write-back** with a live-progress modal, and reuses the ServiceNow
instance + credentials the admin already stored for the write-back (encrypted at rest). It pushes the SAME
configuration the CLI does, so the two produce an identical ServiceNow setup:

  * system properties ``policypilot.webhook.url`` / ``.token`` / ``.server_id`` / ``.layer`` / ``.apply``,
  * a Business Rule on ``incident`` that POSTs the access request to the webhook on insert,
  * (optional) the custom request columns, and (optional) a sample incident to trigger the flow.

``provision()`` is a generator that yields one progress event per backend step (``{step, status, detail}``)
so the router can stream it to the UI. TLS verification is always on (httpx bundles its own CA store);
the ServiceNow password is never echoed into an event, and the webhook token is masked.

NOTE: keep the Business-Rule script + field list in sync with ``tools/servicenow_setup.py``.
NOTE: the stored write-back account must have rights to create system properties / business rules /
dictionary columns (i.e. admin). A least-privilege write-back user will get clear HTTP 403 steps.
"""
from __future__ import annotations

from typing import Iterator

import httpx

# --- The identical config the CLI writes (keep in sync with tools/servicenow_setup.py) -----------------
BR_NAME = "PolicyPilot - access automation"
PROP_PREFIX = "policypilot."
CUSTOM_FIELDS = [
    ("u_source", "Source", 100),
    ("u_source_kind", "Source kind", 40),
    ("u_destination", "Destination", 100),
    ("u_destination_kind", "Destination kind", 40),
    ("u_protocol", "Protocol", 20),
    ("u_port", "Port", 40),
    ("u_service", "Service", 60),
    ("u_application", "Application", 60),
    ("u_action", "Action (verdict)", 20),
    ("u_inline_layer", "Inline layer", 100),
    ("u_vpn", "VPN community", 200),
    ("u_time", "Time", 200),
    ("u_content", "Content (data types)", 200),
    ("u_content_direction", "Content direction", 10),
    ("u_install_on", "Install on", 200),
    ("u_action_limit", "Bandwidth limit", 60),
    ("u_package", "Policy package", 60),
]
BUSINESS_RULE_SCRIPT = """(function executeRule(current, previous /*null when async*/) {
  try {
    var url   = gs.getProperty('policypilot.webhook.url');
    var token = gs.getProperty('policypilot.webhook.token');
    if (!url || !token) { gs.error('PolicyPilot: policypilot.webhook.url/token property not set'); return; }

    // Every access-rule column PolicyPilot supports. Blank fields are ignored by the webhook, so unused
    // columns can stay empty. Reuse-only objects (VPN / time / content / install-on / limit) must already
    // exist on the SMS -- PolicyPilot never invents them.
    function v(f) { return (current[f] || '').toString(); }
    var body = {
      ticket_id:         current.number.toString(),
      server_id:         parseInt(gs.getProperty('policypilot.server_id', '1'), 10),
      layer:             gs.getProperty('policypilot.layer', 'Network'),
      package:           v('u_package'),
      source:            v('u_source'),
      source_kind:       v('u_source_kind') || 'ip',
      destination:       v('u_destination'),
      destination_kind:  v('u_destination_kind') || 'ip',
      protocol:          v('u_protocol') || 'tcp',
      port:              v('u_port'),
      service:           v('u_service'),
      application:       v('u_application'),
      verdict:           v('u_action'),
      inline_layer:      v('u_inline_layer'),
      vpn:               v('u_vpn'),
      time:              v('u_time'),
      content:           v('u_content'),
      content_direction: v('u_content_direction') || 'any',
      install_on:        v('u_install_on'),
      action_limit:      v('u_action_limit'),
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


def _event(step: str, status: str, detail: str = "") -> dict:
    """One progress event. status is one of: running | ok | exists | error | done."""
    return {"step": step, "status": status, "detail": detail}


class _Snow:
    """Minimal ServiceNow Table API client over httpx (TLS verified, preemptive basic auth)."""

    def __init__(self, instance: str, user: str, password: str):
        base = instance.rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        self.base = base
        self._client = httpx.Client(timeout=30.0, verify=True, auth=(user, password),
                                    headers={"Accept": "application/json"})

    def close(self) -> None:
        self._client.close()

    def ping(self) -> None:
        """Cheap authenticated GET to validate the URL + credentials (a 401 raises here, before any write)."""
        r = self._client.get(f"{self.base}/api/now/table/incident", params={"sysparm_limit": 1})
        r.raise_for_status()

    def find(self, table: str, query: str, fields: str = "sys_id") -> dict | None:
        r = self._client.get(f"{self.base}/api/now/table/{table}",
                             params={"sysparm_query": query, "sysparm_fields": fields, "sysparm_limit": 1})
        r.raise_for_status()
        rows = r.json().get("result") or []
        return rows[0] if rows else None

    def upsert(self, table: str, query: str, payload: dict) -> tuple[str, bool]:
        """Create the row, or PATCH it if one already matches ``query``. Returns (sys_id, created?).
        httpx encodes the query value exactly once, so a name with spaces matches (no duplicate rows)."""
        existing = self.find(table, query)
        if existing:
            sid = existing["sys_id"]
            r = self._client.patch(f"{self.base}/api/now/table/{table}/{sid}", json=payload)
            r.raise_for_status()
            return sid, False
        r = self._client.post(f"{self.base}/api/now/table/{table}", json=payload)
        r.raise_for_status()
        return (r.json().get("result") or {}).get("sys_id", ""), True

    def create(self, table: str, payload: dict) -> dict:
        r = self._client.post(f"{self.base}/api/now/table/{table}", json=payload)
        r.raise_for_status()
        return r.json().get("result") or {}

    def delete(self, table: str, sys_id: str) -> None:
        r = self._client.delete(f"{self.base}/api/now/table/{table}/{sys_id}")
        r.raise_for_status()


def _http_reason(exc: httpx.HTTPError) -> str:
    """A short, safe reason from an httpx error (status code for an HTTP error, else the transport reason).
    A 403 is called out because it usually means the write-back account lacks admin/provisioning rights."""
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            return (f"HTTP {code} — the ServiceNow account lacks permission for this "
                    "(provisioning needs admin/rest rights)")
        return f"HTTP {code}"
    return str(exc) or exc.__class__.__name__


def provision(*, instance: str, user: str, password: str, webhook_url: str, token: str,
              server_id: int, layer: str, apply: bool = False,
              create_fields: bool = True, create_sample: bool = False) -> Iterator[dict]:
    """Push the webhook config into ServiceNow, yielding a progress event per step. Never raises — a failed
    step yields an ``error`` event and the run continues to the terminal ``done`` (with an errored summary)."""
    if not (instance and user and password):
        yield _event("Check ServiceNow credentials", "error",
                     "Set the ServiceNow instance, user and password in Ticket write-back first.")
        yield _event("Done", "done", "aborted — missing ServiceNow credentials")
        return
    if not token:
        yield _event("Check webhook token", "error",
                     "Set an inbound webhook token in Ticketing webhook first, then retry.")
        yield _event("Done", "done", "aborted — missing webhook token")
        return

    snow = _Snow(instance, user, password)
    errors = 0
    try:
        yield _event("Connect to ServiceNow", "running", snow.base)
        try:
            snow.ping()
            yield _event("Connect to ServiceNow", "ok", snow.base)
        except httpx.HTTPError as exc:
            yield _event("Connect to ServiceNow", "error", _http_reason(exc))
            yield _event("Done", "done", "aborted — could not reach ServiceNow")
            return

        props = [
            ("webhook.url", webhook_url, "PolicyPilot access-automation webhook URL"),
            ("webhook.token", token, "PolicyPilot webhook token (X-PolicyPilot-Token)"),
            ("server_id", str(server_id), "Target PolicyPilot management server id"),
            ("layer", layer, "Check Point access layer to evaluate"),
            ("apply", "true" if apply else "false", "true = apply + publish the rule; false = preview only"),
        ]
        for name, value, desc in props:
            key = PROP_PREFIX + name
            shown = "••••••••" if name == "webhook.token" else (value or "(blank)")   # never echo the token
            yield _event(f"Set property {key}", "running", "")
            try:
                _sid, created = snow.upsert("sys_properties", f"name={key}",
                                            {"name": key, "value": value, "type": "string",
                                             "description": desc})
                yield _event(f"Set property {key}", "ok", f"{'created' if created else 'updated'} = {shown}")
            except httpx.HTTPError as exc:
                errors += 1
                yield _event(f"Set property {key}", "error", _http_reason(exc))

        if create_fields:
            for element, label, length in CUSTOM_FIELDS:
                try:
                    _sid, created = snow.upsert("sys_dictionary", f"name=incident^element={element}",
                                                {"name": "incident", "element": element,
                                                 "column_label": label, "internal_type": "string",
                                                 "max_length": length, "active": "true"})
                    yield _event(f"Field incident.{element}", "ok" if created else "exists",
                                 f"{label}")
                except httpx.HTTPError as exc:
                    errors += 1
                    yield _event(f"Field incident.{element}", "error", _http_reason(exc))

        yield _event("Create Business Rule", "running", BR_NAME)
        try:
            _sid, created = snow.upsert("sys_script", f"name={BR_NAME}^collection=incident",
                                        {"name": BR_NAME, "collection": "incident", "active": "true",
                                         "advanced": "true", "when": "after", "action_insert": "true",
                                         "action_update": "false", "order": "100",
                                         "script": BUSINESS_RULE_SCRIPT,
                                         "description": "POSTs the access request to the PolicyPilot "
                                                        "webhook on incident creation."})
            yield _event("Create Business Rule", "ok",
                         f"{'created' if created else 'updated'} on incident (fires after insert)")
        except httpx.HTTPError as exc:
            errors += 1
            yield _event("Create Business Rule", "error", _http_reason(exc))

        if create_sample:
            yield _event("Create sample incident", "running", "")
            try:
                row = snow.create("incident", {
                    "short_description": "PolicyPilot demo - allow 192.168.9.9 -> 172.16.5.10:443",
                    "u_source": "192.168.9.9", "u_destination": "172.16.5.10",
                    "u_port": "443", "u_protocol": "tcp"})
                yield _event("Create sample incident", "ok",
                             f"{row.get('number', '?')} created — check its work notes")
            except httpx.HTTPError as exc:
                errors += 1
                yield _event("Create sample incident", "error", _http_reason(exc))

        if errors:
            yield _event("Done", "done", f"completed with {errors} error(s) — see the steps above")
        else:
            yield _event("Done", "done", "ServiceNow is configured — create an incident to drive PolicyPilot")
    finally:
        snow.close()


def deprovision(*, instance: str, user: str, password: str, remove_fields: bool = False) -> Iterator[dict]:
    """Remove everything ``provision()`` created: the Business Rule (the POST-to-webhook) and the
    ``policypilot.*`` system properties, and -- only when ``remove_fields`` is set -- the custom incident
    columns (destructive: drops the column + its data). Incidents are NEVER touched. Yields a progress
    event per step and never raises (a failed step yields ``error`` and continues to the terminal ``done``)."""
    if not (instance and user and password):
        yield _event("Check ServiceNow credentials", "error",
                     "Set the ServiceNow instance, user and password in Ticket write-back first.")
        yield _event("Done", "done", "aborted — missing ServiceNow credentials")
        return

    snow = _Snow(instance, user, password)
    errors = 0
    try:
        yield _event("Connect to ServiceNow", "running", snow.base)
        try:
            snow.ping()
            yield _event("Connect to ServiceNow", "ok", snow.base)
        except httpx.HTTPError as exc:
            yield _event("Connect to ServiceNow", "error", _http_reason(exc))
            yield _event("Done", "done", "aborted — could not reach ServiceNow")
            return

        # Business Rule(s) -- delete every match (an older build could have created duplicates).
        yield _event("Remove Business Rule", "running", BR_NAME)
        try:
            n = 0
            for _ in range(50):
                br = snow.find("sys_script", f"name={BR_NAME}^collection=incident")
                if not br:
                    break
                snow.delete("sys_script", br["sys_id"])
                n += 1
            yield _event("Remove Business Rule", "ok" if n else "skip",
                         f"deleted {n} rule(s)" if n else "none found")
        except httpx.HTTPError as exc:
            errors += 1
            yield _event("Remove Business Rule", "error", _http_reason(exc))

        # System properties.
        for name in ("webhook.url", "webhook.token", "server_id", "layer", "apply"):
            key = PROP_PREFIX + name
            try:
                prop = snow.find("sys_properties", f"name={key}")
                if prop:
                    snow.delete("sys_properties", prop["sys_id"])
                    yield _event(f"Remove property {key}", "ok", "deleted")
                else:
                    yield _event(f"Remove property {key}", "skip", "not present")
            except httpx.HTTPError as exc:
                errors += 1
                yield _event(f"Remove property {key}", "error", _http_reason(exc))

        # Custom fields -- optional, and destructive (drops the incident column + any data in it).
        if remove_fields:
            for element, _label, _length in CUSTOM_FIELDS:
                try:
                    fld = snow.find("sys_dictionary", f"name=incident^element={element}")
                    if fld:
                        snow.delete("sys_dictionary", fld["sys_id"])
                        yield _event(f"Remove field incident.{element}", "ok", "deleted")
                    else:
                        yield _event(f"Remove field incident.{element}", "skip", "not present")
                except httpx.HTTPError as exc:
                    errors += 1
                    yield _event(f"Remove field incident.{element}", "error", _http_reason(exc))
        else:
            yield _event("Custom fields", "skip", "left in place (tick 'also remove fields' to drop them)")

        tail = "Incidents were left untouched — close or delete them in ServiceNow if you want."
        if errors:
            yield _event("Done", "done", f"completed with {errors} error(s) — see the steps above")
        else:
            yield _event("Done", "done", f"ServiceNow integration removed. {tail}")
    finally:
        snow.close()


def status(*, instance: str, user: str, password: str) -> dict:
    """A quick 'is the integration configured on ServiceNow?' check for the Settings badge. Two cheap
    reads (the Business Rule + the webhook.url property). Returns a small dict with a ``state``:
      no_creds -> write-back credentials not set; not_configured -> neither piece present;
      partial -> only one present; configured -> both present; error -> a ServiceNow/HTTP problem."""
    if not (instance and user and password):
        return {"state": "no_creds"}
    snow = _Snow(instance, user, password)
    try:
        has_br = snow.find("sys_script", f"name={BR_NAME}^collection=incident") is not None
        has_prop = snow.find("sys_properties", f"name={PROP_PREFIX}webhook.url") is not None
        if has_br and has_prop:
            state = "configured"
        elif has_br or has_prop:
            state = "partial"
        else:
            state = "not_configured"
        return {"state": state, "business_rule": has_br, "properties": has_prop}
    except httpx.HTTPError as exc:
        return {"state": "error", "detail": _http_reason(exc)}
    finally:
        snow.close()


def details(*, instance: str, user: str, password: str) -> dict:
    """List the ServiceNow objects the integration created/uses, each with a deep link, for the
    'view configuration' modal. Read-only; the webhook token value is masked."""
    if not (instance and user and password):
        return {"state": "no_creds", "items": []}
    snow = _Snow(instance, user, password)
    base = snow.base
    items: list = []
    try:
        br = snow.find("sys_script", f"name={BR_NAME}^collection=incident")
        has_br = br is not None
        if has_br:
            items.append({"kind": "Business Rule", "label": BR_NAME,
                          "url": f"{base}/sys_script.do?sys_id={br['sys_id']}"})
        props_present = 0
        for name in ("webhook.url", "webhook.token", "server_id", "layer", "apply"):
            key = PROP_PREFIX + name
            p = snow.find("sys_properties", f"name={key}", fields="sys_id,value")
            if p:
                props_present += 1
                val = "••••••••" if name == "webhook.token" else (p.get("value") or "")
                items.append({"kind": "Property", "label": key, "value": val,
                              "url": f"{base}/sys_properties.do?sys_id={p['sys_id']}"})
        if snow.find("sys_dictionary", "name=incident^elementSTARTSWITHu_source"):
            items.append({"kind": "Custom fields", "label": "incident u_* request columns",
                          "url": f"{base}/sys_dictionary_list.do?sysparm_query=name=incident^elementSTARTSWITHu_"})
        state = "configured" if (has_br and props_present) else ("partial" if (has_br or props_present) else "not_configured")
        return {"state": state, "instance": base, "items": items}
    except httpx.HTTPError as exc:
        return {"state": "error", "detail": _http_reason(exc), "items": []}
    finally:
        snow.close()
