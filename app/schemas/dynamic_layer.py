"""Dynamic Layer (Gaia API 'set-dynamic-content') object specs, payload builder, and the
apply engine that mirrors the gateway's show-task result (change-summary + validation).

The gateway-side API takes `objects` (definitions to create), `access-layers-content` (the
rulebase), and `referenced-objects` (names defined elsewhere). Objects created this way are
temporary and gateway-scoped. We don't deeply validate every field (the gateway does that);
the engine focuses on names + reference resolution, which is what drives change-summary and
the realistic "used but not defined" warnings.
"""
from __future__ import annotations

# --- Supported object types (full coverage of the documented set-dynamic-content examples) --
# Each spec drives the builder UI; the engine only requires a `name` and passes fields through.
# kind: text | ip | int | bool | list (comma-separated) | json (free-form)
OBJECT_SPECS: dict[str, dict] = {
    "hosts": {"label": "Host", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "ip-address", "label": "IP address", "kind": "ip", "required": True},
    ]},
    "networks": {"label": "Network", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "subnet4", "label": "IPv4 subnet", "kind": "ip"},
        {"name": "mask-length4", "label": "IPv4 mask length", "kind": "int"},
        {"name": "subnet6", "label": "IPv6 subnet", "kind": "ip"},
        {"name": "mask-length6", "label": "IPv6 mask length", "kind": "int"},
    ]},
    "address-ranges": {"label": "Address range", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "ipv4-address-first", "label": "IPv4 first", "kind": "ip"},
        {"name": "ipv4-address-last", "label": "IPv4 last", "kind": "ip"},
        {"name": "ipv6-address-first", "label": "IPv6 first", "kind": "ip"},
        {"name": "ipv6-address-last", "label": "IPv6 last", "kind": "ip"},
    ]},
    "wildcards": {"label": "Wildcard", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "ipv4-address", "label": "IPv4 address", "kind": "ip"},
        {"name": "ipv4-mask-wildcard", "label": "IPv4 wildcard mask", "kind": "ip"},
        {"name": "ipv6-address", "label": "IPv6 address", "kind": "ip"},
        {"name": "ipv6-mask-wildcard", "label": "IPv6 wildcard mask", "kind": "ip"},
    ]},
    "services-tcp": {"label": "Service (TCP)", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "port", "label": "Port", "kind": "text", "required": True},
        {"name": "source-port", "label": "Source port", "kind": "text"},
        {"name": "session-timeout", "label": "Session timeout", "kind": "int"},
    ]},
    "services-udp": {"label": "Service (UDP)", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "port", "label": "Port", "kind": "text", "required": True},
        {"name": "source-port", "label": "Source port", "kind": "text"},
        {"name": "accept-replies", "label": "Accept replies", "kind": "bool"},
    ]},
    "services-icmp": {"label": "Service (ICMP)", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "icmp-type", "label": "ICMP type", "kind": "int"},
        {"name": "icmp-code", "label": "ICMP code", "kind": "int"},
    ]},
    "services-other": {"label": "Service (Other)", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "ip-protocol", "label": "IP protocol", "kind": "int", "required": True},
        {"name": "accept-replies", "label": "Accept replies", "kind": "bool"},
    ]},
    "service-groups": {"label": "Service group", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "members", "label": "Members", "kind": "list", "required": True},
    ]},
    "network-groups": {"label": "Network group", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "members", "label": "Members", "kind": "list", "required": True},
    ]},
    "groups-with-exclusion": {"label": "Group with exclusion", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "include", "label": "Include", "kind": "text", "required": True},
        {"name": "except", "label": "Except", "kind": "text", "required": True},
    ]},
    "application-sites": {"label": "Application site", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "clone-of", "label": "Clone of", "kind": "text"},
        {"name": "url-list", "label": "URL list", "kind": "list"},
        {"name": "services", "label": "Services", "kind": "text"},
    ]},
    "application-site-groups": {"label": "Application site group", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "members", "label": "Members", "kind": "list", "required": True},
    ]},
    "dynamic-objects": {"label": "Dynamic object", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
    ]},
    "dns-domains": {"label": "DNS domain", "fields": [
        {"name": "name", "label": "Name (e.g. .example.com)", "kind": "text", "required": True},
        {"name": "is-sub-domain", "label": "Is sub-domain", "kind": "bool"},
    ]},
    "access-roles": {"label": "Access role", "fields": [
        {"name": "name", "label": "Name", "kind": "text", "required": True},
        {"name": "users", "label": "Users (any / all identified / names)", "kind": "text"},
        {"name": "networks", "label": "Networks (any / names)", "kind": "text"},
        {"name": "machines", "label": "Machines (JSON, optional)", "kind": "json"},
    ]},
}

OBJECT_TYPES = list(OBJECT_SPECS.keys())

# Reference categories for externally-defined names (referenced-objects).
REFERENCE_TYPES = [
    "access-layers", "application-sites", "application-site-categories",
    "services-tcp", "services-udp", "services-icmp", "updatable-objects",
]

RULE_ACTIONS = ["Accept", "Drop", "Reject", "Drop with Block message", "Ask", "Inform"]
TRACK_TYPES = ["None", "Log", "Detailed Log", "Extended Log", "Alert"]
OPERATIONS = ["replace"]

# Names that always resolve on the gateway without being defined/referenced.
BUILTIN_REFS = {"any", "internet", "_gw_", "all identified", "all_internet", "none"}


def _names_in(value) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def referenced_object_names(objects: dict, rulebase: list, referenced_map: dict | None = None) -> list[str]:
    """Names a layer's rules use that are NOT defined in the layer and not built-in — i.e. objects
    resolved elsewhere on the gateway (predefined services, applications, …). Unions an explicit
    referenced-objects map (minus access-layers, which is the layer itself). Drives the
    'Referenced objects' views."""
    defined = {o["name"] for items in (objects or {}).values() for o in (items or [])
               if isinstance(o, dict) and o.get("name")}
    seen: set[str] = set()
    out: list[str] = []

    def add(name) -> None:
        if not isinstance(name, str):
            return
        n = name.strip()
        if n and n not in defined and n.lower() not in BUILTIN_REFS and n not in seen:
            seen.add(n)
            out.append(n)

    for r in (rulebase or []):
        if isinstance(r, dict):
            for field in ("source", "destination", "service"):
                for n in _names_in(r.get(field)):
                    add(n)
    for category, names in (referenced_map or {}).items():
        if category != "access-layers":
            for n in (names or []):
                add(n)
    return sorted(out)


def build_set_dynamic_content(layer, *, dry_run: bool = False) -> dict:
    """Assemble the exact Gaia API 'set-dynamic-content' request body from a stored layer."""
    c = layer.content or {}
    objects = {k: v for k, v in (c.get("objects") or {}).items() if v}
    rulebase = c.get("rulebase") or []

    refs = dict(c.get("referenced_objects") or {})
    access_layers = list(refs.get("access-layers") or [])
    if layer.layer_name not in access_layers:
        access_layers.append(layer.layer_name)
    refs["access-layers"] = access_layers
    refs = {k: v for k, v in refs.items() if v}

    payload: dict = {
        "comments": c.get("comments", ""),
        "tags": c.get("tags", []),
        "dry-run": bool(dry_run),
        "referenced-objects": refs,
        "objects": objects,
        "access-layers-content": [{
            "name": layer.layer_name,
            "operation": c.get("operation", "replace"),
            "rulebase": rulebase,
        }],
    }
    if c.get("custom_fields"):
        payload["custom-fields"] = c["custom_fields"]
    return payload


def evaluate_dynamic_content(payload: dict) -> dict:
    """Mirror an R82 gateway processing set-dynamic-content: produce a show-task-style result
    with a change-summary and validation warnings/errors."""
    objects = payload.get("objects") or {}
    layers = payload.get("access-layers-content") or []
    refs = payload.get("referenced-objects") or {}

    defined: set[str] = set()
    for items in objects.values():
        for o in (items or []):
            if isinstance(o, dict) and o.get("name"):
                defined.add(o["name"])
    referenced: set[str] = set()
    for names in refs.values():
        for n in (names or []):
            referenced.add(n)

    def resolves(name) -> bool:
        name = "" if name is None else str(name)   # rule cells may hold a non-string (e.g. a port int)
        return (not name) or name.lower() in BUILTIN_REFS or name in defined or name in referenced

    errors: list[dict] = []
    warnings: list[dict] = []
    layer_summaries: list[dict] = []

    if not layers:
        errors.append({"layer": "", "rule": "", "object": "",
                       "message": "No access-layers-content provided."})

    for layer in layers:
        lname = layer.get("name", "")
        rule_names: list[str] = []
        for i, r in enumerate(layer.get("rulebase") or []):
            rn = r.get("name") or f"rule-{i + 1}"
            rule_names.append(rn)
            if not r.get("action"):
                errors.append({"layer": lname, "rule": rn, "object": "",
                               "message": f"Rule '{rn}' is missing an action."})
            for field in ("source", "destination", "service"):
                for nm in _names_in(r.get(field)):
                    if not resolves(nm):
                        warnings.append({"layer": lname, "rule": rn, "object": nm,
                                         "message": f"Object '{nm}' is used in the policy but not "
                                                    f"defined on the Security Gateway."})
        layer_summaries.append({"name": lname,
                                "rules": {"create": rule_names, "delete": [], "modify": []}})

    change_summary = {
        "layers": layer_summaries,
        "objects": {"create": sorted(defined), "delete": [], "modify": []},
    }
    ok = not errors
    return {
        "status": "succeeded" if ok else "failed",
        "status_code": 200 if ok else 400,
        "change_summary": change_summary,
        "validation_warnings": warnings,
        "validation_errors": errors,
        "dry_run": bool(payload.get("dry-run", False)),
        "comments": payload.get("comments", ""),
        "tags": payload.get("tags", []),
    }


def validate_layer_content(content: dict) -> None:
    """Light validation when saving an authored layer (the gateway/dry-run does the deep checks)."""
    objects = content.get("objects") or {}
    if not isinstance(objects, dict):
        raise ValueError("Objects must be a JSON object mapping each type to a list.")
    for t, items in objects.items():
        if t not in OBJECT_SPECS:
            raise ValueError(f"Unknown object type: {t!r}")
        if items is not None and not isinstance(items, list):
            raise ValueError(f"Objects for {t!r} must be a JSON list.")
        for o in (items or []):
            if not isinstance(o, dict) or not o.get("name"):
                raise ValueError(f"Every {t} object needs a name.")
    rulebase = content.get("rulebase") or []
    if not isinstance(rulebase, list):
        raise ValueError("The rulebase must be a JSON list of rules.")
    if not rulebase:
        raise ValueError("Add at least one rule to the layer.")
    for i, r in enumerate(rulebase):
        if not isinstance(r, dict):
            raise ValueError(f"Rule #{i + 1} must be a JSON object.")
        if not r.get("name"):
            raise ValueError(f"Rule #{i + 1} needs a name.")
        if not r.get("action"):
            raise ValueError(f"Rule '{r.get('name')}' needs an action.")
