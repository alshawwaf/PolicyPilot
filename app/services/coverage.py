"""Serve the bundled, spec-generated coverage artifacts to the /coverage page.

Reads the versioned JSON produced by ``tools/build_coverage.py`` (in ``app/coverage_data/``): every
object/command, its full field set with per-field **API / Terraform / Ansible** support, and a web_api
JSON example. Provides the object list (grouped + with object-level support), and, per object, the
field-level diff + the **four** example forms (web_api JSON / mgmt_cli / Terraform / Ansible).
"""
from __future__ import annotations

import functools
import json
import os
import re

ART_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "coverage_data")


# --- artifact loading -------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _index() -> list[dict]:
    try:
        with open(os.path.join(ART_DIR, "index.json")) as f:
            return json.load(f).get("artifacts", [])
    except (OSError, ValueError):
        return []


@functools.lru_cache(maxsize=32)
def _artifact(api_type: str, version: str) -> dict:
    for a in _index():
        if a["api_type"] == api_type and a["version"] == version:
            with open(os.path.join(ART_DIR, a["file"])) as f:
                return json.load(f)
    return {}


def _vkey(v: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", v)] or [0]


def versions() -> dict[str, list[str]]:
    """Available versions per api_type, newest first (numeric sort: v1.10 > v1.9)."""
    out: dict[str, list[str]] = {}
    for a in _index():
        out.setdefault(a["api_type"], []).append(a["version"])
    for k in out:
        out[k] = sorted(set(out[k]), key=_vkey, reverse=True)
    return out


def latest(api_type: str) -> str:
    v = versions().get(api_type, [])
    return v[0] if v else ""


# --- categorisation (group the flat object list) ----------------------------------------------

_MGMT_CATS = [
    ("Services", lambda n: n.startswith("service-")),
    ("Applications", lambda n: n.startswith("application-")),
    ("Access policy", lambda n: n.startswith("access-") and n != "access-role"),
    ("NAT", lambda n: n.startswith("nat-")),
    ("Threat Prevention", lambda n: n.startswith(("threat-", "ips-")) or n == "exception-group"),
    ("HTTPS Inspection", lambda n: n.startswith("https-")),
    ("VPN", lambda n: n.startswith("vpn-")),
    ("Identity / users / servers", lambda n: n in {"access-role", "identity-tag", "identity-provider",
        "user", "user-group", "user-template", "administrator", "ldap-group", "radius-group",
        "radius-server", "tacacs-group", "tacacs-server", "securid-server", "trusted-client", "api-key"}),
    ("Data Center", lambda n: "data-center" in n),
    ("Network objects", lambda n: n in {"host", "network", "group", "address-range", "group-with-exclusion",
        "multicast-address-range", "wildcard", "dns-domain", "security-zone", "tag", "dynamic-object",
        "dynamic-global-network-object", "simple-gateway", "simple-cluster", "checkpoint-host",
        "interoperable-device", "gsn-handover-group", "updatable-object", "logical-server", "time", "time-group"}),
]
_GAIA_CATS = [
    ("Interfaces", lambda n: "interface" in n or n == "ipv6"),
    ("Routing", lambda n: any(x in n for x in ("route", "bgp", "ospf", "rip", "pim", "isis", "igmp", "mld", "pbr"))),
    ("Services", lambda n: n in {"dns", "ntp", "proxy", "dhcp-server", "dhcp6-server", "dhcp6-config",
        "snmp", "snmp-user", "snmp-trap-receiver", "snmp-custom-trap", "syslog", "remote-syslog", "arp", "lldp"}),
    ("AAA / access", lambda n: n in {"user", "role", "system-group", "radius", "tacacs", "allowed-clients",
        "password-policy", "ssh-server-settings", "expert-password", "grub-password", "authentication-order"}),
    ("System", lambda n: n in {"hostname", "hostname-on-login-page", "time-and-date", "banner",
        "message-of-the-day", "domainname"}),
]


def _category(api_type: str, name: str) -> str:
    cats = _MGMT_CATS if api_type == "management" else _GAIA_CATS
    for label, match in cats:
        if match(name):
            return label
    return "Other"


def object_groups(api_type: str, version: str) -> list[dict]:
    """Objects grouped by category, each with object-level API/TF/Ansible support + field counts."""
    art = _artifact(api_type, version)
    buckets: dict[str, list] = {}
    for o in art.get("objects", []):
        stored = [f for f in o["fields"] if not f.get("request_only")]
        n = len(stored)
        tf_fields = sum(1 for f in stored if f["tf"])
        ansible_fields = sum(1 for f in stored if f["ansible"])
        has_tf = o["terraform"] is not None
        has_ansible = o["ansible"] is not None
        # "Fully supported" = the tool has the object AND covers every managed field. request-only
        # params are already excluded from `stored`, so a shortfall here is a genuine field gap (e.g.
        # subordinate-ca 7/8), not an n/a artefact — surfaced so partials aren't hidden behind a green Yes.
        tf_full = has_tf and tf_fields >= n
        ans_full = has_ansible and ansible_fields >= n
        row = {
            "name": o["name"], "command": o["command"],
            "has_tf": has_tf, "has_ansible": has_ansible,
            "fields": n, "tf_fields": tf_fields, "ansible_fields": ansible_fields,
            "tf_full": tf_full, "ans_full": ans_full, "full": tf_full and ans_full,
        }
        buckets.setdefault(_category(api_type, o["name"]), []).append(row)
    order = [c[0] for c in (_MGMT_CATS if api_type == "management" else _GAIA_CATS)] + ["Other"]
    out = []
    for cat in order:
        rows = sorted(buckets.get(cat, []), key=lambda r: r["name"])
        if rows:
            out.append({"title": cat, "rows": rows, "total": len(rows),
                        # object-level misses (kept for back-compat) + the richer "not fully supported"
                        # count (object OR field gap) that drives the header badge + "gaps only" filter.
                        "gaps": sum(1 for r in rows if not (r["has_tf"] and r["has_ansible"])),
                        "incomplete": sum(1 for r in rows if not r["full"])})
    return out


# --- per-object detail: field diff + the four example forms -----------------------------------

def _u(name: str) -> str:
    return name.replace("-", "_")


def _hcl(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_hcl(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{_u(k)} = {_hcl(x)}" for k, x in v.items()) + " }"
    return '"' + str(v).replace('"', '\\"') + '"'


def _tf_assign(key, v, indent) -> list[str]:
    """Render a value as HCL: a dict → a ``key { }`` block, a list-of-dicts → repeated blocks, anything
    else → ``key = <value>``. The Check Point provider models nested settings (nat_settings, interfaces,
    host_servers, hours_ranges, …) as blocks, not map assignments — so this keeps the example valid HCL."""
    pad = "  " * indent
    if isinstance(v, dict):
        out = [f"{pad}{key} {{"]
        for k, x in v.items():
            out += _tf_assign(_u(k), x, indent + 1)
        out.append(f"{pad}}}")
        return out
    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
        out = []
        for item in v:
            out.append(f"{pad}{key} {{")
            for k, x in item.items():
                out += _tf_assign(_u(k), x, indent + 1)
            out.append(f"{pad}}}")
        return out
    return [f"{pad}{key} = {_hcl(v)}"]


def _yaml(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_yaml(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{_u(k)}: {_yaml(x)}" for k, x in v.items()) + " }"
    return '"' + str(v).replace('"', '\\"') + '"'


def _cli_arg(key, v) -> list[str]:
    if isinstance(v, list):
        return [f'{key}.{i} {_cli_scalar(x)}' for i, x in enumerate(v, 1)]
    if isinstance(v, dict):
        out = []
        for k, x in v.items():
            out += _cli_arg(f"{key}.{k}", x)
        return out
    return [f"{key} {_cli_scalar(v)}"]


def _cli_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return '"' + str(v).replace('"', '\\"') + '"'


def _examples(obj: dict, api_type: str) -> dict:
    cmd, ex = obj["command"], obj.get("example", {})
    fmap = {f["name"]: f for f in obj["fields"]}   # carries the real per-tool field name
    base = "/web_api/" if api_type == "management" else "/gaia_api/"   # Gaia uses gaia_api, NOT web_api

    out = {"web_api": (f"POST {base}{cmd}\nContent-Type: application/json\nX-chkp-sid: <session id>\n\n"
                       + json.dumps(ex, indent=2))}

    # mgmt_cli is a Management-API tool only; Gaia's CLI is clish (per-command syntax — not shown here).
    if api_type == "management":
        cli_parts = []
        for k, v in ex.items():
            cli_parts += _cli_arg(k, v)
        out["mgmt_cli"] = f"mgmt_cli {cmd.replace('-', ' ', 1)} " + " ".join(cli_parts) + " -s id.txt"

    if obj["terraform"]:
        header = ['# provider "checkpoint" { context = "gaia_api" }'] if api_type == "gaia" else []
        tf_lines, seen = header + [f'resource "{obj["terraform"]}" "example" {{'], set()
        for k, v in ex.items():
            tn = (fmap.get(k) or {}).get("tf_name")   # real TF arg (ip-address -> ipv4_address); None = skip
            if tn and tn not in seen:
                seen.add(tn)
                tf_lines += _tf_assign(tn, v, 1)      # dict/list-of-dicts → blocks, scalars → key = value
        tf_lines.append("}")
        out["terraform"] = "\n".join(tf_lines)
    else:
        out["terraform"] = f"# No Terraform resource for {obj['name']}."

    if obj["ansible"]:
        coll = "check_point.mgmt" if api_type == "management" else "check_point.gaia"
        ans_lines, seen = [f"- name: Add {obj['name']}", f"  {coll}.{obj['ansible']}:"], set()
        for k, v in ex.items():
            an = (fmap.get(k) or {}).get("ansible_name")
            if an and an not in seen:
                seen.add(an)
                ans_lines.append(f"    {an}: {_yaml(v)}")
        ans_lines.append("    state: present")
        out["ansible"] = "\n".join(ans_lines)
    else:
        out["ansible"] = f"# No Ansible module for {obj['name']}."

    return out


# Documentation links so the user can verify support / browse fields per tool. The "api" link points at the
# portal's OWN integrated API explorer (this project vendors the CP-Docs-To-Swagger converter as
# app.services.cp_docs) — a relative URL on the current site, never a retired external service.


def _doc_urls(api_type: str, obj: dict) -> dict:
    docs = {"api": f"/api-explorer?api={api_type}"}
    if obj["terraform"]:
        # The Check Point provider's registry doc slug KEEPS the resource prefix (the doc files are named
        # checkpoint_<resource>.html.markdown) — unlike most providers — so do NOT strip "checkpoint_".
        docs["terraform"] = ("https://registry.terraform.io/providers/CheckPointSW/checkpoint/latest/"
                             f"docs/resources/{obj['terraform']}")
    if obj["ansible"]:
        coll = "mgmt" if api_type == "management" else "gaia"
        docs["ansible"] = (f"https://docs.ansible.com/ansible/latest/collections/check_point/{coll}/"
                          f"{obj['ansible']}_module.html")
    return docs


def object_detail(api_type: str, version: str, name: str) -> dict:
    art = _artifact(api_type, version)
    obj = next((o for o in art.get("objects", []) if o["name"] == name), None)
    if not obj:
        return {"error": "Object not found."}
    fields = [{"name": f["name"], "type": f.get("type", "string"), "required": f.get("required", False),
               "request_only": f.get("request_only", False),
               "api": f["api"], "tf": f["tf"], "ansible": f["ansible"],
               "tf_name": f.get("tf_name"), "ansible_name": f.get("ansible_name")} for f in obj["fields"]]
    return {"name": obj["name"], "command": obj["command"], "terraform": obj["terraform"],
            "ansible": obj["ansible"], "fields": fields, "examples": _examples(obj, api_type),
            "docs": _doc_urls(api_type, obj)}


def page_context(api_type: str, version: str) -> dict:
    art = _artifact(api_type, version)
    return {"api_type": api_type, "version": version, "versions": versions(),
            "tool_versions": art.get("tool_versions", {}), "object_count": art.get("object_count", 0),
            "groups": object_groups(api_type, version)}
