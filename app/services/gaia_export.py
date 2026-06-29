"""Export a Check Point appliance's **Gaia OS configuration** (hostname, DNS, NTP, timezone, physical
interfaces, static routes, proxy) to Infrastructure-as-Code — for a gateway OR an SMS (both run Gaia).

Pulls the live config over the **Gaia REST API** (``login`` → ``show-*`` → ``logout``, TLS pinned, never
skip-verify) and renders three targets:
  * **Terraform** — the ``CheckPointSW/checkpoint`` provider in ``context = "gaia_api"`` mode
    (``checkpoint_gaia_*`` resources).
  * **Ansible** — the ``check_point.gaia`` collection over ``connection: httpapi`` (matching the
    conventions in the user's Ansible_Check_Point_Gaia_Playbooks: one play, ``gather_facts: false``,
    ``collections: [check_point.gaia]``, bare ``cp_gaia_*`` modules, ``servers``/``next_hop`` as inline
    lists of dicts).
  * **clish** — native Gaia CLI ``set``/``save config`` commands.

Secrets are NEVER inlined into generated code — the Ansible inventory sources the password from Vault /
env, Terraform from a variable. Pure ``generate(cfg)`` is unit-tested without a device.
"""
from __future__ import annotations

import json
import re
import ssl
import time

import httpx

GAIA_VERSION = "v1.9"   # matches apply_runner's Gaia API version
_SECTIONS = ("hostname", "dns", "ntp", "time", "interfaces", "routes", "proxy")


# --- pull over the Gaia REST API -------------------------------------------------------------

def _pinned_ssl_context(cert_pem: str) -> ssl.SSLContext:
    """Trust ONLY the pinned cert (CERT_REQUIRED, TLS 1.2+, hostname check off — the reviewed pin is
    the identity check). Never a skip-verify path."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=cert_pem)
    return ctx


def _login_error(resp) -> str:
    try:
        body = resp.json() or {}
        msg = body.get("message") or body.get("errors") or body.get("error") or ""
    except Exception:  # noqa: BLE001
        msg = ""
    if resp.status_code in (401, 403):
        return f"Gaia login failed ({resp.status_code}): the device rejected the credentials" + (
            f" — {msg}" if msg else "") + "."
    return f"Gaia login failed (HTTP {resp.status_code})." + (f" {msg}" if msg else "")


def pull_gaia(host: str, port: int, user: str, secret: str, cert_pem: str | None = None) -> dict:
    """Read the OS config over the Gaia API. Returns {ok, config, trace, error}."""
    verify = _pinned_ssl_context(cert_pem) if (cert_pem or "").strip() else True
    base = f"https://{host}:{port}/gaia_api/{GAIA_VERSION}"
    cfg: dict = {}
    trace: list[dict] = []

    def rec(cmd, resp, t0):
        trace.append({"command": cmd, "status": getattr(resp, "status_code", 0),
                      "ms": round((time.perf_counter() - t0) * 1000)})

    try:
        with httpx.Client(verify=verify, timeout=30.0) as c:
            t = time.perf_counter()
            try:
                login = c.post(f"{base}/login", json={"user": user, "password": secret})
            except (httpx.ConnectError, ssl.SSLError, httpx.ConnectTimeout) as exc:
                return {"ok": False, "config": {}, "trace": trace,
                        "error": f"Could not reach {host}:{port} over TLS — {exc}. Check the host/port, "
                                 "firewall, and the pinned cert / auto-trust."}
            rec("login", login, t)
            if login.status_code >= 400:
                return {"ok": False, "config": {}, "trace": trace, "error": _login_error(login)}
            sid = (login.json() or {}).get("sid")
            if not sid:
                return {"ok": False, "config": {}, "trace": trace,
                        "error": "Gaia login returned no session id (sid)."}
            headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}

            def show(cmd, body=None):
                t0 = time.perf_counter()
                r = c.post(f"{base}/{cmd}", json=body or {}, headers=headers)
                rec(cmd, r, t0)
                try:
                    return r.json() or {}
                except Exception:  # noqa: BLE001
                    return {}

            try:
                cfg["hostname"] = show("show-hostname")
                cfg["dns"] = show("show-dns")
                cfg["ntp"] = show("show-ntp")
                cfg["time"] = show("show-time-and-date")
                cfg["interfaces"] = show("show-physical-interfaces", {"limit": 500}).get("objects", [])
                cfg["vlan_interfaces"] = show("show-vlan-interfaces", {"limit": 500}).get("objects", [])
                cfg["bond_interfaces"] = show("show-bond-interfaces", {"limit": 500}).get("objects", [])
                cfg["bridge_interfaces"] = show("show-bridge-interfaces", {"limit": 500}).get("objects", [])
                cfg["loopback_interfaces"] = show("show-loopback-interfaces", {"limit": 500}).get("objects", [])
                cfg["routes"] = show("show-static-routes", {"limit": 500}).get("objects", [])
                cfg["proxy"] = show("show-proxy")
            finally:
                try:
                    c.post(f"{base}/logout", headers=headers)
                except Exception:  # noqa: BLE001
                    pass
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "config": cfg, "trace": trace, "error": f"Gaia request failed: {exc}"}
    return {"ok": True, "config": cfg, "trace": trace, "error": None}


def pull_and_generate(host: str, port: int, user: str, secret: str, cert_pem: str | None = None) -> dict:
    pulled = pull_gaia(host, port, user, secret, cert_pem)
    if not pulled["ok"]:
        return {"error": pulled["error"], "trace": pulled.get("trace", [])}
    art = generate(pulled["config"])
    art["trace"] = pulled.get("trace", [])
    return art


# --- helpers ---------------------------------------------------------------------------------

def _q(s) -> str:
    text = re.sub(r"\s*\n\s*", " ", str(s)).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _clq(s) -> str:
    """A clish-safe double-quoted argument: collapse newlines and neutralise embedded double-quotes so
    a comment / value can't break out of (or inject into) the generated set-command."""
    return '"' + re.sub(r"\s*\n\s*", " ", str(s)).replace('"', "'") + '"'


def _slug(s: str, used: set[str]) -> str:
    out = re.sub(r"[^0-9A-Za-z_]", "_", str(s or "")).strip("_").lower() or "x"
    if out[0].isdigit():
        out = "n_" + out
    cand, i = out, 2
    while cand in used:
        cand, i = f"{out}_{i}", i + 1
    used.add(cand)
    return cand


def _present(v) -> bool:
    return not (v is None or (isinstance(v, str) and v == ""))


def _route_dst(r: dict) -> str:
    addr, mask = r.get("address"), r.get("mask-length")
    if str(addr) in ("0.0.0.0", "default") and str(mask) in ("0", "", "None"):
        return "default"
    return f"{addr}/{mask}"


def _priority(nh: dict):
    p = nh.get("priority")
    if p is None or str(p).strip().lower() == "default":
        return None
    return int(p) if str(p).lstrip("-").isdigit() else None


def _iface_ip(i: dict) -> bool:
    return _present(i.get("ipv4-address"))


# --- extra interface types (vlan / bond / bridge / loopback) ----------------------------------
# Common L3 fields on every Gaia interface; bonds add link-aggregation params; bonds+bridges add members.
# Each (cp-key, kind) → rendered with the tool's arg name (hyphens→underscores for TF/Ansible).
_IFACE_COMMON = [("ipv4-address", "str"), ("ipv4-mask-length", "int"), ("ipv6-address", "str"),
                 ("ipv6-mask-length", "int"), ("ipv6-autoconfig", "bool"), ("enabled", "bool"),
                 ("mtu", "int"), ("comments", "str")]
_BOND_EXTRA = [("mode", "str"), ("lacp-rate", "str"), ("xmit-hash-policy", "str"), ("mii-interval", "int"),
               ("min-links", "int"), ("up-delay", "int"), ("down-delay", "int"), ("primary", "str")]
# (config key set by pull_gaia, slug for resource/module/command, extra fields, carries a members list)
_IFACE_TYPES = [
    ("vlan_interfaces", "vlan", [], False),
    ("bond_interfaces", "bond", _BOND_EXTRA, True),
    ("bridge_interfaces", "bridge", [], True),
    ("loopback_interfaces", "loopback", [], False),
]


def _members(i: dict) -> list[str]:
    return [m.get("name") if isinstance(m, dict) else m for m in (i.get("members") or []) if m]


def _iface_count(cfg: dict) -> int:
    return sum(len(cfg.get(key) or []) for key, *_ in _IFACE_TYPES)


def _iface_tf(cfg: dict) -> list[str]:
    out, used = [], set()
    for key, slug, extra, has_members in _IFACE_TYPES:
        for i in cfg.get(key) or []:
            blk = [f'resource "checkpoint_gaia_{slug}_interface" "{_slug(slug + "_" + str(i.get("name", "")), used)}" {{',
                   f'  name = {_q(i.get("name", ""))}']
            for cpk, knd in _IFACE_COMMON + extra:
                v = i.get(cpk)
                if knd == "bool" and cpk in i:
                    blk.append(f'  {cpk.replace("-", "_")} = {"true" if v else "false"}')
                elif knd == "int" and str(v).lstrip("-").isdigit():
                    blk.append(f'  {cpk.replace("-", "_")} = {v}')
                elif knd == "str" and _present(v):
                    blk.append(f'  {cpk.replace("-", "_")} = {_q(v)}')
            if has_members and _members(i):
                blk.append("  members = [%s]" % ", ".join(_q(m) for m in _members(i)))
            out += [*blk, "}", ""]
    return out


def _iface_ansible(cfg: dict) -> list[str]:
    out = []
    for key, slug, extra, has_members in _IFACE_TYPES:
        for i in cfg.get(key) or []:
            out.append(f'    - name: {slug.capitalize()} interface {i.get("name", "")}')
            out.append(f"      cp_gaia_{slug}_interface:")
            out.append(f'        name: {_q(i.get("name", ""))}')
            for cpk, knd in _IFACE_COMMON + extra:
                v = i.get(cpk)
                if knd == "bool" and cpk in i:
                    out.append(f'        {cpk.replace("-", "_")}: {"true" if v else "false"}')
                elif knd == "int" and str(v).lstrip("-").isdigit():
                    out.append(f'        {cpk.replace("-", "_")}: {v}')
                elif knd == "str" and _present(v):
                    out.append(f'        {cpk.replace("-", "_")}: {_q(v)}')
            if has_members and _members(i):
                out.append(f"        members: {_yaml_dict_list([_q(m) for m in _members(i)])}")
            out.append("        state: present")
    return out


def _iface_web_api(cfg: dict) -> list[dict]:
    ops = []
    for key, slug, extra, has_members in _IFACE_TYPES:
        for i in cfg.get(key) or []:
            body = {"name": i.get("name", "")}
            for cpk, knd in _IFACE_COMMON + extra:
                v = i.get(cpk)
                if knd == "bool" and cpk in i:
                    body[cpk] = bool(v)
                elif knd == "int" and str(v).lstrip("-").isdigit():
                    body[cpk] = int(v)
                elif knd == "str" and _present(v):
                    body[cpk] = v
            if has_members and _members(i):
                body["members"] = _members(i)
            ops.append({"command": f"set-{slug}-interface", "body": body})
    return ops


def _clish_set_iface(i: dict) -> list[str]:
    """The `set interface <name> …` lines shared once an interface exists (any type)."""
    nm, out = i.get("name", ""), []
    if _present(i.get("ipv4-address")) and str(i.get("ipv4-mask-length", "")).isdigit():
        out.append(f'set interface {nm} ipv4-address {i.get("ipv4-address")} mask-length {i.get("ipv4-mask-length")}')
    if _present(i.get("ipv6-address")) and str(i.get("ipv6-mask-length", "")).isdigit():
        out.append(f'set interface {nm} ipv6-address {i.get("ipv6-address")} mask-length {i.get("ipv6-mask-length")}')
    if "enabled" in i:
        out.append(f'set interface {nm} state {"on" if i.get("enabled") else "off"}')
    if str(i.get("mtu", "")).isdigit():
        out.append(f'set interface {nm} mtu {i.get("mtu")}')
    if _present(i.get("comments")):
        out.append(f'set interface {nm} comments {_clq(i.get("comments"))}')
    return out


def _iface_clish(cfg: dict) -> list[str]:
    """Native Gaia clish, including the create command each type needs before `set` (the VLAN parent/id,
    the bonding/bridging group + member adds)."""
    out: list[str] = []
    for i in cfg.get("loopback_interfaces") or []:        # loopbacks pre-exist (loopN) — just set
        out += _clish_set_iface(i)
    for i in cfg.get("vlan_interfaces") or []:
        nm = i.get("name", "")
        if "." in nm:                                     # eth1.100 → add interface eth1 vlan 100
            parent, vid = nm.rsplit(".", 1)
            out.append(f"add interface {parent} vlan {vid}")
        out += _clish_set_iface(i)
    for i in cfg.get("bond_interfaces") or []:
        nm = i.get("name", "")
        gid = nm[4:] if nm.startswith("bond") else nm     # bond0 → group 0
        out.append(f"add bonding group {gid}")
        for m in _members(i):
            out.append(f"add bonding group {gid} interface {m}")
        for cpk in ("mode", "lacp-rate", "xmit-hash-policy", "mii-interval", "min-links",
                    "up-delay", "down-delay", "primary"):
            if _present(i.get(cpk)):
                out.append(f"set bonding group {gid} {cpk} {i.get(cpk)}")
        out += _clish_set_iface(i)
    for i in cfg.get("bridge_interfaces") or []:
        nm = i.get("name", "")
        gid = nm[2:] if nm.startswith("br") else nm       # br0 → group 0
        out.append(f"add bridging group {gid}")
        for m in _members(i):
            out.append(f"add bridging group {gid} interface {m}")
        out += _clish_set_iface(i)
    return out


# --- Terraform (checkpoint_gaia_*, context = "gaia_api") --------------------------------------

def _tf(cfg: dict) -> str:
    L = ['# Terraform export of Check Point Gaia OS configuration.',
         '# Provider: CheckPointSW/checkpoint in Gaia mode (context = "gaia_api").',
         '# Set the provider server/credentials (use a variable / env — do not inline secrets).',
         "",
         "terraform {", "  required_providers {", "    checkpoint = {",
         '      source = "CheckPointSW/checkpoint"', "    }", "  }", "}", "",
         'provider "checkpoint" {',
         '  # server   = "GW_OR_SMS_IP"',
         '  # username = "admin"',
         '  # password = var.checkpoint_password',
         '  context = "gaia_api"', "}", ""]

    name = (cfg.get("hostname") or {}).get("name")
    if _present(name):
        L += [f'resource "checkpoint_gaia_hostname" "this" {{', f"  name = {_q(name)}", "}", ""]

    dns = cfg.get("dns") or {}
    dns_lines = [f"  {k} = {_q(dns[k])}" for k in ("primary", "secondary", "tertiary", "suffix")
                 if _present(dns.get(k))]
    if dns_lines:
        L += ['resource "checkpoint_gaia_dns" "this" {', *dns_lines, "}", ""]

    ntp = cfg.get("ntp") or {}
    servers = ntp.get("servers") or []
    if servers or "enabled" in ntp:
        block = ['resource "checkpoint_gaia_ntp" "this" {',
                 f'  enabled = {"true" if ntp.get("enabled", True) else "false"}']
        for s in servers:
            block.append("  servers {")
            block.append(f'    address = {_q(s.get("address", ""))}')
            if _present(s.get("type")):
                block.append(f'    type = {_q(s.get("type"))}')
            if str(s.get("version", "")).isdigit():
                block.append(f'    version = {s.get("version")}')
            block.append("  }")
        L += [*block, "}", ""]

    tz = (cfg.get("time") or {}).get("timezone")
    if _present(tz):
        L += ['resource "checkpoint_gaia_time_and_date" "this" {', f"  timezone = {_q(tz)}", "}", ""]

    used: set[str] = set()
    for i in cfg.get("interfaces") or []:
        if not _iface_ip(i):
            continue
        slug = _slug("if_" + str(i.get("name", "")), used)
        blk = [f'resource "checkpoint_gaia_physical_interface" "{slug}" {{',
               f'  name = {_q(i.get("name", ""))}',
               f'  ipv4_address = {_q(i.get("ipv4-address"))}']
        if str(i.get("ipv4-mask-length", "")).isdigit():
            blk.append(f'  ipv4_mask_length = {i.get("ipv4-mask-length")}')
        for cpk, tfk in (("ipv6-address", "ipv6_address"), ("mac-addr", "mac_addr"),
                         ("speed", "speed"), ("duplex", "duplex")):
            if _present(i.get(cpk)):
                blk.append(f'  {tfk} = {_q(i.get(cpk))}')
        if str(i.get("ipv6-mask-length", "")).isdigit():
            blk.append(f'  ipv6_mask_length = {i.get("ipv6-mask-length")}')
        if str(i.get("mtu", "")).isdigit():
            blk.append(f'  mtu = {i.get("mtu")}')
        for cpk, tfk in (("enabled", "enabled"), ("ipv6-autoconfig", "ipv6_autoconfig"),
                         ("auto-negotiation", "auto_negotiation"), ("monitor-mode", "monitor_mode")):
            if cpk in i:
                blk.append(f'  {tfk} = {"true" if i.get(cpk) else "false"}')
        for cpk, tfk in (("rx-ringsize", "rx_ringsize"), ("tx-ringsize", "tx_ringsize")):
            if str(i.get(cpk, "")).isdigit():
                blk.append(f'  {tfk} = {i.get(cpk)}')
        if _present(i.get("comments")):
            blk.append(f'  comments = {_q(i.get("comments"))}')
        L += [*blk, "}", ""]

    L += _iface_tf(cfg)            # vlan / bond / bridge / loopback interfaces

    rused: set[str] = set()
    for r in cfg.get("routes") or []:
        slug = _slug("route_" + _route_dst(r).replace("/", "_").replace(".", "_"), rused)
        rtype = r.get("type") or "gateway"
        blk = [f'resource "checkpoint_gaia_static_route" "{slug}" {{',
               f'  address = {_q("0.0.0.0" if _route_dst(r) == "default" else r.get("address"))}',
               f'  mask_length = {r.get("mask-length", 0) if str(r.get("mask-length", "")).isdigit() else 0}',
               f"  type = {_q(rtype)}"]
        if _present(r.get("comment")):
            blk.append(f'  comment = {_q(r.get("comment"))}')
        if str(r.get("rank", "")).isdigit():
            blk.append(f'  rank = {r.get("rank")}')
        for cpk, tfk in (("ping", "ping"), ("scope-local", "scope_local")):
            if cpk in r:
                blk.append(f'  {tfk} = {"true" if r.get(cpk) else "false"}')
        if rtype == "gateway":
            for nh in r.get("next-hop") or []:
                blk.append("  next_hop {")
                blk.append(f'    gateway = {_q(nh.get("gateway", ""))}')
                pr = _priority(nh)
                if pr is not None:
                    blk.append(f"    priority = {pr}")
                blk.append("  }")
        L += [*blk, "}", ""]

    proxy = cfg.get("proxy") or {}
    if _present(proxy.get("address")):
        blk = ['resource "checkpoint_gaia_proxy" "this" {', f'  address = {_q(proxy.get("address"))}']
        if str(proxy.get("port", "")).isdigit():
            blk.append(f'  port = {proxy.get("port")}')
        L += [*blk, "}", ""]

    return "\n".join(L).rstrip() + "\n"


# --- Ansible (check_point.gaia over httpapi) --------------------------------------------------

def _yaml_dict_list(items: list[str]) -> str:
    return "[" + ", ".join(items) + "]"


def _ansible(cfg: dict) -> str:
    L = ['# Ansible export of Check Point Gaia OS configuration (collection: check_point.gaia).',
         '#',
         '# Inventory (hosts) — source the password from Ansible Vault / env, never inline:',
         '#   [checkpoint]',
         '#   gw ansible_host=GW_OR_SMS_IP',
         '#   [checkpoint:vars]',
         '#   ansible_user=admin',
         '#   ansible_network_os=check_point.gaia.checkpoint',
         '#   ansible_connection=httpapi',
         '#   ansible_httpapi_use_ssl=True',
         '#   ansible_httpapi_validate_certs=False',
         '#   # ansible_password: "{{ vault_gaia_password }}"',
         '#',
         '# Run:  ansible-galaxy collection install check_point.gaia',
         '#       ansible-playbook -i hosts gaia_config.yml',
         "---",
         "- name: Restore Check Point Gaia OS configuration",
         "  hosts: checkpoint",
         "  connection: httpapi",
         "  gather_facts: false",
         "  collections:",
         "    - check_point.gaia",
         "  tasks:"]

    def task(title, module, lines):
        L.append(f"    - name: {title}")
        L.append(f"      {module}:")
        L.extend(f"        {ln}" for ln in lines)

    name = (cfg.get("hostname") or {}).get("name")
    if _present(name):
        task("Hostname", "cp_gaia_hostname", [f"name: {_q(name)}"])

    dns = cfg.get("dns") or {}
    dns_lines = [f"{k}: {_q(dns[k])}" for k in ("primary", "secondary", "tertiary", "suffix")
                 if _present(dns.get(k))]
    if dns_lines:
        task("DNS", "cp_gaia_dns", dns_lines)

    ntp = cfg.get("ntp") or {}
    servers = ntp.get("servers") or []
    if servers or "enabled" in ntp:
        items = []
        for s in servers:
            parts = [f'address: {_q(s.get("address", ""))}']
            if _present(s.get("type")):
                parts.append(f'type: {_q(s.get("type"))}')
            if str(s.get("version", "")).isdigit():
                parts.append(f'version: {s.get("version")}')
            items.append("{ " + ", ".join(parts) + " }")
        lines = [f'enabled: {"true" if ntp.get("enabled", True) else "false"}']
        if items:
            lines.append("servers: " + _yaml_dict_list(items))
        task("NTP", "cp_gaia_ntp", lines)

    tz = (cfg.get("time") or {}).get("timezone")
    if _present(tz):
        task("Time / timezone", "cp_gaia_time_and_date", [f"timezone: {_q(tz)}"])

    for i in cfg.get("interfaces") or []:
        if not _iface_ip(i):
            continue
        lines = [f'name: {_q(i.get("name", ""))}', f'ipv4_address: {_q(i.get("ipv4-address"))}']
        if str(i.get("ipv4-mask-length", "")).isdigit():
            lines.append(f'ipv4_mask_length: {i.get("ipv4-mask-length")}')
        for cpk, ak in (("ipv6-address", "ipv6_address"), ("mac-addr", "mac_addr"),
                        ("speed", "speed"), ("duplex", "duplex")):
            if _present(i.get(cpk)):
                lines.append(f'{ak}: {_q(i.get(cpk))}')
        if str(i.get("ipv6-mask-length", "")).isdigit():
            lines.append(f'ipv6_mask_length: {i.get("ipv6-mask-length")}')
        if str(i.get("mtu", "")).isdigit():
            lines.append(f'mtu: {i.get("mtu")}')
        for cpk, ak in (("enabled", "enabled"), ("ipv6-autoconfig", "ipv6_autoconfig"),
                        ("auto-negotiation", "auto_negotiation"), ("monitor-mode", "monitor_mode")):
            if cpk in i:
                lines.append(f'{ak}: {"true" if i.get(cpk) else "false"}')
        for cpk, ak in (("rx-ringsize", "rx_ringsize"), ("tx-ringsize", "tx_ringsize")):
            if str(i.get(cpk, "")).isdigit():
                lines.append(f'{ak}: {i.get(cpk)}')
        if _present(i.get("comments")):
            lines.append(f'comments: {_q(i.get("comments"))}')
        task(f'Interface {i.get("name", "")}', "cp_gaia_physical_interface", lines)

    L += _iface_ansible(cfg)       # vlan / bond / bridge / loopback interfaces

    for r in cfg.get("routes") or []:
        rtype = r.get("type") or "gateway"
        lines = ["state: present",
                 f'address: {_q("0.0.0.0" if _route_dst(r) == "default" else r.get("address"))}',
                 f'mask_length: {r.get("mask-length", 0) if str(r.get("mask-length", "")).isdigit() else 0}',
                 f"type: {_q(rtype)}"]
        if _present(r.get("comment")):
            lines.append(f'comment: {_q(r.get("comment"))}')
        if str(r.get("rank", "")).isdigit():
            lines.append(f'rank: {r.get("rank")}')
        for cpk, ak in (("ping", "ping"), ("scope-local", "scope_local")):
            if cpk in r:
                lines.append(f'{ak}: {"true" if r.get(cpk) else "false"}')
        if rtype == "gateway":
            hops = []
            for nh in r.get("next-hop") or []:
                parts = [f'gateway: {_q(nh.get("gateway", ""))}']
                pr = _priority(nh)
                if pr is not None:
                    parts.append(f"priority: {pr}")
                hops.append("{ " + ", ".join(parts) + " }")
            if hops:
                lines.append("next_hop: " + _yaml_dict_list(hops))
        task(f"Static route {_route_dst(r)}", "cp_gaia_static_route", lines)

    proxy = cfg.get("proxy") or {}
    if _present(proxy.get("address")):
        lines = ["state: present", f'address: {_q(proxy.get("address"))}']
        if str(proxy.get("port", "")).isdigit():
            lines.append(f'port: {proxy.get("port")}')
        task("Proxy", "cp_gaia_proxy", lines)

    return "\n".join(L).rstrip() + "\n"


# --- clish script -----------------------------------------------------------------------------

def _clish(cfg: dict) -> str:
    L = ["# Gaia clish restore script. Run inside clish, or:  clish -f gaia_config.clish",
         "# Review before applying; it ends with 'save config' to persist.", ""]

    name = (cfg.get("hostname") or {}).get("name")
    if _present(name):
        L.append(f"set hostname {name}")

    dns = cfg.get("dns") or {}
    for k in ("primary", "secondary", "tertiary", "suffix"):
        if _present(dns.get(k)):
            L.append(f"set dns {k} {dns[k]}")

    ntp = cfg.get("ntp") or {}
    if ntp.get("servers") or "enabled" in ntp:
        L.append(f'set ntp active {"on" if ntp.get("enabled", True) else "off"}')
        for s in ntp.get("servers") or []:
            tier = s.get("type") or "primary"
            ver = f' version {s.get("version")}' if str(s.get("version", "")).isdigit() else ""
            L.append(f'set ntp server {tier} {s.get("address", "")}{ver}')

    tz = (cfg.get("time") or {}).get("timezone")
    if _present(tz):
        L.append(f'set timezone "{tz}"')

    for i in cfg.get("interfaces") or []:
        if not _iface_ip(i):
            continue
        nm = i.get("name", "")
        if str(i.get("ipv4-mask-length", "")).isdigit():
            L.append(f'set interface {nm} ipv4-address {i.get("ipv4-address")} mask-length {i.get("ipv4-mask-length")}')
        if "enabled" in i:
            L.append(f'set interface {nm} state {"on" if i.get("enabled") else "off"}')
        if str(i.get("mtu", "")).isdigit():
            L.append(f'set interface {nm} mtu {i.get("mtu")}')
        if _present(i.get("ipv6-address")) and str(i.get("ipv6-mask-length", "")).isdigit():
            L.append(f'set interface {nm} ipv6-address {i.get("ipv6-address")} mask-length {i.get("ipv6-mask-length")}')
        for cpk, kw in (("auto-negotiation", "auto-negotiation"), ("monitor-mode", "monitor-mode")):
            if cpk in i:
                L.append(f'set interface {nm} {kw} {"on" if i.get(cpk) else "off"}')
        for cpk, kw in (("speed", "speed"), ("duplex", "duplex"), ("mac-addr", "mac-addr")):
            if _present(i.get(cpk)):
                L.append(f'set interface {nm} {kw} {i.get(cpk)}')
        if _present(i.get("comments")):
            L.append(f'set interface {nm} comments {_clq(i.get("comments"))}')

    L += _iface_clish(cfg)         # vlan / bond / bridge / loopback (incl. their create commands)

    for r in cfg.get("routes") or []:
        dst = _route_dst(r)
        rtype = r.get("type") or "gateway"
        if rtype == "gateway":
            for nh in r.get("next-hop") or []:
                pr = _priority(nh)
                prs = f" priority {pr}" if pr is not None else ""
                L.append(f'set static-route {dst} nexthop gateway address {nh.get("gateway", "")}{prs} on')
        else:
            L.append(f"set static-route {dst} nexthop {rtype}")
        if str(r.get("rank", "")).isdigit():
            L.append(f"set static-route {dst} rank {r.get('rank')}")
        if r.get("ping"):
            L.append(f"set static-route {dst} ping on")

    proxy = cfg.get("proxy") or {}
    if _present(proxy.get("address")):
        port = f' port {proxy.get("port")}' if str(proxy.get("port", "")).isdigit() else ""
        L.append(f'set proxy address {proxy.get("address")}{port}')

    L += ["", "save config"]
    return "\n".join(L).rstrip() + "\n"


def _web_api(cfg: dict) -> str:
    """Replayable Gaia backup: ordered web_api set-*/add-* ops (POST /gaia_api/<command>)."""
    ops = []
    name = (cfg.get("hostname") or {}).get("name")
    if _present(name):
        ops.append({"command": "set-hostname", "body": {"name": name}})
    dns = cfg.get("dns") or {}
    db = {k: dns[k] for k in ("primary", "secondary", "tertiary", "suffix") if _present(dns.get(k))}
    if db:
        ops.append({"command": "set-dns", "body": db})
    ntp = cfg.get("ntp") or {}
    if ntp.get("servers") or "enabled" in ntp:
        servers = [{k: s.get(k) for k in ("address", "type", "version") if s.get(k) is not None}
                   for s in ntp.get("servers") or []]
        ops.append({"command": "set-ntp", "body": {"enabled": bool(ntp.get("enabled", True)), "servers": servers}})
    tz = (cfg.get("time") or {}).get("timezone")
    if _present(tz):
        ops.append({"command": "set-time-and-date", "body": {"timezone": tz}})
    for i in cfg.get("interfaces") or []:
        if not _iface_ip(i):
            continue
        body = {"name": i.get("name", "")}
        for k in ("ipv4-address", "ipv4-mask-length", "ipv6-address", "ipv6-mask-length", "mtu",
                  "comments", "speed", "duplex", "mac-addr", "rx-ringsize", "tx-ringsize"):
            if _present(i.get(k)):
                body[k] = i[k]
        for k in ("enabled", "ipv6-autoconfig", "auto-negotiation", "monitor-mode"):
            if k in i:
                body[k] = bool(i[k])
        ops.append({"command": "set-physical-interface", "body": body})
    ops += _iface_web_api(cfg)     # vlan / bond / bridge / loopback interfaces
    for r in cfg.get("routes") or []:
        body = {"address": "0.0.0.0" if _route_dst(r) == "default" else r.get("address"),
                "mask-length": r.get("mask-length"), "type": r.get("type") or "gateway"}
        if body["type"] == "gateway" and r.get("next-hop"):
            body["next-hop"] = [{"gateway": nh.get("gateway"),
                                 **({"priority": _priority(nh)} if _priority(nh) is not None else {})}
                                for nh in r["next-hop"]]
        if str(r.get("rank", "")).isdigit():
            body["rank"] = r["rank"]
        for k in ("ping", "scope-local"):
            if k in r:
                body[k] = bool(r[k])
        if _present(r.get("comment")):
            body["comment"] = r["comment"]
        ops.append({"command": "set-static-route", "body": body})
    proxy = cfg.get("proxy") or {}
    if _present(proxy.get("address")):
        body = {"address": proxy.get("address")}
        if str(proxy.get("port", "")).isdigit():
            body["port"] = proxy["port"]
        ops.append({"command": "set-proxy", "body": body})
    return json.dumps(ops, indent=2)


def generate(cfg: dict) -> dict:
    """Render a pulled Gaia config dict to all four targets + stats. Pure."""
    ifaces = [i for i in (cfg.get("interfaces") or []) if _iface_ip(i)]
    routes = cfg.get("routes") or []
    sections = [s for s in _SECTIONS
                if (cfg.get(s) and (cfg[s] if s in ("interfaces", "routes") else
                                    any(_present(v) for v in (cfg[s] or {}).values())))]
    stats = {"sections": sections, "interfaces": len(ifaces) + _iface_count(cfg), "routes": len(routes),
             "ntp_servers": len((cfg.get("ntp") or {}).get("servers") or [])}
    return {"terraform": _tf(cfg), "ansible": _ansible(cfg), "clish": _clish(cfg),
            "web_api": _web_api(cfg), "stats": stats}
