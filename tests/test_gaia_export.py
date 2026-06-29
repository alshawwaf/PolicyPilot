"""Gaia OS config exporter: render Terraform / Ansible / clish from a pulled config (no device)."""
from app.services import gaia_export

CFG = {
    "hostname": {"name": "fw-poc-01"},
    "dns": {"primary": "8.8.8.8", "secondary": "1.1.1.1", "suffix": "lab.local"},
    "ntp": {"enabled": True, "servers": [
        {"address": "192.0.2.10", "type": "primary", "version": 4},
        {"address": "192.0.2.11", "type": "secondary", "version": 4}]},
    "time": {"timezone": "Asia / Jerusalem"},
    "interfaces": [
        {"name": "eth1", "ipv4-address": "10.0.1.1", "ipv4-mask-length": 24,
         "enabled": True, "mtu": 1500, "comments": "LAN",
         "ipv6-address": "2001:db8::1", "ipv6-mask-length": 64, "speed": "10G",
         "auto-negotiation": True, "mac-addr": "00:1c:7f:11:22:33"},
        {"name": "eth9"}],                       # no IP → skipped
    "routes": [
        {"address": "192.168.50.0", "mask-length": 24, "type": "gateway", "comment": "to lab",
         "rank": 60, "ping": True, "scope-local": False,
         "next-hop": [{"gateway": "10.0.1.254", "priority": 1}]},
        {"address": "0.0.0.0", "mask-length": 0, "type": "gateway",
         "next-hop": [{"gateway": "10.0.1.1", "priority": "default"}]}],   # default route, no priority
    "proxy": {"address": "proxy.lab.local", "port": 8080},
}


def test_gaia_stats():
    s = gaia_export.generate(CFG)["stats"]
    assert s["interfaces"] == 1 and s["routes"] == 2 and s["ntp_servers"] == 2   # eth9 (no IP) skipped
    for sec in ("hostname", "dns", "ntp", "time", "interfaces", "routes", "proxy"):
        assert sec in s["sections"]


def test_gaia_terraform():
    tf = gaia_export.generate(CFG)["terraform"]
    assert 'context = "gaia_api"' in tf                       # Gaia mode of the provider
    assert 'resource "checkpoint_gaia_hostname" "this"' in tf and 'name = "fw-poc-01"' in tf
    assert 'resource "checkpoint_gaia_dns" "this"' in tf and 'suffix = "lab.local"' in tf
    assert "servers {" in tf and 'address = "192.0.2.10"' in tf and "version = 4" in tf
    assert 'timezone = "Asia / Jerusalem"' in tf
    assert 'resource "checkpoint_gaia_physical_interface" "if_eth1"' in tf
    assert "ipv4_mask_length = 24" in tf and "mtu = 1500" in tf
    assert 'ipv6_address = "2001:db8::1"' in tf and "ipv6_mask_length = 64" in tf   # full iface fields
    assert 'speed = "10G"' in tf and "auto_negotiation = true" in tf and 'mac_addr = "00:1c:7f:11:22:33"' in tf
    assert "if_eth9" not in tf                                 # unconfigured interface skipped
    assert "next_hop {" in tf and 'gateway = "10.0.1.254"' in tf and "priority = 1" in tf
    assert "rank = 60" in tf and "ping = true" in tf           # full static-route fields
    assert 'resource "checkpoint_gaia_proxy" "this"' in tf and "port = 8080" in tf


def test_gaia_ansible_matches_collection_conventions():
    ans = gaia_export.generate(CFG)["ansible"]
    assert "connection: httpapi" in ans and "gather_facts: false" in ans
    assert "- check_point.gaia" in ans                         # collections: key
    assert "ansible_network_os=check_point.gaia.checkpoint" in ans   # inventory hint
    assert "cp_gaia_hostname:" in ans and 'name: "fw-poc-01"' in ans
    assert "cp_gaia_ntp:" in ans and 'servers: [{ address: "192.0.2.10", type: "primary", version: 4 }' in ans
    assert "cp_gaia_static_route:" in ans and "state: present" in ans
    assert 'next_hop: [{ gateway: "10.0.1.254", priority: 1 }]' in ans
    assert "cp_gaia_proxy:" in ans
    assert "vault" in ans.lower()                              # password sourced from Vault, never inlined


def test_gaia_clish():
    sh = gaia_export.generate(CFG)["clish"]
    assert "set hostname fw-poc-01" in sh
    assert "set dns primary 8.8.8.8" in sh and "set dns suffix lab.local" in sh
    assert "set ntp active on" in sh and "set ntp server primary 192.0.2.10 version 4" in sh
    assert 'set timezone "Asia / Jerusalem"' in sh
    assert "set interface eth1 ipv4-address 10.0.1.1 mask-length 24" in sh
    assert "set interface eth1 ipv6-address 2001:db8::1 mask-length 64" in sh and "set interface eth1 speed 10G" in sh
    assert "set static-route 192.168.50.0/24 nexthop gateway address 10.0.1.254 priority 1 on" in sh
    assert "set static-route 192.168.50.0/24 rank 60" in sh and "set static-route 192.168.50.0/24 ping on" in sh
    assert "set static-route default nexthop gateway address 10.0.1.1 on" in sh   # default route, no priority
    assert "set proxy address proxy.lab.local port 8080" in sh
    assert sh.strip().endswith("save config")


def test_gaia_web_api_ops():
    """Gaia web_api target: replayable set-*/add-* op list (POST /gaia_api/<command> bodies)."""
    import json as _json
    ops = _json.loads(gaia_export.generate(CFG)["web_api"])
    cmds = [o["command"] for o in ops]
    assert "set-hostname" in cmds and "set-static-route" in cmds and "set-physical-interface" in cmds
    iface = next(o for o in ops if o["command"] == "set-physical-interface")
    assert iface["body"]["ipv4-address"] == "10.0.1.1" and iface["body"]["ipv6-address"] == "2001:db8::1"
    route = next(o for o in ops if o["command"] == "set-static-route")
    assert route["body"]["next-hop"][0]["gateway"] == "10.0.1.254" and route["body"]["rank"] == 60


def test_gaia_generate_is_resilient_to_empty_config():
    art = gaia_export.generate({})                            # device returned nothing → never crash
    assert art["stats"]["interfaces"] == 0 and art["stats"]["sections"] == []
    assert 'context = "gaia_api"' in art["terraform"]
    assert "save config" in art["clish"]


def test_gaia_extra_interface_types():
    """vlan / bond / bridge / loopback render across all four targets, incl. clish create commands."""
    import json as _json
    cfg = {
        "vlan_interfaces": [{"name": "eth1.100", "ipv4-address": "10.1.2.1", "ipv4-mask-length": 24,
                             "enabled": True, "mtu": 1500}],
        "bond_interfaces": [{"name": "bond0", "ipv4-address": "10.1.3.1", "ipv4-mask-length": 24,
                             "mode": "8023AD", "lacp-rate": "slow", "members": ["eth2", "eth3"]}],
        "bridge_interfaces": [{"name": "br0", "members": [{"name": "eth4"}, {"name": "eth5"}]}],
        "loopback_interfaces": [{"name": "loop0", "ipv4-address": "1.1.1.1", "ipv4-mask-length": 32}],
    }
    art = gaia_export.generate(cfg)
    assert art["stats"]["interfaces"] == 4
    tf = art["terraform"]
    for slug in ("vlan", "bond", "bridge", "loopback"):
        assert f'resource "checkpoint_gaia_{slug}_interface"' in tf
    assert 'members = ["eth2", "eth3"]' in tf                     # bond members resolved
    cl = art["clish"]
    assert "add interface eth1 vlan 100" in cl                    # vlan create
    assert "add bonding group 0" in cl and "add bonding group 0 interface eth2" in cl
    assert "set bonding group 0 mode 8023AD" in cl
    assert "add bridging group 0 interface eth4" in cl
    cmds = [o["command"] for o in _json.loads(art["web_api"])]
    assert {"set-vlan-interface", "set-bond-interface", "set-bridge-interface",
            "set-loopback-interface"} <= set(cmds)
    assert "cp_gaia_bond_interface:" in art["ansible"]
