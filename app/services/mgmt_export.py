"""Turn a pulled Check Point policy (a layer's rulebase + the objects it references) into
Infrastructure-as-Code — **Terraform** (``CheckPointSW/checkpoint``), **Ansible**
(``check_point.mgmt``) and a **mgmt_cli** shell script — as a config *backup-as-code*.

Goal: a faithful round-trip. For every supported object type we emit **all publicly-settable fields**
(name, color, comments, tags, the type-specific fields, and nested blocks such as NAT settings,
aggressive aging, host interfaces / server roles, time ranges) using the exact argument name each tool
expects. Field maps were built from the official docs (Terraform provider, check_point.mgmt Ansible
collection, web_api ``add-*`` reference) — see ``OBJ_SPECS``.

Design notes (mirroring CP's ExportImportPolicyPackage resilience):
  * **Never fail on an unknown object type** — it's counted under ``stats.skipped`` and commented, not
    dropped silently or crashed on.
  * **Predefined objects** (the read-only "Check Point Data" domain — ``Any``, predefined services, the
    ``Accept``/``Drop`` actions, ``Log`` track …) exist on every SMS, so they're referenced by name and
    never re-emitted.
  * **Group membership** is captured from the group's ``members`` (not a ``groups`` arg on each object —
    Terraform has no such arg, and it would be redundant), so the exported set is internally consistent.
  * **Order is preserved** — sections/rules emit top→bottom and append to the layer's bottom on restore;
    Terraform also gets a ``depends_on`` chain.
  * Object↔object and rule→object references resolve to real Terraform resource addresses when the
    target is in the export set, so ``terraform apply`` builds the dependency graph correctly; Ansible /
    mgmt_cli reference by name (objects are created before the rules/groups that use them).

Pure functions over the bundle ``mgmt_api.pull_for_export`` returns — no network — so fully unit-tested.
"""
from __future__ import annotations

import json
import re


# --- field model -----------------------------------------------------------------------------
# A field maps one source key (what ``show-*`` returns, hyphenated) to its argument name in each tool.
# kinds:
#   str | int | bool          scalar value
#   strlist                    list of plain strings (e.g. additional-ports, recurrence days)
#   names                      list of object references → resolved to TF resource addresses
#   namelist                   list of object names emitted as plain strings (tags — not ref-wired)
#   ref                        single object reference → TF resource address when in the set
#   weekdays                   list in Ansible/cli; comma-joined string in Terraform (TF arg is singular)
#   nested                     a dict → a block (sub = field list)
#   nestedlist                 a list of dicts → repeated blocks (sub = field list)
# A tool key of ``None`` means that tool doesn't expose the field (skip it there).
def F(src, tf, ans, cli, kind, sub=None):
    return {"src": src, "tf": tf, "ans": ans, "cli": cli, "kind": kind, "sub": sub}


# Common to (effectively) every object.
_COMMON = [
    F("color", "color", "color", "color", "str"),
    F("comments", "comments", "comments", "comments", "str"),
    F("tags", "tags", "tags", "tags", "namelist"),
]

# Shared nested blocks.
_NAT = F("nat-settings", "nat_settings", "nat_settings", "nat-settings", "nested", [
    F("auto-rule", "auto_rule", "auto_rule", "auto-rule", "bool"),
    F("ipv4-address", "ipv4_address", "ipv4_address", "ipv4-address", "str"),
    F("ipv6-address", "ipv6_address", "ipv6_address", "ipv6-address", "str"),
    F("hide-behind", "hide_behind", "hide_behind", "hide-behind", "str"),
    F("install-on", "install_on", "install_on", "install-on", "ref"),
    F("method", "method", "method", "method", "str"),
])
_AGING = F("aggressive-aging", "aggressive_aging", "aggressive_aging", "aggressive-aging", "nested", [
    F("enable", "enable", "enable", "enable", "bool"),
    F("timeout", "timeout", "timeout", "timeout", "int"),
    F("use-default-timeout", "use_default_timeout", "use_default_timeout", "use-default-timeout", "bool"),
    F("default-timeout", "default_timeout", "default_timeout", "default-timeout", "int"),
])
_HOST_IFACES = F("interfaces", "interfaces", "interfaces", "interfaces", "nestedlist", [
    F("name", "name", "name", "name", "str"),
    F("subnet4", "subnet4", "subnet4", "subnet4", "str"),
    F("subnet6", "subnet6", "subnet6", "subnet6", "str"),
    F("mask-length4", "mask_length4", "mask_length4", "mask-length4", "int"),
    F("mask-length6", "mask_length6", "mask_length6", "mask-length6", "int"),
    F("color", "color", "color", "color", "str"),
    F("comments", "comments", "comments", "comments", "str"),
])
_HOST_SERVERS = F("host-servers", "host_servers", "host_servers", "host-servers", "nested", [
    F("dns-server", "dns_server", "dns_server", "dns-server", "bool"),
    F("mail-server", "mail_server", "mail_server", "mail-server", "bool"),
    F("web-server", "web_server", "web_server", "web-server", "bool"),
    F("web-server-config", "web_server_config", "web_server_config", "web-server-config", "nested", [
        F("additional-ports", "additional_ports", "additional_ports", "additional-ports", "strlist"),
        F("application-engines", "application_engines", "application_engines", "application-engines", "strlist"),
        F("listen-standard-port", "listen_standard_port", "listen_standard_port", "listen-standard-port", "bool"),
        F("operating-system", "operating_system", "operating_system", "operating-system", "str"),
        F("protected-by", "protected_by", "protected_by", "protected-by", "ref"),
    ]),
])
_TIME_POINT = [   # shared by time.start / time.end
    F("date", "date", "date", "date", "str"),
    F("iso-8601", "iso_8601", "iso_8601", "iso-8601", "str"),
    F("posix", "posix", "posix", "posix", "int"),
    F("time", "time", "time", "time", "str"),
]
# Log-server reference lists shared by gateways / clusters / Check Point hosts (resolved to refs).
_LOG_TARGETS = [
    F("save-logs-locally", "save_logs_locally", "save_logs_locally", "save-logs-locally", "bool"),
    F("send-logs-to-server", "send_logs_to_server", "send_logs_to_server", "send-logs-to-server", "names"),
    F("send-logs-to-backup-server", "send_logs_to_backup_server", "send_logs_to_backup_server",
      "send-logs-to-backup-server", "names"),
    F("send-alerts-to-server", "send_alerts_to_server", "send_alerts_to_server", "send-alerts-to-server", "names"),
]
# Standard software-blade toggles on a gateway / cluster (1:1 hyphen→underscore in TF + Ansible). Only
# the blades actually returned by show-* are emitted (the _empty guard), so this superset is safe to share.
_GW_BLADES = [F(_b, _b.replace("-", "_"), _b.replace("-", "_"), _b, "bool") for _b in (
    "firewall", "vpn", "application-control", "url-filtering", "content-awareness", "ips",
    "anti-bot", "anti-virus", "threat-emulation", "threat-extraction", "identity-awareness",
    "mobile-access", "data-loss-prevention", "anti-spam-and-email-security", "monitoring",
    "zero-phishing", "icap-server", "hit-count", "nat-hide-internal-interfaces", "enable-https-inspection",
    "qos", "rtm-counters-report", "rtm-traffic-report", "rtm-traffic-report-per-connection",
    "show-portals-certificate",
)]
# Gateways/clusters/CP-hosts are managed devices: SIC trust, topology and the one-time-password are set
# up on the device, never exported. The object + its blades restore as code; finish setup on the gateway.
_SIC_NOTE = ("managed device — SIC trust, interface topology and one-time-password are established during "
             "gateway setup and are NOT exported; on restore, set up the gateway/SIC then install policy.")


# Per-type: Terraform resource, Ansible module, mgmt_cli object, and the type-specific fields.
# `_COMMON` is appended to every type below.
OBJ_SPECS: dict[str, dict] = {
    "host": {"tf": "checkpoint_management_host", "ansible": "cp_mgmt_host", "cli": "host", "fields": [
        F("ipv4-address", "ipv4_address", "ipv4_address", "ipv4-address", "str"),
        F("ipv6-address", "ipv6_address", "ipv6_address", "ipv6-address", "str"),
        _HOST_IFACES, _NAT, _HOST_SERVERS,
    ]},
    "network": {"tf": "checkpoint_management_network", "ansible": "cp_mgmt_network", "cli": "network", "fields": [
        F("subnet4", "subnet4", "subnet4", "subnet4", "str"),
        F("subnet6", "subnet6", "subnet6", "subnet6", "str"),
        F("mask-length4", "mask_length4", "mask_length4", "mask-length4", "int"),
        F("mask-length6", "mask_length6", "mask_length6", "mask-length6", "int"),
        F("broadcast", "broadcast", "broadcast", "broadcast", "str"),
        _NAT,
    ]},
    "address-range": {"tf": "checkpoint_management_address_range", "ansible": "cp_mgmt_address_range",
                      "cli": "address-range", "fields": [
        F("ipv4-address-first", "ipv4_address_first", "ipv4_address_first", "ipv4-address-first", "str"),
        F("ipv4-address-last", "ipv4_address_last", "ipv4_address_last", "ipv4-address-last", "str"),
        F("ipv6-address-first", "ipv6_address_first", "ipv6_address_first", "ipv6-address-first", "str"),
        F("ipv6-address-last", "ipv6_address_last", "ipv6_address_last", "ipv6-address-last", "str"),
        _NAT,
    ]},
    "group": {"tf": "checkpoint_management_group", "ansible": "cp_mgmt_group", "cli": "group", "fields": [
        F("members", "members", "members", "members", "names"),
    ]},
    "group-with-exclusion": {"tf": "checkpoint_management_group_with_exclusion",
                             "ansible": "cp_mgmt_group_with_exclusion", "cli": "group-with-exclusion", "fields": [
        F("include", "include", "include", "include", "ref"),
        F("except", "except", "except", "except", "ref"),
    ]},
    "wildcard": {"tf": "checkpoint_management_wildcard", "ansible": "cp_mgmt_wildcard", "cli": "wildcard", "fields": [
        F("ipv4-address", "ipv4_address", "ipv4_address", "ipv4-address", "str"),
        F("ipv4-mask-wildcard", "ipv4_mask_wildcard", "ipv4_mask_wildcard", "ipv4-mask-wildcard", "str"),
        F("ipv6-address", "ipv6_address", "ipv6_address", "ipv6-address", "str"),
        F("ipv6-mask-wildcard", "ipv6_mask_wildcard", "ipv6_mask_wildcard", "ipv6-mask-wildcard", "str"),
    ]},
    "multicast-address-range": {"tf": "checkpoint_management_multicast_address_range",
                                "ansible": "cp_mgmt_multicast_address_range",
                                "cli": "multicast-address-range", "fields": [
        F("ipv4-address", "ipv4_address", "ipv4_address", "ipv4-address", "str"),
        F("ipv6-address", "ipv6_address", "ipv6_address", "ipv6-address", "str"),
        F("ipv4-address-first", "ipv4_address_first", "ipv4_address_first", "ipv4-address-first", "str"),
        F("ipv4-address-last", "ipv4_address_last", "ipv4_address_last", "ipv4-address-last", "str"),
        F("ipv6-address-first", "ipv6_address_first", "ipv6_address_first", "ipv6-address-first", "str"),
        F("ipv6-address-last", "ipv6_address_last", "ipv6_address_last", "ipv6-address-last", "str"),
    ]},
    "dns-domain": {"tf": "checkpoint_management_dns_domain", "ansible": "cp_mgmt_dns_domain",
                   "cli": "dns-domain", "fields": [
        F("is-sub-domain", "is_sub_domain", "is_sub_domain", "is-sub-domain", "bool"),
    ]},
    "security-zone": {"tf": "checkpoint_management_security_zone", "ansible": "cp_mgmt_security_zone",
                      "cli": "security-zone", "fields": []},
    "tag": {"tf": "checkpoint_management_tag", "ansible": "cp_mgmt_tag", "cli": "tag", "fields": []},
    "service-tcp": {"tf": "checkpoint_management_service_tcp", "ansible": "cp_mgmt_service_tcp",
                    "cli": "service-tcp", "fields": [
        F("port", "port", "port", "port", "str"),
        F("source-port", "source_port", "source_port", "source-port", "str"),
        F("protocol", "protocol", "protocol", "protocol", "str"),
        F("match-by-protocol-signature", "match_by_protocol_signature", "match_by_protocol_signature",
          "match-by-protocol-signature", "bool"),
        F("match-for-any", "match_for_any", "match_for_any", "match-for-any", "bool"),
        F("override-default-settings", "override_default_settings", "override_default_settings",
          "override-default-settings", "bool"),
        F("enable-tcp-resource", "enable_tcp_resource", "enable_tcp_resource", "enable-tcp-resource", "bool"),
        F("use-delayed-sync", "use_delayed_sync", "use_delayed_sync", "use-delayed-sync", "bool"),
        F("delayed-sync-value", "delayed_sync_value", "delayed_sync_value", "delayed-sync-value", "int"),
        F("keep-connections-open-after-policy-installation", "keep_connections_open_after_policy_installation",
          "keep_connections_open_after_policy_installation", "keep-connections-open-after-policy-installation", "bool"),
        F("session-timeout", "session_timeout", "session_timeout", "session-timeout", "int"),
        F("use-default-session-timeout", "use_default_session_timeout", "use_default_session_timeout",
          "use-default-session-timeout", "bool"),
        F("sync-connections-on-cluster", "sync_connections_on_cluster", "sync_connections_on_cluster",
          "sync-connections-on-cluster", "bool"),
        _AGING,
    ]},
    "service-udp": {"tf": "checkpoint_management_service_udp", "ansible": "cp_mgmt_service_udp",
                    "cli": "service-udp", "fields": [
        F("port", "port", "port", "port", "str"),
        F("source-port", "source_port", "source_port", "source-port", "str"),
        F("protocol", "protocol", "protocol", "protocol", "str"),
        F("accept-replies", "accept_replies", "accept_replies", "accept-replies", "bool"),
        F("match-by-protocol-signature", "match_by_protocol_signature", "match_by_protocol_signature",
          "match-by-protocol-signature", "bool"),
        F("match-for-any", "match_for_any", "match_for_any", "match-for-any", "bool"),
        F("override-default-settings", "override_default_settings", "override_default_settings",
          "override-default-settings", "bool"),
        F("keep-connections-open-after-policy-installation", "keep_connections_open_after_policy_installation",
          "keep_connections_open_after_policy_installation", "keep-connections-open-after-policy-installation", "bool"),
        F("session-timeout", "session_timeout", "session_timeout", "session-timeout", "int"),
        F("use-default-session-timeout", "use_default_session_timeout", "use_default_session_timeout",
          "use-default-session-timeout", "bool"),
        F("sync-connections-on-cluster", "sync_connections_on_cluster", "sync_connections_on_cluster",
          "sync-connections-on-cluster", "bool"),
        _AGING,
    ]},
    "service-icmp": {"tf": "checkpoint_management_service_icmp", "ansible": "cp_mgmt_service_icmp",
                     "cli": "service-icmp", "fields": [
        F("icmp-type", "icmp_type", "icmp_type", "icmp-type", "int"),
        F("icmp-code", "icmp_code", "icmp_code", "icmp-code", "int"),
        F("keep-connections-open-after-policy-installation", "keep_connections_open_after_policy_installation",
          "keep_connections_open_after_policy_installation", "keep-connections-open-after-policy-installation", "bool"),
    ]},
    "service-other": {"tf": "checkpoint_management_service_other", "ansible": "cp_mgmt_service_other",
                      "cli": "service-other", "fields": [
        F("ip-protocol", "ip_protocol", "ip_protocol", "ip-protocol", "int"),
        F("protocol", "protocol", "protocol", "protocol", "str"),
        F("match", "match", "match", "match", "str"),
        F("action", "action", "action", "action", "str"),
        F("accept-replies", "accept_replies", "accept_replies", "accept-replies", "bool"),
        F("match-for-any", "match_for_any", "match_for_any", "match-for-any", "bool"),
        F("override-default-settings", "override_default_settings", "override_default_settings",
          "override-default-settings", "bool"),
        F("source-port", "source_port", "source_port", "source-port", "str"),
        F("keep-connections-open-after-policy-installation", "keep_connections_open_after_policy_installation",
          "keep_connections_open_after_policy_installation", "keep-connections-open-after-policy-installation", "bool"),
        F("session-timeout", "session_timeout", "session_timeout", "session-timeout", "int"),
        F("use-default-session-timeout", "use_default_session_timeout", "use_default_session_timeout",
          "use-default-session-timeout", "bool"),
        F("sync-connections-on-cluster", "sync_connections_on_cluster", "sync_connections_on_cluster",
          "sync-connections-on-cluster", "bool"),
        _AGING,
    ]},
    "service-group": {"tf": "checkpoint_management_service_group", "ansible": "cp_mgmt_service_group",
                      "cli": "service-group", "fields": [
        F("members", "members", "members", "members", "names"),
    ]},
    "service-dce-rpc": {"tf": "checkpoint_management_service_dce_rpc", "ansible": "cp_mgmt_service_dce_rpc",
                        "cli": "service-dce-rpc", "fields": [
        F("interface-uuid", "interface_uuid", "interface_uuid", "interface-uuid", "str"),
        F("keep-connections-open-after-policy-installation", "keep_connections_open_after_policy_installation",
          "keep_connections_open_after_policy_installation", "keep-connections-open-after-policy-installation", "bool"),
    ]},
    "service-rpc": {"tf": "checkpoint_management_service_rpc", "ansible": "cp_mgmt_service_rpc",
                    "cli": "service-rpc", "fields": [
        F("program-number", "program_number", "program_number", "program-number", "int"),
        F("keep-connections-open-after-policy-installation", "keep_connections_open_after_policy_installation",
          "keep_connections_open_after_policy_installation", "keep-connections-open-after-policy-installation", "bool"),
    ]},
    "service-sctp": {"tf": "checkpoint_management_service_sctp", "ansible": "cp_mgmt_service_sctp",
                     "cli": "service-sctp", "fields": [
        F("port", "port", "port", "port", "str"),
        F("source-port", "source_port", "source_port", "source-port", "str"),
        F("match-for-any", "match_for_any", "match_for_any", "match-for-any", "bool"),
        F("keep-connections-open-after-policy-installation", "keep_connections_open_after_policy_installation",
          "keep_connections_open_after_policy_installation", "keep-connections-open-after-policy-installation", "bool"),
        F("session-timeout", "session_timeout", "session_timeout", "session-timeout", "int"),
        F("use-default-session-timeout", "use_default_session_timeout", "use_default_session_timeout",
          "use-default-session-timeout", "bool"),
        F("sync-connections-on-cluster", "sync_connections_on_cluster", "sync_connections_on_cluster",
          "sync-connections-on-cluster", "bool"),
        _AGING,
    ]},
    "time": {"tf": "checkpoint_management_time", "ansible": "cp_mgmt_time", "cli": "time", "fields": [
        F("start", "start", "start", "start", "nested", _TIME_POINT),
        F("end", "end", "end", "end", "nested", _TIME_POINT),
        F("start-now", "start_now", "start_now", "start-now", "bool"),
        F("end-never", "end_never", "end_never", "end-never", "bool"),
        F("hours-ranges", "hours_ranges", "hours_ranges", "hours-ranges", "nestedlist", [
            F("enabled", "enabled", "enabled", "enabled", "bool"),
            F("from", "from", "from", "from", "str"),
            F("index", "index", "index", "index", "int"),
            F("to", "to", "to", "to", "str"),
        ]),
        F("recurrence", "recurrence", "recurrence", "recurrence", "nested", [
            F("days", "days", "days", "days", "strlist"),
            F("month", "month", "month", "month", "str"),
            F("pattern", "pattern", "pattern", "pattern", "str"),
            F("weekdays", "weekday", "weekdays", "weekdays", "weekdays"),   # TF singular; Ansible/cli list
        ]),
    ]},
    "service-icmp6": {"tf": "checkpoint_management_service_icmp6", "ansible": "cp_mgmt_service_icmp6",
                      "cli": "service-icmp6", "fields": [
        F("icmp-type", "icmp_type", "icmp_type", "icmp-type", "int"),
        F("icmp-code", "icmp_code", "icmp_code", "icmp-code", "int"),
        F("keep-connections-open-after-policy-installation", "keep_connections_open_after_policy_installation",
          "keep_connections_open_after_policy_installation", "keep-connections-open-after-policy-installation", "bool"),
    ]},
    "service-citrix-tcp": {"tf": "checkpoint_management_service_citrix_tcp", "ansible": "cp_mgmt_service_citrix_tcp",
                           "cli": "service-citrix-tcp", "fields": [
        F("application", "application", "application", "application", "str"),
    ]},
    "service-compound-tcp": {"tf": "checkpoint_management_service_compound_tcp",
                             "ansible": "cp_mgmt_service_compound_tcp", "cli": "service-compound-tcp", "fields": [
        F("compound-service", "compound_service", "compound_service", "compound-service", "str"),
        F("keep-connections-open-after-policy-installation", "keep_connections_open_after_policy_installation",
          "keep_connections_open_after_policy_installation", "keep-connections-open-after-policy-installation", "bool"),
    ]},
    "time-group": {"tf": "checkpoint_management_time_group", "ansible": "cp_mgmt_time_group",
                   "cli": "time-group", "fields": [
        F("members", "members", "members", "members", "names"),
    ]},
    "application-site": {"tf": "checkpoint_management_application_site", "ansible": "cp_mgmt_application_site",
                         "cli": "application-site", "fields": [
        F("primary-category", "primary_category", "primary_category", "primary-category", "str"),
        F("url-list", "url_list", "url_list", "url-list", "strlist"),
        F("urls-defined-as-regular-expression", "urls_defined_as_regular_expression",
          "urls_defined_as_regular_expression", "urls-defined-as-regular-expression", "bool"),
        F("additional-categories", "additional_categories", "additional_categories",
          "additional-categories", "strlist"),
        F("description", "description", "description", "description", "str"),
    ]},
    "application-site-group": {"tf": "checkpoint_management_application_site_group",
                               "ansible": "cp_mgmt_application_site_group", "cli": "application-site-group",
                               "fields": [F("members", "members", "members", "members", "names")]},
    "application-site-category": {"tf": "checkpoint_management_application_site_category",
                                  "ansible": "cp_mgmt_application_site_category", "cli": "application-site-category",
                                  "fields": [F("description", "description", "description", "description", "str")]},
    # --- gateways / hosts / VPN peers ----------------------------------------------------------
    "simple-gateway": {"tf": "checkpoint_management_simple_gateway", "ansible": "cp_mgmt_simple_gateway",
                       "cli": "simple-gateway", "fields": [
        F("ipv4-address", "ipv4_address", "ipv4_address", "ipv4-address", "str"),
        F("ipv6-address", "ipv6_address", "ipv6_address", "ipv6-address", "str"),
        F("version", "version", "version", "version", "str"),
        F("os-name", "os_name", "os_name", "os-name", "str"),
        F("hardware", "hardware", "hardware", "hardware", "str"),
        F("hardware-subtype", "hardware_subtype", "hardware_subtype", "hardware-subtype", "str"),
        F("auto-generate-ip", "auto_generate_ip", "auto_generate_ip", "auto-generate-ip", "bool"),
        F("threat-prevention-mode", "threat_prevention_mode", "threat_prevention_mode",
          "threat-prevention-mode", "str"),
        F("ips-update-policy", "ips_update_policy", "ips_update_policy", "ips-update-policy", "str"),
        _NAT, *_GW_BLADES, *_LOG_TARGETS,
    ], "note": _SIC_NOTE},
    "simple-cluster": {"tf": "checkpoint_management_simple_cluster", "ansible": "cp_mgmt_simple_cluster",
                       "cli": "simple-cluster", "fields": [
        F("ipv4-address", "ipv4_address", "ipv4_address", "ipv4-address", "str"),
        F("ipv6-address", "ipv6_address", "ipv6_address", "ipv6-address", "str"),
        F("version", "version", "version", "version", "str"),
        F("os-name", "os_name", "os_name", "os-name", "str"),
        F("hardware", "hardware", "hardware", "hardware", "str"),
        F("cluster-mode", "cluster_mode", "cluster_mode", "cluster-mode", "str"),
        F("geo-mode", "geo_mode", "geo_mode", "geo-mode", "bool"),
        F("threat-prevention-mode", "threat_prevention_mode", "threat_prevention_mode",
          "threat-prevention-mode", "str"),
        F("ips-update-policy", "ips_update_policy", "ips_update_policy", "ips-update-policy", "str"),
        _NAT, *_GW_BLADES, *_LOG_TARGETS,
    ], "note": _SIC_NOTE + " Cluster members and their interfaces are configured on the cluster object."},
    "checkpoint-host": {"tf": "checkpoint_management_checkpoint_host", "ansible": "cp_mgmt_checkpoint_host",
                        "cli": "checkpoint-host", "fields": [
        F("ipv4-address", "ipv4_address", "ipv4_address", "ipv4-address", "str"),
        F("ipv6-address", "ipv6_address", "ipv6_address", "ipv6-address", "str"),
        F("version", "version", "version", "version", "str"),
        F("hardware", "hardware", "hardware", "hardware", "str"),
        F("os", "os", "os", "os", "str"),
        _HOST_IFACES, _NAT, *_LOG_TARGETS,
    ], "note": _SIC_NOTE},
    "interoperable-device": {"tf": "checkpoint_management_interoperable_device",
                             "ansible": "cp_mgmt_interoperable_device", "cli": "interoperable-device", "fields": [
        F("ipv4-address", "ipv4_address", "ipv4_address", "ipv4-address", "str"),
        F("ipv6-address", "ipv6_address", "ipv6_address", "ipv6-address", "str"),
        F("autonomous-system-number", "autonomous_system_number", "autonomous_system_number",
          "autonomous-system-number", "str"),
        F("domains-to-process", "domains_to_process", "domains_to_process", "domains-to-process", "names"),
        _HOST_IFACES, _NAT,
    ]},
    "logical-server": {"tf": "checkpoint_management_logical_server", "ansible": "cp_mgmt_logical_server",
                       "cli": "logical-server", "fields": [
        F("ipv4-address", "ipv4_address", "ipv4_address", "ipv4-address", "str"),
        F("ipv6-address", "ipv6_address", "ipv6_address", "ipv6-address", "str"),
        F("server-type", "server_type", "server_type", "server-type", "str"),
        F("balance-method", "balance_method", "balance_method", "balance-method", "str"),
        F("persistency-type", "persistency_type", "persistency_type", "persistency-type", "str"),
        F("persistence-mode", "persistence_mode", "persistence_mode", "persistence-mode", "bool"),
        F("server-group", "server_group", "server_group", "server-group", "ref"),
    ]},
    # --- dynamic / identity / GTP objects ------------------------------------------------------
    "dynamic-object": {"tf": "checkpoint_management_dynamic_object", "ansible": "cp_mgmt_dynamic_object",
                       "cli": "dynamic-object", "fields": []},
    "gsn-handover-group": {"tf": "checkpoint_management_gsn_handover_group",
                           "ansible": "cp_mgmt_gsn_handover_group", "cli": "gsn-handover-group", "fields": [
        F("members", "members", "members", "members", "names"),
        F("enforce-gtp", "enforce_gtp", "enforce_gtp", "enforce-gtp", "bool"),
        F("gtp-rate", "gtp_rate", "gtp_rate", "gtp-rate", "int"),
    ]},
    "user-group": {"tf": "checkpoint_management_user_group", "ansible": "cp_mgmt_user_group",
                   "cli": "user-group", "fields": [
        F("members", "members", "members", "members", "names"),
        F("email", "email", "email", "email", "str"),
    ]},
    # access-role: networks export cleanly; users/machines are a show↔add format mismatch — flag, don't guess.
    "access-role": {"tf": "checkpoint_management_access_role", "ansible": "cp_mgmt_access_role",
                    "cli": "access-role", "fields": [
        F("networks", "networks", "networks", "networks", "names"),
    ], "note": "users / machines / remote-access-clients are not auto-exported (the show output and the "
               "add-access-role schema differ) — re-add identity sources manually."},
}
for _spec in OBJ_SPECS.values():
    _spec["fields"] = _spec["fields"] + _COMMON


# Objects that are part of every management database (predefined) — referenced, never emitted.
_PREDEFINED_TYPES = {"CpmiAnyObject", "RulebaseAction", "Track", "Global", "CpmiGatewayPlain"}
_PREDEFINED_NAMES = {"Any", "Original", "None", "Policy Targets", "All_Internet"}


def is_predefined(obj: dict) -> bool:
    if (((obj.get("domain") or {}).get("domain-type")) or "") == "data domain":
        return True
    if obj.get("type") in _PREDEFINED_TYPES:
        return True
    return obj.get("name") in _PREDEFINED_NAMES


# --- small helpers ---------------------------------------------------------------------------

def slugify(name: str, used: set[str]) -> str:
    """A unique, valid Terraform/Ansible identifier for an object name."""
    s = re.sub(r"[^0-9A-Za-z_]", "_", (name or "").strip())
    s = re.sub(r"_+", "_", s).strip("_").lower() or "obj"
    if s[0].isdigit():
        s = "n_" + s
    cand, i = s, 2
    while cand in used:
        cand, i = f"{s}_{i}", i + 1
    used.add(cand)
    return cand


def _q(s) -> str:
    """Double-quoted, escaped, single-line scalar for HCL / YAML. NOT shell-safe (use _sh for bash)."""
    text = re.sub(r"\s*\n\s*", " ", str(s)).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _sh(s) -> str:
    """Single-quoted bash literal for the generated mgmt_cli script. Single quotes disable ALL shell
    expansion ($(...), backticks, $VAR), so object / rule / comment names pulled from a customer SMS
    can never execute when the SE runs the script. The '\\'' idiom embeds a literal single quote;
    newlines are collapsed so a value can't break out of its line."""
    return "'" + re.sub(r"\s*\n\s*", " ", str(s)).replace("'", "'\\''") + "'"


def _one_line(s) -> str:
    """Collapse newlines so an interpolated value can't break out of a single-line shell comment."""
    return re.sub(r"\s*\n\s*", " ", str(s))


def _is_int(v) -> bool:
    return str(v).lstrip("-").isdigit()


def _empty(v) -> bool:
    if v is None:
        return True
    if isinstance(v, str) and v == "":
        return True
    return isinstance(v, (list, dict, tuple)) and len(v) == 0


def _name_of(v) -> str:
    if isinstance(v, dict):
        return v.get("name") or v.get("uid") or ""
    return str(v)


def _names(v) -> list[str]:
    out = []
    for m in v or []:
        out.append(m.get("name") or m.get("uid") if isinstance(m, dict) else m)
    return [x for x in out if x]


def _cell(values: list[str]) -> list[str]:
    return values if values else ["Any"]


# --- public entry point ----------------------------------------------------------------------

def generate(bundle: dict, host: str = "", domain: str = "") -> dict:
    """Render a pulled-policy bundle to all targets.
    bundle = {layer, rules (structured rows), objects_by_type {type: [obj]}}; ``host``/``domain`` (the
    source SMS / MDS domain) pre-fill the Ansible inventory. Returns {layer, terraform, ansible, mgmt_cli,
    web_api, stats}."""
    layer = bundle.get("layer", "")
    rules = [dict(r) for r in bundle.get("rules", [])]
    objects_by_type: dict[str, list] = bundle.get("objects_by_type", {})

    used: set[str] = set()
    emit: list[dict] = []
    skipped: dict[str, int] = {}
    ref_map: dict[str, str] = {}

    for cp_type in sorted(objects_by_type):
        spec = OBJ_SPECS.get(cp_type)
        objs = objects_by_type[cp_type]
        if not spec:
            skipped[cp_type] = skipped.get(cp_type, 0) + len(objs)
            continue
        for o in objs:
            slug = slugify(o.get("name", ""), used)
            emit.append({"cp_type": cp_type, "spec": spec, "obj": o, "slug": slug})
            if o.get("name"):
                ref_map[o["name"]] = f'{spec["tf"]}.{slug}.name'

    for row in rules:
        if row.get("kind") == "section":
            row["_slug"] = slugify("sec_" + (row.get("name") or "section"), used)
        elif row.get("kind") == "rule":
            row["_slug"] = slugify("rule_" + (row.get("name") or f"rule_{row.get('number') or ''}"), used)

    stats = {"objects": len(emit), "rules": sum(1 for r in rules if r.get("kind") == "rule"),
             "sections": sum(1 for r in rules if r.get("kind") == "section"), "skipped": skipped}
    return {
        "layer": layer,
        "terraform": _render_terraform(layer, emit, rules, ref_map, skipped),
        "ansible": _render_ansible(layer, emit, rules, skipped, host, domain),
        "mgmt_cli": _render_mgmt_cli(layer, emit, rules, skipped),
        "web_api": _render_web_api(layer, emit, rules),
        "stats": stats,
    }


# --- web_api (replayable JSON: POST /web_api/<command> with each body) ------------------------

def _api_value(f, v):
    kind = f["kind"]
    if kind == "nested":
        return _api_body(f["sub"], v)
    if kind == "nestedlist":
        return [_api_body(f["sub"], it) for it in v]
    if kind in ("names", "namelist", "weekdays"):
        return _names(v)
    if kind == "strlist":
        return list(v)
    if kind == "ref":
        return _name_of(v)
    if kind == "bool":
        return bool(v)
    if kind == "int" and _is_int(v):
        return int(v)
    return v


def _api_body(fields, obj):
    body = {}
    for f in fields:
        v = obj.get(f["src"])
        if not _empty(v):
            body[f["src"]] = _api_value(f, v)
    return body


def _api_rule_body(row, layer):
    b = {"layer": layer, "position": "bottom", "name": row.get("name") or "",
         "source": _cell(row.get("source", [])), "destination": _cell(row.get("destination", [])),
         "service": _cell(row.get("service", [])), "action": row.get("action") or "Drop",
         "enabled": bool(row.get("enabled", True))}
    if row.get("content"):
        b["content"] = row["content"]
        if row.get("content_direction"):
            b["content-direction"] = row["content_direction"]
    if row.get("vpn"):
        b["vpn"] = row["vpn"]
    if row.get("inline_layer"):
        b["inline-layer"] = row["inline_layer"]
    tk = row.get("track_full") or {}
    if tk.get("type"):
        track = {"type": tk["type"]}
        for k in ("accounting", "per_connection", "per_session", "enable_firewall_session"):
            if tk.get(k):
                track[k.replace("_", "-")] = True
        if tk.get("alert"):
            track["alert"] = tk["alert"]      # parity with the TF / Ansible renderers
        b["track"] = track
    elif row.get("track"):
        b["track"] = {"type": row["track"]}
    if row.get("time"):
        b["time"] = row["time"]
    if row.get("install_on"):
        b["install-on"] = row["install_on"]
    if any((row.get("custom_fields") or {}).values()):
        b["custom-fields"] = {k: v for k, v in row["custom_fields"].items() if v}
    for neg, key in (("source_negate", "source-negate"), ("destination_negate", "destination-negate"),
                     ("service_negate", "service-negate"), ("content_negate", "content-negate")):
        if row.get(neg):
            b[key] = True
    if row.get("comments"):
        b["comments"] = row["comments"]
    return b


def _render_web_api(layer, emit, rules) -> str:
    """A replayable backup: an ordered list of web_api operations. Log in, POST each body to
    /web_api/<command> with the X-chkp-sid header, then the trailing publish commits."""
    ops = []
    for e in emit:
        ops.append({"command": f"add-{e['cp_type']}",
                    "body": {"name": e["obj"].get("name", ""), **_api_body(e["spec"]["fields"], e["obj"])}})
    for row in rules:
        if row.get("kind") == "section":
            ops.append({"command": "add-access-section",
                        "body": {"layer": layer, "position": "bottom", "name": row.get("name") or "Section"}})
        elif row.get("kind") == "rule":
            ops.append({"command": "add-access-rule", "body": _api_rule_body(row, layer)})
    ops.append({"command": "publish", "body": {}})
    return json.dumps(ops, indent=2)


# --- Terraform (CheckPointSW/checkpoint) ------------------------------------------------------

def _tf_ref(name: str, ref_map: dict[str, str]) -> str:
    return ref_map[name] if name in ref_map else _q(name)


def _tf_fields(fields, obj, ref_map, indent) -> list[str]:
    pad = "  " * indent
    out: list[str] = []
    for f in fields:
        v = obj.get(f["src"])
        k, kind = f["tf"], f["kind"]
        if _empty(v) or not k:
            continue
        if kind == "nested":
            inner = _tf_fields(f["sub"], v, ref_map, indent + 1)
            if inner:
                out.append(f"{pad}{k} {{")
                out.extend(inner)
                out.append(f"{pad}}}")
        elif kind == "nestedlist":
            for item in v:
                inner = _tf_fields(f["sub"], item, ref_map, indent + 1)
                if inner:
                    out.append(f"{pad}{k} {{")
                    out.extend(inner)
                    out.append(f"{pad}}}")
        elif kind == "names":
            out.append(f"{pad}{k} = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in _names(v)))
        elif kind == "namelist":
            out.append(f"{pad}{k} = [%s]" % ", ".join(_q(n) for n in _names(v)))
        elif kind == "strlist":
            out.append(f"{pad}{k} = [%s]" % ", ".join(_q(x) for x in v))
        elif kind == "weekdays":
            out.append(f"{pad}{k} = {_q(','.join(_names(v)))}")
        elif kind == "ref":
            out.append(f"{pad}{k} = {_tf_ref(_name_of(v), ref_map)}")
        elif kind == "bool":
            out.append(f'{pad}{k} = {"true" if v else "false"}')
        elif kind == "int" and _is_int(v):
            out.append(f"{pad}{k} = {v}")
        else:
            out.append(f"{pad}{k} = {_q(v)}")
    return out


def _render_terraform(layer, emit, rules, ref_map, skipped) -> str:
    L = [f'# Terraform export of Check Point access layer "{layer}".',
         "# Provider: CheckPointSW/checkpoint. Configure the provider, then `terraform init && apply`.",
         "# Restore into an EMPTY layer/domain to reproduce order and avoid name clashes.",
         "",
         "terraform {", "  required_providers {", "    checkpoint = {",
         '      source = "CheckPointSW/checkpoint"', "    }", "  }", "}", ""]
    if skipped:
        L.append(_skip_banner(skipped, "#"))
        L.append("")
    for e in emit:
        spec, o, slug = e["spec"], e["obj"], e["slug"]
        L.append(f'resource "{spec["tf"]}" "{slug}" {{')
        L.append(f'  name = {_q(o.get("name", ""))}')
        L.extend(_tf_fields(spec["fields"], o, ref_map, 1))
        if spec.get("note"):
            L.append(f'  # NOTE: {spec["note"]}')
        L.append("}")
        L.append("")

    prev = None
    for row in rules:
        kind = row.get("kind")
        if kind == "section":
            addr = f'checkpoint_management_access_section.{row["_slug"]}'
            L.append(f'resource "checkpoint_management_access_section" "{row["_slug"]}" {{')
            L.append(f'  name = {_q(row.get("name") or "Section")}')
            L.append(f"  layer = {_q(layer)}")
            L.append('  position = "bottom"')
            if prev:
                L.append(f"  depends_on = [{prev}]")
            L.append("}")
            L.append("")
            prev = addr
        elif kind == "rule":
            addr = f'checkpoint_management_access_rule.{row["_slug"]}'
            L.append(f'resource "checkpoint_management_access_rule" "{row["_slug"]}" {{')
            L.append(f'  name = {_q(row.get("name") or "")}')
            L.append(f"  layer = {_q(layer)}")
            L.append('  position = "bottom"')
            L.append("  source = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in _cell(row.get("source", []))))
            L.append("  destination = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in _cell(row.get("destination", []))))
            L.append("  service = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in _cell(row.get("service", []))))
            if row.get("content"):
                L.append("  content = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in row["content"]))
                if row.get("content_direction"):
                    L.append(f'  content_direction = {_q(row["content_direction"])}')
            if row.get("vpn"):   # Terraform models a community list as `vpn_communities`
                L.append("  vpn_communities = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in row["vpn"]))
            L.append(f'  action = {_q(row.get("action") or "Drop")}')
            if row.get("inline_layer"):
                L.append(f'  inline_layer = {_q(row["inline_layer"])}')
            tk = row.get("track_full") or {}
            if tk.get("type"):
                tl = [f'    type = {_q(tk["type"])}']
                for b in ("accounting", "per_connection", "per_session", "enable_firewall_session"):
                    if tk.get(b):
                        tl.append(f"    {b} = true")
                if tk.get("alert"):
                    tl.append(f'    alert = {_q(tk["alert"])}')
                L.append("  track {\n" + "\n".join(tl) + "\n  }")
            elif row.get("track"):
                L.append(f'  track {{\n    type = {_q(row["track"])}\n  }}')
            if row.get("time"):
                L.append("  time = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in row["time"]))
            if row.get("install_on"):
                L.append("  install_on = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in row["install_on"]))
            cf = row.get("custom_fields") or {}
            if any(cf.values()):
                L.append("  custom_fields {")
                for k in ("field-1", "field-2", "field-3"):
                    if cf.get(k):
                        L.append(f'    {k.replace("-", "_")} = {_q(cf[k])}')
                L.append("  }")
            L.append(f'  enabled = {"true" if row.get("enabled", True) else "false"}')
            for neg in ("source_negate", "destination_negate", "service_negate", "content_negate"):
                if row.get(neg):
                    L.append(f"  {neg} = true")
            if row.get("comments"):
                L.append(f'  comments = {_q(row["comments"])}')
            if prev:
                L.append(f"  depends_on = [{prev}]")
            L.append("}")
            L.append("")
            prev = addr
        else:
            L.append(f'# unsupported rulebase item: {_one_line(row.get("type", "unknown"))} {_one_line(row.get("name", ""))}')
            L.append("")
    return "\n".join(L).rstrip() + "\n"


# --- Ansible (check_point.mgmt) ---------------------------------------------------------------

def _yaml_list(values) -> str:
    return "[" + ", ".join(_q(v) for v in values) + "]"


def _ansible_fields(fields, obj, indent) -> list[str]:
    pad = "  " * indent
    out: list[str] = []
    for f in fields:
        v = obj.get(f["src"])
        k, kind = f["ans"], f["kind"]
        if _empty(v) or not k:
            continue
        if kind == "nested":
            inner = _ansible_fields(f["sub"], v, indent + 1)
            if inner:
                out.append(f"{pad}{k}:")
                out.extend(inner)
        elif kind == "nestedlist":
            items = [_ansible_fields(f["sub"], it, indent + 2) for it in v]
            items = [it for it in items if it]
            if items:
                out.append(f"{pad}{k}:")
                for it in items:                       # YAML list-of-dicts: first key after "- "
                    out.append(f'{"  " * (indent + 1)}- {it[0].lstrip()}')
                    out.extend(it[1:])
        elif kind in ("names", "namelist"):
            out.append(f"{pad}{k}: {_yaml_list(_names(v))}")
        elif kind == "strlist":
            out.append(f"{pad}{k}: {_yaml_list(v)}")
        elif kind == "weekdays":
            out.append(f"{pad}{k}: {_yaml_list(_names(v))}")
        elif kind == "ref":
            out.append(f"{pad}{k}: {_q(_name_of(v))}")
        elif kind == "bool":
            out.append(f'{pad}{k}: {"true" if v else "false"}')
        elif kind == "int" and _is_int(v):
            out.append(f"{pad}{k}: {v}")
        else:
            out.append(f"{pad}{k}: {_q(v)}")
    return out


def _render_ansible(layer, emit, rules, skipped, host="", domain="") -> str:
    """check_point.mgmt runs over the httpapi connection plugin targeting the Management server (NOT
    localhost). Emit a copy-paste inventory so the play talks to the SMS; the password comes from Vault/env."""
    target = host or "MGMT_SERVER_IP"
    L = [f'# Ansible export of Check Point access layer "{layer}" (collection: check_point.mgmt).',
         '#',
         '# 1) Save this inventory as "hosts" (source the password from Vault/env — never inline it):',
         '#      [checkpoint]',
         f'#      cp-mgmt ansible_host={target}',
         '#      [checkpoint:vars]',
         '#      ansible_user=admin',
         '#      ansible_network_os=check_point.mgmt.checkpoint',
         '#      ansible_connection=httpapi',
         '#      ansible_httpapi_use_ssl=True',
         '#      ansible_httpapi_validate_certs=True   # keep TLS verification on; import the SMS CA if self-signed',
         '#      ansible_httpapi_port=443',
         '#      # ansible_password: "{{ vault_cp_password }}"']
    if domain:
        L.append(f'#      # MDS/Multi-Domain: this layer lives in domain "{domain}" — point ansible_host')
        L.append(f'#      #   at that domain\'s CMA (or its Management API IP).')
    L += ['#',
          '# 2) ansible-galaxy collection install check_point.mgmt',
          '# 3) ansible-playbook -i hosts restore_policy.yml',
          '#',
          '# Restore into an EMPTY layer/domain to reproduce rule order.']
    if skipped:
        L.append(_skip_banner(skipped, "#"))
    L += ["---", f'- name: {_q(f"Restore Check Point policy - layer {layer}")}',
          "  hosts: checkpoint", "  connection: httpapi", "  gather_facts: false", "  tasks:"]

    for e in emit:
        spec, o = e["spec"], e["obj"]
        L.append(f'    - name: {_q("Add " + str(spec["cli"]) + " " + o.get("name", ""))}')
        L.append(f'      check_point.mgmt.{spec["ansible"]}:')
        L.append(f'        name: {_q(o.get("name", ""))}')
        L.extend(_ansible_fields(spec["fields"], o, 4))
        L.append("        state: present")
        if spec.get("note"):
            L.append(f'      # NOTE: {spec["note"]}')

    for row in rules:
        kind = row.get("kind")
        if kind == "section":
            L.append(f'    - name: {_q("Add section " + (row.get("name") or "Section"))}')
            L.append("      check_point.mgmt.cp_mgmt_access_section:")
            L.append(f"        layer: {_q(layer)}")
            L.append("        position: bottom")
            L.append(f'        name: {_q(row.get("name") or "Section")}')
            L.append("        state: present")
        elif kind == "rule":
            L.append(f'    - name: {_q("Add rule " + str(row.get("name") or row.get("number") or ""))}')
            L.append("      check_point.mgmt.cp_mgmt_access_rule:")
            L.append(f"        layer: {_q(layer)}")
            L.append("        position: bottom")
            L.append(f'        name: {_q(row.get("name") or "")}')
            L.append(f"        source: {_yaml_list(_cell(row.get('source', [])))}")
            L.append(f"        destination: {_yaml_list(_cell(row.get('destination', [])))}")
            L.append(f"        service: {_yaml_list(_cell(row.get('service', [])))}")
            if row.get("content"):
                L.append(f"        content: {_yaml_list(row['content'])}")
                if row.get("content_direction"):
                    L.append(f'        content_direction: {_q(row["content_direction"])}')
            if row.get("vpn"):
                L.append(f"        vpn: {_yaml_list(row['vpn'])}")
            L.append(f'        action: {_q(row.get("action") or "Drop")}')
            if row.get("inline_layer"):
                L.append(f'        inline_layer: {_q(row["inline_layer"])}')
            tk = row.get("track_full") or {}
            if tk.get("type"):
                L.append("        track:")
                L.append(f'          type: {_q(tk["type"])}')
                for b in ("accounting", "per_connection", "per_session", "enable_firewall_session"):
                    if tk.get(b):
                        L.append(f"          {b}: true")
                if tk.get("alert"):
                    L.append(f'          alert: {_q(tk["alert"])}')
            elif row.get("track"):
                L.append("        track:")
                L.append(f'          type: {_q(row["track"])}')
            if row.get("time"):
                L.append(f"        time: {_yaml_list(row['time'])}")
            if row.get("install_on"):
                L.append(f"        install_on: {_yaml_list(row['install_on'])}")
            cf = row.get("custom_fields") or {}
            if any(cf.values()):
                L.append("        custom_fields:")
                for k in ("field-1", "field-2", "field-3"):
                    if cf.get(k):
                        L.append(f'          {k.replace("-", "_")}: {_q(cf[k])}')
            L.append(f'        enabled: {"true" if row.get("enabled", True) else "false"}')
            for neg in ("source_negate", "destination_negate", "service_negate", "content_negate"):
                if row.get(neg):
                    L.append(f"        {neg}: true")
            if row.get("comments"):
                L.append(f'        comments: {_q(row["comments"])}')
            L.append("        state: present")
        else:
            L.append(f'    # unsupported rulebase item: {_one_line(row.get("type", "unknown"))} {_one_line(row.get("name", ""))}')

    L += ["    - name: Publish", "      check_point.mgmt.cp_mgmt_publish:"]
    return "\n".join(L).rstrip() + "\n"


# --- mgmt_cli script --------------------------------------------------------------------------

def _cli_parts(fields, obj, prefix="") -> list[str]:
    parts: list[str] = []
    for f in fields:
        v = obj.get(f["src"])
        k, kind = prefix + (f["cli"] or ""), f["kind"]
        if _empty(v) or not f["cli"]:
            continue
        if kind == "nested":
            parts.extend(_cli_parts(f["sub"], v, k + "."))
        elif kind == "nestedlist":
            for i, item in enumerate(v, 1):
                parts.extend(_cli_parts(f["sub"], item, f"{k}.{i}."))
        elif kind in ("names", "namelist", "weekdays"):
            for i, n in enumerate(_names(v), 1):
                parts.append(f"{k}.{i} {_sh(n)}")
        elif kind == "strlist":
            for i, x in enumerate(v, 1):
                parts.append(f"{k}.{i} {_sh(x)}")
        elif kind == "ref":
            parts.append(f"{k} {_sh(_name_of(v))}")
        elif kind == "bool":
            parts.append(f'{k} {"true" if v else "false"}')
        elif kind == "int" and _is_int(v):
            parts.append(f"{k} {v}")
        else:
            parts.append(f"{k} {_sh(v)}")
    return parts


def _render_mgmt_cli(layer, emit, rules, skipped) -> str:
    L = ["#!/bin/bash",
         f'# mgmt_cli export of Check Point access layer "{_one_line(layer)}".',
         "# 1) Log in (writes the session id to id.txt — fill in your host/credentials):",
         '#    mgmt_cli login user "admin" password "PASSWORD" management "MGMT_IP" > id.txt',
         '#    (add: domain "DOMAIN" for an MDS / CMA)',
         "# 2) Run this script. 3) It publishes and logs out at the end.",
         "set -e", ""]
    if skipped:
        L.append(_skip_banner(skipped, "#"))
        L.append("")

    def add(kind: str, parts: list[str]) -> str:
        return f'mgmt_cli add {kind} {" ".join(parts)} --ignore-warnings true -s id.txt'

    for e in emit:
        spec, o = e["spec"], e["obj"]
        parts = [f'name {_sh(o.get("name", ""))}'] + _cli_parts(spec["fields"], o)
        L.append(add(spec["cli"], parts))
        if spec.get("note"):
            L.append(f'# NOTE: {spec["note"]}')

    for row in rules:
        kind = row.get("kind")
        if kind == "section":
            L.append(add("access-section",
                         [f'layer {_sh(layer)}', "position bottom", f'name {_sh(row.get("name") or "Section")}']))
        elif kind == "rule":
            parts = [f"layer {_sh(layer)}", "position bottom", f'name {_sh(row.get("name") or "")}',
                     _cli_idx("source", _cell(row.get("source", []))),
                     _cli_idx("destination", _cell(row.get("destination", []))),
                     _cli_idx("service", _cell(row.get("service", []))),
                     f'action {_sh(row.get("action") or "Drop")}']
            if row.get("content"):
                parts.append(_cli_idx("content", row["content"]))
                if row.get("content_direction"):
                    parts.append(f'content-direction {_sh(row["content_direction"])}')
            if row.get("vpn"):
                parts.append(_cli_idx("vpn", row["vpn"]))
            if row.get("inline_layer"):
                parts.append(f'inline-layer {_sh(row["inline_layer"])}')
            tk = row.get("track_full") or {}
            if tk.get("type"):
                parts.append(f'track-settings.type {_sh(tk["type"])}')
                for b, key in (("accounting", "accounting"), ("per_connection", "per-connection"),
                               ("per_session", "per-session"), ("enable_firewall_session", "enable-firewall-session")):
                    if tk.get(b):
                        parts.append(f"track-settings.{key} true")
            elif row.get("track"):
                parts.append(f'track-settings.type {_sh(row["track"])}')
            if row.get("time"):
                parts.append(_cli_idx("time", row["time"]))
            if row.get("install_on"):
                parts.append(_cli_idx("install-on", row["install_on"]))
            cf = row.get("custom_fields") or {}
            for k in ("field-1", "field-2", "field-3"):
                if cf.get(k):
                    parts.append(f'custom-fields.{k} {_sh(cf[k])}')
            parts.append(f'enabled {"true" if row.get("enabled", True) else "false"}')
            for neg, key in (("source_negate", "source-negate"), ("destination_negate", "destination-negate"),
                             ("service_negate", "service-negate"), ("content_negate", "content-negate")):
                if row.get(neg):
                    parts.append(f"{key} true")
            if row.get("comments"):
                parts.append(f'comments {_sh(row["comments"])}')
            L.append(add("access-rule", parts))
        else:
            L.append(f'# unsupported rulebase item: {_one_line(row.get("type", "unknown"))} {_one_line(row.get("name", ""))}')

    L += ["", "mgmt_cli publish -s id.txt", "mgmt_cli logout -s id.txt"]
    return "\n".join(L).rstrip() + "\n"


def _cli_idx(prefix: str, values) -> str:
    return " ".join(f"{prefix}.{i} {_sh(v)}" for i, v in enumerate(values, start=1))


def _skip_banner(skipped: dict[str, int], comment: str) -> str:
    lines = [f"{comment} Skipped {sum(skipped.values())} object(s) of unsupported type(s) "
             "(no IaC mapping yet):"]
    for t in sorted(skipped):
        lines.append(f"{comment}   - {t}: {skipped[t]}")
    return "\n".join(lines)
