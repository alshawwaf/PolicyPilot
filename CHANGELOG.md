# Changelog

All notable changes to **PolicyPilot** are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## 1.0.0 — 2026-06-28

First general release for SEs and customers. Validated against a live Check Point **R82.10** Management
Server. 900+ automated tests, all green.

### Simulate the systems Check Point integrates with (poll side)
- **Data center mocks**, each built to the provider's exact API contract: OpenStack (Keystone/Nova/Neutron),
  VMware vCenter (vSphere SOAP + REST), VMware NSX-T (Local Manager) and **Global NSX-T** (Federation),
  Proxmox VE, Cisco ACI (APIC XML), Kubernetes (kube-apiserver), and Nutanix Prism (v3 + v4).
- **Feeds**: Generic Data Center (sk167210), Network Feed (flat list / JSON + JQ), and IoC / Custom
  Intelligence (CSV / STIX 1.x / Custom CSV / Snort).
- **Test Connection** and **Live polls** show objects syncing in the provider's own format.

### Push & reverse
- **Dynamic Layers** — author an Access Control rulebase and push it to a gateway's Gaia API
  (`set-dynamic-content`) or a built-in mock gateway, with async task + change summary.
- **SIEM receiver** — a Log Exporter sink that auto-detects CEF / LEEF / JSON / key=value / syslog over
  TCP+UDP and shows logs arriving live.

### Management side (drive a real SMS)
- **Management API export** — pull layers + access rulebase and export to Terraform / Ansible / `mgmt_cli`.
- **Gaia config export** — pull a gateway's/SMS's Gaia OS config and export to Terraform / Ansible / clish.
- **Access Automation** — a ticket (ServiceNow / Jira / any webhook) becomes a Check Point rule. The
  decide/grant engine computes the minimal first-match-safe change (no-op / widen / create), with **full
  access-rule column support** — action (Accept / Drop / Reject / Ask / Inform / Apply Layer) + content,
  time, install-on, and VPN columns — preview, approval-gated apply, and one-click rollback. Reuse-only
  object resolution, conservative safety guards, and a behavior-profile / per-layer customization framework.
- **MCP server + REST API** — the access-automation + policy tools over `/mcp` (for n8n / LLM agents) and a
  general REST API at `/dbapi/v1`, both with scoped API-key auth. In-app onboarding at `/mcp-guide`, a live
  Swagger explorer at `/api-explorer`, and an IaC-coverage matrix at `/coverage`.

### Live-demo tooling
- **Scenarios** with SE talk-tracks, timed preset runs, and baseline/reset.
- **One-click seed** of a realistic environment; portable **export/import** bundles (never carry secrets).
- **Activity log** — every request/response, redacted, filterable.

### Security
- All gateway/SMS TLS **always verified** (trust-on-first-use cert pinning for self-signed lab boxes).
- Saved gateway / datacenter / management credentials **AES-256-GCM encrypted at rest**.
- Scoped, revocable **API keys** (mcp / webhook / api), SHA-256-hashed at rest.
- Defensive HTTP response headers (anti-clickjacking, nosniff, Referrer-Policy, HSTS).
- Parameterized queries throughout; portal logins use PBKDF2; secrets never logged.
- Reproducible build (pinned dependencies, non-root container, healthcheck).
