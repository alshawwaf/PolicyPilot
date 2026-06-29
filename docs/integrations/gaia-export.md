# Gaia OS config export (backup-as-code)

Pulls the **live Gaia OS configuration** off a saved Gateway or Management Server — hostname, DNS, NTP,
timezone, interfaces (physical/VLAN/bond/bridge/loopback), static routes, proxy — and renders it as
**Terraform**, **Ansible**, **clish**, and a replayable **web_api** op list. In a PoV this is the
"prove your appliance config is reproducible IaC" story: read the box, hand the customer a reviewable
backup-as-code, no hardware-specific export tooling required. The SMS is a Gaia appliance too, so the
exact same flow works from the policy viewer.

- Routes (gateway): [`app/routers/gateways.py`](../../app/routers/gateways.py)
- Routes (Management Server): [`app/routers/mgmt.py`](../../app/routers/mgmt.py)
- Pull + generate service (pure `generate(cfg)`): [`app/services/gaia_export.py`](../../app/services/gaia_export.py)
- TLS cert fetch / pin (trust-on-first-use): [`app/services/gaia_client.py`](../../app/services/gaia_client.py)
- Page: [`app/templates/gaia_export.html`](../../app/templates/gaia_export.html)

## Use it

1. Portal → **Gateways → (a gateway) → Export Gaia config →**, or **Management → (a server) →
   Gaia config →**. Both land on the same Gaia config export page for that appliance.
2. The OS password is sourced from the saved encrypted credential if you stored one on **Edit**;
   otherwise type it into the password field for this run only.
3. **Run** — the portal logs into the appliance's `gaia_api`, reads the config, and renders the four
   targets side by side (with a section/interface/route summary and the HTTP trace of each call).
   Copy the **Terraform**, **Ansible**, **clish**, or **web_api** output.

## Endpoints

The page and its JSON runner exist twice — once per appliance kind — backed by the same service:

- `GET  /gateways/{gid}/gaia-export` / `POST /gateways/{gid}/gaia-export/run`
- `GET  /management/{sid}/gaia-export` / `POST /management/{sid}/gaia-export/run`

The `/run` POST takes an optional `password` form field and returns JSON
(`pull_and_generate`): `{terraform, ansible, clish, web_api, stats, trace}`, or `{error, trace}` if the
pull fails.

## What it pulls

Over the Gaia REST API (`/gaia_api/v1.9`, `login` → `show-*` → `logout`):
`show-hostname`, `show-dns`, `show-ntp`, `show-time-and-date`, `show-physical-interfaces`,
`show-vlan-interfaces`, `show-bond-interfaces`, `show-bridge-interfaces`, `show-loopback-interfaces`,
`show-static-routes`, `show-proxy` (interface/route calls paginate at `limit: 500`).

## Export targets

- **Terraform** — `CheckPointSW/checkpoint` provider in `context = "gaia_api"` mode, emitting
  `checkpoint_gaia_hostname` / `_dns` / `_ntp` / `_time_and_date` / `_physical_interface` /
  `_vlan_interface` / `_bond_interface` / `_bridge_interface` / `_loopback_interface` / `_static_route`
  / `_proxy` resources.
- **Ansible** — the `check_point.gaia` collection over `connection: httpapi`, one play with
  `gather_facts: false` and bare `cp_gaia_*` modules (`cp_gaia_hostname`, `cp_gaia_dns`, `cp_gaia_ntp`,
  `cp_gaia_physical_interface`, `cp_gaia_static_route`, …). Includes the inventory + `ansible-galaxy
  collection install check_point.gaia` header as comments.
- **clish** — native Gaia CLI `set …` lines, including the `add interface … vlan`, `add bonding/bridging
  group …` create commands each interface type needs, ending with `save config`.
- **web_api** — an ordered JSON list of `set-*` ops you can replay against the appliance's
  `gaia_api` to restore it.

## Security notes

- **TLS is always verified.** The pull pins to the appliance's cert via `ensure_pinned` (trust-on-first-
  use) before the handshake — `CERT_REQUIRED`, TLS 1.2+, never a skip-verify path.
- **Secrets are never inlined** into generated code: the Ansible inventory sources the password from
  Vault/env, Terraform from a variable, and the page footers say so. Saved OS passwords are stored
  encrypted (least-privilege: a read-only OS account is enough — every call is a `show-*`).
- `generate(cfg)` is a **pure** function (no device), so the rendering is unit-tested independently of a
  live appliance. Free-text values (comments) are quote-escaped per target to prevent clish injection.
