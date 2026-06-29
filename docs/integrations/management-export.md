# Management API policy viewer + IaC export

The portal acts as a real Check Point **Management API (`web_api`) client**: save a connection profile to a
live R82.10 SMS (or an MDS domain), browse its access layers and rulebase, optionally make explicit
per-rule edits, then export any layer to **Infrastructure-as-Code** — Terraform, Ansible, a `mgmt_cli`
script, or replayable web_api JSON. For an SE this turns "show me your policy" into a clickable viewer and
a backup-as-code artifact, with no SmartConsole.

- Profiles + viewer/export router: [`app/routers/mgmt.py`](../../app/routers/mgmt.py)
- The `web_api` client (login → sid → calls → logout, read-only session pool): [`app/services/mgmt_api.py`](../../app/services/mgmt_api.py)
- IaC generator (Terraform / Ansible / mgmt_cli / web_api): [`app/services/mgmt_export.py`](../../app/services/mgmt_export.py)
- Encrypted secret storage (AES-256-GCM): [`app/services/mgmt_creds.py`](../../app/services/mgmt_creds.py)
- TLS cert fetch / pin (trust-on-first-use): [`app/services/gaia_client.py`](../../app/services/gaia_client.py)

## Use it

1. Portal → **Management** → **New**. Enter a name, the SMS **host** + **port** (default `443`), the API
   **username**, and the **password / API key** (stored encrypted; see below). For a Multi-Domain server,
   set the optional **domain** to target a CMA. Leave auto-trust ticked so the cert is pinned on save.
2. **Test connection** logs in (a fresh read-only session), reads the API version, domains and layer count,
   then logs out — proving the credentials and TLS before you rely on them.
3. Open the server (**Policy viewer**): pick a layer (loaded live) and the rulebase renders with every
   cell resolved to object names. The full **HTTP trace** of each `web_api` call is shown. From the viewer
   you can also make an explicit per-rule edit (enable/disable, action, track, rename, comments), which
   defaults to a **dry-run** (validated against the SMS, then discarded) and only commits when you publish.
4. **Export**: from the viewer choose a layer, then **Generate**. Pull runs once and renders four tabs —
   **Terraform**, **Ansible**, **mgmt_cli**, **web_api JSON** — each previewable and downloadable
   (`.tf`, `.ansible.yml`, `.mgmt_cli.sh`, `.web_api.json`).

## Endpoints

All under `/management`, owner-scoped, behind auth:

- `GET /management` · `GET|POST /management/new` · `GET|POST /management/{sid}/edit` · `POST /management/{sid}/delete` — profile CRUD.
- `POST /management/fetch-cert` · `POST /management/{sid}/test` — fetch the presented cert / Test connection.
- `GET /management/{sid}` — the policy viewer page.
- `GET /management/{sid}/layers` — JSON: the access layers on this server/domain (`show-access-layers`).
- `GET /management/{sid}/rulebase?name=<layer>` — JSON: a layer's rulebase, cells resolved to names.
- `POST /management/{sid}/apply` — JSON body `{layer, uid, changes, publish}`: apply one rule edit (`set-access-rule`); `publish:false` (default) is a dry-run that discards, `publish:true` commits.
- `GET /management/{sid}/export?layer=<layer>` — the export page.
- `POST /management/{sid}/export?name=<layer>` — JSON `{layer, terraform, ansible, mgmt_cli, web_api, stats}`.
- `GET|POST /management/{sid}/gaia-export[/run]` — export the SMS's own **Gaia OS** config (it's a Gaia appliance too) to Terraform/Ansible/clish; see [gaia-config-exporter](gaia-export.md) if present.

## What the export covers

`pull_for_export` pulls the layer's rulebase **and** its object dictionary with full details
(`dereference-group-members` so a group resolves to members), then `mgmt_export.generate` renders it.
Per object type it emits **all publicly-settable fields** using each tool's exact argument names
(`checkpoint_management_*` for Terraform, `cp_mgmt_*` for Ansible, the `mgmt_cli add-*` names).
**Predefined** objects (`Any`, predefined services, `Accept`/`Drop`, the `Log` track) are referenced by
name, never re-emitted. Order is preserved; Terraform also wires a `depends_on` chain. Unsupported object
types are **counted and commented**, never dropped silently or crashed on (see `stats.skipped`).

## Security notes

- **Reads are read-only against the SMS.** Browsing layers, the rulebase, and the export pull all use a
  `read-only` `web_api` login that takes no object/rule locks. The only write path is the explicit per-rule
  **apply** action, which defaults to a dry-run (discarded, zero commit) and commits only when you set
  `publish:true`; the portal does exactly what the API account is permitted to (least privilege — scope the
  account accordingly).
- **TLS verification is always on.** Against a pinned certificate (trust-on-first-use, the SSH `known_hosts`
  model — pinned on save via `pin_now`, otherwise lazily on first connect via `ensure_pinned`) when one is
  set, else system trust. There is **no** skip-verify path; TLS 1.2+ is enforced.
- **Secrets are encrypted at rest** (AES-256-GCM, `mgmt_creds`); set `DCSIM_ENCRYPTION_KEY` in prod. If
  encryption is unavailable the password is simply not stored (you'll be told), never written in cleartext.
- **Session-safe.** Reads share one long-lived read-only session per (server, domain) — Check Point throttles
  remote logins (3/admin/domain/60s) and caps concurrent sessions — re-logging-in transparently on expiry.
- The generated `mgmt_cli` script single-quotes every value pulled from the customer SMS, so an object or
  comment name can never execute as shell. The Ansible inventory keeps `validate_certs=True` and sources the
  password from Vault/env — never inlined.
