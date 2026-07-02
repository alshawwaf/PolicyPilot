# Deploying to Dokploy

Hosted on **Dokploy** — its Traefik handles the domain and Let's Encrypt TLS, so PolicyPilot is reached over
publicly-trusted HTTPS with no cert-trust step. (Caddy / `docker-compose.yml` are only for standalone local runs.)

## One-time setup

1. **Create an Application** — your project → *Create Service* → *Application*.
2. **Source** — the Git repo (a Check Point-approved remote per org policy), or a Docker image you've pushed.
3. **Build** — type **Dockerfile**; build context `.`, Dockerfile path `Dockerfile`.
4. **Port** — set the exposed port to **8000** (uvicorn's listen port).
5. **Domain** — add your domain (e.g. `policypilot.example.com`); Dokploy provisions the Let's Encrypt cert via
   Traefik automatically.
6. **Persistent volume** — mount a named volume at container path **`/data`**. The SQLite DB lives there; without
   it, your saved management servers, gateways, dynamic layers, settings, and API keys are wiped on every redeploy.
7. **Environment variables** (the bootstrap set — see the full `PILOT_*` list below):
   ```
   PILOT_BASE_URL=https://<your-domain>            # MUST equal the domain in step 5
   PILOT_SESSION_SECRET=<openssl rand -base64 32>
   PILOT_ENCRYPTION_KEY=<openssl rand -base64 32>  # encrypts saved gateway / SMS creds at rest — PERSIST IT
   PILOT_ADMIN_USERNAME=admin
   PILOT_ADMIN_PASSWORD=<choose a strong password>
   PILOT_TRUSTED_PROXY_HOPS=1                       # Traefik/Caddy = 1 proxy in front
   ```
   Don't set `PILOT_DATABASE_URL` — the `Dockerfile` already points it at `/data/policypilot.db`.
8. **Deploy.** Sign in at your domain as the admin user above.

### The full `PILOT_*` environment (`app/config.py`)

Only the five in step 7 are needed to boot. Everything else has a safe default **or** is settable later from
the **Settings** UI — see the note under this table.

| Env var | Purpose | Default / if unset |
|---|---|---|
| `PILOT_BASE_URL` | Public HTTPS domain; stamped into MCP/webhook/`gaia_api` endpoint URLs and decides the cookie `Secure` flag. | `http://localhost:8000` |
| `PILOT_SESSION_SECRET` | Signs the portal session cookie. | ephemeral key (logs everyone out on restart) |
| `PILOT_ENCRYPTION_KEY` | AES-256-GCM key for secrets at rest (saved SMS/gateway creds + portal-set MCP/webhook/ServiceNow secrets). | falls back to `PILOT_SESSION_SECRET` — **see warning below** |
| `PILOT_ADMIN_USERNAME` | Seed admin username (structurally protected — can't be demoted/disabled). | `admin` |
| `PILOT_ADMIN_PASSWORD` | Seed admin password. | random password generated + **printed once** to the container log |
| `PILOT_DATABASE_URL` | SQLAlchemy URL. Leave unset in Docker. | `sqlite:///./data/policypilot.db` (Dockerfile → `/data/…`) |
| `PILOT_TRUSTED_PROXY_HOPS` | Reverse-proxy hops in front (see below). | `0` (trust the direct TCP peer) |
| `PILOT_WEBHOOK_TOKEN` | `X-PolicyPilot-Token` shared secret enabling the ticketing webhook. | unset → webhook disabled |
| `PILOT_WEBHOOK_SERVER_IDS` | Comma-separated server ids the webhook may target. | blank = all allowed servers |
| `PILOT_MCP_TOKEN` | Bearer for the **standalone** `python -m app.mcp_server` run mode only (the portal-mounted `/mcp` uses an mcp-scope API key instead). | unset |
| `PILOT_SERVICENOW_INSTANCE` / `_USER` / `_PASSWORD` / `_TABLE` | Optional ServiceNow Table API write-back of the decision + rule UID. | unset (`_TABLE` = `incident`) |

> **Most of these are also settable from the Settings UI now** (portal-configurable secrets, encrypted at
> rest — the MCP token, webhook token/server-ids, and ServiceNow creds). A portal-set value **takes
> precedence** over its `PILOT_*` env var, so env is the **bootstrap path** and you rotate secrets from the
> browser with no redeploy. See [docs/settings.md](docs/settings.md).

> ⚠️ **`PILOT_ENCRYPTION_KEY` must be set and persisted.** All saved credentials and portal-set secrets are
> encrypted with it. If it's unset it derives from `PILOT_SESSION_SECRET`; if **both** are unset (dev), the
> ephemeral session key changes on every restart and **every stored secret becomes undecryptable** — you'd
> re-enter them in Settings. Even with a value, don't derive it from the session secret in prod: **rotating
> the session/cookie secret then orphans every stored secret.** Set a dedicated `PILOT_ENCRYPTION_KEY` and
> keep it stable for the life of the deployment.

Everything rides Traefik on **443** — there are no extra ports to publish.

## Why each setting matters

- **`PILOT_BASE_URL`** is stamped into the MCP / webhook / `gaia_api` endpoint URLs shown on the guide pages, and
  decides the session cookie's `Secure` flag — it must match the public HTTPS domain.
- **`PILOT_ENCRYPTION_KEY`** encrypts saved gateway and management-server credentials at rest (AES-256-GCM). It
  falls back to `PILOT_SESSION_SECRET`; set a dedicated key so rotating the session secret doesn't orphan stored
  credentials.
- **`PILOT_TRUSTED_PROXY_HOPS`** is the number of reverse proxies in front of the app (1 for a single
  Traefik/Caddy). It lets the **login brute-force throttle** and the activity log key on the *real* client
  from `X-Forwarded-For` rather than a spoofable header — without it set, the throttle could be bypassed by
  rotating XFF. Set it to match your proxy chain (0 if the app is exposed directly).
- **Run a single uvicorn worker** — the `Dockerfile` already does; **do not add `--workers N`**. The
  housekeeping / retention loop runs per process against the single SQLite file, so multiple workers would run
  duplicate loops. Scale by running more instances behind the load balancer if ever needed, not more workers.
- **Integration secrets are better set from the UI than baked into the deploy.** The MCP token, ticketing webhook
  secret, and ServiceNow credentials can be set in **Settings** (encrypted at rest, no redeploy) and take
  precedence over the `PILOT_MCP_TOKEN` / `PILOT_WEBHOOK_TOKEN` / `PILOT_SERVICENOW_*` env fallbacks. See
  [docs/settings.md](docs/settings.md).
- A Docker `HEALTHCHECK` hits `/healthz`, so Dokploy reports container health.

## The agent (MCP) endpoint

The MCP endpoint is served at **`/mcp`** over the same domain and Traefik (HTTPS) — no extra port. It activates
once you mint an **mcp-scope API key** (Settings → API keys, or right on `/mcp-guide`); clients send it as
`Authorization: Bearer <key>`. The `/mcp` mount depends on the `mcp` SDK, which ships from **Check Point
Artifactory, not public PyPI** — it's import-guarded (`app/mcp_server.py`): if the SDK isn't present the
endpoint is simply not mounted and the rest of PolicyPilot (portal + REST API) is unaffected. `/version`
reports `mcp_ready` once the SDK is present **and** an mcp-scope key exists. See [docs/mcp-n8n.md](docs/mcp-n8n.md).

## Updating

Push to the tracked branch (or hit *Redeploy*). The `/data` volume preserves your servers, gateways, dynamic
layers, and settings across deploys.

## Reachability check

The portal must be reachable at `https://<your-domain>` on 443. From any shell:
- `curl -s https://<your-domain>/healthz` → `{"status":"ok"}` (liveness)
- `curl -s https://<your-domain>/readyz` → `{"status":"ready"}` (DB reachable)
- `curl -s https://<your-domain>/version` → `{"version":…,"build":…,"built_at":…,"mcp_tools":29,"mcp_ready":…}`
  (`build` is the short git SHA baked at image build, `built_at` its timestamp — use them to confirm exactly
  which commit is live. Also shown in the Apple-style **About** menu.)

## After deploy — validate

Run the **[15-minute live validation](docs/live-validation.md)** to prove both rails (management access +
dynamic layers) against your real SMS and a Gaia gateway, including the publish / layer-push gates.
