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
7. **Environment variables:**
   ```
   PILOT_BASE_URL=https://<your-domain>            # MUST equal the domain in step 5
   PILOT_SESSION_SECRET=<openssl rand -base64 32>
   PILOT_ENCRYPTION_KEY=<openssl rand -base64 32>  # encrypts saved gateway / SMS creds at rest
   PILOT_ADMIN_USERNAME=admin
   PILOT_ADMIN_PASSWORD=<choose a strong password>
   PILOT_TRUSTED_PROXY_HOPS=1                       # Traefik/Caddy = 1 proxy in front
   ```
   Don't set `PILOT_DATABASE_URL` — the `Dockerfile` already points it at `/data/policypilot.db`.
8. **Deploy.** Sign in at your domain as the admin user above.

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
`Authorization: Bearer <key>`. The `mcp` SDK is installed from `requirements.txt` during the Docker build. See
[docs/mcp-n8n.md](docs/mcp-n8n.md).

## Updating

Push to the tracked branch (or hit *Redeploy*). The `/data` volume preserves your servers, gateways, dynamic
layers, and settings across deploys.

## Reachability check

The portal must be reachable at `https://<your-domain>` on 443. From any shell:
- `curl -s https://<your-domain>/healthz` → `{"status":"ok"}` (liveness)
- `curl -s https://<your-domain>/readyz` → `{"status":"ready"}` (DB reachable)
- `curl -s https://<your-domain>/version` → `{"version":…,"mcp_tools":21,"mcp_ready":…}`

## After deploy — validate

Run the **[15-minute live validation](docs/live-validation.md)** to prove both rails (management access +
dynamic layers) against your real SMS and a Gaia gateway, including the publish / layer-push gates.
