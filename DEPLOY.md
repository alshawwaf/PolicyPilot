# Deploying PolicyPilot

PolicyPilot runs as a **single Docker container**: it listens on port **8000** (plain HTTP via uvicorn),
persists all state in SQLite under **`/data`**, reads its config from `PILOT_*` environment variables, runs as
a non-root user, and ships a Docker `HEALTHCHECK` on `/healthz`. It expects a **TLS-terminating reverse proxy
in front** — the app speaks HTTP on 8000; your proxy speaks publicly-trusted HTTPS to the world.

Nothing about PolicyPilot is tied to a particular platform. Any Docker host works — a VM, a container PaaS, or
your own orchestrator. Pick whichever path below fits your environment.

## Option A — `docker compose` with Caddy (automatic HTTPS)

The quickest self-host, with no manual certificate step. The repo ships a `docker-compose.yml` (app + **Caddy**)
and a `Caddyfile`; Caddy obtains a Let's Encrypt certificate for your domain automatically (or an internal cert
when `PILOT_DOMAIN=localhost` for a local demo).

```bash
cp .env.example .env         # then edit it (see below)
docker compose up -d --build
```

Set in `.env`:

```
PILOT_DOMAIN=policypilot.example.com             # public hostname Caddy issues a cert for
PILOT_BASE_URL=https://policypilot.example.com   # MUST equal the domain above
PILOT_SESSION_SECRET=<openssl rand -base64 32>
PILOT_ENCRYPTION_KEY=<openssl rand -base64 32>   # PERSIST THIS — see the warning below
PILOT_ADMIN_USERNAME=admin
PILOT_ADMIN_PASSWORD=<choose a strong password>
```

Caddy publishes ports **80/443**; the app is reachable only through it. `PILOT_TRUSTED_PROXY_HOPS=1` is already
set in the compose file (Caddy is one proxy in front). Sign in at `https://<PILOT_DOMAIN>` as the admin above.

## Option B — plain Docker behind your own proxy or platform

Build and run the image, then put **any** TLS-terminating reverse proxy or PaaS in front:

```bash
docker build -t policypilot .
docker run -d --name policypilot -p 8000:8000 -v policypilot-data:/data \
  -e PILOT_BASE_URL=https://policypilot.example.com \
  -e PILOT_SESSION_SECRET=... \
  -e PILOT_ENCRYPTION_KEY=... \
  -e PILOT_ADMIN_PASSWORD=... \
  -e PILOT_TRUSTED_PROXY_HOPS=1 \
  policypilot
```

Whatever fronts it — nginx, Caddy, Traefik, HAProxy, a cloud load balancer, or a container PaaS such as
Dokploy / Coolify / Render / Fly.io — must:

- forward to container port **8000**;
- terminate TLS and pass the `X-Forwarded-*` headers (the app runs uvicorn with `--proxy-headers`);
- mount a persistent volume at **`/data`** — SQLite lives here; without it, saved management servers,
  gateways, dynamic layers, settings, and API keys are wiped on every redeploy;
- provide the environment below — `PILOT_BASE_URL` must equal the public HTTPS URL, and
  `PILOT_TRUSTED_PROXY_HOPS` must equal the number of proxies in front.

Leave `PILOT_DATABASE_URL` unset — the image already points it at `/data/policypilot.db`.

### Example: a build-from-Dockerfile PaaS (Dokploy, Coolify, Render, …)

Most such platforms follow the same shape:

1. **Create an application** from this Git repo (a Check Point-approved remote per org policy) or a pushed image.
2. **Build type** Dockerfile (context `.`, Dockerfile path `Dockerfile`).
3. **Port** — the exposed/container port is **8000**.
4. **Domain** — add your domain; the platform provisions the TLS certificate (e.g. via its built-in
   Traefik / ingress).
5. **Persistent volume** — mount one at container path **`/data`**.
6. **Environment** — set the bootstrap set below.
7. **Deploy**, then sign in at your domain as the admin.

## The full `PILOT_*` environment (`app/config.py`)

Only a few are needed to boot (base URL, session secret, encryption key, admin password). Everything else has a
safe default **or** is settable later from the **Settings** UI — see the note under this table.

| Env var | Purpose | Default / if unset |
|---|---|---|
| `PILOT_BASE_URL` | Public HTTPS URL; stamped into MCP/webhook/`gaia_api` endpoint URLs and decides the cookie `Secure` flag. | `http://localhost:8000` |
| `PILOT_SESSION_SECRET` | Signs the portal session cookie. | ephemeral key (logs everyone out on restart) |
| `PILOT_ENCRYPTION_KEY` | AES-256-GCM key for secrets at rest (saved SMS/gateway creds + portal-set MCP/webhook/ServiceNow secrets). | falls back to `PILOT_SESSION_SECRET` — **see warning below** |
| `PILOT_ADMIN_USERNAME` | Seed admin username (structurally protected — can't be demoted/disabled). | `admin` |
| `PILOT_ADMIN_PASSWORD` | Seed admin password. | random password generated + **printed once** to the container log |
| `PILOT_DATABASE_URL` | SQLAlchemy URL. Leave unset in Docker. | `sqlite:///./data/policypilot.db` (image → `/data/…`) |
| `PILOT_TRUSTED_PROXY_HOPS` | Reverse-proxy hops in front (see below). | `0` (trust the direct TCP peer) |
| `PILOT_WEBHOOK_TOKEN` | `X-PolicyPilot-Token` shared secret enabling the ticketing webhook. | unset → webhook disabled |
| `PILOT_WEBHOOK_SERVER_IDS` | Comma-separated server ids the webhook may target. | blank = all allowed servers |
| `PILOT_MCP_TOKEN` | Bearer for the **standalone** `python -m app.mcp_server` run mode only (the portal-mounted `/mcp` uses an mcp-scope API key instead). | unset |
| `PILOT_SERVICENOW_INSTANCE` / `_USER` / `_PASSWORD` / `_TABLE` | Optional ServiceNow Table API write-back of the decision + rule UID. | unset (`_TABLE` = `incident`) |

> **Most of these are also settable from the Settings UI now** (portal-configurable secrets, encrypted at
> rest — the MCP token, webhook token/server-ids, and ServiceNow creds). A portal-set value **takes
> precedence** over its `PILOT_*` env var, so env is the **bootstrap path** and you rotate secrets from the
> browser with no redeploy. See [docs/settings.md](docs/settings.md).

> **`PILOT_ENCRYPTION_KEY` must be set and persisted.** All saved credentials and portal-set secrets are
> encrypted with it. If it's unset it derives from `PILOT_SESSION_SECRET`; if **both** are unset (dev), the
> ephemeral session key changes on every restart and **every stored secret becomes undecryptable** — you'd
> re-enter them in Settings. Even with a value, don't derive it from the session secret in prod: **rotating
> the session/cookie secret then orphans every stored secret.** Set a dedicated `PILOT_ENCRYPTION_KEY` and
> keep it stable for the life of the deployment.

## Why each setting matters

- **`PILOT_BASE_URL`** is stamped into the MCP / webhook / `gaia_api` endpoint URLs shown on the guide pages,
  and decides the session cookie's `Secure` flag — it must match the public HTTPS URL your proxy serves.
- **`PILOT_ENCRYPTION_KEY`** encrypts saved gateway and management-server credentials at rest (AES-256-GCM). It
  falls back to `PILOT_SESSION_SECRET`; set a dedicated key so rotating the session secret doesn't orphan stored
  credentials.
- **`PILOT_TRUSTED_PROXY_HOPS`** is the number of reverse proxies in front of the app (`1` for a single proxy
  like the bundled Caddy). It lets the **login brute-force throttle** and the activity log key on the *real*
  client from `X-Forwarded-For` rather than a spoofable header — without it set correctly, the throttle could be
  bypassed by rotating XFF. Set it to match your proxy chain (`0` if the app is exposed directly).
- **Run a single uvicorn worker** — the image already does; **do not add `--workers N`**. The housekeeping /
  retention loop runs per process against the single SQLite file, so multiple workers would run duplicate loops.
  Scale by running more instances behind a load balancer if ever needed, not more workers.
- **Integration secrets are better set from the UI than baked into the deploy.** The MCP token, ticketing
  webhook secret, and ServiceNow credentials can be set in **Settings** (encrypted at rest, no redeploy) and
  take precedence over the `PILOT_MCP_TOKEN` / `PILOT_WEBHOOK_TOKEN` / `PILOT_SERVICENOW_*` env fallbacks. See
  [docs/settings.md](docs/settings.md).
- A Docker `HEALTHCHECK` hits `/healthz`, so your platform or orchestrator can report container health.

## The agent (MCP) endpoint

The MCP endpoint is served at **`/mcp`** over the same domain and reverse proxy (HTTPS) — no extra port. It
activates once you mint an **mcp-scope API key** (Settings → API keys, or right on `/mcp-guide`); clients send
it as `Authorization: Bearer <key>`. The `/mcp` mount depends on the `mcp` SDK, which ships from **Check Point
Artifactory, not public PyPI** — it's import-guarded (`app/mcp_server.py`): if the SDK isn't present the
endpoint is simply not mounted and the rest of PolicyPilot (portal + REST API) is unaffected. `/version`
reports `mcp_ready` once the SDK is present **and** an mcp-scope key exists. See [docs/mcp-n8n.md](docs/mcp-n8n.md).

## Health & version checks

The portal must be reachable at `https://<your-domain>` on 443. From any shell:

- `curl -s https://<your-domain>/healthz` → `{"status":"ok"}` (liveness)
- `curl -s https://<your-domain>/readyz` → `{"status":"ready"}` (DB reachable)
- `curl -s https://<your-domain>/version` → `{"version":…,"build":…,"built_at":…,"mcp_tools":29,"mcp_ready":…}`
  (`build` is the short git SHA baked at image build, `built_at` its timestamp — use them to confirm exactly
  which commit is live. Also shown in the Apple-style **About** menu.)
- `curl -s https://<your-domain>/dbapi/v1/conformance` — a read-only self-check that the agent surface is wired
  and safe (no live SMS/gateway calls, no mutations).

## Updating

Rebuild and restart: `docker compose up -d --build` (compose), or redeploy on your platform. The `/data` volume
preserves your servers, gateways, dynamic layers, settings, and API keys across deploys.

## After deploy — validate

Run the **[15-minute live validation](docs/live-validation.md)** to prove both rails (management access +
dynamic layers) against your real SMS and a Gaia gateway, including the publish / layer-push gates.
