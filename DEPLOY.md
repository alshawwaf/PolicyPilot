# Deploying PolicyPilot

PolicyPilot runs as a **single Docker container**: it listens on port **8000** (plain HTTP via uvicorn),
persists all state in SQLite under **`/data`**, reads its config from `PILOT_*` environment variables, runs as
a non-root user, and ships a Docker `HEALTHCHECK` on `/healthz`. It expects a **TLS-terminating reverse proxy
in front** — the app speaks HTTP on 8000; your proxy speaks publicly-trusted HTTPS to the world.

Nothing about PolicyPilot is tied to a particular platform — it runs on any Docker host. Pick the install
method that fits your environment; the shared configuration reference is below the methods.

## Choose an install method

<details>
<summary><b>Docker Compose — bundled Caddy, automatic HTTPS (turnkey self-host)</b></summary>

The quickest path, with no manual certificate step. The repo ships a `docker-compose.yml` (app + **Caddy**)
and a `Caddyfile`; Caddy obtains a Let's Encrypt certificate for your domain automatically (or an internal
cert when `PILOT_DOMAIN=localhost` for a local demo).

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

Caddy publishes ports **80/443**; the app is reachable only through it. `PILOT_TRUSTED_PROXY_HOPS=1` is
already set in the compose file (Caddy is one proxy in front). Sign in at `https://<PILOT_DOMAIN>` as the
admin above.

</details>

<details>
<summary><b>Plain Docker — bring your own reverse proxy</b></summary>

Build and run the image, then put any TLS-terminating reverse proxy in front (nginx, Caddy, Traefik, HAProxy,
a cloud load balancer):

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

Your proxy must forward to container port **8000**, terminate TLS, and pass the `X-Forwarded-*` headers (the
app runs uvicorn with `--proxy-headers`). Mount a persistent volume at **`/data`** — SQLite lives there;
without it, saved management servers, gateways, dynamic layers, settings, and API keys are wiped on every
redeploy. Set `PILOT_TRUSTED_PROXY_HOPS` to the number of proxies in front, and leave `PILOT_DATABASE_URL`
unset (the image already points it at `/data/policypilot.db`).

</details>

<details>
<summary><b>Dokploy (or another build-from-Dockerfile PaaS: Coolify, Render, Fly.io, …)</b></summary>

Most build-from-Dockerfile platforms follow the same shape. Using **Dokploy** as the worked example:

1. **Create an Application** — your project → *Create Service* → *Application*.
2. **Source** — the Git repo (a Check Point-approved remote per org policy), or a Docker image you've pushed.
3. **Build** — type **Dockerfile**; build context `.`, Dockerfile path `Dockerfile`.
4. **Port** — set the exposed port to **8000** (uvicorn's listen port).
5. **Domain** — add your domain (e.g. `policypilot.example.com`); Dokploy provisions the Let's Encrypt cert via
   its Traefik automatically. (On other platforms, their ingress does the same.)
6. **Persistent volume** — mount a named volume at container path **`/data`**. The SQLite DB lives there;
   without it, your saved servers, gateways, dynamic layers, settings, and API keys are wiped on every redeploy.
7. **Environment variables** (the bootstrap set — see the full `PILOT_*` list below):
   ```
   PILOT_BASE_URL=https://<your-domain>            # MUST equal the domain in step 5
   PILOT_SESSION_SECRET=<openssl rand -base64 32>
   PILOT_ENCRYPTION_KEY=<openssl rand -base64 32>  # encrypts saved gateway / SMS creds at rest — PERSIST IT
   PILOT_ADMIN_USERNAME=admin
   PILOT_ADMIN_PASSWORD=<choose a strong password>
   PILOT_TRUSTED_PROXY_HOPS=1                       # one proxy (Traefik/ingress) in front
   ```
   Don't set `PILOT_DATABASE_URL` — the `Dockerfile` already points it at `/data/policypilot.db`.
8. **Deploy.** Sign in at your domain as the admin user above. Redeploy (or push to the tracked branch) to
   update; the `/data` volume preserves everything across deploys.

</details>

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
| `PILOT_MCP_TOKEN` | Bearer for the MCP endpoint. On boot the app seeds an **active mcp-scope API key** from this value (`_seed_mcp_key()`), so the portal-mounted `/mcp` (and the standalone `python -m app.mcp_server`) accept `Authorization: Bearer $PILOT_MCP_TOKEN` with no admin minting a key by hand. | unset |
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

Rebuild and restart: `docker compose up -d --build` (compose), `docker build` + recreate the container (plain
Docker), or redeploy on your platform. The `/data` volume preserves your servers, gateways, dynamic layers,
settings, and API keys across deploys.

## After deploy — validate

Run the **[15-minute live validation](docs/live-validation.md)** to prove both rails (management access +
dynamic layers) against your real SMS and a Gaia gateway, including the publish / layer-push gates.
