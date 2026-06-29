# Deploying to Dokploy

Hosted on **Dokploy** (your own Dokploy panel). Dokploy's Traefik handles the
domain and Let's Encrypt TLS, so the Check Point gateway sees a publicly-trusted HTTPS feed with
no cert-trust step. (Caddy / `docker-compose.yml` are only for standalone local/lab runs.)

## One-time setup

1. **Create an Application** — your project → *Create Service* → *Application*.
2. **Source** — the Git repo for this project (use a Check Point-approved remote per org policy),
   or a Docker image you've pushed to a registry.
3. **Build** — type *Dockerfile*; build context `/`, Dockerfile `Dockerfile`.
4. **Port** — set the app/exposed port to **8000** (uvicorn's listen port).
5. **Domain** — add your domain (e.g. `dcsim.example.com`). Dokploy provisions the
   Let's Encrypt cert via Traefik automatically.
6. **Persistent volume** — add a mount at container path **`/data`**. SQLite lives there;
   without this, all feeds and poll history are wiped on every redeploy.
7. **Environment variables**:
   ```
   DCSIM_BASE_URL=https://<your-domain>          # MUST equal the domain in step 5
   DCSIM_SESSION_SECRET=<openssl rand -base64 32>
   DCSIM_ADMIN_USERNAME=admin
   DCSIM_ADMIN_PASSWORD=<choose a strong password>
   DCSIM_DATABASE_URL=sqlite:////data/dcsim.db
   DCSIM_ENCRYPTION_KEY=<openssl rand -base64 32>   # optional — encrypts saved gateway + DC creds
   DCSIM_SYSLOG_PORT=5514                            # SIEM receiver port (0 disables it)
   ```
8. **Deploy.** Sign in at your domain as the admin user above.

## Non-HTTP ports (SIEM 5514, Nutanix 9440) — read this before you fight it

Most of the portal rides Traefik on 443 and just works. **Two integrations don't**, and getting them
working on a fresh Ubuntu/Dokploy host cost a full day of debugging once. This is the whole picture so
it doesn't again. Skip whichever you won't demo.

- **SIEM receiver — 5514 (TCP *and* UDP).** Log Exporter sends raw syslog/CEF/LEEF, **not** HTTP, so it
  bypasses Traefik. Needs `DCSIM_SYSLOG_PORT=5514` *and* the port reaching the app container.
- **Nutanix — 9440 (TCP).** CloudGuard's Prism connector hardcodes 9440; the portal must answer there.

**Why "just publish the port" silently fails on Dokploy/Swarm** — three independent traps, each of
which drops the traffic while *every local/loopback test still passes* (the tell: `tcpdump` on the host
shows the packets arriving, but `/siem` or the Nutanix viewer stays empty):

1. **Swarm ingress drops UDP.** Dokploy publishes via the Swarm routing mesh, which mangles UDP and
   rewrites the source IP. A host-mode publish or a **host-network socat** is required for 5514.
2. **The host firewall (`ufw`).** A default `-P INPUT DROP` blocks external packets that loopback never
   hits (loopback has its own early `-i lo -j ACCEPT`). Worse, ufw can be in a **zombie state**:
   `ufw status` lists your `allow` rules but `ufw reload` says *"Firewall not enabled"*, meaning they
   were never loaded. Usual cause — a stray line (e.g. a leftover heredoc delimiter) after `COMMIT` in
   `/etc/ufw/after.rules`, which makes `iptables-restore` fail. Remove it, then re-enable ufw.
3. **A hardened `DOCKER-USER` lockdown.** Some hosts carry a deliberate `-A DOCKER-USER -i <iface> -j DROP`
   (in `after.rules`, "force traffic through Traefik") that blocks *all* external→container traffic
   except an allow-list — which **also defeats host-mode publish** for any port not on it. A
   host-network socat sidesteps it: it receives on the host and forwards host→container, never the
   guarded `iface→container` forward path the rule guards.

### The recipe that works (even on a locked-down host)

**1 — Open the ports and confirm ufw truly enforces:**
```bash
sudo ufw allow 5514/tcp && sudo ufw allow 5514/udp && sudo ufw allow 9440/tcp
sudo ufw status verbose
sudo ufw reload
```
If `reload` prints *"Firewall not enabled"* while `status` says active, the rules aren't live — fix
`/etc/ufw/after.rules` (drop any stray non-iptables line after `COMMIT`), then `sudo ufw disable && sudo ufw enable`. `22/tcp` stays allowed, so SSH survives.

**2 — SIEM 5514 → app**, via a host-network socat to the app's `docker_gwbridge` IP. That IP changes on
every redeploy, so use the bundled helper (`tools/siem-host-socat.sh` in this repo), which re-resolves it
each run. Copy it onto the host and run it:
```bash
sudo install -m 0755 tools/siem-host-socat.sh /usr/local/bin/siem-host-socat   # from a repo checkout
# or, if you're on the host without the repo: scp the file over, then chmod +x it
sudo siem-host-socat
```

**3 — Nutanix 9440 → Traefik 443**, a raw-TCP passthrough (TLS/SNI flow straight to Traefik's cert):
```bash
docker run -d --name dcsim-nutanix-9440 --restart unless-stopped --network host \
  alpine/socat TCP-LISTEN:9440,fork,reuseaddr TCP:127.0.0.1:443
```
This targets `127.0.0.1:443` (stable across redeploys), so unlike the SIEM forwarder it survives.

**4 — Open the same ports at the cloud / CloudShare edge.** Whatever publishes 443 to the internet must
also pass 5514 (tcp+udp) and 9440 — add them to the security group / NSG / environment policy. 443
works only because the edge forwards it; the others stay dropped until you add them.

### After every redeploy
A redeploy gives the app a new `docker_gwbridge` IP, so **re-point the SIEM forwarder** — one command:
```bash
sudo siem-host-socat
```
Then confirm `/siem` is receiving, and re-run the Nutanix import in SmartConsole. (The 9440 socat targets
Traefik, so it doesn't need this.)

> `DCSIM_SYSLOG_PORT=0` turns the SIEM listener off entirely. The **full diagnostic ladder** for
> "packets reach the host but nothing shows up" — NIC → firewall → host socket → container — is in
> [docs/integrations/siem.md](docs/integrations/siem.md#troubleshooting--packets-reach-the-host-but-nothing-shows-on-siem).

## Why each setting matters

- **`DCSIM_BASE_URL`** is what the portal prints as the feed URL you paste into SmartConsole —
  it must match the public domain, or the URLs you hand out will be wrong.
- The container runs uvicorn with `--proxy-headers`, so the **live poll log shows the real
  gateway IP** (from Traefik's `X-Forwarded-For`), not Traefik's address.
- **Run a single uvicorn worker** — the `Dockerfile` already does; **do not add `--workers N`** (in a
  Dokploy build/run override or a custom command). The SIEM syslog listener binds `DCSIM_SYSLOG_PORT`
  *once per process* and the retention/housekeeping loop runs *per process*, so multiple workers would
  fight over the port (only one binds — the rest log a bind warning and the SIEM demo silently breaks)
  and run duplicate loops against the single SQLite file. One worker is correct here; scale by running
  more instances behind the load balancer if ever needed, not more workers.
- **`DCSIM_ENCRYPTION_KEY`** encrypts saved gateway and datacenter credentials at rest (AES-256-GCM).
  Optional — it falls back to `DCSIM_SESSION_SECRET`; set a dedicated key so rotating the session
  secret doesn't make stored credentials unreadable.
- **Integration secrets are better set from the UI than baked into the deploy.** The MCP token,
  ticketing webhook secret, and ServiceNow credentials can be set in **Settings** (encrypted at rest,
  no redeploy) and take precedence over any `DCSIM_MCP_TOKEN` / `DCSIM_WEBHOOK_TOKEN` /
  `DCSIM_SERVICENOW_*` env vars — those env vars are just fallbacks. See [docs/settings.md](docs/settings.md).
- A Docker `HEALTHCHECK` hits `/healthz`, so Dokploy reports container health.

## Updating

Push to the tracked branch (or hit *Redeploy*). The `/data` volume preserves all feeds and poll
history across deploys.

## Reachability check

The customer's CP Management/Gateway must reach `https://<your-domain>` on 443. From a gateway
shell: `curl -s https://<your-domain>/healthz` should return `{"status":"ok"}`.
