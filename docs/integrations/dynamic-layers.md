# Dynamic Layers (Gaia API push)

Unlike the feeds and datacenter mocks (which CloudGuard **polls**), this is a **push** model: the
portal authors an Access Control rulebase and applies it to a gateway's **Gaia API**
(`set-dynamic-content`, R82.10) — either a **real gateway**, or the built-in **mock Gaia API** for a
no-hardware demo with a realistic async task + change summary.

- Builder/apply router: [`app/routers/dynamic_layers.py`](../../app/routers/dynamic_layers.py)
- Real-gateway apply flow (the Gaia API session): [`app/services/apply_runner.py`](../../app/services/apply_runner.py)
- TLS cert fetch / pin (trust-on-first-use): [`app/services/gaia_client.py`](../../app/services/gaia_client.py)
- Mock Gaia API: [`app/routers/gaia_mock.py`](../../app/routers/gaia_mock.py)
- Gateways: [`app/routers/gateways.py`](../../app/routers/gateways.py)

## Use it

1. Portal → **Layers & Gateways → New Dynamic Layer**. Build the rulebase: define **referenced
   objects** (hosts, networks, services) first, then **rules** that use them.
2. **Apply** to a target:
   - **Real gateway** (default): enter the Gaia API host + credentials (or prefill from a saved
     **Gateway**). The portal logs in, calls `set-dynamic-content`, polls `show-task`, logs out.
   - **Mock gateway** (checkbox): the portal calls its own mock Gaia API — same flow, no hardware.
3. Watch **live progress** (async task) and the full **HTTP trace** of each Gaia call. Results are
   merged into the layer's Rulebase view; the **History** page keeps prior applies (with delete).

## Real-gateway push

`apply_runner` uses `httpx` against the gateway's Gaia API (cert pinning is handled by `gaia_client`):

- `login` → session id (sid) → `set-dynamic-content` → `show-task` (poll until done) → `logout`.
- **TLS is verified by default.** For a self-signed lab gateway you have two policy-safe options,
  both of which keep verification **on** (it is never silently disabled):
  - **Trust-on-first-use (default).** Leave the cert field blank and keep *"Trust this gateway's
    certificate automatically"* ticked. On the first connect (`ensure_pinned`) the portal fetches the
    certificate the gateway presents, pins it to the profile, and verifies against that pinned PEM on
    every connect after — the SSH `known_hosts` model. This is the default for new gateways so the SE
    isn't forced to fetch a cert manually.
  - **Manual pin.** Untick auto-trust and fetch (`fetch-cert`) or paste a specific certificate to pin,
    so you can review the SHA-256 fingerprint before saving.
- **No credentials are persisted** by default. A gateway's password may optionally be **stored
  encrypted** (AES-256-GCM, `app/services/gateway_creds.py`); set `DCSIM_ENCRYPTION_KEY` in prod.

## Mock Gaia API (for no-hardware demos)

Served under `/gaia_api` (version-prefixed and bare forms), mirroring the real API:

- `POST /gaia_api/login` → `{ sid }`
- `POST /gaia_api/set-dynamic-content` → `{ task-id }` (async)
- `POST /gaia_api/show-task` → task progress → succeeded (with a change summary)
- `POST /gaia_api/show-dynamic-layer` / `show-dynamic-layers` — inspect applied content
- `POST /gaia_api/logout`

Every call is captured in the **Activity log** (kind *Mock Gaia API*), with bodies redacted.

## Object model

A Dynamic Layer is an **Access Control rulebase**: referenced objects (hosts/networks/services) +
rules that reference them. The default layer ships with referenced objects and rules that use them.
Long object lists are paginated in the builder (designed for e.g. a customer with 300 hosts).

## Notes

- The real R82.10 commands are `set-dynamic-content` (push the layer's content) and
  `set/show-dynamic-layer(s)` (manage the layers). See the memory note `gaia-dynamic-layer-api`.
- This is the one integration where the portal is the **client** (pushing) rather than the server
  (being polled) — useful when a PoV can't expose a pollable URL to the gateway.
