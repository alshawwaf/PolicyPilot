"""Runtime configuration, sourced from environment / .env (prefix PILOT_)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="PILOT_", extra="ignore")

    app_name: str = "PolicyPilot"

    # Public base URL used to build the feed URLs shown to the SE. Behind Caddy
    # this is the HTTPS domain (e.g. https://policypilot.example.com). Set via env.
    base_url: str = "http://localhost:8000"

    # Cookie-signing key for portal sessions. MUST be set in production.
    # If empty, an ephemeral key is generated at startup (dev only — logs out on restart).
    session_secret: str = ""

    # Dedicated key for encrypting secrets at rest (saved gateway/DC passwords + the portal-set MCP /
    # webhook / ServiceNow secrets, AES-256-GCM). Falls back to session_secret. If both are empty, stored
    # secrets cannot be decrypted after a restart — set PILOT_ENCRYPTION_KEY (or PILOT_SESSION_SECRET) in
    # prod. RECOMMENDED: set PILOT_ENCRYPTION_KEY independently of PILOT_SESSION_SECRET — otherwise
    # rotating the session/cookie secret changes the derivation base and ORPHANS every stored secret
    # (they become undecryptable and silently fall back to env/disabled; you'd re-enter them in Settings).
    encryption_key: str = ""

    # Seed portal admin. Never hardcode a password — set PILOT_ADMIN_PASSWORD via env.
    # If empty, a random password is generated and printed once at startup (dev convenience).
    admin_username: str = "admin"
    admin_password: str = ""

    database_url: str = "sqlite:///./data/policypilot.db"

    # Reverse-proxy hops in front of the app that APPEND the client to X-Forwarded-For (1 for a single
    # Caddy / Traefik / nginx). Used to derive the real client IP for the login brute-force throttle WITHOUT
    # trusting a spoofable XFF. 0 (default) = no proxy / don't trust XFF (use the direct TCP peer). Behind
    # the bundled Caddy or a Dokploy/Traefik proxy, set PILOT_TRUSTED_PROXY_HOPS=1 so the throttle keys on
    # the real client and can't be bypassed by rotating the header.
    trusted_proxy_hops: int = 0

    # Access automation — generic ticketing webhook (ServiceNow, Jira, Remedy, custom portal …).
    # The inbound webhook (POST /access-automation/webhook) is DISABLED unless a shared secret is set;
    # the caller must send it as the X-PolicyPilot-Token header.
    # SECURITY: this token grants policy publish on every ALLOWED management server, so treat it as a
    # top-tier secret. Optionally scope it to specific servers with the webhook_server_ids allowlist.
    # NOTE: these are now FALLBACKS — Settings → Ticketing webhook (DB-backed, token encrypted at rest)
    # takes precedence and can be set/rotated from the portal with no redeploy.
    webhook_token: str = ""
    webhook_server_ids: str = ""    # comma-separated server ids the webhook may target; blank = all

    # MCP server (for n8n / LLM agents). The /mcp endpoint is mounted whenever the `mcp` SDK is installed
    # (Artifactory) and is ENABLED once a bearer token is set; clients send it as `Authorization: Bearer
    # <token>`. Like the webhook token it can drive policy writes, gated by the mcp_allow_publish setting
    # (default OFF). NOTE: this env var is a FALLBACK — Settings → MCP / agent (DB-backed, encrypted at
    # rest) takes precedence and lets an admin set/rotate/clear the token from the portal with no redeploy.
    mcp_token: str = ""

    # Optional BUILT-IN write-back: post the decision + rule UID to a ServiceNow incident's work notes
    # via the Table API. (Other vendors use the generic per-request `callback_url`, or just read the
    # synchronous response.) TLS verification is always on. NOTE: these are FALLBACKS — Settings →
    # Ticket write-back (DB-backed, password encrypted at rest) takes precedence over the env vars.
    servicenow_instance: str = ""   # e.g. https://dev12345.service-now.com
    servicenow_user: str = ""
    servicenow_password: str = ""
    servicenow_table: str = "incident"


@lru_cache
def get_settings() -> Settings:
    return Settings()
