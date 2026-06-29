"""ORM models: portal users, management servers + gateways (and their encrypted secrets), dynamic-layer
policies + apply tasks, applied-change history, API keys, settings/state, notifications, and the activity log."""
import datetime as dt
import uuid

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def new_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    first_name: Mapped[str] = mapped_column(String(80), default="")
    last_name: Mapped[str] = mapped_column(String(80), default="")
    email: Mapped[str] = mapped_column(String(200), default="")
    title: Mapped[str] = mapped_column(String(120), default="")          # role / job title
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def display_name(self) -> str:
        return (f"{self.first_name} {self.last_name}".strip()) or self.username


class DynamicLayer(Base):
    """An authored Dynamic Layer policy, stored on the portal and applied to a gateway
    (real or the built-in mock) via the Gaia API 'set-dynamic-content'."""

    __tablename__ = "dynamic_layers"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    # The access-layer name on the gateway (must be marked "Set as a Dynamic Layer").
    layer_name: Mapped[str] = mapped_column(String(200), default="dynamic_layer")
    # Authored payload: {objects:{type:[...]}, rulebase:[...], referenced_objects:{...},
    #                    operation, comments, tags, custom_fields}
    content: Mapped[dict] = mapped_column(JSON, default=dict)

    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    tasks: Mapped[list["LayerTask"]] = relationship(
        back_populates="layer", cascade="all, delete-orphan", order_by="LayerTask.at.desc()"
    )


class LayerTask(Base):
    """A recorded set-dynamic-content apply (to the mock or a real gateway) and its result —
    mirrors the Gaia API async task / show-task response."""

    __tablename__ = "layer_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), index=True)
    layer_id: Mapped[int | None] = mapped_column(
        ForeignKey("dynamic_layers.id"), nullable=True, index=True
    )
    target: Mapped[str] = mapped_column(String(32), default="mock")  # mock | gateway
    gateway_host: Mapped[str | None] = mapped_column(String(200), nullable=True)
    dry_run: Mapped[bool] = mapped_column(default=False)
    status: Mapped[str] = mapped_column(String(32), default="succeeded")
    status_code: Mapped[int] = mapped_column(Integer, default=200)
    # show-task-style payload: {change_summary, validation_warnings, validation_errors, ...}
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")

    layer: Mapped["DynamicLayer"] = relationship(back_populates="tasks")


class ActivityLog(Base):
    """App-wide log of traffic — REST / MCP / webhook calls, gateway reads, and layer applies — each
    with the actual (redacted) request/response for troubleshooting + demos."""

    __tablename__ = "activity_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # api | ui | gateway_read | layer_apply
    direction: Mapped[str] = mapped_column(String(12), default="inbound")  # inbound|outbound
    method: Mapped[str] = mapped_column(String(10), default="")
    path: Mapped[str] = mapped_column(String(400), default="")
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(String(300), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # {request:{...}, response:{...}} or {trace}


class Gateway(Base):
    """A saved gateway connection profile. The login password is optional: if set it is stored
    AES-256-GCM-encrypted in a separate table (GatewaySecret); otherwise it is entered per apply.
    Optionally pins a self-signed cert (PEM) for TLS verification."""

    __tablename__ = "gateways"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    host: Mapped[str] = mapped_column(String(200))
    port: Mapped[int] = mapped_column(Integer, default=443)
    username: Mapped[str] = mapped_column(String(120), default="")
    cert_pem: Mapped[str] = mapped_column(Text, default="")
    # Trust-on-first-use: when set and no cert is pinned yet, the next connect fetches the gateway's
    # presented cert and pins it here (TLS verification then validates against it — never disabled).
    auto_trust: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    snapshot: Mapped["GatewayLayerSnapshot"] = relationship(
        back_populates="gateway", cascade="all, delete-orphan", uselist=False)
    secret: Mapped["GatewaySecret"] = relationship(
        back_populates="gateway", cascade="all, delete-orphan", uselist=False)


class GatewaySecret(Base):
    """The optional gateway login password, encrypted at rest with AES-256-GCM (org policy:
    credentials at rest must use AES-256 or stronger). Kept in its own table so the secret is
    never loaded or serialized alongside the gateway profile unless an apply/fetch needs it."""

    __tablename__ = "gateway_secrets"

    id: Mapped[int] = mapped_column(primary_key=True)
    gateway_id: Mapped[int] = mapped_column(ForeignKey("gateways.id"), unique=True, index=True)
    # Versioned, base64-encoded AES-256-GCM token (nonce + ciphertext + tag). Never the plaintext.
    ciphertext: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    gateway: Mapped["Gateway"] = relationship(back_populates="secret")


class GatewayLayerSnapshot(Base):
    """Persisted snapshot of the dynamic layers last fetched from a gateway (show-dynamic-layers /
    show-dynamic-layer), so the 'what's on this gateway' view survives the fetch modal closing."""

    __tablename__ = "gateway_layer_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    gateway_id: Mapped[int] = mapped_column(ForeignKey("gateways.id"), unique=True, index=True)
    layers: Mapped[list] = mapped_column(JSON, default=list)
    ok: Mapped[bool] = mapped_column(default=True)
    error: Mapped[str] = mapped_column(Text, default="")
    fetched_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    gateway: Mapped["Gateway"] = relationship(back_populates="snapshot")


class AppState(Base):
    """A tiny key→value store for cross-process runtime flags + portal settings that must be shared
    across uvicorn workers / Swarm replicas (which each have their own memory) — e.g. the cached
    settings map. Kept in the DB so a change from any process reaches the others."""

    __tablename__ = "app_state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), default="")


class IdempotencyRecord(Base):
    """The stored result of a committed write (apply / push), keyed by a caller-supplied idempotency key, so a
    retry replays the first result instead of committing twice. ``result`` is the full JSON payload (Text, not
    capped). Records are kept for a TTL (see app.services.idempotency) and survive a worker restart because
    they live in the DB."""

    __tablename__ = "idempotency_records"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiKey(Base):
    """A named, revocable API key for the machine endpoints (MCP /mcp, the ticketing webhook). Only the
    SHA-256 HASH of the secret is stored — the plaintext is shown once at creation and never again — so a
    DB leak exposes no usable key. ``scope`` says which endpoint the key authorizes; ``hint`` is the last
    few characters, kept for display so an admin can tell keys apart without revealing the secret."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    scope: Mapped[str] = mapped_column(String(20), default="mcp", index=True)   # "mcp" | "webhook" | "api"
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # sha256 hex of the secret
    hint: Mapped[str] = mapped_column(String(12), default="")                   # last chars, for display
    # Capability: a read-only key may call read/preview tools (decide_access, fetch_dynamic_layer, …) but
    # every write tool (apply/remove/amend/revert/add/remove-rule/import/push) refuses. Default True so
    # existing keys keep full access; mint a read-only key to give an agent look-but-don't-touch access.
    can_write: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(120), default="")
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AppliedChange(Base):
    """An access-automation change that was PUBLISHED to a live policy — recorded so it can be rolled back.
    PolicyPilot knows EXACTLY what it did, so each row stores the precomputed INVERSE op(s) (the AlgoSec /
    Tufin 'change set' model): reverting replays that inverse in one publish, surgically undoing just this
    change without touching the rest of the policy or doing a heavy full-DB revision rollback. Dry-runs are
    never recorded (nothing was committed). Objects the change created (hosts/networks/services) are NOT
    deleted on revert — they may now be referenced elsewhere — only the rule change is undone."""

    __tablename__ = "applied_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    created_by: Mapped[str] = mapped_column(String(120), default="")   # "user:alice" | "mcp:<key>" | "webhook"
    server_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    server_name: Mapped[str] = mapped_column(String(255), default="")  # snapshot (the server may be deleted)
    layer: Mapped[str] = mapped_column(String(255), default="")
    package: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(12), default="apply")   # "apply" | "remove"
    outcome: Mapped[str] = mapped_column(String(12), default="")       # create | widen | disable | deny
    summary: Mapped[str] = mapped_column(Text, default="")             # human one-liner for the history list
    ticket_id: Mapped[str] = mapped_column(String(120), default="")
    request_json: Mapped[dict] = mapped_column(JSON, default=dict)     # the request tuple (display + audit)
    inverse_json: Mapped[list] = mapped_column(JSON, default=list)     # precomputed inverse op(s) — see revert
    objects_json: Mapped[list] = mapped_column(JSON, default=list)     # object names touched (display only)
    reverted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # resolved-at
    reverted_by: Mapped[str] = mapped_column(String(120), default="")
    revert_error: Mapped[str] = mapped_column(Text, default="")        # last failed-revert reason, if any
    resolution: Mapped[str] = mapped_column(String(16), default="")    # "" open | "reverted" (inverse applied)
    #                                                                    | "deleted" (a disabled rule was deleted)


class Notification(Base):
    """A persisted, per-user notification for the header bell. Every flash message is also recorded
    here so the admin can review and delete past notifications (transient toast + durable history)."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="success")   # success | error | info
    text: Mapped[str] = mapped_column(Text, default="")
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class LoginThrottle(Base):
    """Brute-force protection for the login form, keyed by CLIENT IP (never username — locking a
    username would let anyone DoS the admin out of their own portal). Too many failures -> a cooldown."""

    __tablename__ = "login_throttle"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)     # client IP
    fails: Mapped[int] = mapped_column(Integer, default=0)
    first_fail: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserTablePref(Base):
    """Per-user, per-table view preferences (visible columns; later density/sort) so a chosen table
    view sticks across sessions/devices and is resolved server-side before first paint."""

    __tablename__ = "user_table_prefs"
    __table_args__ = (UniqueConstraint("owner_id", "table_id", name="uq_user_table"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    table_id: Mapped[str] = mapped_column(String(64))
    prefs: Mapped[dict] = mapped_column(JSON, default=dict)


class UserDesktopPref(Base):
    """Per-user desktop layout for the OS-style Home: which apps sit on the dock and which icons sit on
    the desktop (with x/y), so a user's arrangement sticks across sessions/devices. One row per user."""

    __tablename__ = "user_desktop_prefs"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, unique=True)
    layout: Mapped[dict] = mapped_column(JSON, default=dict)


class GlobalPref(Base):
    """Portal-wide JSON defaults set by an admin (no length cap, unlike AppState's String value) — e.g.
    the default desktop layout that new / un-customised users inherit. ``key`` is the pref name."""

    __tablename__ = "global_prefs"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)


class ManagementServer(Base):
    """A saved Check Point Management Server (or MDS domain/CMA) connection the portal drives over the
    `web_api`: pull layers/objects, view/edit them, export to IaC. Login password / API key is stored
    AES-256-GCM-encrypted in `ManagementSecret`; an optional pinned cert (or trust-on-first-use) keeps
    TLS verification on. Holds a *real* customer policy once pulled — treat the instance as sensitive."""

    __tablename__ = "management_servers"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    host: Mapped[str] = mapped_column(String(200))
    port: Mapped[int] = mapped_column(Integer, default=443)
    username: Mapped[str] = mapped_column(String(120), default="")
    domain: Mapped[str] = mapped_column(String(200), default="")   # MDS/CMA domain; blank = single SMS
    cert_pem: Mapped[str] = mapped_column(Text, default="")
    auto_trust: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    secret: Mapped["ManagementSecret"] = relationship(
        back_populates="server", cascade="all, delete-orphan", uselist=False)


class ManagementSecret(Base):
    """The Management Server login password or API key, encrypted at rest (AES-256-GCM), in its own
    table so it's never loaded or serialized with the server profile unless a call needs it."""

    __tablename__ = "management_secrets"

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("management_servers.id"), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="password")   # password | api_key
    ciphertext: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    server: Mapped["ManagementServer"] = relationship(back_populates="secret")


