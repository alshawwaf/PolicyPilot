"""Portal Settings — user-tunable behaviour for how the tool talks to a Check Point management server
(session reuse + revision-based policy cache). Auth-gated; values persist via ``services.app_settings``
(DB-backed ``AppState``) so an admin controls the behaviour from the portal, never from code or env."""
import datetime as dt

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..security import get_user_or_none
from ..services import api_keys, app_settings, table_prefs
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)


def _grouped():
    groups: dict[str, list] = {}
    for s in app_settings.SETTINGS:
        groups.setdefault(s.group, []).append(s)
    return groups


EXPIRY_PRESETS = [("30", "30 days"), ("90", "90 days"), ("365", "1 year"), ("never", "Never")]


def _parse_expiry(form) -> dt.datetime | None:
    """Compute an expiry datetime from the create form: an explicit date wins, else a preset day-count;
    'never' / unparseable → None (no expiry). Good hygiene defaults to a preset rather than never."""
    raw_date = (form.get("expires_date") or "").strip()
    if raw_date:
        try:
            d = dt.datetime.strptime(raw_date, "%Y-%m-%d")
            return d.replace(hour=23, minute=59, second=59, tzinfo=dt.timezone.utc)
        except ValueError:
            pass
    preset = (form.get("expires") or "90").strip()
    if preset == "never":
        return None
    try:
        days = int(preset)
    except (TypeError, ValueError):
        days = 90
    return dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=max(1, days))


def _key_rows(now: dt.datetime) -> list[dict]:
    """API keys annotated with a hygiene status for the table (expired / expiring-soon / unused / ok)."""
    from ..services import api_keys
    out = []
    for k in api_keys.list_keys():
        exp = api_keys.as_utc(k.expires_at)
        created = api_keys.as_utc(k.created_at)
        used = api_keys.as_utc(k.last_used_at)
        if exp and exp <= now:
            status = "expired"
        elif exp and (exp - now).days < 7:
            status = "soon"
        elif used is None and created and (now - created).days >= 30:
            status = "unused"
        else:
            status = "ok"
        out.append({"id": k.id, "name": k.name, "scope": k.scope, "hint": k.hint,
                    "created": created, "last_used": used, "expires": exp, "status": status,
                    "can_write": bool(k.can_write)})
    return out


def _detected_base_url(request: Request) -> str:
    """The public URL this request arrived on, honoring the reverse proxy's X-Forwarded-* headers — so
    the admin can adopt it for base_url with one click instead of typing it blind. Suggestion only."""
    h = request.headers
    proto = (h.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
    host = (h.get("x-forwarded-host") or h.get("host") or request.url.netloc or "").split(",")[0].strip()
    return f"{proto}://{host}".rstrip("/") if host else ""


# --- Settings: one macOS System-Settings style page — a fixed category sidebar + a detail pane that swaps
# in place (no page navigation). key -> (label, settings-group it edits, icon token, sidebar tile colour,
# one-line blurb). "keys" is special (API keys, not a settings group). Order = sidebar + pane order.
SECTIONS = [
    ("agent",      "Agent access",        "MCP / agent",             "robot",        "#7b5cff", "What an LLM agent over /mcp may do — publish, Autopilot, rate limit."),
    ("logic",      "Automation logic",    "Access automation logic", "sliders",      "#3b82f6", "How the engine shapes a change — the Behavior profile."),
    ("naming",     "Automation naming",   "Access automation",       "tag",          "#1d9e75", "How auto-created objects and rules are named."),
    ("management", "Management API",      "Management API",          "server",       "#5566dd", "How the portal logs in and caches when reading/writing the SMS."),
    ("storage",    "Storage & retention", "Storage & retention",     "database",     "#7c8794", "Bound the activity log so a long run never fills the disk."),
    ("governance", "Governance & audit",  "Governance & audit",      "shield-check", "#639922", "A work-note after every committed change."),
    ("webhook",    "Ticketing webhook",   "Ticketing webhook",       "webhook",      "#ba7517", "Turn a ServiceNow / Jira / custom ticket into a policy change."),
    ("writeback",  "Ticket write-back",   "Ticket write-back",       "reply",        "#d4537e", "Optional ServiceNow write-back adapter."),
    ("portal",     "Portal",              "Portal",                  "layout",       "#7c8794", "Portal-wide options."),
    ("keys",       "API keys",            None,                      "key",          "#ef9f27", "Named, scoped, revocable keys for /mcp, the REST API, and the webhook."),
]
_SECTION_GROUP = {key: group for key, _l, group, _i, _c, _b in SECTIONS if group}
_SECTION_KEYS = {key for key, *_rest in SECTIONS}


def _active_mode(vals: dict) -> str:
    """The Operating mode implied by the current gate + profile values (else 'custom')."""
    p, a, pr = vals.get("mcp_allow_publish"), vals.get("aa_autopilot"), vals.get("aa_profile")
    if p and a and pr == "aggressive":
        return "autonomous"
    if p and not a and pr == "balanced":
        return "supervised"
    if (not p) and (not a) and pr == "balanced":
        return "readonly"
    return "custom"


def _section_summaries(vals: dict, secrets: dict, key_count: int) -> dict:
    """A short current-state line per launcher tile."""
    mode = {"readonly": "Read-only", "supervised": "Supervised", "autonomous": "Autonomous"}.get(_active_mode(vals), "Custom")
    recs = vals.get("activity_max_records") or 0
    return {
        "agent": mode,
        "logic": (vals.get("aa_profile") or "balanced").split(" ")[0].title(),
        "naming": "object + rule templates",
        "management": "session reuse " + ("on" if vals.get("mgmt_session_reuse") else "off"),
        "storage": (str(recs) + " records") if recs else "by age",
        "governance": "audit " + ("on" if vals.get("audit_notify") else "off") + (" · webhook" if secrets.get("audit_webhook_url") else ""),
        "webhook": "enabled" if secrets.get("webhook_token") else "disabled",
        "writeback": "ServiceNow set" if secrets.get("servicenow_password") else "not configured",
        "portal": "portal options",
        "keys": str(key_count) + (" key" if key_count == 1 else " keys"),
    }


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    """The whole Settings surface as one page: a fixed category sidebar + a detail pane per section that the
    browser swaps in place (client-side, by URL hash) — no per-section navigation. Lands on Overview."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    vals = app_settings.all_values(fresh=True)
    secrets = app_settings.secret_status()
    grouped = _grouped()
    panes = [{"key": k, "label": l, "icon": i, "color": c, "blurb": b,
              "items": grouped.get(g, []) if g else []}
             for (k, l, g, i, c, b) in SECTIONS]
    return templates.TemplateResponse(request, "settings.html", {
        "panes": panes, "vals": vals, "active_mode": _active_mode(vals),
        "secrets": secrets, "crypto_ok": app_settings.secret_available(),
        "detected_base_url": _detected_base_url(request),
        "summaries": _section_summaries(vals, secrets, len(api_keys.list_keys())),
        "api_keys": _key_rows(dt.datetime.now(dt.timezone.utc)), "api_scopes": api_keys.SCOPES,
        "expiry_presets": EXPIRY_PRESETS, "new_key": request.session.pop("new_api_key", None),
        "flash": _pop_flash(request),
    })


@router.get("/settings/{section}", response_class=HTMLResponse)
def settings_section(section: str, request: Request, db: Session = Depends(get_db)):
    """Back-compat for old per-section links/bookmarks — the page is now a single view, so deep-link
    straight to the relevant pane via the URL hash (the page activates it client-side on load)."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dest = ("/settings#" + section) if section in _SECTION_KEYS else "/settings"
    return RedirectResponse(dest, status_code=303)


@router.post("/settings")
async def settings_save(request: Request, db: Session = Depends(get_db)):
    """Section-scoped save: persist ONLY the keys belonging to the posted section (so a partial form never
    resets another section's toggles). ``section=mode`` saves the three Operating-mode keys. Redirects back
    to the matching pane via the URL hash."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    section = (form.get("section") or "").strip()
    if section == "mode":
        keys, dest = {"mcp_allow_publish", "aa_autopilot", "aa_profile"}, "/settings"
    elif section in _SECTION_GROUP:
        group = _SECTION_GROUP[section]
        keys, dest = {s.key for s in app_settings.SETTINGS if s.group == group}, "/settings#" + section
    else:
        return RedirectResponse("/settings", status_code=303)

    new: dict = {}
    for s in app_settings.SETTINGS:
        if s.key not in keys or s.kind == "secret":
            continue
        if s.kind == "bool":
            new[s.key] = s.key in form          # only this section's bools — others are untouched
        elif s.key in form:
            new[s.key] = form[s.key]
    if new:
        app_settings.save(new)

    secret_err = None
    for s in app_settings.secret_settings():
        if s.key not in keys:
            continue
        if form.get(s.key + "__clear"):
            app_settings.clear_secret(s.key)
            continue
        value = (form.get(s.key) or "").strip()
        if value:
            try:
                app_settings.set_secret(s.key, value)
            except RuntimeError:
                secret_err = ("Can't store secrets: at-rest encryption is unavailable. Set "
                              "PILOT_ENCRYPTION_KEY (or PILOT_SESSION_SECRET) and restart, or keep using "
                              "the PILOT_* env vars.")
    _flash(request, secret_err or "Saved — changes take effect immediately.")
    return RedirectResponse(dest, status_code=303)


@router.post("/settings/reset")
def settings_reset(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    app_settings.save(app_settings.defaults())
    _flash(request, "Settings restored to defaults.")
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/api-keys")
async def api_key_create(request: Request, db: Session = Depends(get_db)):
    """Generate a new API key. The plaintext is shown ONCE via a one-time session entry (never written
    to the notification log), then only its hash remains."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    name = (form.get("name") or "").strip() or "key"
    scope = form.get("scope") or "mcp"
    expires_at = _parse_expiry(form)
    can_write = "readonly" not in form           # checkbox "readonly" → a preview/read-only key
    row, secret = api_keys.generate(name, scope, created_by=user.username, expires_at=expires_at,
                                    can_write=can_write)
    exp_txt = expires_at.strftime("%Y-%m-%d") if expires_at else "never"
    cap_txt = "read-write" if can_write else "read-only"
    request.session["new_api_key"] = {"name": row.name, "scope": row.scope, "key": secret,
                                      "expires": exp_txt, "can_write": can_write}
    _flash(request, f"API key '{row.name}' ({row.scope}, {cap_txt}, expires {exp_txt}) created — copy it "
                    "now, it's shown only once.")
    return RedirectResponse("/settings#keys", status_code=303)


@router.post("/settings/api-keys/{key_id}/expiry")
async def api_key_set_expiry(key_id: int, request: Request, db: Session = Depends(get_db)):
    """Change an existing key's expiry. Explicit (no create-form 90-day default): a picked date wins, else
    a chosen preset ('never' → no expiry); anything else is a no-op so an empty submit never changes it."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    raw_date = (form.get("expires_date") or "").strip()
    preset = (form.get("expires") or "").strip()
    if raw_date:
        try:
            expires_at = dt.datetime.strptime(raw_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=dt.timezone.utc)
        except ValueError:
            _flash(request, "That date wasn’t valid — expiry left unchanged.")
            return RedirectResponse("/settings#keys", status_code=303)
    elif preset == "never":
        expires_at = None
    elif preset.isdigit():
        expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=max(1, int(preset)))
    else:
        _flash(request, "Pick a date or a preset — expiry left unchanged.")
        return RedirectResponse("/settings#keys", status_code=303)
    if api_keys.set_expiry(key_id, expires_at):
        exp_txt = expires_at.strftime("%Y-%m-%d") if expires_at else "never"
        _flash(request, f"API key expiry updated to {exp_txt}.")
    return RedirectResponse("/settings#keys", status_code=303)


@router.post("/settings/api-keys/{key_id}/revoke")
def api_key_revoke(key_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if api_keys.revoke(key_id):
        _flash(request, "API key revoked — it can no longer authenticate.")
    return RedirectResponse("/settings#keys", status_code=303)


@router.post("/prefs/table/{table_id}/columns")
async def save_table_columns(table_id: str, request: Request, db: Session = Depends(get_db)):
    """Persist a user's visible-column choice for a table, then return to the page (server re-renders
    the chosen columns — no flash). Column ids are validated against the table's spec allowlist."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    nxt = str(form.get("next") or "")
    # Same-origin only: reject protocol-relative ("//evil.com") and scheme-bearing targets so a crafted
    # next= can't open-redirect off-site.
    if not nxt.startswith("/") or nxt.startswith("//") or "://" in nxt:
        nxt = "/"
    if table_prefs.spec(table_id):                      # ignore unknown table ids (no junk rows)
        if "reset" in form:
            table_prefs.reset(db, user.id, table_id)
        else:
            table_prefs.save_columns(db, user.id, table_id, form.getlist("cols"))
    return RedirectResponse(nxt, status_code=303)
