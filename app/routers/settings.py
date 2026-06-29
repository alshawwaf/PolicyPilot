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
                    "created": created, "last_used": used, "expires": exp, "status": status})
    return out


def _detected_base_url(request: Request) -> str:
    """The public URL this request arrived on, honoring the reverse proxy's X-Forwarded-* headers — so
    the admin can adopt it for base_url with one click instead of typing it blind. Suggestion only."""
    h = request.headers
    proto = (h.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
    host = (h.get("x-forwarded-host") or h.get("host") or request.url.netloc or "").split(",")[0].strip()
    return f"{proto}://{host}".rstrip("/") if host else ""


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    new_key = request.session.pop("new_api_key", None)   # one-time reveal (NOT via _flash → not persisted)
    now = dt.datetime.now(dt.timezone.utc)
    return templates.TemplateResponse(request, "settings.html",
                                      {"groups": _grouped(), "vals": app_settings.all_values(fresh=True),
                                       "secrets": app_settings.secret_status(),       # {key: is_set} — never the value
                                       "crypto_ok": app_settings.secret_available(),
                                       "api_keys": _key_rows(now),
                                       "api_scopes": api_keys.SCOPES,
                                       "expiry_presets": EXPIRY_PRESETS,
                                       "new_key": new_key,
                                       "detected_base_url": _detected_base_url(request),
                                       "flash": _pop_flash(request)})


@router.post("/settings")
async def settings_save(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    new: dict = {}
    for s in app_settings.SETTINGS:
        if s.kind == "secret":
            continue                            # secrets handled write-only below, never echoed/round-tripped
        if s.kind == "bool":
            new[s.key] = s.key in form          # an unchecked checkbox is simply absent from the form
        elif s.key in form:
            new[s.key] = form[s.key]            # validated + clamped in app_settings.save()
    app_settings.save(new)

    # Secrets are write-only: a blank field means "keep current"; a "<key>__clear" checkbox removes it;
    # a non-empty value sets/rotates it (encrypted at rest). Refuse cleartext storage if crypto is off.
    secret_err = None
    for s in app_settings.secret_settings():
        if form.get(s.key + "__clear"):
            app_settings.clear_secret(s.key)
            continue
        value = (form.get(s.key) or "").strip()
        if value:
            try:
                app_settings.set_secret(s.key, value)
            except RuntimeError:
                secret_err = ("Can't store secrets: at-rest encryption is unavailable. Set "
                              "DCSIM_ENCRYPTION_KEY (or DCSIM_SESSION_SECRET) and restart, or keep using "
                              "the DCSIM_* env vars.")
    _flash(request, secret_err or "Settings saved — they take effect immediately.")
    return RedirectResponse("/settings", status_code=303)


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
    row, secret = api_keys.generate(name, scope, created_by=user.username, expires_at=expires_at)
    exp_txt = expires_at.strftime("%Y-%m-%d") if expires_at else "never"
    request.session["new_api_key"] = {"name": row.name, "scope": row.scope, "key": secret, "expires": exp_txt}
    _flash(request, f"API key '{row.name}' ({row.scope}, expires {exp_txt}) created — copy it now, "
                    "it's shown only once.")
    return RedirectResponse("/settings#grp-api-keys", status_code=303)


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
            return RedirectResponse("/settings#grp-api-keys", status_code=303)
    elif preset == "never":
        expires_at = None
    elif preset.isdigit():
        expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=max(1, int(preset)))
    else:
        _flash(request, "Pick a date or a preset — expiry left unchanged.")
        return RedirectResponse("/settings#grp-api-keys", status_code=303)
    if api_keys.set_expiry(key_id, expires_at):
        exp_txt = expires_at.strftime("%Y-%m-%d") if expires_at else "never"
        _flash(request, f"API key expiry updated to {exp_txt}.")
    return RedirectResponse("/settings#grp-api-keys", status_code=303)


@router.post("/settings/api-keys/{key_id}/revoke")
def api_key_revoke(key_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if api_keys.revoke(key_id):
        _flash(request, "API key revoked — it can no longer authenticate.")
    return RedirectResponse("/settings#grp-api-keys", status_code=303)


@router.post("/prefs/table/{table_id}/columns")
async def save_table_columns(table_id: str, request: Request, db: Session = Depends(get_db)):
    """Persist a user's visible-column choice for a table, then return to the page (server re-renders
    the chosen columns — no flash). Column ids are validated against the table's spec allowlist."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    nxt = str(form.get("next") or "")
    if not nxt.startswith("/"):
        nxt = "/"
    if table_prefs.spec(table_id):                      # ignore unknown table ids (no junk rows)
        if "reset" in form:
            table_prefs.reset(db, user.id, table_id)
        else:
            table_prefs.save_columns(db, user.id, table_id, form.getlist("cols"))
    return RedirectResponse(nxt, status_code=303)
