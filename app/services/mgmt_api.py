"""Client for the Check Point Management API (``web_api``) — the real-SMS side of the policy
viewer/editor/exporter.

A session does ``login`` (with an optional MDS ``domain``) → carries the ``sid`` on every call →
``publish``/``discard`` for writes → ``logout``. TLS verification is **always on**: against a pinned
certificate (trust-on-first-use, like saved gateways) when one is set, otherwise system trust. Never a
skip-verify path. Each call is recorded on ``session.trace`` so the UI can show exactly what ran.
"""
from __future__ import annotations

import base64
import contextlib
import ssl
import threading
import time

import httpx

from .gaia_client import ensure_pinned  # noqa: F401 — re-exported; routers pin a server's cert the same way


class MgmtError(Exception):
    """A web_api login or command failed — carries a clean, user-facing message."""


def _pinned_ssl_context(cert_pem: str) -> ssl.SSLContext:
    """Trust ONLY the pinned certificate. Verification stays on (CERT_REQUIRED, TLS 1.2+); hostname
    matching is off because management certs are often issued for a name the lab reaches it by — the
    operator-reviewed pin is the identity check. (Same policy-safe approach as the gateway apply.)"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=cert_pem)
    return ctx


def _verify_for(server):
    pem = (getattr(server, "cert_pem", "") or "").strip()
    return _pinned_ssl_context(pem) if pem else True


class MgmtSession:
    """One authenticated web_api session. Use as a context manager so logout + close always run::

        with MgmtSession(server, secret) as s:
            layers = s.list_access_layers()
    """

    def __init__(self, server, secret: str, timeout: float = 30.0, *, read_only: bool = False,
                 session_timeout: int | None = None, session_description: str = "",
                 auto_relogin: bool = False):
        self.server = server
        self._secret = secret
        self.base = f"https://{server.host}:{server.port}/web_api"
        self._read_only = read_only          # read-only sessions take no locks; safe to share + reuse
        self._session_timeout = session_timeout
        self._session_description = session_description
        self._auto_relogin = auto_relogin    # pooled read sessions transparently re-login on expiry
        try:
            verify = _verify_for(server)
        except ssl.SSLError as exc:
            raise MgmtError(f"The saved certificate for {server.host} is not valid PEM — re-paste it "
                            f"on the Edit page ({exc}).") from exc
        self._client = httpx.Client(verify=verify, timeout=timeout)
        self.sid: str | None = None
        self.login_info: dict = {}
        self.trace: list[dict] = []

    # --- lifecycle ---------------------------------------------------------------------------
    def __enter__(self) -> "MgmtSession":
        try:
            self.login()
        except Exception:
            self._client.close()   # __exit__ won't run if __enter__ raises — don't leak the client
            raise
        return self

    def __exit__(self, *exc) -> None:
        try:
            # A read-WRITE session leaving via an exception may still hold uncommitted changes + locks;
            # on Check Point a logout does NOT discard them, so they'd linger until session timeout. Best-
            # effort discard as a backstop (execute() already handles its own paths). Read-only sessions
            # hold no locks, and a clean exit has already published/discarded, so only act on the error path.
            if exc and exc[0] is not None and not self._read_only and self.sid:
                try:
                    self.discard()
                except Exception:  # noqa: BLE001 — never mask the original error
                    pass
            self.logout()
        finally:
            self._client.close()

    def login(self) -> dict:
        payload: dict = {"user": self.server.username, "password": self._secret}
        if (self.server.domain or "").strip():
            payload["domain"] = self.server.domain.strip()   # MDS/CMA target; omitted for a single SMS
        if self._read_only:
            payload["read-only"] = True          # no object/rule locks; doesn't consume a write slot
        if self._session_timeout:
            payload["session-timeout"] = int(self._session_timeout)
        # session-name / -comments / -description are REJECTED by the API in read-only mode
        # ("…are unexpected, when login is done in the readonly mode" / HTTP 400) — only send for writes.
        if self._session_description and not self._read_only:
            payload["session-description"] = self._session_description
        attempt = 0
        while True:
            try:
                t = time.perf_counter()
                r = self._client.post(f"{self.base}/login", json=payload)
            except (httpx.ConnectError, ssl.SSLError, httpx.ConnectTimeout) as exc:
                raise MgmtError(f"Could not reach {self.server.host}:{self.server.port} over TLS — {exc}. "
                                "Check the host/port, the firewall, and (for a self-signed cert) the pinned "
                                "cert / auto-trust.") from exc
            self._record("login", {"user": self.server.username, "password": "***",
                                   **({"domain": self.server.domain} if self.server.domain else {})}, r, t)
            if r.status_code == 200:
                break
            # Check Point throttles remote logins (3/admin/domain/60s). A burst of apply/publish calls
            # out-paces it -> HTTP 429. Wait out the window and retry (the session pools amortise the login,
            # so this only fires on a cold burst / a pooled re-login after expiry), then fail loud.
            if r.status_code == 429 and attempt < _login_retries():
                attempt += 1
                _THROTTLE_SLEEP(_login_backoff(attempt))
                continue
            raise MgmtError(_login_error(r))
        self.login_info = _safe_json(r)
        self.sid = self.login_info.get("sid")
        if not self.sid:
            raise MgmtError("Login returned no session id (sid).")
        return self.login_info

    def logout(self) -> None:
        if not self.sid:
            return
        try:
            self.call("logout")
        except Exception:  # noqa: BLE001 — best-effort; the session expires server-side anyway
            pass
        self.sid = None

    # --- calls -------------------------------------------------------------------------------
    def call(self, command: str, payload: dict | None = None, *, _retry: bool = True) -> dict:
        if not self.sid:
            if self._auto_relogin:
                self.login()
            else:
                raise MgmtError("Not logged in.")
        t = time.perf_counter()
        try:
            r = self._client.post(f"{self.base}/{command}", json=payload or {},
                                  headers={"X-chkp-sid": self.sid})
        except (httpx.HTTPError, ssl.SSLError, OSError) as exc:
            # A MID-SESSION transport drop (idle RST, SMS reboot/timeout, network blip) — login() wraps
            # these but call() did not, so they used to escape as a raw 500 to the SE mid-pull/apply. Wrap
            # into MgmtError so every consumer (read pool, write pool, mgmt router, MCP/REST tools) reports
            # a clean, user-facing error instead of a stack trace.
            raise MgmtError(f"lost connection to {self.server.host}:{self.server.port} during “{command}” "
                            f"({exc}). Check the SMS is reachable and retry.") from exc
        self._record(command, payload or {}, r, t)
        data = _safe_json(r)
        if r.status_code != 200:
            # A shared/reused read session can have expired server-side (idle timeout). Re-login ONCE
            # and retry. NEVER for a write session (auto_relogin off): a re-login would silently drop
            # its uncommitted changes mid-transaction — fail loudly instead.
            if _retry and self._auto_relogin and command != "logout" and _is_session_expired(r, data):
                self.login()
                return self.call(command, payload, _retry=False)
            raise MgmtError(_cp_error_detail(data) or f"{command} failed (HTTP {r.status_code}).")
        return data

    def keepalive(self) -> None:
        """Reset the session's idle timer without a new login (does NOT count against the login
        throttle). Best-effort; auto_relogin in call() is the real expiry safety net."""
        try:
            self.call("keepalive")
        except MgmtError:
            pass

    def call_paged(self, command: str, payload: dict | None = None, *,
                   key: str = "objects", limit: int = 500) -> list[dict]:
        """Walk CP's offset/total pagination for a show-* list command, returning all items."""
        base = dict(payload or {})
        out: list[dict] = []
        offset = 0
        while True:
            page = self.call(command, {**base, "limit": limit, "offset": offset, "details-level": "full"})
            items = page.get(key) or []
            out.extend(items)
            total = page.get("total", len(out))
            offset += len(items)
            if not items or offset >= total:
                return out

    def publish(self) -> dict:
        """Publish is ASYNCHRONOUS: it returns a task-id and the commit runs in the background. We must
        wait for that task to actually succeed before reporting done — otherwise a still-pending or
        failed publish is mis-reported as committed and the session is left Open holding its locks."""
        res = self.call("publish")
        task_id = res.get("task-id")
        if task_id:
            res["task"] = self.wait_for_task(task_id, what="publish")
        # A successful publish advanced this server's policy revision -> drop its read cache NOW so the next
        # preview/decide sees the new rulebase immediately, not the (up-to-revalidate-window) stale copy.
        # Doing it here covers EVERY write path uniformly — execute/remove/revert AND the generic policy
        # editor (apply_changes), which previously published without invalidating (stale-preview window).
        invalidate_cache(self.server)
        return res

    def wait_for_task(self, task_id: str, *, what: str = "task",
                      timeout: float = 120.0, interval: float = 1.0) -> dict:
        """Poll show-task until the async task leaves 'in progress'. Returns the task on success;
        raises MgmtError on failure/timeout so the caller can discard and release locks."""
        elapsed = 0.0
        while True:
            tasks = self.call("show-task", {"task-id": task_id,
                                            "details-level": "full"}).get("tasks") or []
            task = tasks[0] if tasks else {}
            status = (task.get("status") or "").lower()
            if status == "succeeded":
                return task
            if status in ("failed", "partially succeeded"):
                detail = _task_error_text(task)
                raise MgmtError(f"{what} failed — the change was NOT committed."
                                + (f" {detail}" if detail else f" (task {task_id}: {status})"))
            if elapsed >= timeout:
                raise MgmtError(f"{what} did not finish within {int(timeout)}s "
                                f"(task {task_id} still '{task.get('status') or 'pending'}').")
            time.sleep(interval)
            elapsed += interval

    def discard(self) -> dict:
        return self.call("discard")

    # --- convenience reads -------------------------------------------------------------------
    def show_domains(self) -> list[dict]:
        try:
            return self.call("show-domains", {"limit": 200}).get("objects", [])
        except MgmtError:
            return []   # not an MDS — single SMS has no domains

    def list_access_layers(self) -> list[dict]:
        # show-access-layers returns the list under "access-layers" — NOT the usual "objects" key.
        return self.call_paged("show-access-layers", key="access-layers")

    def _record(self, command: str, payload: dict, resp, t0: float) -> None:
        entry = {"command": command, "params": payload, "status": resp.status_code,
                 "ms": round((time.perf_counter() - t0) * 1000)}
        if resp.status_code != 200:
            entry["error"] = _cp_error_detail(_safe_json(resp))[:500]
        self.trace.append(entry)


def _safe_json(resp) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {"objects": data} if isinstance(data, list) else {}
    except Exception:  # noqa: BLE001
        return {}


def _maybe_b64(s: str) -> str:
    """Some Check Point task-detail fields are base64-encoded text — decode when it cleanly does."""
    try:
        txt = base64.b64decode(s, validate=True).decode("utf-8")
    except Exception:  # noqa: BLE001
        return s
    return txt if (txt and (txt.isprintable() or "\n" in txt)) else s


def _cp_error_detail(data: dict) -> str:
    """A readable error from a web_api error body, surfacing the structured validation detail
    (blocking-errors / errors / warnings) rather than just the one-line message."""
    parts: list[str] = []
    if data.get("message"):
        parts.append(str(data["message"]))
    for key in ("blocking-errors", "errors", "warnings"):
        for item in data.get(key) or []:
            m = item.get("message") if isinstance(item, dict) else item
            if m:
                parts.append(f"• {m}")
    out, seen = [], set()
    for p in parts:
        p = str(p).strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return "  ".join(out)


def _task_error_text(task: dict) -> str:
    """Dig the human-readable error(s) out of a failed show-task result (task-details / messages),
    base64-decoding fields where Check Point encodes them."""
    found: list[str] = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str) and v and any(w in str(k).lower()
                        for w in ("message", "error", "description", "warning", "reason")):
                    found.append(_maybe_b64(v))
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(task)
    out, seen = [], set()
    for f in found:
        f = (f or "").strip()
        if f and f.lower() not in ("succeeded", "in progress", "failed") and f not in seen:
            seen.add(f)
            out.append(f)
    return " | ".join(out)[:800]


def _login_error(resp) -> str:
    msg = ""
    try:
        body = resp.json() or {}
        msg = body.get("message") or body.get("errors") or body.get("error") or ""
    except Exception:  # noqa: BLE001
        msg = ""
    if resp.status_code in (401, 403):
        return (f"Management login failed ({resp.status_code}): the server rejected the credentials"
                + (f" — {msg}" if msg else "")
                + ". For MDS, also check the target domain.")
    return f"Management login failed (HTTP {resp.status_code})." + (f" {msg}" if msg else "")


# Login-throttle retry knobs. _THROTTLE_SLEEP is module-level so tests stub the wait (no real sleep).
_THROTTLE_SLEEP = time.sleep


def _login_retries() -> int:
    """How many times to retry a rate-limited (HTTP 429) login. From Settings; 0 if unavailable."""
    try:
        from . import app_settings
        return max(0, int(app_settings.get("mgmt_login_retries")))
    except Exception:  # noqa: BLE001 — never let a settings hiccup turn a login into a crash
        return 0


def _login_backoff(attempt: int) -> float:
    """Seconds to wait before the Nth (1-based) login retry. ~20s per step ≈ Check Point's 3/60s window,
    so two retries cover a full throttle window worst-case."""
    return 20.0 * attempt


def _is_session_expired(resp, data: dict) -> bool:
    """Does this error mean our session id is no longer valid (idle-expired / disconnected)? Used to
    decide whether a pooled read session should transparently re-login and retry."""
    if resp.status_code == 401:
        return True
    msg = (_cp_error_detail(data) or "").lower()
    code = str(data.get("code") or "").lower()
    if "err_session" in code or "expired" in code or "wrong_session" in code:
        return True
    return "session" in msg and any(w in msg for w in
                                    ("expired", "invalid", "timed out", "wrong", "not logged in"))


# --- shared read-only session pool -----------------------------------------------------------
# Real integrations do NOT log in per request — Check Point throttles remote logins (3/admin/domain/
# 60s) and caps concurrent sessions (100). So all READS share one long-lived read-only session per
# (server, domain): one login, reused across requests, keepalive'd when idle, re-logged-in on expiry,
# and serialized by a per-session lock (a sid is a transaction handle, not a stateless bearer token).
# WRITES never use this pool — they get an isolated read-write session (see apply_changes / execute).
_POOL: dict = {}
_POOL_LOCK = threading.Lock()


class _PooledRead:
    __slots__ = ("session", "call_lock", "last_used")

    def __init__(self, session: "MgmtSession"):
        self.session = session
        self.call_lock = threading.Lock()
        self.last_used = time.monotonic()


def _pool_key(server):
    sid = getattr(server, "id", None)
    if sid is None:
        sid = f"{getattr(server, 'host', '')}:{getattr(server, 'port', '')}"
    return (sid, (getattr(server, "domain", "") or "").strip())


@contextlib.contextmanager
def read_session(server, secret: str):
    """Yield a shared, long-lived READ-ONLY session for ``server``, serialized so only one request uses
    its sid at a time. One login is amortised across every read. Falls back to a private per-call
    session when reuse is disabled in Settings. The yielded session's ``trace`` holds ONLY this
    operation's calls."""
    from . import app_settings
    if not app_settings.get("mgmt_session_reuse"):
        with MgmtSession(server, secret, read_only=True,
                         session_timeout=app_settings.get("mgmt_session_timeout")) as s:
            yield s
        return

    key = _pool_key(server)
    with _POOL_LOCK:
        entry = _POOL.get(key)
    if entry is None:
        # Build + login OUTSIDE _POOL_LOCK: login() can now BLOCK (it retries a throttled HTTP 429 with
        # backoff), and _POOL_LOCK is process-global — holding it through a slow login would stall every
        # server's reads. Double-check on re-insert and close the loser if another thread won the race.
        sess = MgmtSession(server, secret, read_only=True, auto_relogin=True,
                           session_timeout=app_settings.get("mgmt_session_timeout"))
        try:
            sess.login()
        except Exception:
            with contextlib.suppress(Exception):
                sess._client.close()
            raise
        with _POOL_LOCK:
            existing = _POOL.get(key)
            if existing is None:
                entry = _PooledRead(sess)
                _POOL[key] = entry
            else:
                entry = existing                   # lost the race -> use the winner, drop our extra session
        if entry.session is not sess:
            with contextlib.suppress(Exception):
                sess.logout()
            with contextlib.suppress(Exception):
                sess._client.close()

    with entry.call_lock:
        if app_settings.get("mgmt_keepalive") and (time.monotonic() - entry.last_used) > 60:
            entry.session.keepalive()          # cheap insurance; call() auto-relogin is the real net
        entry.session.trace = []               # fresh trace for this (serialized) operation
        try:
            yield entry.session
        finally:
            entry.last_used = time.monotonic()


def close_pool() -> None:
    """Log out + close every pooled read session. Wire into the app shutdown (lifespan) hook so we
    don't leave sessions lingering toward the 100-session ceiling."""
    with _POOL_LOCK:
        for entry in _POOL.values():
            try:
                entry.session.logout()
            except Exception:  # noqa: BLE001
                pass
            with contextlib.suppress(Exception):
                entry.session._client.close()
        _POOL.clear()
    close_write_pool()


# --- shared read-WRITE session pool ----------------------------------------------------------
# A burst of applies (a batch of tickets) logs in per change -> Check Point's 3-logins-per-minute throttle
# rejects the 4th (HTTP 429). So apply/publish reuse ONE read-write session per (server, domain). A per-key
# lock serializes the WHOLE apply (get/create/use/clean) for that server — only one apply touches its sid at
# a time, and there is no stale-handle race — while different servers proceed in parallel. SAFETY INVARIANT:
# a pooled write session is only ever kept if it is CLEAN (no pending changes -> it holds no object locks
# while idle, preserving the "locks clear fast" guarantee a fresh-per-apply session gave). The caller
# publishes/discards inside the block; the manager then defensively discards. On ANY error in the block, or
# if that discard fails, the session is DROPPED (logout + close) rather than reused dirty/locked.
_WRITE_POOL: dict = {}            # key -> the live reusable MgmtSession
_WRITE_LOCKS: dict = {}           # key -> threading.Lock (one per server+domain)
_WRITE_META_LOCK = threading.Lock()   # guards the two dicts above


def _write_lock(key) -> threading.Lock:
    with _WRITE_META_LOCK:
        lk = _WRITE_LOCKS.get(key)
        if lk is None:
            lk = threading.Lock()
            _WRITE_LOCKS[key] = lk
        return lk


def _drop_write(key, s: "MgmtSession") -> None:
    """Discard (release locks) + log out + close a pooled write session and remove it from the pool."""
    with contextlib.suppress(Exception):
        s.discard()                   # release any object locks before we drop the sid
    try:
        s.logout()
    except Exception:  # noqa: BLE001
        pass
    with contextlib.suppress(Exception):
        s._client.close()
    with _WRITE_META_LOCK:
        if _WRITE_POOL.get(key) is s:
            del _WRITE_POOL[key]


def _write_session_alive(s: "MgmtSession") -> bool:
    """Is a pooled write session still usable? A cheap keepalive doubles as a liveness probe; ANY failure —
    an API error OR a transport error (call() does not wrap httpx/ssl/OS errors the way login() does) — means
    it idle-expired or the box bounced, so report not-alive and let write_session drop it + re-login. A
    narrow ``except MgmtError`` would let a raw ConnectError/ReadTimeout escape and leave the dead session
    pooled (every later apply would then re-probe and re-crash)."""
    if not s.sid:
        return False
    try:
        s.call("keepalive")
        return True
    except (MgmtError, httpx.HTTPError, ssl.SSLError, OSError):
        return False


@contextlib.contextmanager
def write_session(server, secret: str):
    """Yield a reusable READ-WRITE session for ``server`` for an apply/publish. The whole apply is
    serialized per (server, domain) so the login is amortised across back-to-back applies (Check Point
    throttles logins 3/admin/domain/60s). The CALLER must publish() or discard() before the block exits;
    the pooled session is then returned clean (it holds no locks while idle). Falls back to a private,
    logged-out-on-exit session when write reuse is disabled in Settings (the original per-apply behaviour).

    On ANY error inside the block — or if the defensive end-of-block discard fails — the session is DROPPED
    (logged out + closed) so a dirty/locked session is never handed to the next apply."""
    from . import app_settings
    timeout = write_session_timeout()
    desc = "DC-Sim access automation (apply)"
    if not app_settings.get("mgmt_write_session_reuse"):
        with MgmtSession(server, secret, session_timeout=timeout, session_description=desc) as s:
            yield s
        return

    key = _pool_key(server)
    with _write_lock(key):                       # serialize the whole apply for this server (no stale race)
        with _WRITE_META_LOCK:
            s = _WRITE_POOL.get(key)
        # A pooled session may have idle-expired since the last apply. It carries NO pending changes (the
        # previous apply published/discarded + the defensive discard below), so re-login is SAFE here —
        # unlike a mid-apply relogin, which would silently drop staged changes.
        if s is not None and not _write_session_alive(s):
            _drop_write(key, s)
            s = None
        if s is None:
            s = MgmtSession(server, secret, session_timeout=timeout, session_description=desc)
            try:
                s.login()                        # a throttled login raises a clean MgmtError (no pool entry)
            except Exception:
                with contextlib.suppress(Exception):
                    s._client.close()            # __enter__ isn't used here -> close the client on login failure
                raise
            with _WRITE_META_LOCK:
                _WRITE_POOL[key] = s
        s.trace = []
        ok = False
        try:
            yield s
            ok = True
        finally:
            if not ok:
                _drop_write(key, s)              # the apply errored -> session state uncertain -> drop it
            else:
                try:
                    s.discard()                  # defensive: never reuse a session with pending changes
                except Exception:  # noqa: BLE001
                    _drop_write(key, s)


def close_write_pool() -> None:
    """Discard (release locks) + log out + close every pooled write session. Wired into app shutdown. Each
    session is torn down UNDER its per-key lock (best-effort, short wait) so an in-flight apply on another
    thread finishes first — never close an httpx client mid-call from two threads."""
    with _WRITE_META_LOCK:
        items = list(_WRITE_POOL.items())
        locks = dict(_WRITE_LOCKS)
    for key, s in items:
        lk = locks.get(key)
        acquired = lk.acquire(timeout=10) if lk is not None else False
        try:
            with _WRITE_META_LOCK:
                if _WRITE_POOL.get(key) is s:   # a racing apply may have already evicted/replaced it
                    del _WRITE_POOL[key]
                else:
                    continue
            with contextlib.suppress(Exception):
                s.discard()
            try:
                s.logout()
            except Exception:  # noqa: BLE001
                pass
            with contextlib.suppress(Exception):
                s._client.close()
        finally:
            if acquired:
                lk.release()


# --- rulebase pull + structuring (the read-only viewer) -------------------------------------

def _obj_names(cell, objdict: dict) -> list[str]:
    """Resolve a rule cell (list of object UIDs, or inline object dicts) to display names."""
    out: list[str] = []
    for it in cell or []:
        if isinstance(it, str):
            out.append((objdict.get(it) or {}).get("name") or it)
        elif isinstance(it, dict):
            out.append(it.get("name") or (objdict.get(it.get("uid")) or {}).get("name") or it.get("uid", ""))
    return out


def _one_name(val, objdict: dict) -> str:
    """Resolve a single-valued cell (action / track type) to a display name."""
    if isinstance(val, str):
        return (objdict.get(val) or {}).get("name") or val
    if isinstance(val, dict):
        return val.get("name") or (objdict.get(val.get("uid")) or {}).get("name") or val.get("uid", "")
    return ""


def _track_full(track, objdict: dict) -> dict:
    """The full Track Settings object (type + the booleans), for a faithful rulebase export."""
    t = track or {}
    return {
        "type": _one_name(t.get("type"), objdict),
        "accounting": bool(t.get("accounting")),
        "alert": t.get("alert") if isinstance(t.get("alert"), str) and t.get("alert") != "none" else "",
        "per_connection": bool(t.get("per-connection")),
        "per_session": bool(t.get("per-session")),
        "enable_firewall_session": bool(t.get("enable-firewall-session")),
    }


def _action_settings(val, objdict: dict) -> dict:
    a = val or {}
    return {"limit": _one_name(a.get("limit"), objdict) if a.get("limit") else "",
            "enable_identity_captive_portal": bool(a.get("enable-identity-captive-portal"))}


def _user_check(val, objdict: dict) -> dict:
    u = val or {}
    out = {"confirm": u.get("confirm", ""), "frequency": u.get("frequency", ""),
           "interaction": _one_name(u.get("interaction"), objdict) if u.get("interaction") else ""}
    return {k: v for k, v in out.items() if v}


def _structure_rule(rule: dict, objdict: dict) -> dict:
    return {
        "kind": "rule",
        "uid": rule.get("uid"),          # target edits by uid — rule numbers shift as rules move
        "number": rule.get("rule-number"),
        "name": rule.get("name", ""),
        "enabled": rule.get("enabled", True),
        "source": _obj_names(rule.get("source"), objdict),
        "source_negate": bool(rule.get("source-negate")),
        "destination": _obj_names(rule.get("destination"), objdict),
        "destination_negate": bool(rule.get("destination-negate")),
        "vpn": _obj_names(rule.get("vpn"), objdict),
        "service": _obj_names(rule.get("service"), objdict),
        "service_negate": bool(rule.get("service-negate")),
        "content": _obj_names(rule.get("content"), objdict),
        "content_negate": bool(rule.get("content-negate")),
        "content_direction": rule.get("content-direction", ""),
        "action": _one_name(rule.get("action"), objdict),
        "action_settings": _action_settings(rule.get("action-settings"), objdict),
        "inline_layer": _one_name(rule.get("inline-layer"), objdict) if rule.get("inline-layer") else "",
        "track": _one_name((rule.get("track") or {}).get("type"), objdict),   # type only (viewer)
        "track_full": _track_full(rule.get("track"), objdict),                # full settings (export)
        "time": _obj_names(rule.get("time"), objdict),
        "install_on": _obj_names(rule.get("install-on"), objdict),
        "custom_fields": rule.get("custom-fields") or {},
        "user_check": _user_check(rule.get("user-check"), objdict),
        "comments": rule.get("comments", ""),
    }


def _structure_rulebase(items: list[dict], objdict: dict) -> list[dict]:
    """Flatten the rulebase into rows the UI renders: section headers + rules (cells resolved to
    names). Unknown item types pass through flagged, mirroring CP's tool — never break on a new type."""
    out: list[dict] = []
    for it in items or []:
        t = it.get("type")
        if t == "access-section":
            out.append({"kind": "section", "name": it.get("name", "")})
            out.extend(_structure_rule(r, objdict) for r in (it.get("rulebase") or []))
        elif t == "access-rule":
            out.append(_structure_rule(it, objdict))
        else:
            out.append({"kind": "other", "type": t or "unknown", "name": it.get("name", "")})
    return out


# --- revision-based policy cache -------------------------------------------------------------
# Stop re-pulling the whole rulebase + objects on every read. Cache the raw pull per (server, domain,
# layer, package) and reuse it while the policy is UNCHANGED. The change signal is the latest published
# session (a database revision) -- cheap to fetch and authoritative; last-modify-time is unreliable on
# publish, so we never use it. Within a short "revalidate" window we serve the cache without even
# asking. Our own publishes call invalidate_cache().
_RAW_CACHE: dict = {}
_RAW_LOCK = threading.Lock()


def _policy_token(session: "MgmtSession") -> str:
    """The latest published-session uid + publish-time: a monotonic, server-authoritative handle for
    the policy revision. Empty string when unavailable (then the cache simply always re-pulls)."""
    try:
        r = session.call("show-sessions", {"view-published-sessions": True, "limit": 1,
                                            "details-level": "full"})
    except MgmtError:
        return ""
    rows = r.get("objects") or r.get("sessions") or []
    if not rows:
        return ""
    top = rows[0] or {}
    pub = top.get("publish-time")
    stamp = pub.get("posix") if isinstance(pub, dict) else pub
    return f"{top.get('uid', '')}:{stamp or ''}"


def _raw_pull(session: "MgmtSession", layer: str, package, max_rules: int) -> dict:
    items: list[dict] = []
    objdict: dict = {}
    total, offset = 0, 0
    while offset < max_rules:
        payload = {"name": layer, "limit": 500, "offset": offset,
                   "use-object-dictionary": True, "details-level": "full",
                   # Expand group members to full objects so the engine can resolve a group cell to IPs
                   # (an unresolved group reads as "extent unknown" and routes every overlap to REVIEW).
                   "dereference-group-members": True}
        if package:
            payload["package"] = package
        page = session.call("show-access-rulebase", payload)
        for o in page.get("objects-dictionary", []):
            if o.get("uid"):
                objdict[o["uid"]] = o
        batch = page.get("rulebase", [])
        items.extend(batch)
        total = page.get("total", total)
        to = page.get("to", 0)
        if not batch or to >= total or to <= offset:
            break
        offset = to
    # Fail loud on truncation so a partial rulebase is never cached or reasoned over (a missing cleanup
    # / deny past the cap would make the access-automation engine under-deny). Raising here also means a
    # truncated pull never reaches cached_raw's store, closing the sticky-cache hole.
    # Compare total to the CAP, not to len(items): `total` counts rules, but `items` is the TOP-LEVEL
    # rulebase (sections wrap their rules), so a sectioned layer — e.g. the standard "Network" layer —
    # has far fewer top-level items than rules. `total > len(items)` wrongly tripped on every such layer.
    if total and total > max_rules:
        raise MgmtError(f"layer “{layer}” has {total} rules, over the {max_rules} cap; refusing to "
                        f"serve a truncated rulebase — raise the cap or split the layer")
    return {"items": items, "objdict": objdict, "total": total}


def cached_raw(session: "MgmtSession", server, layer: str, package=None, max_rules: int = 50000) -> dict:
    """Raw rulebase pull for ``layer`` ({items, objdict, total, cached}), reusing a process cache that is
    invalidated by the published-revision token. ``session`` is an already-open read session."""
    from . import app_settings
    if not app_settings.get("mgmt_policy_cache"):
        return {**_raw_pull(session, layer, package, max_rules), "cached": False}
    key = (_pool_key(server), layer, package or "", max_rules)   # cap is part of the key (no cross-serve)
    now = time.monotonic()

    def _hit(e):
        return {"items": e["items"], "objdict": e["objdict"], "total": e["total"], "cached": True}

    with _RAW_LOCK:
        entry = _RAW_CACHE.get(key)
    token = None
    if entry is not None:
        if (now - entry["at"]) < app_settings.get("mgmt_cache_revalidate"):
            return _hit(entry)                       # within revalidate window -> don't even ask
        token = _policy_token(session)
        if (token and token == entry["token"]
                and (now - entry["at"]) < app_settings.get("mgmt_cache_max_age")):
            with _RAW_LOCK:
                entry["at"] = now                    # unchanged since last publish -> serve cache
            return _hit(entry)

    raw = _raw_pull(session, layer, package, max_rules)
    if token is None:
        token = _policy_token(session)               # cold pull: capture token for future compares
    with _RAW_LOCK:
        _RAW_CACHE[key] = {**raw, "token": token, "at": now}
    return {**raw, "cached": False}


def invalidate_cache(server=None) -> None:
    """Drop cached policy (all, or just one server's) — call after a publish so the next read re-pulls."""
    with _RAW_LOCK:
        if server is None:
            _RAW_CACHE.clear()
            return
        pk = _pool_key(server)
        for k in [k for k in _RAW_CACHE if k[0] == pk]:
            _RAW_CACHE.pop(k, None)


def pull_layers(server, secret: str) -> dict:
    with read_session(server, secret) as s:
        layers = s.list_access_layers()
        return {"layers": [{"name": l.get("name"), "uid": l.get("uid")} for l in layers], "trace": s.trace}


def pull_rulebase(server, secret: str, layer: str, max_rules: int = 50000) -> dict:
    """Pull a layer's access rulebase with its object dictionary and resolve every cell to names. Uses
    the revision-based policy cache. Returns {layer, rows, total, shown, cached, trace}."""
    with read_session(server, secret) as s:
        raw = cached_raw(s, server, layer, max_rules=max_rules)
        rows = _structure_rulebase(raw["items"], raw["objdict"])
        shown = sum(1 for r in rows if r["kind"] == "rule")
        return {"layer": layer, "rows": rows, "total": raw["total"], "shown": shown,
                "cached": raw["cached"], "trace": s.trace}


def _collect_export_objects(objdict: dict) -> dict:
    """Group the referenced objects by type for export, skipping predefined ones and recursing into
    group members (which arrive as full nested objects at details-level full). Keyed by CP type."""
    from . import mgmt_export   # local import avoids a cycle (mgmt_export has no api dependency)

    by_type: dict[str, list] = {}
    seen: set[str] = set()

    def add(o: dict) -> None:
        uid = o.get("uid")
        if not uid or uid in seen:
            return
        seen.add(uid)
        for m in o.get("members") or []:          # pull nested group/service-group members up too
            if isinstance(m, dict):
                add(m)
            elif isinstance(m, str) and m in objdict:
                add(objdict[m])
        if mgmt_export.is_predefined(o):
            return
        by_type.setdefault(o.get("type") or "unknown", []).append(o)

    for o in list(objdict.values()):
        add(o)
    return by_type


def pull_for_export(server, secret: str, layer: str, max_rules: int = 50000) -> dict:
    """Pull a layer's rulebase with FULL object details, returning the structured rows plus the
    referenced objects grouped by type. Feeds ``mgmt_export.generate`` — no rendering here."""
    with read_session(server, secret) as s:
        raw = cached_raw(s, server, layer, max_rules=max_rules)
        rows = _structure_rulebase(raw["items"], raw["objdict"])
        return {"layer": layer, "rules": rows,
                "objects_by_type": _collect_export_objects(raw["objdict"]),
                "total": raw["total"], "cached": raw["cached"], "trace": s.trace}


def test_connection(server, secret: str) -> dict:
    """Login, read the API version + domains, log out. Returns {ok, version, domains, layers, trace}."""
    out: dict = {"ok": False, "version": "", "domains": [], "layers": 0, "trace": [], "message": ""}
    try:
        # A deliberate, user-initiated connectivity + credential check -> a fresh isolated read-only
        # login (not the pool), so it always validates the live credentials.
        with MgmtSession(server, secret, read_only=True) as s:
            ver = s.call("show-api-versions")
            out["version"] = ver.get("current-version", "")
            out["domains"] = [d.get("name") for d in s.show_domains() if d.get("name")]
            out["layers"] = len(s.list_access_layers())
            out["ok"] = True
            out["trace"] = s.trace
    except MgmtError as exc:
        out["message"] = str(exc)
    except Exception as exc:  # noqa: BLE001 — surface anything unexpected as a clean message
        out["message"] = f"Unexpected error: {exc}"
    return out


# --- writes: edit a rule, then publish or discard (Phase 4) ----------------------------------

_RULE_EDIT_FIELDS = ("enabled", "action", "track", "name", "comments")


def write_session_timeout() -> int:
    """Idle timeout (seconds) for a read-write apply/publish session — admin-tunable so a lock left by
    an interrupted apply expires fast. Falls back to a safe default."""
    try:
        return int(app_settings.get("mgmt_write_session_timeout"))
    except Exception:  # noqa: BLE001
        return 300


def _is_lock_error(msg: str) -> bool:
    """A Check Point object-lock conflict ('Requested object … locked: [Locked for editing by admin]')."""
    return "lock" in (msg or "").lower()


def show_sessions(server, secret: str) -> list[dict]:
    """Every current management session (read-only, via the shared pooled session)."""
    with read_session(server, secret) as s:
        return s.call_paged("show-sessions", key="objects")


def locking_sessions(server, secret: str) -> list[dict]:
    """The open sessions holding uncommitted changes / object locks — the usual cause of a
    'Locked for editing' error. Best-effort + read-only; returns [] if it can't be determined.
    A read-only session (like our own pooled reader) never holds locks, so it's filtered out."""
    try:
        out: list[dict] = []
        for sess in show_sessions(server, secret):
            locks = sess.get("locks") or sess.get("number-of-locks") or sess.get("locks-count") or 0
            changes = sess.get("changes") or 0
            if (not locks and not changes) or sess.get("read-only"):
                continue
            ll = sess.get("last-login-time")
            out.append({
                "uid": sess.get("uid"),
                "user": sess.get("user") or sess.get("name") or "—",
                "application": sess.get("application") or "—",
                "locks": int(locks or 0), "changes": int(changes or 0),
                "last_login": (ll.get("iso-8601") if isinstance(ll, dict) else ll) or "",
            })
        out.sort(key=lambda x: (x["locks"], x["changes"]), reverse=True)
        return out
    except MgmtError:
        return []


def take_over_session(server, secret: str, uid: str) -> dict:
    """Take ownership of another open session and DISCARD its uncommitted changes, releasing its object
    locks. DESTRUCTIVE — it drops that session's unpublished work — so the caller must confirm. Uses a
    read-write session (a read-only one can't take over). Returns {ok} or {ok, error}."""
    if not uid:
        return {"ok": False, "error": "No session id to take over."}
    try:
        with MgmtSession(server, secret, session_timeout=write_session_timeout(),
                         session_description="DC-Sim portal (take over + release locks)") as s:
            # disconnect-active-session lets us take over a session still attached to a live GUI client.
            s.call("take-over-session", {"uid": uid, "disconnect-active-session": True})
            s.discard()
        return {"ok": True}
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}


def build_set_rule_op(layer: str, uid: str, changes: dict) -> dict:
    """Build a single ``set-access-rule`` op from a small change dict. Only the keys actually present
    in ``changes`` are sent, so the op touches nothing else on the rule. Returns
    {command, payload, summary} — pure, so the UI can preview the exact call before it runs."""
    payload: dict = {"uid": uid, "layer": layer}
    parts: list[str] = []
    if "enabled" in changes:
        payload["enabled"] = bool(changes["enabled"])
        parts.append("enable" if payload["enabled"] else "disable")
    if changes.get("action"):
        payload["action"] = changes["action"]
        parts.append(f"action → {changes['action']}")
    if changes.get("track"):
        payload["track"] = {"type": changes["track"]}   # Track Settings object, matching show output
        parts.append(f"track → {changes['track']}")
    if changes.get("name"):        # only rename to a non-empty value; never blank an existing rule's name
        payload["new-name"] = changes["name"]
        parts.append(f"rename → {changes['name']!r}")
    if "comments" in changes:
        payload["comments"] = changes["comments"]
        parts.append("comments")
    return {"command": "set-access-rule", "payload": payload,
            "summary": "set-access-rule (" + (", ".join(parts) or "no changes") + ")"}


def apply_changes(server, secret: str, ops: list[dict], *, publish: bool) -> dict:
    """Run write ops in ONE session, then **publish** (commit) or **discard** (dry-run — validates the
    payloads against the SMS with zero commit). On any error the session is discarded so a partial
    change never lingers. Returns {ok, published, results, trace, error?}."""
    results: list[dict] = []
    try:
        with MgmtSession(server, secret, session_timeout=write_session_timeout(),
                         session_description="DC-Sim portal (apply changes)") as s:
            try:
                for op in ops:
                    s.call(op["command"], op.get("payload") or {})
                    results.append({"summary": op.get("summary", op["command"]), "ok": True})
                if publish:
                    s.publish()
                else:
                    s.discard()
            except MgmtError:
                try:
                    s.discard()   # never leave uncommitted changes in the session on failure
                except MgmtError:
                    pass
                raise
            return {"ok": True, "published": publish, "results": results, "trace": s.trace}
    except MgmtError as exc:
        out = {"ok": False, "published": False, "error": str(exc), "results": results}
        if _is_lock_error(str(exc)):                       # surface who holds the lock + enable take-over
            out["lock_conflict"] = True
            out["sessions"] = locking_sessions(server, secret)
        return out
