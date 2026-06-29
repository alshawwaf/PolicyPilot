"""Admin-customisable naming for the objects access-automation auto-creates (host / network / service)
and the rule it writes. Templates are editable on the Settings page; the defaults reproduce the
built-in ``h-`` / ``n-`` scheme exactly, so behaviour is unchanged unless an admin customises it.

Substitution is forgiving (unknown placeholders render empty, never raise) and the result is sanitised
to a safe Check Point object name, so a malformed template can never break an add-host/network/service
or produce an invalid name."""
from __future__ import annotations

import re

from . import app_settings

# Defaults MUST match the historical hard-coded names so existing deployments don't change silently.
DEFAULTS = {
    "name_host": "h-{ip_dashed}",          # /32  -> h-9-9-9-9
    "name_network": "n-{ip_dashed}-{prefix}",  # CIDR -> n-10-1-1-0-24
    "name_service": "{PROTO}-{port}",      # port -> TCP-443
    "name_rule": "TKT-{ticket}",           # rule -> TKT-INC0012345
}

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")    # CP object name: keep letters/digits . _ - ; collapse the rest
_MAX = 100


class _Lenient(dict):
    def __missing__(self, key):            # an unknown {placeholder} renders empty instead of raising
        return ""


def _template(key: str) -> str:
    try:
        val = (app_settings.get(key) or "").strip()
    except Exception:  # noqa: BLE001 — a settings read must never break the apply path
        val = ""
    return val or DEFAULTS[key]


def _render(template: str, ctx: dict, fallback: str) -> str:
    try:
        name = template.format_map(_Lenient(ctx))
    except Exception:  # noqa: BLE001 — never let a bad template raise
        name = fallback
    name = _SAFE.sub("_", (name or "").strip()).strip("-_.")
    return name[:_MAX] or _SAFE.sub("_", fallback).strip("-_.")[:_MAX]


def _dashed(ip: str) -> str:
    return ip.replace(".", "-").replace(":", "-")


def host_name(ip: str) -> str:
    return _render(_template("name_host"), {"ip": ip, "ip_dashed": _dashed(ip)}, f"h-{_dashed(ip)}")


def network_name(ip: str, prefix: int) -> str:
    return _render(_template("name_network"),
                   {"ip": ip, "ip_dashed": _dashed(ip), "prefix": prefix},
                   f"n-{_dashed(ip)}-{prefix}")


def service_name(protocol: str, port) -> str:
    proto = (protocol or "").lower()
    return _render(_template("name_service"),
                   {"proto": proto, "PROTO": proto.upper(), "port": port},
                   f"{proto.upper()}-{port}")


def rule_name(ticket: str, ctx: dict = None):
    """The name for a created rule, or None to leave it unnamed (Check Point auto-names it). Preserves
    the prior behaviour: a ticket-based template with no ticket id stays unnamed. ``ctx`` adds extra
    placeholders ({app}, {service}, {source}, {dest}, {layer}, {action}, {proto}, {port}) for richer
    templates like ``TKT-{ticket}-{app}``."""
    template = _template("name_rule")
    ticket = (ticket or "").strip()
    if not ticket and "{ticket}" in template:
        return None
    rctx = {"ticket": ticket}
    if ctx:
        rctx.update({k: ("" if v is None else str(v)) for k, v in ctx.items()})
    return _render(template, rctx, "") or None


def _render_text(template: str, ctx: dict, cap: int = 300) -> str:
    """Render a FREE-TEXT template (e.g. a rule comment) — lenient like _render, but NOT sanitised to an
    object name, so spaces/punctuation are kept. Never raises."""
    try:
        s = template.format_map(_Lenient(ctx))
    except Exception:  # noqa: BLE001
        s = ""
    return " ".join((s or "").split())[:cap]   # collapse whitespace, trim


def rule_comment(ctx: dict) -> str:
    """The comment/justification written onto a created rule, from the ``aa_rule_comment`` template
    (default: 'Automated from ticket {ticket}'). Same placeholders as rule_name's ctx."""
    try:
        tmpl = (app_settings.get("aa_rule_comment") or "").strip()
    except Exception:  # noqa: BLE001
        tmpl = ""
    return _render_text(tmpl or "Automated from ticket {ticket}", ctx)


def rule_track() -> str:
    """The track/log setting for a created rule (``aa_rule_track``; default 'Log'). The choice Setting
    constrains the value, so this is a plain read with a safe default."""
    try:
        return (app_settings.get("aa_rule_track") or "").strip() or "Log"
    except Exception:  # noqa: BLE001
        return "Log"


def rule_tags() -> list:
    """Tag names to attach to a created rule (``aa_rule_tags``, comma/semicolon-separated). Empty list if
    unset. Tags must already exist on the SMS (add-access-rule won't auto-create them)."""
    try:
        raw = (app_settings.get("aa_rule_tags") or "").strip()
    except Exception:  # noqa: BLE001
        raw = ""
    return [t.strip() for t in raw.replace(";", ",").split(",") if t.strip()]


def rule_section() -> str:
    """The section that floor-placed (above-cleanup) rules are grouped into, so a created rule never lands
    INSIDE the cleanup section (Check Point's organize-by-section best practice). ``aa_rule_section``;
    cleared to "" falls back to bare bottom placement (no section management). Trusted admin Setting —
    kept verbatim (CP section names allow spaces/punctuation), only trimmed + length-capped."""
    try:
        raw = (app_settings.get("aa_rule_section") or "").strip()
    except Exception:  # noqa: BLE001 — a settings read must never break the apply path
        raw = ""
    return raw[:120]
