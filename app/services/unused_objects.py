"""Unused-object discovery — the read-only foundation of object cleanup.

Lists the objects no rule / group / other object references, via the management API's
``show-unused-objects`` command, grouped by type for review. This is the safe first half of the
"tag → grace period → replace-then-delete" story (ported in spirit from CheckPointSW/UsefulManagementApiTools
AddTagToObjects + ReplaceReference): surfacing the cruft is useful on its own and carries zero write risk.

The mutating half (bulk-tag as cleanup candidates, delete after a grace period, re-point references before
delete) is a separate, publish-gated step that needs per-type object commands and live validation — it is
NOT implemented here yet.
"""
from __future__ import annotations

from . import mgmt_api

# Predefined/system objects that show up as "unused" but must never be offered for cleanup.
_SKIP_TYPES = {"CpmiAnyObject", "Global"}


def _summary(obj: dict) -> dict:
    return {"uid": obj.get("uid"), "name": obj.get("name") or obj.get("uid") or "?",
            "type": obj.get("type") or "unknown",
            "domain": ((obj.get("domain") or {}).get("name") if isinstance(obj.get("domain"), dict) else "")}


def scan_unused(session, *, max_objects: int = 20000) -> dict:
    """Pull the unused objects (paged) and group them by type. Returns
    ``{objects: [...], by_type: {type: count}, total, truncated}``."""
    objects: list[dict] = []
    truncated = False
    for obj in session.call_paged("show-unused-objects", key="objects"):
        if obj.get("type") in _SKIP_TYPES:
            continue
        objects.append(_summary(obj))
        if len(objects) >= max_objects:
            truncated = True
            break
    by_type: dict[str, int] = {}
    for o in objects:
        by_type[o["type"]] = by_type.get(o["type"], 0) + 1
    objects.sort(key=lambda o: (o["type"], o["name"].lower()))
    return {"objects": objects, "by_type": dict(sorted(by_type.items())),
            "total": len(objects), "truncated": truncated}


def list_unused(server, secret: str, *, max_objects: int = 20000) -> dict:
    """Unused objects on ``server`` grouped by type (read-only, pooled session)."""
    with mgmt_api.read_session(server, secret) as s:
        out = scan_unused(s, max_objects=max_objects)
        out["trace"] = s.trace
    return out
