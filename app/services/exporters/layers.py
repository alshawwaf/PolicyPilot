"""Export builder: the Dynamic Layers list (owner-scoped, mirrors /layers)."""
from sqlalchemy import select

from ...models import DynamicLayer, Gateway
from ..exporting import ExportTable, fmt_dt, register


def _last_apply(layer) -> str:
    """Reproduce the 'Last apply' cell: status + target (· dry-run) · timestamp, or 'never applied'."""
    task = layer.tasks[0] if layer.tasks else None
    if task is None:
        return "never applied"
    parts = [task.status or "", task.target or ""]
    detail = task.target or ""
    if task.dry_run:
        detail += " · dry-run"
    when = fmt_dt(task.at)
    bits = " · ".join(p for p in [detail, when] if p)
    label = task.status or ""
    return f"{label} ({bits})" if bits else label


@register("layers")
def build(db, user, qp) -> ExportTable:
    layers = db.scalars(
        select(DynamicLayer)
        .where(DynamicLayer.owner_id == user.id)
        .order_by(DynamicLayer.created_at.desc())
    ).all()
    gws = {g.id: g for g in db.scalars(
        select(Gateway).where(Gateway.owner_id == user.id)
    ).all()}

    columns = ["Name", "Gateway", "Gateway layer", "Objects", "Rules", "Last apply", "Created"]
    rows = []
    for layer in layers:
        content = layer.content or {}
        objs = sum(len(v or []) for v in (content.get("objects") or {}).values())
        rules = len(content.get("rulebase") or [])
        gid = content.get("gateway_id")
        gw = gws.get(gid)
        rows.append([
            layer.name or "",
            gw.name if gw else "—",
            layer.layer_name or "",
            objs,
            rules,
            _last_apply(layer),
            fmt_dt(layer.created_at),
        ])

    return ExportTable(
        title="Dynamic Layers",
        columns=columns,
        rows=rows,
        subtitle=f"{len(rows)} dynamic layer(s)",
        numeric_cols={3, 4},
    )
