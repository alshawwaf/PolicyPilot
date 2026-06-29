"""Export builder: the Activity log (honours the page's status/type/data-center/search filters)."""
from sqlalchemy import and_, select

from ...models import ActivityLog
from ..exporting import ExportTable, fmt_dt, register


@register("activity")
def build(db, user, qp) -> ExportTable:
    # Reuse the page's exact filter logic so an export matches what the user is looking at.
    from ...routers.activity import KIND_LABELS, _clean_kinds, _filter_conds

    sel = _clean_kinds(qp.getlist("kinds"))
    dc = qp.getlist("dc")
    status = qp.getlist("status")
    q = qp.get("q", "")
    conds = _filter_conds(sel, dc, q, status)

    stmt = select(ActivityLog)
    if conds:
        stmt = stmt.where(and_(*conds))
    rows = db.scalars(stmt.order_by(ActivityLog.at.desc())).all()

    columns = ["Time (UTC)", "Method", "Status", "Kind", "Path", "Source IP", "Latency (ms)"]
    data = [[fmt_dt(r.at), r.method or "", r.status or "", KIND_LABELS.get(r.kind, r.kind),
             r.path or "", r.source_ip or "", r.duration_ms] for r in rows]

    meta = []
    if sel:
        meta.append(("Type", ", ".join(KIND_LABELS.get(k, k) for k in sel)))
    if status:
        meta.append(("Status", ", ".join(status)))
    if q:
        meta.append(("Search", q))

    return ExportTable(title="Activity log", columns=columns, rows=data,
                       subtitle="Every API call the portal served — methods, status, timing and source.",
                       meta=meta, numeric_cols={6})
