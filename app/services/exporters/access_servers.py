"""Export builder: the Access automation server list (Name / Address / Domain / Secret)."""
from sqlalchemy import select

from ...models import ManagementServer
from ..exporting import ExportTable, register


@register("access-servers")
def build(db, user, qp) -> ExportTable:
    from ..mgmt_creds import has_secret

    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()
    columns = ["Name", "Address", "Domain", "Secret"]
    data = [
        [
            m.name or "",
            f"{m.host}:{m.port}",
            m.domain or "—",
            "saved" if has_secret(db, m) else "none",
        ]
        for m in servers
    ]
    return ExportTable(
        title="Access automation — management servers",
        columns=columns,
        rows=data,
        subtitle="Saved Management Servers available for ticket-driven access automation.",
        meta=[("Servers", len(data))],
    )
