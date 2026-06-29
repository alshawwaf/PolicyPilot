"""Export builder: the Management Servers list (saved web_api connection profiles, owner-scoped)."""
from sqlalchemy import select

from ...models import ManagementServer
from ..exporting import ExportTable, fmt_dt, register


def _tls_label(ms: ManagementServer) -> str:
    if ms.cert_pem:
        return "pinned cert"
    if ms.auto_trust:
        return "auto-trust"
    return "system trust"


@register("management")
def build(db, user, qp) -> ExportTable:
    from ..mgmt_creds import has_secret

    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()

    columns = ["Name", "Address", "Domain", "Username", "TLS", "Secret", "Created"]
    data = [[
        ms.name or "",
        f"{ms.host}:{ms.port}",
        ms.domain or "—",
        ms.username or "—",
        _tls_label(ms),
        "saved" if has_secret(db, ms) else "none",
        fmt_dt(ms.created_at),
    ] for ms in servers]

    return ExportTable(
        title="Management Servers",
        columns=columns,
        rows=data,
        subtitle="Saved Check Point Management Server / MDS-domain connection profiles driven over web_api.",
    )
