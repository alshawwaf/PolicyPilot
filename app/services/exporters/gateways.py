"""Export builder: saved gateway connection profiles (name, address, TLS trust, layer count, …)."""
from sqlalchemy import select

from ...models import DynamicLayer, Gateway
from ..exporting import ExportTable, fmt_dt, register


def _tls_label(gw: Gateway) -> str:
    """The same pill text the page renders for the gateway's TLS trust."""
    if gw.cert_pem:
        return "pinned cert"
    if gw.auto_trust:
        return "auto-trust"
    return "system trust"


@register("gateways")
def build(db, user, qp) -> ExportTable:
    gws = db.scalars(
        select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.created_at.desc())
    ).all()

    # Layer count per gateway, mirroring the router: count this owner's Dynamic Layers whose
    # content.gateway_id targets each gateway.
    layers = db.scalars(select(DynamicLayer).where(DynamicLayer.owner_id == user.id)).all()
    counts: dict[int, int] = {}
    for layer in layers:
        gid = (layer.content or {}).get("gateway_id")
        if gid:
            counts[gid] = counts.get(gid, 0) + 1

    # Column order mirrors the on-screen table: Name, Address, Username, TLS, Layers, Created.
    columns = ["Name", "Address", "Username", "TLS", "Layers", "Created"]
    data = [[gw.name, f"{gw.host}:{gw.port}", gw.username or "—", _tls_label(gw),
             counts.get(gw.id, 0), fmt_dt(gw.created_at)] for gw in gws]

    return ExportTable(title="Gateways", columns=columns, rows=data,
                       subtitle="Saved gateway connection profiles — address, TLS trust, and targeting layers.",
                       numeric_cols={4})
