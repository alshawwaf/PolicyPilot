"""Per-user table view preferences — which columns are visible, resolved SERVER-SIDE so the GET route
renders exactly the chosen columns (no flash of defaults). Backed by UserTablePref (JSON), validated +
versioned: unknown column ids are dropped, locked columns are always included, an empty/absent pref
falls back to the table's spec defaults."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import UserTablePref


@dataclass(frozen=True)
class Col:
    id: str
    label: str
    default: bool = True       # shown unless the user hides it
    locked: bool = False       # the identifier column — can never be hidden


# Per-table column specs. A table opts into customization by appearing here; templates iterate the
# spec for the chooser and gate each optional column on the resolved visible set.
TABLE_SPECS: dict[str, list[Col]] = {
    "datacenters": [
        Col("name", "Name", locked=True),
        Col("provider", "Provider"),
        Col("inventory", "Inventory"),
        Col("created", "Created", default=False),
    ],
    # All currently-shown columns stay default-on (the view doesn't change); "created" is a new opt-in.
    "feeds": [
        Col("name", "Name", locked=True),
        Col("type", "Type"),
        Col("items", "Items"),
        Col("interval", "Interval"),
        Col("auth", "Auth"),
        Col("url", "Feed URL"),
        Col("created", "Created", default=False),
    ],
    "gateways": [
        Col("name", "Name", locked=True),
        Col("address", "Address"),
        Col("username", "Username"),
        Col("tls", "TLS"),
        Col("layers", "Layers"),
        Col("created", "Created", default=False),
    ],
    "management": [
        Col("name", "Name", locked=True),
        Col("address", "Address"),
        Col("domain", "Domain"),
        Col("username", "Username"),
        Col("tls", "TLS"),
        Col("secret", "Secret"),
        Col("created", "Created", default=False),
    ],
    "layers": [
        Col("name", "Name", locked=True),
        Col("gateway", "Gateway"),
        Col("gwlayer", "Gateway layer"),
        Col("objects", "Objects"),
        Col("rules", "Rules"),
        Col("lastapply", "Last apply"),
        Col("created", "Created", default=False),
    ],
    "access-servers": [
        Col("name", "Name", locked=True),
        Col("address", "Address"),
        Col("domain", "Domain"),
        Col("secret", "Secret"),
    ],
}


def spec(table_id: str) -> list[Col]:
    return TABLE_SPECS.get(table_id, [])


def _defaults(cols: list[Col]) -> list[str]:
    return [c.id for c in cols if c.default or c.locked]


def visible_columns(db: Session, owner_id: int, table_id: str) -> list[str]:
    """The resolved visible column ids for this user+table, in spec order. Defaults when unset."""
    cols = spec(table_id)
    if not cols:
        return []
    valid = {c.id for c in cols}
    locked = {c.id for c in cols if c.locked}
    row = db.scalar(select(UserTablePref).where(UserTablePref.owner_id == owner_id,
                                                UserTablePref.table_id == table_id))
    saved = (row.prefs or {}).get("columns") if row and isinstance(row.prefs, dict) else None
    chosen = ({c for c in saved if c in valid} | locked) if saved else set(_defaults(cols))
    return [c.id for c in cols if c.id in chosen]


def save_columns(db: Session, owner_id: int, table_id: str, ids) -> list[str]:
    """Persist the chosen column ids (validated against the spec allowlist; locked always kept; empty
    falls back to defaults). Upserts the per-user row. Returns the resolved visible ids."""
    cols = spec(table_id)
    valid = {c.id for c in cols}
    locked = {c.id for c in cols if c.locked}
    chosen = ({i for i in ids if i in valid} | locked) or set(_defaults(cols))
    keep = [c.id for c in cols if c.id in chosen]          # spec order
    row = db.scalar(select(UserTablePref).where(UserTablePref.owner_id == owner_id,
                                                UserTablePref.table_id == table_id))
    if row is None:
        db.add(UserTablePref(owner_id=owner_id, table_id=table_id, prefs={"columns": keep}))
    else:
        row.prefs = {**(row.prefs or {}), "columns": keep}
    db.commit()
    return keep


def reset(db: Session, owner_id: int, table_id: str) -> None:
    row = db.scalar(select(UserTablePref).where(UserTablePref.owner_id == owner_id,
                                                UserTablePref.table_id == table_id))
    if row is not None:
        db.delete(row)
        db.commit()
