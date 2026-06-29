"""Table export framework — turn any portal list into a CSV download or a print-quality PDF.

PDF is produced by the **browser's own print engine** (a dedicated branded print view + print CSS that
repeats the header on every page and never splits a row across a page break), so multi-page exports
look clean and we add no new server dependency (which also keeps us inside the package-install policy).
CSV is generated with the stdlib ``csv`` module.

Each table registers a *builder* that loads its FULL (optionally filtered) dataset and maps it to a
header + rows; the CSV and print endpoints are generic over the resulting ``ExportTable``. Builders live
in ``app/services/exporters/`` and are auto-discovered, so adding a table is one self-contained file.
"""
from __future__ import annotations

import csv
import datetime as dt
import importlib
import io
import pkgutil
from dataclasses import dataclass, field
from typing import Callable, Optional

MAX_ROWS = 20000   # defensive ceiling so an export can never exhaust memory


@dataclass
class ExportTable:
    title: str
    columns: list[str]
    rows: list[list]                                   # each row: cells aligned to `columns`
    subtitle: str = ""                                 # e.g. "Management API · v2.1"
    meta: list[tuple[str, str]] = field(default_factory=list)   # [(label, value)] for the print header
    numeric_cols: set[int] = field(default_factory=set)         # column indices to right-align in print


# (db, user, query_params) -> ExportTable.  query_params is a Starlette QueryParams (.get / .getlist).
Builder = Callable[..., ExportTable]
REGISTRY: dict[str, Builder] = {}


def register(table_id: str):
    def deco(fn: Builder) -> Builder:
        REGISTRY[table_id] = fn
        return fn
    return deco


def fmt_dt(value) -> str:
    """Stable, sortable timestamp for a cell (UTC, no tz suffix to keep CSV clean)."""
    if not isinstance(value, dt.datetime):
        return "" if value is None else str(value)
    return value.strftime("%Y-%m-%d %H:%M:%S")


_CSV_INJECT = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralise CSV formula injection: a string cell beginning with =,+,-,@,tab,CR is prefixed with a
    single quote so a spreadsheet treats it as text, never an executable formula (OWASP). Numbers (real
    int/float cells, e.g. counts/latency) are untouched, so they stay numeric in the sheet."""
    if isinstance(value, str) and value and value[0] in _CSV_INJECT:
        return "'" + value
    return "" if value is None else value


def to_csv(et: ExportTable) -> str:
    """RFC-4180 CSV with a UTF-8 BOM so Excel opens non-ASCII (object names, IPs) correctly. Cells are
    sanitised against spreadsheet formula injection."""
    buf = io.StringIO()
    buf.write("\ufeff")  # UTF-8 BOM
    w = csv.writer(buf)
    w.writerow(et.columns)
    for r in et.rows:
        w.writerow([_csv_safe(c) for c in r])
    return buf.getvalue()


_loaded = False


def _load_builders() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    from . import exporters
    for mod in pkgutil.iter_modules(exporters.__path__):
        try:
            importlib.import_module(f"{exporters.__name__}.{mod.name}")
        except Exception:  # noqa: BLE001 — a broken exporter must not disable every other export
            import logging
            logging.getLogger("dcsim.exporting").exception("failed to load exporter %s", mod.name)


def build(table_id: str, db, user, params) -> Optional[ExportTable]:
    """Build the export for a table id, or None if unknown. Rows are capped at MAX_ROWS."""
    _load_builders()
    fn = REGISTRY.get(table_id)
    if fn is None:
        return None
    et = fn(db, user, params)
    if et is not None and len(et.rows) > MAX_ROWS:
        et.rows = et.rows[:MAX_ROWS]
    return et


def known() -> set[str]:
    _load_builders()
    return set(REGISTRY)
