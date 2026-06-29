"""Database engine, session factory, and schema bootstrap (SQLAlchemy 2.0)."""
import os
from collections.abc import Iterator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
_is_sqlite = _settings.database_url.startswith("sqlite")
_connect_args = {"check_same_thread": False, "timeout": 30} if _is_sqlite else {}
engine = create_engine(_settings.database_url, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):   # WAL + 30s busy wait so readers and one writer coexist
        cur = dbapi_conn.cursor()                # instead of raising "database is locked" under contention
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    # Ensure the SQLite directory exists before creating tables.
    url = _settings.database_url
    if url.startswith("sqlite:///"):
        path = url.replace("sqlite:///", "", 1)
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
    # Import models so they register on the metadata before create_all.
    from . import models  # noqa: F401

    Base.metadata.create_all(engine)
    _ensure_columns()


# Additive, idempotent column migrations for SQLite (no Alembic): create_all won't add a column to an
# already-existing table, so columns introduced later are added here on boot.
_ADDED_COLUMNS = {
    "gateways": {"auto_trust": "BOOLEAN DEFAULT 1"},
    "users": {
        "first_name": "VARCHAR(80) DEFAULT ''",
        "last_name": "VARCHAR(80) DEFAULT ''",
        "email": "VARCHAR(200) DEFAULT ''",
        "title": "VARCHAR(120) DEFAULT ''",
    },
    "api_keys": {"expires_at": "DATETIME"},     # key-expiry, added after the table shipped
    "applied_changes": {"resolution": "VARCHAR(16) DEFAULT ''"},   # rolled-back vs disabled-rule-deleted
}


def _ensure_columns() -> None:
    insp = inspect(engine)
    names = set(insp.get_table_names())
    for table, cols in _ADDED_COLUMNS.items():
        if table not in names:
            continue
        existing = {c["name"] for c in insp.get_columns(table)}
        for col, ddl in cols.items():
            if col not in existing:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))
