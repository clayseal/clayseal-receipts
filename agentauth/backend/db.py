"""Database engine + session management (SQLAlchemy 2.0, SQLite by default)."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
_connect_args = (
    {"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {}
)
engine = create_engine(_settings.database_url, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create all tables, then add any columns missing from existing ones.

    Import models so they register on the metadata first.
    """
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _add_missing_columns()


def _add_missing_columns() -> None:
    """Non-destructive schema sync for the prototype's SQLite store.

    ``create_all`` adds new *tables* but never new *columns* to a table that
    already exists, so a DB created before a model gained a column (e.g. the v2
    identity work added ``agents.spiffe_id`` / ``agents.selectors``) would fail
    on insert with "no such column". With no Alembic in the prototype, we add
    any column the ORM knows about but the table lacks. Existing rows take the
    column's default (NULL, or ``'[]'`` for JSON lists). Columns are only ever
    added — never dropped or altered — so this can't lose data.
    """
    from sqlalchemy import inspect, text
    from sqlalchemy.types import JSON

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    # Order is irrelevant for ADD COLUMN (tables already exist), so iterate the
    # plain table map rather than sorted_tables (which warns on FK cycles).
    for table in Base.metadata.tables.values():
        if table.name not in existing_tables:
            continue  # freshly created by create_all
        existing_cols = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing_cols:
                continue
            col_type = col.type.compile(dialect=engine.dialect)
            default = " DEFAULT '[]'" if isinstance(col.type, JSON) else ""
            with engine.begin() as conn:
                conn.execute(
                    text(
                        f'ALTER TABLE "{table.name}" '
                        f'ADD COLUMN "{col.name}" {col_type}{default}'
                    )
                )


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
