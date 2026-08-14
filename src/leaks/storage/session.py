"""Fábrica de engine y sesiones.

SQLite embebida por default. Se activan foreign keys explícitamente porque en
SQLite vienen apagadas y sin eso el `ON DELETE CASCADE` de `pii_records` sería
decorativo.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def _enable_sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    """FK on + WAL: integridad referencial real y lecturas concurrentes."""
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def create_db_engine(database_url: str) -> Engine:
    """Crea el engine y se asegura de que el directorio de la DB exista."""
    if database_url.startswith("sqlite:///"):
        db_path = Path(database_url.removeprefix("sqlite:///"))
        if str(db_path) != ":memory:":
            db_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(database_url, future=True)
    event.listen(engine, "connect", _enable_sqlite_pragmas)
    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Sessionmaker del proyecto."""
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Unidad de trabajo: commit al salir bien, rollback ante cualquier error."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
