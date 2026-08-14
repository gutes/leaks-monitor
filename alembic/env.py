"""Entorno de Alembic.

La URL de la base sale de la configuración del proyecto (entorno/.env), nunca
de `alembic.ini`: así no hay rutas ni credenciales versionadas.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool

from leaks.config import get_settings
from leaks.storage.models import Base
from leaks.storage.session import create_db_engine

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    """Permite override por `-x db_url=...`; si no, la config del proyecto."""
    override = context.get_x_argument(as_dictionary=True).get("db_url")
    return override or get_settings().database_url


def run_migrations_offline() -> None:
    """Genera SQL sin conectarse a la base."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Aplica las migraciones contra la base configurada."""
    engine = create_db_engine(_database_url())
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # SQLite no soporta ALTER completo: batch mode hace el
            # create-copy-drop por nosotros en migraciones futuras.
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()


# `pool` se importa para que Alembic no lo marque como no usado en plantillas
# que lo referencian; acá el engine lo arma create_db_engine.
_ = pool
