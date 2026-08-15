"""Puesta al día del esquema al arrancar.

El problema que resuelve: `Base.metadata.create_all` crea las tablas que
faltan pero **nunca agrega una columna a una tabla que ya existe**. Con eso
alcanzaba mientras el esquema no cambiaba; en cuanto se sumó una columna, las
instalaciones ya desplegadas siguieron arrancando y recién fallaban al primer
`SELECT` que la tocaba. Un error de esquema tiene que aparecer al arrancar, no
en la cara del usuario.

Ahora manda Alembic:

* **Base nueva** — se crean las tablas y se sella (`stamp`) en la última
  revisión.
* **Base con `alembic_version`** — `upgrade head`, el camino normal.
* **Base anterior a Alembic** (tiene tablas pero no `alembic_version`) — se
  reconcilia agregando las columnas que falten y se sella. Es un arreglo de una
  sola vez: a partir de ahí queda bajo control de Alembic.
"""

from __future__ import annotations

import logging

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect, text

from leaks.config import Settings, get_settings
from leaks.storage.models import Base

logger = logging.getLogger(__name__)


def _alembic_config(database_url: str, settings: Settings) -> Config | None:
    """Config de Alembic, o `None` si las migraciones no están disponibles.

    Instalado como wheel, el paquete no vive al lado del repo: si no se copiaron
    las migraciones a la imagen, no hay que reventar el arranque. Se degrada a
    reconciliar columnas y se avisa.
    """
    if not settings.alembic_dir.is_dir():
        logger.warning(
            "No se encontraron las migraciones en %s; se reconcilia el esquema sin Alembic",
            settings.alembic_dir,
        )
        return None

    ini = settings.alembic_ini
    config = Config(str(ini)) if ini.is_file() else Config()
    config.set_main_option("script_location", str(settings.alembic_dir))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _missing_columns(engine: Engine) -> list[tuple[str, str]]:
    """Columnas declaradas en los modelos que no están en la base."""
    inspector = inspect(engine)
    faltantes: list[tuple[str, str]] = []
    existentes = set(inspector.get_table_names())

    for tabla in Base.metadata.sorted_tables:
        if tabla.name not in existentes:
            continue
        en_base = {c["name"] for c in inspector.get_columns(tabla.name)}
        faltantes.extend(
            (tabla.name, columna.name) for columna in tabla.columns if columna.name not in en_base
        )
    return faltantes


def _add_missing_columns(engine: Engine) -> int:
    """Agrega las columnas que falten. Solo aditivo y solo nullable.

    Es la red de seguridad para bases anteriores a Alembic. No renombra, no
    borra y no cambia tipos: eso es trabajo de una migración de verdad.
    """
    faltantes = _missing_columns(engine)
    if not faltantes:
        return 0

    tablas = {t.name: t for t in Base.metadata.sorted_tables}
    with engine.begin() as conexion:
        for nombre_tabla, nombre_columna in faltantes:
            columna = tablas[nombre_tabla].columns[nombre_columna]
            if not columna.nullable:
                logger.error(
                    "Falta la columna NOT NULL %s.%s: hace falta una migración manual",
                    nombre_tabla,
                    nombre_columna,
                )
                continue
            tipo = columna.type.compile(engine.dialect)
            conexion.execute(text(f"ALTER TABLE {nombre_tabla} ADD COLUMN {nombre_columna} {tipo}"))
            logger.warning("Base anterior a Alembic: se agregó %s.%s", nombre_tabla, nombre_columna)
    return len(faltantes)


def ensure_schema(engine: Engine, database_url: str, settings: Settings | None = None) -> None:
    """Deja la base al día antes de que el proceso la use."""
    config = _alembic_config(database_url, settings or get_settings())
    tablas = set(inspect(engine).get_table_names())

    if config is None:
        # Sin migraciones disponibles: al menos que el esquema sirva.
        Base.metadata.create_all(engine)
        _add_missing_columns(engine)
        return

    if not tablas:
        # Base nueva: se crea del modelo y se sella, más rápido que encadenar
        # todas las migraciones.
        Base.metadata.create_all(engine)
        command.stamp(config, "head")
        logger.info("Base nueva creada y sellada en head")
        return

    if "alembic_version" not in tablas:
        Base.metadata.create_all(engine)
        agregadas = _add_missing_columns(engine)
        command.stamp(config, "head")
        logger.warning(
            "Base anterior a Alembic puesta al día (%d columnas) y sellada en head", agregadas
        )
        return

    command.upgrade(config, "head")
