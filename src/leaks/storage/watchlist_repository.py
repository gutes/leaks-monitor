"""Watchlist gestionable: persistencia y construcción.

La watchlist pasó de ser un YAML de solo lectura a un catálogo editable desde
la UI. El YAML sigue existiendo como **semilla**: se importa la primera vez y
queda versionado en el repo como respaldo y como documentación de la lista
base.

Por qué en la base y no editando el YAML: el contenedor corre con el
filesystem de solo lectura, y la base ya vive en un volumen. Además da altas,
bajas y estado por entrada sin inventar un formato de override.

`enabled=False` es baja lógica: la entrada deja de matchear, no se pierde, y
se puede rehabilitar cuando se quiera.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from leaks.relevance.watchlist import (
    MIN_KEYWORD_LENGTH,
    Watchlist,
    WatchlistSector,
    build_watchlist,
    normalize_text,
)
from leaks.storage.models import WatchlistEntryRow
from leaks.storage.session import session_scope

logger = logging.getLogger(__name__)

KIND_DOMAIN = "domain"
KIND_KEYWORD = "keyword"
VALID_KINDS = (KIND_DOMAIN, KIND_KEYWORD)

#: Un dominio razonable. No acepta rutas ni protocolos: se normalizan antes.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


class WatchlistValidationError(ValueError):
    """La entrada que mandaron no es usable."""


def normalize_domain(value: str) -> str:
    """Deja el dominio en su forma canónica.

    Acepta lo que el investigador tenga a mano —una URL entera, un comodín
    `*.foo.gob.ar`, algo con `www.`— y devuelve `foo.gob.ar`. El match ya cubre
    subdominios, así que el comodín es redundante y se descarta.
    """
    limpio = normalize_text(value).strip()
    for prefijo in ("https://", "http://"):
        limpio = limpio.removeprefix(prefijo)
    limpio = limpio.split("/", 1)[0].split(":", 1)[0]
    limpio = limpio.removeprefix("*.").removeprefix("www.").strip(".")
    return limpio


def validate_entry(kind: str, value: str) -> str:
    """Valida y normaliza una entrada. Lanza si no sirve."""
    if kind not in VALID_KINDS:
        raise WatchlistValidationError(f"Tipo inválido: {kind!r}. Usá 'domain' o 'keyword'.")

    if kind == KIND_DOMAIN:
        dominio = normalize_domain(value)
        if not _DOMAIN_RE.match(dominio):
            raise WatchlistValidationError(
                f"{value!r} no parece un dominio válido (ej.: prevision-ejemplo.gob.ar)."
            )
        return dominio

    keyword = " ".join(value.split())
    if len(keyword) < MIN_KEYWORD_LENGTH:
        raise WatchlistValidationError(
            f"La keyword debe tener al menos {MIN_KEYWORD_LENGTH} caracteres: "
            "las siglas cortas generan demasiados falsos positivos."
        )
    return keyword


@dataclass(frozen=True)
class WatchlistEntry:
    """Una entrada tal como la ve la API."""

    id: int
    kind: str
    value: str
    sector: str
    label: str
    critical: bool
    enabled: bool
    origin: str
    created_at: datetime
    updated_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "value": self.value,
            "sector": self.sector,
            "label": self.label,
            "critical": self.critical,
            "enabled": self.enabled,
            "origin": self.origin,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def _to_entry(row: WatchlistEntryRow) -> WatchlistEntry:
    return WatchlistEntry(
        id=row.id,
        kind=row.kind,
        value=row.value,
        sector=row.sector,
        label=row.label,
        critical=row.critical,
        enabled=row.enabled,
        origin=row.origin,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class WatchlistRepository:
    """Altas, bajas, estado y armado de la watchlist efectiva."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Lectura -------------------------------------------------------------

    def list_entries(
        self,
        *,
        kind: str | None = None,
        sector: str | None = None,
        enabled: bool | None = None,
        q: str | None = None,
    ) -> tuple[WatchlistEntry, ...]:
        """Entradas filtradas, ordenadas por sector y valor."""
        with session_scope(self._session_factory) as session:
            stmt = select(WatchlistEntryRow)
            if kind:
                stmt = stmt.where(WatchlistEntryRow.kind == kind)
            if sector:
                stmt = stmt.where(WatchlistEntryRow.sector == sector)
            if enabled is not None:
                stmt = stmt.where(WatchlistEntryRow.enabled == enabled)
            if q:
                patron = "%{}%".format(q.strip().replace("%", r"\%").replace("_", r"\_"))
                stmt = stmt.where(
                    WatchlistEntryRow.value.ilike(patron, escape="\\")
                    | WatchlistEntryRow.label.ilike(patron, escape="\\")
                )
            filas = session.scalars(
                stmt.order_by(
                    WatchlistEntryRow.sector, WatchlistEntryRow.kind, WatchlistEntryRow.value
                )
            ).all()
            return tuple(_to_entry(f) for f in filas)

    def counts(self) -> dict[str, int]:
        """Totales para el encabezado de la sección."""
        with session_scope(self._session_factory) as session:
            total = session.scalar(select(func.count()).select_from(WatchlistEntryRow)) or 0
            habilitadas = (
                session.scalar(
                    select(func.count())
                    .select_from(WatchlistEntryRow)
                    .where(WatchlistEntryRow.enabled.is_(True))
                )
                or 0
            )
            dominios = (
                session.scalar(
                    select(func.count())
                    .select_from(WatchlistEntryRow)
                    .where(WatchlistEntryRow.kind == KIND_DOMAIN)
                )
                or 0
            )
            return {
                "total": int(total),
                "enabled": int(habilitadas),
                "disabled": int(total) - int(habilitadas),
                "domains": int(dominios),
                "keywords": int(total) - int(dominios),
            }

    def sectors(self) -> tuple[str, ...]:
        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(WatchlistEntryRow.sector).distinct().order_by(WatchlistEntryRow.sector)
            ).all()
            return tuple(filas)

    # -- Escritura -----------------------------------------------------------

    def add(
        self,
        *,
        kind: str,
        value: str,
        sector: str,
        label: str | None = None,
        critical: bool = False,
        origin: str = "user",
    ) -> WatchlistEntry:
        """Agrega una entrada. Lanza si ya existe o si no valida."""
        valor = validate_entry(kind, value)
        sector_limpio = (sector or "").strip() or "sin_sector"
        ahora = datetime.now(UTC)

        with session_scope(self._session_factory) as session:
            existente = session.scalar(
                select(WatchlistEntryRow).where(
                    WatchlistEntryRow.kind == kind, WatchlistEntryRow.value == valor
                )
            )
            if existente is not None:
                raise WatchlistValidationError(
                    f"{valor!r} ya está en la watchlist (sector {existente.sector})."
                )

            fila = WatchlistEntryRow(
                kind=kind,
                value=valor,
                sector=sector_limpio,
                label=(label or sector_limpio).strip(),
                critical=critical,
                enabled=True,
                origin=origin,
                created_at=ahora,
                updated_at=ahora,
            )
            session.add(fila)
            session.flush()
            return _to_entry(fila)

    def set_enabled(self, entry_id: int, enabled: bool) -> WatchlistEntry | None:
        """Habilita o deshabilita. El estado persiste hasta que se cambie."""
        with session_scope(self._session_factory) as session:
            fila = session.get(WatchlistEntryRow, entry_id)
            if fila is None:
                return None
            fila.enabled = enabled
            fila.updated_at = datetime.now(UTC)
            session.flush()
            return _to_entry(fila)

    def remove(self, entry_id: int) -> bool:
        """Borra una entrada. Devuelve si existía."""
        with session_scope(self._session_factory) as session:
            fila = session.get(WatchlistEntryRow, entry_id)
            if fila is None:
                return False
            session.delete(fila)
            return True

    # -- Semilla y construcción ----------------------------------------------

    def is_empty(self) -> bool:
        with session_scope(self._session_factory) as session:
            return (session.scalar(select(func.count()).select_from(WatchlistEntryRow)) or 0) == 0

    def seed_from_yaml(self, path: Path, *, force: bool = False) -> int:
        """Importa el YAML semilla. No pisa nada salvo que se lo pidan.

        Devuelve cuántas entradas insertó. Es idempotente: correrlo dos veces
        no duplica.
        """
        if not path.exists():
            logger.warning("No se encontró el YAML semilla en %s", path)
            return 0
        if not force and not self.is_empty():
            return 0

        crudo = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        ahora = datetime.now(UTC)
        insertadas = 0

        with session_scope(self._session_factory) as session:
            if force:
                # Solo se descarta lo que vino del YAML: lo que agregó el
                # investigador a mano no se toca nunca.
                session.execute(delete(WatchlistEntryRow).where(WatchlistEntryRow.origin == "seed"))

            existentes = {
                (f.kind, f.value) for f in session.scalars(select(WatchlistEntryRow)).all()
            }

            for definicion in crudo.get("sectors") or []:
                sector = definicion["name"]
                label = definicion.get("label", sector)
                critical = bool(definicion.get("critical", False))

                for dominio in definicion.get("domains") or []:
                    try:
                        valor = validate_entry(KIND_DOMAIN, dominio)
                    except WatchlistValidationError:
                        logger.warning("Semilla: dominio inválido %r, se omite", dominio)
                        continue
                    if (KIND_DOMAIN, valor) in existentes:
                        continue
                    existentes.add((KIND_DOMAIN, valor))
                    session.add(
                        WatchlistEntryRow(
                            kind=KIND_DOMAIN,
                            value=valor,
                            sector=sector,
                            label=label,
                            critical=critical,
                            enabled=True,
                            origin="seed",
                            created_at=ahora,
                            updated_at=ahora,
                        )
                    )
                    insertadas += 1

                for keyword in definicion.get("keywords") or []:
                    try:
                        valor = validate_entry(KIND_KEYWORD, keyword)
                    except WatchlistValidationError:
                        # Las siglas cortas se descartan por diseño.
                        continue
                    if (KIND_KEYWORD, valor) in existentes:
                        continue
                    existentes.add((KIND_KEYWORD, valor))
                    session.add(
                        WatchlistEntryRow(
                            kind=KIND_KEYWORD,
                            value=valor,
                            sector=sector,
                            label=label,
                            critical=critical,
                            enabled=True,
                            origin="seed",
                            created_at=ahora,
                            updated_at=ahora,
                        )
                    )
                    insertadas += 1

        if insertadas:
            logger.info("Watchlist sembrada desde %s: %d entradas", path, insertadas)
        return insertadas

    def build(self) -> Watchlist:
        """Arma la watchlist efectiva con lo que está habilitado.

        Se llama al principio de cada corrida, así los cambios hechos desde la
        UI aplican en la siguiente sin reiniciar nada.
        """
        entradas = self.list_entries(enabled=True)

        agrupados: dict[str, dict[str, Any]] = {}
        for entrada in entradas:
            sector = agrupados.setdefault(
                entrada.sector,
                {
                    "label": entrada.label,
                    "critical": entrada.critical,
                    "domains": set(),
                    "keywords": [],
                },
            )
            # Basta con que una entrada del sector sea crítica.
            sector["critical"] = sector["critical"] or entrada.critical
            if entrada.kind == KIND_DOMAIN:
                sector["domains"].add(entrada.value)
            else:
                sector["keywords"].append(entrada.value)

        sectores = tuple(
            WatchlistSector(
                name=nombre,
                label=datos["label"],
                critical=bool(datos["critical"]),
                domains=frozenset(datos["domains"]),
                keywords=tuple(datos["keywords"]),
            )
            for nombre, datos in sorted(agrupados.items())
        )
        return build_watchlist(sectores)
