"""Consultas de solo lectura que alimentan la API y el frontend.

Separado del repositorio de escritura a propósito: son responsabilidades
distintas (el pipeline escribe, la API lee) y mezclarlas termina en un objeto
que hace de todo. Acá no hay ningún método que modifique la base.

Ninguna consulta toca `pii_records`: el frontend no expone PII ni con el flag
activado. Para leer esa tabla hace falta la clave y un acceso deliberado.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, sessionmaker

from leaks.storage.models import FindingRow, RunEventRow, SourceRunRow
from leaks.storage.session import session_scope


def _as_utc(value: datetime | None) -> datetime | None:
    """SQLite no guarda offset: al leer reponemos el UTC que escribimos."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@dataclass(frozen=True)
class FindingFilters:
    """Filtros del listado. Todos opcionales y combinables con AND."""

    source: str | None = None
    sector: str | None = None
    severity: str | None = None
    leak_type: str | None = None
    actor: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    #: Búsqueda por texto sobre nombre y dominio de la víctima.
    q: str | None = None
    #: `reciente`, `historico` o `sin_fecha`. Se calcula sobre `occurred_at`.
    freshness: str | None = None
    #: Umbral en días para decidir qué es reciente.
    fresh_days: int = 30


@dataclass(frozen=True)
class Page:
    """Una página de resultados, con el total para paginar en el frontend."""

    items: tuple[dict[str, Any], ...]
    total: int
    limit: int
    offset: int


class FindingQueryService:
    """Lecturas sobre `findings` y la telemetría de fuentes."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Listado -------------------------------------------------------------

    def list_findings(self, filters: FindingFilters, *, limit: int, offset: int) -> Page:
        """Hallazgos ordenados por fecha de descubrimiento, del más nuevo al más viejo."""
        with session_scope(self._session_factory) as session:
            total = session.scalar(
                self._apply(select(func.count()).select_from(FindingRow), filters)
            )
            filas = session.scalars(
                self._apply(select(FindingRow), filters)
                .order_by(FindingRow.discovered_at.desc(), FindingRow.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            return Page(
                items=tuple(self._to_dict(f) for f in filas),
                total=int(total or 0),
                limit=limit,
                offset=offset,
            )

    @staticmethod
    def _apply(stmt: Select[Any], filters: FindingFilters) -> Select[Any]:
        """Aplica los filtros activos. Los `None` no filtran."""
        if filters.source:
            stmt = stmt.where(FindingRow.source == filters.source)
        if filters.sector:
            stmt = stmt.where(FindingRow.sector == filters.sector)
        if filters.severity:
            stmt = stmt.where(FindingRow.severity == filters.severity)
        if filters.leak_type:
            stmt = stmt.where(FindingRow.leak_type == filters.leak_type)
        if filters.actor:
            stmt = stmt.where(FindingRow.actor == filters.actor)
        if filters.since:
            stmt = stmt.where(FindingRow.discovered_at >= filters.since)
        if filters.until:
            stmt = stmt.where(FindingRow.discovered_at <= filters.until)
        if filters.freshness:
            # La frescura se filtra sobre la fecha del EVENTO, no sobre cuándo
            # lo importamos: es toda la diferencia que introdujo este cambio.
            limite = datetime.now(UTC) - timedelta(days=filters.fresh_days)
            if filters.freshness == "reciente":
                stmt = stmt.where(
                    FindingRow.occurred_at.is_not(None), FindingRow.occurred_at >= limite
                )
            elif filters.freshness == "historico":
                stmt = stmt.where(
                    FindingRow.occurred_at.is_not(None), FindingRow.occurred_at < limite
                )
            elif filters.freshness == "sin_fecha":
                stmt = stmt.where(FindingRow.occurred_at.is_(None))

        if filters.q:
            # `q` viene de la query string: va como parámetro ligado, nunca
            # interpolado. El escape de comodines evita que un `%` del usuario
            # convierta la búsqueda en un match total.
            patron = "%{}%".format(filters.q.strip().replace("%", r"\%").replace("_", r"\_"))
            stmt = stmt.where(
                FindingRow.victim_name.ilike(patron, escape="\\")
                | FindingRow.victim_domain.ilike(patron, escape="\\")
            )
        return stmt

    @staticmethod
    def _to_dict(row: FindingRow) -> dict[str, Any]:
        """Proyección explícita: se lista campo por campo lo que sale a la API."""
        return {
            "id": row.id,
            "source": row.source,
            "leak_type": row.leak_type,
            "victim_name": row.victim_name,
            "victim_domain": row.victim_domain,
            "country": row.country,
            "sector": row.sector,
            "actor": row.actor,
            "discovered_at": _as_utc(row.discovered_at),
            "published_at": _as_utc(row.published_at),
            "raw_ref": row.raw_ref,
            "ar_match_reason": list(row.ar_match_reason or []),
            "ar_match_detail": row.ar_match_detail or {},
            "severity": row.severity,
            "description": row.description,
            "occurred_at": _as_utc(row.occurred_at) if row.occurred_at else None,
            "occurred_at_basis": row.occurred_at_basis or "sin_dato",
            "backfill": bool(row.backfill),
            "download_links": row.download_links or [],
            "first_seen_at": _as_utc(row.first_seen_at),
            "last_seen_at": _as_utc(row.last_seen_at),
        }

    # -- Agregados -----------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Totales para el encabezado del frontend."""
        with session_scope(self._session_factory) as session:
            total = session.scalar(select(func.count()).select_from(FindingRow)) or 0
            return {
                "total": int(total),
                "by_severity": self._count_by(session, FindingRow.severity),
                "by_source": self._count_by(session, FindingRow.source),
                "by_sector": self._count_by(session, FindingRow.sector),
                "by_leak_type": self._count_by(session, FindingRow.leak_type),
                "latest_discovered_at": _as_utc(
                    session.scalar(select(func.max(FindingRow.discovered_at)))
                ),
            }

    @staticmethod
    def _count_by(session: Session, column: Any) -> dict[str, int]:
        filas = session.execute(
            select(column, func.count()).group_by(column).order_by(func.count().desc())
        ).all()
        return {str(valor): int(cantidad) for valor, cantidad in filas if valor is not None}

    def distinct_values(self, column_name: str) -> tuple[str, ...]:
        """Valores distintos de una columna, para poblar los filtros de la UI."""
        columnas = {
            "source": FindingRow.source,
            "sector": FindingRow.sector,
            "severity": FindingRow.severity,
            "actor": FindingRow.actor,
            "leak_type": FindingRow.leak_type,
        }
        columna = columnas.get(column_name)
        if columna is None:
            return ()
        with session_scope(self._session_factory) as session:
            valores = session.scalars(select(columna).distinct().order_by(columna)).all()
            return tuple(str(v) for v in valores if v is not None)

    # -- Salud de las fuentes ------------------------------------------------

    def latest_runs(self) -> tuple[dict[str, Any], ...]:
        """Última corrida de cada fuente.

        Es lo que hace visible la regla de aislamiento: si un feed viene
        fallando, se ve en la UI en vez de pasar como "no hubo novedades".
        """
        with session_scope(self._session_factory) as session:
            ultimo = (
                select(
                    SourceRunRow.source.label("source"),
                    func.max(SourceRunRow.started_at).label("started_at"),
                )
                .group_by(SourceRunRow.source)
                .subquery()
            )
            filas = session.scalars(
                select(SourceRunRow)
                .join(
                    ultimo,
                    (SourceRunRow.source == ultimo.c.source)
                    & (SourceRunRow.started_at == ultimo.c.started_at),
                )
                .order_by(SourceRunRow.source)
            ).all()
            return tuple(
                {
                    "source": f.source,
                    "status": f.status,
                    "started_at": _as_utc(f.started_at),
                    "finished_at": _as_utc(f.finished_at),
                    "items_fetched": f.items_fetched,
                    "items_matched": f.items_matched,
                    "items_persisted": f.items_persisted,
                    "error": f.error,
                }
                for f in filas
            )

    # -- Bitácora de actividad ------------------------------------------------

    def list_events(self, *, after_id: int = 0, limit: int = 200) -> tuple[dict[str, Any], ...]:
        """Eventos posteriores a `after_id`, en orden cronológico.

        El frontend guarda el último id que vio y pide solo lo nuevo: así la
        consola no repite líneas ni tiene que recargar todo en cada poll.
        """
        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(RunEventRow)
                .where(RunEventRow.id > after_id)
                .order_by(RunEventRow.id)
                .limit(limit)
            ).all()
            return tuple(
                {
                    "id": f.id,
                    "occurred_at": _as_utc(f.occurred_at),
                    "level": f.level,
                    "kind": f.kind,
                    "source": f.source,
                    "message": f.message,
                    "url": f.url,
                    "status_code": f.status_code,
                    "duration_ms": f.duration_ms,
                    "bytes_received": f.bytes_received,
                }
                for f in filas
            )

    def last_event_id(self) -> int:
        """Último id de la bitácora, para que el frontend arranque desde ahí."""
        with session_scope(self._session_factory) as session:
            return int(session.scalar(select(func.max(RunEventRow.id))) or 0)

    def recent_sources(self) -> Sequence[str]:
        """Fuentes con al menos un hallazgo persistido."""
        return self.distinct_values("source")
