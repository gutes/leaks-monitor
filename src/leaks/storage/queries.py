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
from typing import Any, ClassVar

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, sessionmaker

from leaks.adapters.registry import FEED_REGISTRY
from leaks.domain.models import SEVERITY_RANK
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
    #: Un hallazgo puntual. Es lo que hace que un hallazgo tenga URL propia:
    #: el widget de avisos pendientes enlaza acá.
    dedup_hash: str | None = None
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
        """Hallazgos por fecha de OCURRENCIA, del más nuevo al más viejo.

        Se ordena por cuándo ocurrió el evento y no por cuándo lo importamos:
        son cosas distintas y confundirlas era el problema original —una fuente
        que trae su histórico de golpe ponía leaks de 2020 arriba de todo solo
        porque los bajamos hoy.

        Los que no se pudieron fechar van al final, no primero: un hallazgo sin
        fecha no es reciente, es desconocido. `nullslast` lo garantiza; sin él
        SQLite pone los `NULL` donde le queda cómodo.
        """
        with session_scope(self._session_factory) as session:
            total = session.scalar(
                self._apply(select(func.count()).select_from(FindingRow), filters)
            )
            filas = session.scalars(
                self._apply(select(FindingRow), filters)
                .order_by(
                    FindingRow.occurred_at.desc().nullslast(),
                    FindingRow.discovered_at.desc(),
                    FindingRow.id.desc(),
                )
                .limit(limit)
                .offset(offset)
            ).all()
            return Page(
                items=tuple(self._to_dict(f) for f in filas),
                total=int(total or 0),
                limit=limit,
                offset=offset,
            )

    def find_by_ids(self, ids: Sequence[int], *, limit: int) -> tuple[dict[str, Any], ...]:
        """Hallazgos por id, para exportar una selección.

        No se respeta el orden en que vinieron los ids: el informe reordena por
        fecha de ocurrencia y el orden en que el usuario tildó las casillas no
        significa nada. Los ids inexistentes se ignoran en silencio —el
        exportador informa cuántos encontró— porque un hallazgo puede haber
        desaparecido entre que se tildó y se pidió el archivo.
        """
        unicos = list(dict.fromkeys(int(i) for i in ids))[:limit]
        if not unicos:
            return ()
        with session_scope(self._session_factory) as session:
            filas = session.scalars(select(FindingRow).where(FindingRow.id.in_(unicos))).all()
            return tuple(self._to_dict(f) for f in filas)

    def para_cobertura(self, *, limit: int) -> tuple[dict[str, Any], ...]:
        """Hallazgos que pueden relacionarse con una entrada de la watchlist.

        Se traen solo los que aportan un host —los que tienen `victim_domain` o
        detalle de exposición—; el resto no puede cruzarse con nada. La
        proyección es la completa porque el cruce necesita fecha, fuente y
        referencia, pero el filtro y el tope acotan cuánto entra en memoria.

        Ordenado del evento más reciente al más viejo, así el tope corta la
        cola histórica y no la señal fresca.
        """
        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(FindingRow)
                .where(
                    FindingRow.victim_domain.is_not(None) | FindingRow.exposure_detail.is_not(None)
                )
                .order_by(FindingRow.occurred_at.desc().nullslast(), FindingRow.id.desc())
                .limit(limit)
            ).all()
            return tuple(self._to_dict(f) for f in filas)

    @staticmethod
    def _apply(stmt: Select[Any], filters: FindingFilters) -> Select[Any]:
        """Aplica los filtros activos. Los `None` no filtran."""
        # Primero el puntual: si se pide un hallazgo por su hash, el resto de
        # los filtros sobra y además podría esconderlo (un enlace a un hallazgo
        # viejo no puede fallar porque el filtro de fecha esté en "reciente").
        if filters.dedup_hash:
            return stmt.where(FindingRow.dedup_hash == filters.dedup_hash)
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
            # Clave estable: es lo que le da URL propia a un hallazgo.
            "dedup_hash": row.dedup_hash,
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
            "exposure_detail": row.exposure_detail or None,
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

    def actor_counts(self) -> dict[str, int]:
        """Actor -> cuántas víctimas argentinas tiene.

        Es lo ÚNICO que la sección de adyacencia le pide al lado argentino, y
        es de solo lectura: con esto parte a los actores en confirmados (ya
        golpearon acá) y candidatos (todavía no).
        """
        with session_scope(self._session_factory) as session:
            conteos = self._count_by(session, FindingRow.actor)
        return {k.strip().lower(): v for k, v in conteos.items() if k and k.strip()}

    def sector_values(self) -> tuple[str, ...]:
        """Sectores de los hallazgos argentinos, con repetición.

        Con repetición a propósito: la afinidad sectorial del score necesita
        saber cuáles se golpean MÁS, no cuáles existen.
        """
        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(FindingRow.sector).where(FindingRow.sector.is_not(None))
            ).all()
        return tuple(f for f in filas if f)

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

    #: Campos por los que un consumidor puede acotar el feed de alertas.
    #:
    #: `first_seen` es el default y el único **monótono**: es cuándo lo
    #: insertamos nosotros. `occurred` puede retroceder —una importación
    #: inicial mete eventos de 2020 hoy— así que un integrador que pagine por
    #: ahí se saltea alertas sin enterarse.
    CAMPOS_FECHA: ClassVar[dict[str, Any]] = {
        "first_seen": FindingRow.first_seen_at,
        "occurred": FindingRow.occurred_at,
        "alerted": FindingRow.alerted_at,
        "discovered": FindingRow.discovered_at,
    }

    def alert_feed(
        self,
        *,
        min_severity: str,
        limit: int,
        offset: int = 0,
        desde: datetime | None = None,
        hasta: datetime | None = None,
        campo: str = "first_seen",
        estado: str = "todas",
        avisables: bool = False,
        max_age_days: int | None = None,
    ) -> Page:
        """Alertas para que las consuma otro software.

        Una «alerta» es un hallazgo que llega al umbral de severidad. Se
        devuelven **independientemente de si se despacharon o no**: que un
        canal las haya mandado es un dato del hallazgo (`alerted_at`), no un
        filtro implícito. Un integrador que corre en paralelo a los canales
        quiere verlas todas.

        A diferencia del despachador, acá **no** se excluye la importación
        inicial ni lo que no se pudo fechar: eso es política de a-quién-
        interrumpir, y un consumidor que pide un rango explícito quiere lo que
        hay. Cada ítem trae `backfill` y `occurred_at` para que decida solo.

        `avisables=True` invierte eso y aplica **la política del despachador**:
        sin importación inicial y sin eventos más viejos que `max_age_days`.
        Existe porque el panel de alertas cuenta con ese criterio, y un widget
        que liste otro conjunto contradice al número que tiene al lado.
        """
        piso = SEVERITY_RANK.get(min_severity.lower(), 0)
        alcanzan = [s for s, rango in SEVERITY_RANK.items() if rango >= piso]
        columna = self.CAMPOS_FECHA.get(campo, FindingRow.first_seen_at)

        def acotar(stmt: Select[Any]) -> Select[Any]:
            stmt = stmt.where(FindingRow.severity.in_(alcanzan))
            if estado == "pendientes":
                stmt = stmt.where(FindingRow.alerted_at.is_(None))
            elif estado == "enviadas":
                stmt = stmt.where(FindingRow.alerted_at.is_not(None))
            if desde is not None:
                stmt = stmt.where(columna.is_not(None), columna >= desde)
            if hasta is not None:
                stmt = stmt.where(columna.is_not(None), columna <= hasta)
            if avisables:
                # La misma política que `list_pending_alerts`: el histórico que
                # recién importamos no es una novedad, y sin fecha no se puede
                # afirmar que algo sea reciente.
                stmt = stmt.where(FindingRow.backfill.is_(False))
                if max_age_days is not None:
                    limite = datetime.now(UTC) - timedelta(days=max_age_days)
                    stmt = stmt.where(
                        FindingRow.occurred_at.is_not(None),
                        FindingRow.occurred_at >= limite,
                    )
            return stmt

        with session_scope(self._session_factory) as session:
            total = session.scalar(acotar(select(func.count()).select_from(FindingRow)))
            filas = session.scalars(
                acotar(select(FindingRow))
                # Más reciente primero: "las últimas alertas" es el caso normal.
                # `nullslast` para que un campo vacío no encabece la lista.
                .order_by(columna.desc().nullslast(), FindingRow.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            return Page(
                items=tuple(self._to_alert(f) for f in filas),
                total=int(total or 0),
                limit=limit,
                offset=offset,
            )

    @staticmethod
    def _to_alert(row: FindingRow) -> dict[str, Any]:
        """Proyección para consumo externo. Explícita, como la del listado."""
        return {
            "id": row.id,
            "dedup_hash": row.dedup_hash,
            "source": row.source,
            "leak_type": row.leak_type,
            "victim_name": row.victim_name,
            "victim_domain": row.victim_domain,
            "country": row.country,
            "sector": row.sector,
            "actor": row.actor,
            "severity": row.severity,
            "ar_match_reason": list(row.ar_match_reason or []),
            "occurred_at": _as_utc(row.occurred_at) if row.occurred_at else None,
            "occurred_at_basis": row.occurred_at_basis or "sin_dato",
            "discovered_at": _as_utc(row.discovered_at),
            "first_seen_at": _as_utc(row.first_seen_at),
            #: Cuándo se despachó por los canales. `None` = todavía no.
            "alerted_at": _as_utc(row.alerted_at) if row.alerted_at else None,
            "notified": row.alerted_at is not None,
            "backfill": bool(row.backfill),
            "raw_ref": row.raw_ref,
        }

    def alert_status(self, *, min_severity: str, max_age_days: int | None = None) -> dict[str, Any]:
        """Cuántos hallazgos esperan aviso y cuándo se avisó por última vez.

        Existe para que la UI pueda decir la verdad incómoda: sin canales
        configurados el pipeline descarta los avisos en silencio, y hasta que
        esto no se mostró nadie se enteraba de que había hallazgos críticos
        esperando a nadie.

        Mismo criterio que `list_pending_alerts`: se excluye la importación
        inicial y lo que no se pudo fechar, o el número diría que hay 200
        pendientes cuando son histórico.
        """
        piso = SEVERITY_RANK.get(min_severity.lower(), 0)
        alcanzan = [s for s, rango in SEVERITY_RANK.items() if rango >= piso]

        with session_scope(self._session_factory) as session:
            stmt = (
                select(func.count())
                .select_from(FindingRow)
                .where(
                    FindingRow.alerted_at.is_(None),
                    FindingRow.severity.in_(alcanzan),
                    FindingRow.backfill.is_(False),
                    FindingRow.occurred_at.is_not(None),
                )
            )
            if max_age_days is not None:
                stmt = stmt.where(
                    FindingRow.occurred_at >= datetime.now(UTC) - timedelta(days=max_age_days)
                )
            pendientes = int(session.scalar(stmt) or 0)
            enviados = int(
                session.scalar(
                    select(func.count())
                    .select_from(FindingRow)
                    .where(FindingRow.alerted_at.is_not(None))
                )
                or 0
            )
            ultimo = session.scalar(select(func.max(FindingRow.alerted_at)))

        return {"pending": pendientes, "sent_total": enviados, "last_sent_at": _as_utc(ultimo)}

    def last_run_at(self) -> datetime | None:
        """Cuándo terminó la última corrida, de la fuente que sea.

        Incluye los sondeos de una sola fuente: son corridas igual, y lo que
        esto responde es "¿el pipeline está vivo?".
        """
        with session_scope(self._session_factory) as session:
            valor = session.scalar(select(func.max(SourceRunRow.finished_at)))
            return _as_utc(valor) if valor else None

    def last_full_run_at(self) -> datetime | None:
        """Cuándo terminó la última corrida **completa**.

        Se mide sobre las fuentes que no se sondean aparte: esas solo corren
        dentro de una corrida entera, así que su última corrida ES la última
        corrida completa. Sin esta distinción, un sondeo de darkforums cada dos
        horas haría parecer que el pipeline entero corrió recién.
        """
        solo_completas = [s.name for s in FEED_REGISTRY if not s.poll_interval_minutes]
        if not solo_completas:
            return None
        with session_scope(self._session_factory) as session:
            valor = session.scalar(
                select(func.max(SourceRunRow.finished_at)).where(
                    SourceRunRow.source.in_(solo_completas)
                )
            )
            return _as_utc(valor) if valor else None

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
                    "gap_from": _as_utc(f.gap_from) if f.gap_from else None,
                    "gap_to": _as_utc(f.gap_to) if f.gap_to else None,
                    "window_from": _as_utc(f.window_from) if f.window_from else None,
                    "window_to": _as_utc(f.window_to) if f.window_to else None,
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
