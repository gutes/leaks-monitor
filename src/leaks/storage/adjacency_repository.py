"""Persistencia de la sección de adyacencia.

Aparte del repositorio argentino a propósito: comparte la sesión pero no las
tablas ni las consultas. Que sea imposible mezclar hallazgos argentinos con
víctimas regionales es el punto, no un efecto colateral.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from leaks.adjacency.registries import RegionalVictim
from leaks.adjacency.scoring import Score, VictimaRegional
from leaks.storage.models import AdjacentActorRow, RegionalVictimRow
from leaks.storage.session import session_scope

logger = logging.getLogger(__name__)

#: Centinela para comparar contra `alerted_at` cuando no hay fecha.
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _as_utc(valor: datetime | None) -> datetime | None:
    if valor is None:
        return None
    return valor if valor.tzinfo else valor.replace(tzinfo=UTC)


@dataclass(frozen=True)
class UpsertResult:
    """Qué pasó al guardar un lote de víctimas regionales."""

    nuevas: int = 0
    existentes: int = 0

    @property
    def total(self) -> int:
        return self.nuevas + self.existentes


@dataclass(frozen=True)
class PerfilActor:
    """Un actor tal como lo ve la API."""

    actor: str
    victims_total: int
    countries: tuple[str, ...]
    first_seen: datetime | None
    last_seen: datetime | None
    hit_ar: bool
    ar_victims: int
    score: float
    score_breakdown: dict[str, float]
    score_prev: float | None
    score_updated_at: datetime | None

    @property
    def variacion(self) -> float | None:
        """Cuánto se movió el score desde la corrida anterior."""
        if self.score_prev is None:
            return None
        return round(self.score - self.score_prev, 1)

    def as_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "victims_total": self.victims_total,
            "countries": list(self.countries),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hit_ar": self.hit_ar,
            "ar_victims": self.ar_victims,
            "score": self.score,
            "score_breakdown": dict(self.score_breakdown),
            "score_prev": self.score_prev,
            "score_updated_at": self.score_updated_at,
            "variacion": self.variacion,
        }


class AdjacencyRepository:
    """Víctimas regionales y perfiles de actor."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Víctimas ------------------------------------------------------------

    def upsert_victims(self, victimas: Iterable[RegionalVictim]) -> UpsertResult:
        """Guarda las que no estaban. Idempotente por la clave natural.

        El feed republica su histórico entero en cada corrida, así que sin la
        deduplicación la tabla crecería en cada pasada.
        """
        lote = list(victimas)
        if not lote:
            return UpsertResult()

        ahora = datetime.now(UTC)
        nuevas = existentes = 0
        with session_scope(self._session_factory) as session:
            ya = {
                (f.actor, f.country, f.victim_name, _as_utc(f.occurred_at))
                for f in session.scalars(
                    select(RegionalVictimRow).where(
                        RegionalVictimRow.actor.in_({v.actor for v in lote})
                    )
                ).all()
            }
            vistas: set[tuple[str, str, str, datetime | None]] = set()
            for v in lote:
                clave = (v.actor, v.country, v.victim_name, _as_utc(v.occurred_at))
                # El propio lote puede traer duplicados: dos países no, pero el
                # mismo país repetido entre fuentes sí.
                if clave in ya or clave in vistas:
                    existentes += 1
                    continue
                vistas.add(clave)
                session.add(
                    RegionalVictimRow(
                        actor=v.actor,
                        country=v.country,
                        victim_name=v.victim_name,
                        victim_domain=v.victim_domain,
                        sector=v.sector,
                        occurred_at=_as_utc(v.occurred_at),
                        source=v.source,
                        first_seen_at=ahora,
                    )
                )
                nuevas += 1
        return UpsertResult(nuevas=nuevas, existentes=existentes)

    def victims_by_actor(self) -> dict[str, list[VictimaRegional]]:
        """Insumo del score: solo lo que la fórmula necesita.

        Las víctimas sin fecha se dejan afuera: no pueden sostener recencia ni
        tendencia, y contarlas para volumen inflaría a los actores peor
        fechados.
        """
        salida: dict[str, list[VictimaRegional]] = {}
        with session_scope(self._session_factory) as session:
            filas = session.execute(
                select(
                    RegionalVictimRow.actor,
                    RegionalVictimRow.country,
                    RegionalVictimRow.occurred_at,
                    RegionalVictimRow.sector,
                    RegionalVictimRow.victim_domain,
                    RegionalVictimRow.critical,
                ).where(RegionalVictimRow.occurred_at.is_not(None))
            ).all()
        for actor, country, ocurrido, sector, dominio, critica in filas:
            momento = _as_utc(ocurrido)
            if momento is None:
                continue
            salida.setdefault(actor, []).append(
                VictimaRegional(
                    country=country,
                    occurred_at=momento.date(),
                    sector=sector or "",
                    victim_domain=dominio,
                    critica=bool(critica),
                )
            )
        return salida

    def reclasificar(self, es_critica: Callable[[str, str | None], tuple[bool, str | None]]) -> int:
        """Recalcula la criticidad de TODAS las víctimas. Devuelve cuántas cambiaron.

        Corre en cada pasada y no solo al insertar, para que editar
        `data/watchlist-regional/<cc>.yaml` reclasifique lo ya guardado sin
        tener que volver a bajar 1.353 filas.
        """
        cambios = 0
        with session_scope(self._session_factory) as session:
            for fila in session.scalars(select(RegionalVictimRow)).all():
                critica, sector = es_critica(fila.country, fila.victim_domain)
                if bool(fila.critical) != critica or fila.regional_sector != sector:
                    fila.critical = critica
                    fila.regional_sector = sector
                    cambios += 1
        return cambios

    def critical_victims(self, *, limit: int = 100, offset: int = 0) -> tuple[dict[str, Any], ...]:
        """Las víctimas regionales que SÍ importan: infraestructura crítica.

        De ~1.350 víctimas regionales, la mayoría son empresas privadas que no
        dicen nada sobre el riesgo argentino. Éstas son las pocas que sí: un
        ministerio, un banco central, una petrolera estatal.

        Es la lista que un investigador quiere leer, y la razón real de que
        exista la watchlist regional — mover el score fue lo de menos.
        """
        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(RegionalVictimRow)
                .where(RegionalVictimRow.critical.is_(True))
                .order_by(RegionalVictimRow.occurred_at.desc().nullslast())
                .limit(limit)
                .offset(offset)
            ).all()
            return tuple(
                {
                    "actor": f.actor,
                    "country": f.country,
                    "victim_name": f.victim_name,
                    "victim_domain": f.victim_domain,
                    "sector": f.regional_sector,
                    "occurred_at": _as_utc(f.occurred_at),
                    "source": f.source,
                }
                for f in filas
            )

    def count_critical(self) -> int:
        with session_scope(self._session_factory) as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(RegionalVictimRow)
                    .where(RegionalVictimRow.critical.is_(True))
                )
                or 0
            )

    def sectores_regionales(self) -> tuple[str, ...]:
        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(RegionalVictimRow.sector)
                .distinct()
                .where(RegionalVictimRow.sector.is_not(None))
            ).all()
        return tuple(sorted(f for f in filas if f))

    def count_victims(self) -> int:
        with session_scope(self._session_factory) as session:
            return int(session.scalar(select(func.count()).select_from(RegionalVictimRow)) or 0)

    # -- Perfiles ------------------------------------------------------------

    def save_actor(
        self,
        actor: str,
        *,
        victims_total: int,
        countries: Sequence[str],
        first_seen: datetime | None,
        last_seen: datetime | None,
        hit_ar: bool,
        ar_victims: int,
        score: Score | None,
    ) -> None:
        """Guarda o actualiza un perfil, preservando el score anterior.

        `score_prev` es lo que hace el score *vivo*: sin él no se puede mostrar
        la variación ni alertar por salto, solo por umbral absoluto.
        """
        ahora = datetime.now(UTC)
        valor = 0.0 if score is None else score.valor
        desglose = {} if score is None else dict(score.breakdown)

        with session_scope(self._session_factory) as session:
            fila = session.scalar(select(AdjacentActorRow).where(AdjacentActorRow.actor == actor))
            if fila is None:
                session.add(
                    AdjacentActorRow(
                        actor=actor,
                        victims_total=victims_total,
                        countries=list(countries),
                        first_seen=_as_utc(first_seen),
                        last_seen=_as_utc(last_seen),
                        hit_ar=hit_ar,
                        ar_victims=ar_victims,
                        score=valor,
                        score_breakdown=desglose,
                        # Primera vez: no hay anterior, y poner 0 fingiría un
                        # salto de 0 a N que nunca ocurrió.
                        score_prev=None,
                        score_updated_at=ahora,
                    )
                )
                return

            fila.victims_total = victims_total
            fila.countries = list(countries)
            fila.first_seen = _as_utc(first_seen)
            fila.last_seen = _as_utc(last_seen)
            fila.hit_ar = hit_ar
            fila.ar_victims = ar_victims
            # Solo se mueve `score_prev` si el número efectivamente cambió: si
            # no, dos corridas seguidas borrarían la variación real.
            if valor != fila.score:
                fila.score_prev = fila.score
                fila.score_updated_at = ahora
            fila.score = valor
            fila.score_breakdown = desglose

    def pending_jumps(self, *, min_jump: float, min_score: float) -> tuple[PerfilActor, ...]:
        """Candidatos cuyo score saltó lo suficiente y todavía no se avisaron.

        Tres condiciones y todas necesarias:

        * **No haber golpeado Argentina.** A los confirmados no se les calcula
          score, así que un "salto" suyo no significa nada.
        * **Haber saltado** `min_jump` respecto de la corrida anterior. Se avisa
          por movimiento y no por umbral absoluto: un actor alto y quieto no es
          novedad, y avisar por umbral lo repetiría en cada corrida.
        * **Estar por encima del piso.** Un salto de 5 a 20 es un salto, pero
          no amerita interrumpir a nadie.

        `score_prev IS NULL` queda afuera: es la primera vez que se lo puntúa y
        no hay salto que medir — contra qué compararlo sería inventado.
        """
        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(AdjacentActorRow)
                .where(
                    AdjacentActorRow.hit_ar.is_(False),
                    AdjacentActorRow.score_prev.is_not(None),
                    AdjacentActorRow.score >= min_score,
                    AdjacentActorRow.score - AdjacentActorRow.score_prev >= min_jump,
                )
                .order_by((AdjacentActorRow.score - AdjacentActorRow.score_prev).desc())
            ).all()
            # Se avisa una vez por salto: si ya se avisó y el score no volvió a
            # moverse, no se repite.
            return tuple(
                _to_perfil(f)
                for f in filas
                if f.alerted_at is None or (f.score_updated_at or _EPOCH) > f.alerted_at
            )

    def mark_alerted(self, actores: Sequence[str]) -> None:
        """Anota que ya se avisó, para no repetir el mismo salto."""
        if not actores:
            return
        ahora = datetime.now(UTC)
        with session_scope(self._session_factory) as session:
            for fila in session.scalars(
                select(AdjacentActorRow).where(AdjacentActorRow.actor.in_(list(actores)))
            ).all():
                fila.alerted_at = ahora

    def list_actors(
        self,
        *,
        hit_ar: bool | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> tuple[PerfilActor, ...]:
        """Perfiles, los candidatos por score y los confirmados por actividad."""
        with session_scope(self._session_factory) as session:
            stmt = select(AdjacentActorRow)
            if hit_ar is not None:
                stmt = stmt.where(AdjacentActorRow.hit_ar == hit_ar)
            stmt = stmt.order_by(
                AdjacentActorRow.hit_ar.desc(),
                AdjacentActorRow.score.desc(),
                AdjacentActorRow.last_seen.desc().nullslast(),
            )
            if limit is not None:
                stmt = stmt.limit(limit).offset(offset)
            filas = session.scalars(stmt).all()
            return tuple(_to_perfil(f) for f in filas)

    def count_actors(self, *, hit_ar: bool | None = None) -> int:
        with session_scope(self._session_factory) as session:
            stmt = select(func.count()).select_from(AdjacentActorRow)
            if hit_ar is not None:
                stmt = stmt.where(AdjacentActorRow.hit_ar == hit_ar)
            return int(session.scalar(stmt) or 0)


def _to_perfil(fila: AdjacentActorRow) -> PerfilActor:
    return PerfilActor(
        actor=fila.actor,
        victims_total=fila.victims_total,
        countries=tuple(fila.countries or []),
        first_seen=_as_utc(fila.first_seen),
        last_seen=_as_utc(fila.last_seen),
        hit_ar=bool(fila.hit_ar),
        ar_victims=fila.ar_victims,
        score=float(fila.score),
        score_breakdown=dict(fila.score_breakdown or {}),
        score_prev=None if fila.score_prev is None else float(fila.score_prev),
        score_updated_at=_as_utc(fila.score_updated_at),
    )
