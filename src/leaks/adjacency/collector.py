"""Colector regional: trae las víctimas y recalcula los perfiles.

Corre después de los feeds argentinos, con el mismo aislamiento: un país que
falla se anota y se sigue con los demás. La adyacencia no puede costar la
corrida diaria.

Pasa por la misma barrera de IP de salida que todo lo demás — no hay motivo
para que estos pedidos salgan desde una IP bloqueada si los otros no pueden.

**No toca `findings`.** Lee de ahí una sola cosa, de solo lectura: qué actores
ya golpearon Argentina y cuántas víctimas tienen acá. Eso es lo que parte la
tabla en confirmados y candidatos.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from leaks.adapters.http import FeedHttpClient
from leaks.adjacency.countries import COUNTRY_CODES
from leaks.adjacency.kinds import kind_for
from leaks.adjacency.regional_watchlist import RegionalWatchlists
from leaks.adjacency.registries import REGIONAL_SOURCES, RegionalVictim, RegistryFetcher
from leaks.adjacency.scoring import VictimaRegional, calcular, sectores_frecuentes
from leaks.pipeline.egress_guard import EgressBlockedError
from leaks.storage.adjacency_repository import AdjacencyRepository

logger = logging.getLogger(__name__)


class ArContext(Protocol):
    """Lo único que la adyacencia le pide al lado argentino, de solo lectura.

    Se declara como protocolo y no se importa `FindingQueryService` para que la
    dirección de la dependencia quede clara: la adyacencia pide un contrato
    mínimo, no se acopla al servicio de consultas entero. `FindingQueryService`
    lo satisface estructuralmente.
    """

    def actor_counts(self) -> dict[str, int]: ...

    def sector_values(self) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class AdjacencyResult:
    """Qué pasó en la pasada regional."""

    victimas_nuevas: int = 0
    victimas_totales: int = 0
    #: Cuántas son infraestructura crítica según la watchlist de su país. Es la
    #: lista corta que un investigador quiere leer.
    victimas_criticas: int = 0
    reclasificadas: int = 0
    actores: int = 0
    confirmados: int = 0
    candidatos: int = 0
    paises_fallidos: tuple[str, ...] = field(default_factory=tuple)


class AdjacencyCollector:
    """Trae víctimas por país y reconstruye los perfiles de actor."""

    def __init__(
        self,
        repository: AdjacencyRepository,
        client_factory: Callable[[], FeedHttpClient],
        ar_context: ArContext,
        *,
        regional_watchlists: RegionalWatchlists | None = None,
        countries: Sequence[str] = COUNTRY_CODES,
        sources: Sequence[tuple[str, RegistryFetcher]] = REGIONAL_SOURCES,
    ) -> None:
        self._repository = repository
        self._client_factory = client_factory
        self._ar = ar_context
        self._regional = regional_watchlists
        self._countries = tuple(countries)
        self._sources = tuple(sources)

    def collect(self) -> AdjacencyResult:
        """Pasada completa: traer, guardar y repuntuar."""
        victimas, fallidos = self._traer()
        guardado = self._repository.upsert_victims(victimas)

        # Antes de puntuar: la criticidad alimenta la afinidad sectorial, y
        # además se recalcula sobre TODO lo guardado para que editar una
        # watchlist regional reclasifique sin volver a bajar nada.
        reclasificadas = self._reclasificar()

        perfiles = self._repuntuar(self._ar.actor_counts(), self._ar.sector_values())

        return AdjacencyResult(
            victimas_nuevas=guardado.nuevas,
            victimas_totales=self._repository.count_victims(),
            victimas_criticas=self._repository.count_critical(),
            reclasificadas=reclasificadas,
            actores=perfiles[0],
            confirmados=perfiles[1],
            candidatos=perfiles[2],
            paises_fallidos=tuple(fallidos),
        )

    def _reclasificar(self) -> int:
        """Marca qué víctimas son infraestructura crítica en su propio país."""
        if self._regional is None:
            return 0

        def evaluar(country: str, domain: str | None) -> tuple[bool, str | None]:
            return (
                self._regional.es_critica(country, domain),  # type: ignore[union-attr]
                self._regional.match(country, domain),  # type: ignore[union-attr]
            )

        return self._repository.reclasificar(evaluar)

    def _traer(self) -> tuple[list[RegionalVictim], list[str]]:
        """Un país por request, aislado. Un cliente para toda la pasada."""
        encontradas: list[RegionalVictim] = []
        fallidos: list[str] = []

        cliente = self._client_factory()
        try:
            for pais in self._countries:
                for nombre, traer in self._sources:
                    try:
                        propias = traer(cliente, pais)
                    except EgressBlockedError:
                        # El control de OPSEC corta la pasada entera, no un país.
                        raise
                    except Exception as exc:
                        logger.info(
                            "adyacencia: %s/%s falló (%s); se sigue con el resto",
                            nombre,
                            pais,
                            type(exc).__name__,
                        )
                        fallidos.append(f"{nombre}/{pais}")
                        continue
                    logger.debug("adyacencia: %s aportó %d de %s", nombre, len(propias), pais)
                    encontradas.extend(propias)
        finally:
            cliente.close()

        return encontradas, fallidos

    def _repuntuar(
        self, ar_actor_counts: Mapping[str, int], ar_sectors: Sequence[str]
    ) -> tuple[int, int, int]:
        """Recalcula todos los perfiles. Devuelve (total, confirmados, candidatos)."""
        por_actor = self._repository.victims_by_actor()
        # De qué universo viene cada uno. Los dos carriles no se comparan entre
        # sí: ver `adjacency/kinds.py`.
        fuentes = self._repository.sources_by_actor()
        # Qué sectores son sensibles acá lo dice el histórico argentino, no una
        # lista escrita a mano.
        sectores_ar = sectores_frecuentes(ar_sectors)
        normalizados = {k.strip().lower(): v for k, v in ar_actor_counts.items() if k}

        confirmados = candidatos = 0
        for actor, victimas in por_actor.items():
            ar_victims = normalizados.get(actor, 0)
            hit_ar = ar_victims > 0
            paises = sorted({v.country for v in victimas})
            fechas = sorted(v.occurred_at for v in victimas)

            # Los confirmados NO llevan score: una probabilidad de que le
            # peguen a Argentina no significa nada para quien ya lo hizo.
            score = None if hit_ar else calcular(victimas, sectores_ar=sectores_ar)

            self._repository.save_actor(
                actor,
                victims_total=len(victimas),
                countries=paises,
                kind=kind_for(fuentes.get(actor, set())),
                first_seen=_a_datetime(fechas[0]) if fechas else None,
                last_seen=_a_datetime(fechas[-1]) if fechas else None,
                hit_ar=hit_ar,
                ar_victims=ar_victims,
                score=score,
            )
            if hit_ar:
                confirmados += 1
            else:
                candidatos += 1

        return len(por_actor), confirmados, candidatos


def _a_datetime(dia: object) -> datetime | None:
    """Las fechas del score son `date`; la base guarda `datetime` en UTC."""
    if isinstance(dia, datetime):
        return dia if dia.tzinfo else dia.replace(tzinfo=UTC)
    if hasattr(dia, "year"):
        return datetime(dia.year, dia.month, dia.day, tzinfo=UTC)  # type: ignore[attr-defined]
    return None


__all__ = ["AdjacencyCollector", "AdjacencyResult", "VictimaRegional"]
