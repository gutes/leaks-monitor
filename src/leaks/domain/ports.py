"""Puertos del dominio (hexagonal).

El núcleo depende de estas abstracciones; las implementaciones concretas
(HTTP, SQLAlchemy, proveedores) son adaptadores que se enchufan por afuera.
Esto es lo que permite testear sin red ni base de datos real.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Protocol, runtime_checkable

from leaks.domain.models import (
    Finding,
    LeakType,
    NormalizedItem,
    RawItem,
    RunEvent,
    SourceRunResult,
)


@runtime_checkable
class FeedAdapter(Protocol):
    """Un feed de leaks.

    Sumar una fuente = implementar esto + una entrada en el registro. El core
    no se toca.
    """

    #: Identificador estable del feed; se persiste en `findings.source`.
    name: str
    #: Naturaleza de lo que produce este feed.
    leak_type: LeakType

    def fetch(self, since: datetime | None) -> Iterable[RawItem]:
        """Trae items del feed, opcionalmente solo los posteriores a `since`.

        Puede lanzar: el runner aísla cada fuente y sigue con las demás.
        """
        ...

    def normalize(self, item: RawItem) -> NormalizedItem | None:
        """Mapea un item crudo al schema común.

        Devuelve `None` si el item es inservible (sin víctima, sin fecha, etc.)
        en lugar de lanzar: un registro malformado no debe cortar la ingesta.
        """
        ...


@runtime_checkable
class FindingRepository(Protocol):
    """Persistencia de hallazgos. Idempotente por `dedup_hash`."""

    def upsert_many(self, findings: Sequence[Finding]) -> int:
        """Persiste hallazgos nuevos y refresca `last_seen_at` de los ya vistos.

        Devuelve la cantidad de hallazgos **nuevos** (los repetidos no cuentan),
        de modo que re-correr el pipeline no infle el conteo.
        """
        ...

    def record_run(self, result: SourceRunResult) -> None:
        """Guarda la telemetría de una fuente dentro de un run."""
        ...

    def list_pending_alerts(
        self, *, min_severity: str, limit: int, max_age_days: int | None = None
    ) -> list[Finding]:
        """Hallazgos que llegan al umbral y todavía no se avisaron.

        Pendiente es `alerted_at IS NULL`: si un envío falla, el hallazgo se
        reintenta en la corrida siguiente en vez de perderse.

        Nunca incluye los de importación inicial ni, con `max_age_days`, los
        eventos viejos: son cosas que recién conocemos, no que recién pasaron.
        """
        ...

    def mark_alerted(self, dedup_hashes: Sequence[str]) -> int:
        """Marca hallazgos como avisados. Solo se llama tras un envío exitoso."""
        ...

    def earliest_occurrence(self, victim_domain: str) -> datetime | None:
        """Fecha más antigua que ya tenemos para ese dominio, de cualquier fuente.

        Corrobora el fechado: si otro feed ya ubicó el mismo evento antes, esa
        fecha es mejor que ninguna. El evento es uno solo aunque lo reporten
        varios.
        """
        ...

    def last_ok_runs(self, sources: Sequence[str]) -> dict[str, datetime | None]:
        """Última corrida **exitosa** de cada fuente pedida.

        `None` para la que nunca tuvo una. Es lo que alimenta el watchdog: se
        mide contra el último éxito y no contra la última corrida, porque una
        fuente que falla cada hora quedaría en verde para siempre.
        """
        ...

    def last_run_was_blocked(self) -> bool:
        """¿La corrida anterior quedó bloqueada por el control de IP de salida?

        Es lo que evita repetir el aviso en cada corrida mientras la VPN siga
        caída: se avisa al entrar al estado, no mientras dura.
        """
        ...

    def get_cursor(self, source: str) -> datetime | None:
        """Marca incremental: hasta dónde llegó la última corrida de esa fuente."""
        ...

    def set_cursor(self, source: str, value: datetime) -> None:
        """Avanza la marca incremental de una fuente."""
        ...


@runtime_checkable
class EventSink(Protocol):
    """Destino de los eventos de actividad del pipeline.

    Se define como puerto para que el cliente HTTP y el runner puedan reportar
    lo que hacen sin saber si eso termina en una base, en un log o en nada.
    Las implementaciones **no deben propagar excepciones**: que falle el
    registro de actividad no puede tumbar una corrida.
    """

    def emit(self, event: RunEvent) -> None:
        """Registra un evento."""
        ...
