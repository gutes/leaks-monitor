"""Orquestador del run.

Tres garantías, y cada una tiene su test:

1. **Aislamiento** — cada feed corre dentro de su propio `try/except`. Uno que
   se cae queda registrado como `failed` y el run sigue con los demás.
2. **Idempotencia** — el dedup es estable, así que re-correr no duplica.
3. **Incremental** — cada fuente lleva su cursor; se procesa solo lo posterior.

Lo que el runner NO hace: decidir qué es relevante (eso es `relevance/`) ni
saber cómo hablar con un feed (eso es `adapters/`).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from leaks.adapters.registry import FeedSpec, build_adapter, resolve_enabled
from leaks.config import Settings
from leaks.domain.models import (
    ArMatchReason,
    EventKind,
    EventLevel,
    Finding,
    NormalizedItem,
    RunEvent,
    SourceRunResult,
    SourceRunStatus,
)
from leaks.domain.ports import EventSink, FindingRepository
from leaks.pipeline.egress_guard import EgressDecision, EgressGuard
from leaks.privacy.scrub import redact_pii, scrub_free_text
from leaks.relevance.rules import evaluate
from leaks.relevance.severity import derive_severity
from leaks.relevance.watchlist import Watchlist
from leaks.storage.dedup import compute_dedup_hash
from leaks.storage.event_sink import NullEventSink
from leaks.storage.pii_vault import PiiVault

logger = logging.getLogger(__name__)


@dataclass
class RunReport:
    """Resumen de una corrida completa."""

    started_at: datetime
    finished_at: datetime
    results: list[SourceRunResult] = field(default_factory=list)
    #: Registros con PII cifrados en esta corrida (0 salvo STORE_PII=true).
    pii_stored: int = 0
    #: Registros con PII vencidos y borrados por retención.
    pii_purged: int = 0
    #: Motivo por el que el control de IP de salida bloqueó la corrida.
    blocked_reason: str | None = None

    @property
    def blocked(self) -> bool:
        return self.blocked_reason is not None

    @property
    def total_new(self) -> int:
        return sum(r.items_persisted for r in self.results)

    @property
    def total_matched(self) -> int:
        return sum(r.items_matched for r in self.results)

    @property
    def total_fetched(self) -> int:
        return sum(r.items_fetched for r in self.results)

    @property
    def failed_sources(self) -> list[str]:
        return [r.source for r in self.results if r.status is SourceRunStatus.FAILED]

    @property
    def ok(self) -> bool:
        """El run es exitoso si al menos una fuente respondió bien.

        Una corrida bloqueada nunca es exitosa: no se consultó nada.
        """
        if self.blocked:
            return False
        return any(r.status is SourceRunStatus.OK for r in self.results)


class PipelineRunner:
    """Ingesta -> relevancia AR -> privacidad -> persistencia."""

    def __init__(
        self,
        *,
        repository: FindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        pii_vault: PiiVault | None = None,
        event_sink: EventSink | None = None,
        egress_guard: EgressGuard | None = None,
        watchlist_provider: Callable[[], Watchlist] | None = None,
        rules_provider: Callable[[], frozenset[ArMatchReason]] | None = None,
        pii_sources_provider: Callable[[], bool] | None = None,
    ) -> None:
        self._repository = repository
        self._watchlist = watchlist
        self._enabled_rules: frozenset[ArMatchReason] | None = None
        self._settings = settings
        # Bitácora de actividad: lo que ve el investigador en la consola.
        self._events: EventSink = event_sink or NullEventSink()
        # Control de OPSEC: si la salida es desde un país bloqueado, la corrida
        # no toca una sola fuente. Ver pipeline/egress_guard.py.
        self._egress_guard = egress_guard
        # Se resuelven al principio de CADA corrida, no en el constructor: es
        # lo que hace que editar la watchlist desde la UI aplique en la
        # siguiente corrida sin reiniciar el proceso.
        self._watchlist_provider = watchlist_provider
        self._rules_provider = rules_provider
        self._pii_sources_provider = pii_sources_provider
        # Sin bóveda, el pipeline simplemente descarta la PII: no hay camino
        # alternativo por el que un payload sensible llegue a la base.
        self._pii_vault = pii_vault

    def run(self, specs: Sequence[tuple[FeedSpec, str | None]] | None = None) -> RunReport:
        """Corre todos los feeds habilitados."""
        pii_habilitado = (
            self._pii_sources_provider() if self._pii_sources_provider is not None else False
        )
        seleccion = (
            list(specs)
            if specs is not None
            else list(resolve_enabled(self._settings, pii_habilitado))
        )

        # Configuración vigente para esta corrida.
        if self._watchlist_provider is not None:
            self._watchlist = self._watchlist_provider()
        self._enabled_rules = self._rules_provider() if self._rules_provider is not None else None

        inicio = datetime.now(UTC)
        reporte = RunReport(started_at=inicio, finished_at=inicio)

        self._emit(
            EventKind.RUN_START,
            f"Corrida iniciada — {len(seleccion)} fuentes en el registro",
        )

        # Control de IP de salida ANTES de tocar cualquier fuente.
        decision = self._check_egress()
        if not decision.allowed:
            reporte.blocked_reason = decision.reason
            for spec, _motivo in seleccion:
                resultado = self._blocked(spec, decision.reason)
                reporte.results.append(resultado)
                self._repository.record_run(resultado)
            reporte.finished_at = datetime.now(UTC)
            return reporte

        for spec, motivo_salteo in seleccion:
            if motivo_salteo is not None:
                resultado = self._skipped(spec, motivo_salteo)
            else:
                resultado, guardados = self._run_one(spec)
                reporte.pii_stored += guardados
            reporte.results.append(resultado)
            self._repository.record_run(resultado)

        # La retención se aplica en cada corrida: una política que nadie
        # ejecuta no es una política.
        if self._pii_vault is not None:
            reporte.pii_purged = self._pii_vault.purge_expired()
            if reporte.pii_purged:
                self._emit(
                    EventKind.RETENTION,
                    f"Retención aplicada: {reporte.pii_purged} registros con PII vencidos",
                )

        reporte.finished_at = datetime.now(UTC)
        duracion = (reporte.finished_at - reporte.started_at).total_seconds()
        self._emit(
            EventKind.RUN_DONE,
            (
                f"Corrida terminada en {duracion:.1f} s — {reporte.total_fetched} traídos, "
                f"{reporte.total_matched} relevantes AR, {reporte.total_new} nuevos"
            ),
            level=EventLevel.ERROR if not reporte.ok else EventLevel.INFO,
            duration_ms=int(duracion * 1000),
        )
        return reporte

    # -- Bitácora ------------------------------------------------------------

    def _check_egress(self) -> EgressDecision:
        """Evalúa el control de IP de salida y lo deja registrado."""
        if self._egress_guard is None:
            return EgressDecision(True, "Control de IP de salida no configurado")

        decision = self._egress_guard.evaluate()
        self._emit(
            EventKind.EGRESS if decision.allowed else EventKind.EGRESS_BLOCKED,
            decision.reason,
            level=EventLevel.INFO if decision.allowed else EventLevel.ERROR,
        )
        if not decision.allowed:
            logger.error("Corrida bloqueada por el control de IP de salida: %s", decision.reason)
        return decision

    def emit_event(self, event: RunEvent) -> None:
        """Entrada del sink para los colaboradores (p. ej. el cliente HTTP).

        Defensa en profundidad: el puerto pide que las implementaciones no
        propaguen, pero el runner no delega en esa promesa. Perder una corrida
        entera porque falló el panel que la muestra sería el peor intercambio
        posible.
        """
        try:
            self._events.emit(event)
        except Exception:
            logger.debug("El sink de eventos falló; la corrida sigue", exc_info=True)

    def _emit(
        self,
        kind: EventKind,
        message: str,
        *,
        level: EventLevel = EventLevel.INFO,
        source: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        # Pasa por `emit_event` para heredar su protección.
        self.emit_event(
            RunEvent(
                occurred_at=datetime.now(UTC),
                level=level,
                kind=kind,
                source=source,
                message=message,
                duration_ms=duration_ms,
            )
        )

    # -- Por fuente ----------------------------------------------------------

    def _blocked(self, spec: FeedSpec, motivo: str) -> SourceRunResult:
        """Marca una fuente como no consultada por el control de salida."""
        ahora = datetime.now(UTC)
        return SourceRunResult(
            source=spec.name,
            status=SourceRunStatus.BLOCKED,
            started_at=ahora,
            finished_at=ahora,
            error=motivo[:500],
        )

    def _skipped(self, spec: FeedSpec, motivo: str) -> SourceRunResult:
        ahora = datetime.now(UTC)
        logger.info("feed %s salteado: %s", spec.name, motivo)
        self._emit(
            EventKind.SOURCE_SKIPPED,
            f"Salteado: {motivo}",
            level=EventLevel.WARN,
            source=spec.name,
        )
        return SourceRunResult(
            source=spec.name,
            status=SourceRunStatus.SKIPPED,
            started_at=ahora,
            finished_at=ahora,
            error=motivo,
        )

    def _run_one(self, spec: FeedSpec) -> tuple[SourceRunResult, int]:
        """Corre un feed. Nunca propaga: el run completo no puede caerse acá.

        Devuelve el resultado y cuántos registros con PII se cifraron.
        """
        inicio = datetime.now(UTC)
        cliente = None
        fetched = 0
        matched = 0
        persisted = 0
        error: str | None = None
        cursor_nuevo: datetime | None = None
        pii_guardados = 0

        self._emit(EventKind.SOURCE_START, "Consultando la fuente…", source=spec.name)

        try:
            adapter, cliente = build_adapter(spec, self._settings, self.emit_event)
            desde = self._repository.get_cursor(spec.name)
            hallazgos: list[Finding] = []
            # Se guarda el crudo junto al hallazgo solo para las fuentes que
            # declaran PII, y solo para mandarlo cifrado al vault más abajo.
            crudos_pii: list[tuple[str, dict[str, Any]]] = []

            for crudo in adapter.fetch(desde):
                fetched += 1

                item = adapter.normalize(crudo)
                if item is None:
                    continue

                # Incremental: el feed no filtra por fecha, filtramos acá.
                if desde is not None and item.discovered_at <= desde:
                    continue

                if cursor_nuevo is None or item.discovered_at > cursor_nuevo:
                    cursor_nuevo = item.discovered_at

                hallazgo = self._to_finding(item, spec)
                if hallazgo is None:
                    continue

                matched += 1
                hallazgos.append(hallazgo)
                if spec.requires_pii:
                    crudos_pii.append((hallazgo.dedup_hash, crudo.payload))

            persisted = self._repository.upsert_many(hallazgos)
            pii_guardados = self._store_pii(spec, crudos_pii)

            if cursor_nuevo is not None:
                self._repository.set_cursor(spec.name, cursor_nuevo)

            estado = SourceRunStatus.OK
            logger.info(
                "feed %s: %d traídos, %d relevantes AR, %d nuevos",
                spec.name,
                fetched,
                matched,
                persisted,
            )
            self._emit(
                EventKind.SOURCE_DONE,
                f"{fetched} traídos, {matched} relevantes AR, {persisted} nuevos",
                source=spec.name,
                duration_ms=int((datetime.now(UTC) - inicio).total_seconds() * 1000),
            )

        except Exception as exc:
            estado = SourceRunStatus.FAILED
            # Solo tipo y mensaje: el body de la respuesta podría traer PII.
            error = f"{type(exc).__name__}: {exc}"[:500]
            logger.warning("feed %s falló: %s", spec.name, error)
            self._emit(
                EventKind.SOURCE_FAILED,
                f"Falló: {error}",
                level=EventLevel.ERROR,
                source=spec.name,
            )

        finally:
            if cliente is not None:
                cliente.close()

        return (
            SourceRunResult(
                source=spec.name,
                status=estado,
                started_at=inicio,
                finished_at=datetime.now(UTC),
                items_fetched=fetched,
                items_matched=matched,
                items_persisted=persisted,
                error=error,
            ),
            pii_guardados,
        )

    def _store_pii(self, spec: FeedSpec, crudos: Sequence[tuple[str, dict[str, Any]]]) -> int:
        """Manda los payloads crudos al vault cifrado. Fail-closed.

        Tres condiciones y todas obligatorias: que el feed declare PII, que
        haya bóveda y que la bóveda esté habilitada (clave presente). Si falta
        alguna, la PII se descarta — nunca se degrada a guardarla en claro.
        """
        if not spec.requires_pii or not crudos:
            return 0
        if self._pii_vault is None or not self._pii_vault.enabled:
            logger.info(
                "feed %s: %d registros con PII descartados (STORE_PII desactivado)",
                spec.name,
                len(crudos),
            )
            return 0
        return sum(
            self._pii_vault.store(dedup_hash=h, source=spec.name, payload=p) for h, p in crudos
        )

    # -- Relevancia + privacidad --------------------------------------------

    def _to_finding(self, item: NormalizedItem, spec: FeedSpec) -> Finding | None:
        """Aplica relevancia AR y privacidad. `None` = no es hallazgo argentino."""
        veredicto = evaluate(item, self._watchlist, self._enabled_rules)
        if not veredicto.is_match:
            return None

        # El texto libre solo sobrevive si pasa el scrubber. En las fuentes de
        # superficie riesgosa (foros) no se persiste texto libre en absoluto.
        descripcion = None if spec.high_pii_surface else scrub_free_text(item.description)

        # El título de un thread de foro puede traer una muestra de los datos
        # robados. Se redacta en vez de descartarse: ver privacy/scrub.py.
        nombre = item.victim_name
        if spec.high_pii_surface:
            nombre = redact_pii(nombre) or nombre

        return Finding(
            **item.model_dump(exclude={"description", "victim_name"}),
            victim_name=nombre,
            description=descripcion,
            ar_match_reason=veredicto.reasons,
            ar_match_detail=veredicto.detail,
            severity=derive_severity(veredicto, item.leak_type),
            dedup_hash=compute_dedup_hash(
                source=item.source,
                victim_name=item.victim_name,
                victim_domain=item.victim_domain,
                actor=item.actor,
                discovered_at=item.discovered_at,
            ),
        )
