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

from leaks.adapters.registry import FeedDeps, FeedSpec, build_adapter, resolve_enabled
from leaks.adjacency.collector import AdjacencyCollector
from leaks.alerts.dispatcher import AlertDispatcher
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
from leaks.extraction.dating import resolve
from leaks.extraction.downloads import extract_download_links
from leaks.pipeline.egress_guard import EgressBlockedError, EgressDecision, EgressGuard
from leaks.privacy.scrub import redact_pii, scrub_free_text
from leaks.relevance.rules import evaluate
from leaks.relevance.severity import derive_severity
from leaks.relevance.watchlist import Watchlist
from leaks.sites.collector import SiteCatalogCollector
from leaks.storage.adjacency_repository import AdjacencyRepository
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
    #: Hallazgos avisados en esta corrida.
    alerts_sent: int = 0
    #: Ubicaciones nuevas en el catálogo de sitios.
    sites_new: int = 0
    #: Víctimas regionales nuevas de la sección de adyacencia.
    adjacency_new: int = 0

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
        alert_dispatcher: AlertDispatcher | None = None,
        site_collector: SiteCatalogCollector | None = None,
        adjacency_collector: AdjacencyCollector | None = None,
        adjacency_repo: AdjacencyRepository | None = None,
        cursor_sink: Callable[[dict[str, str]], None] | None = None,
        channel_error_sink: Callable[[dict[str, str]], None] | None = None,
        feed_deps: FeedDeps | None = None,
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
        self._alerts = alert_dispatcher
        self._sites = site_collector
        self._adjacency = adjacency_collector
        self._adjacency_repo = adjacency_repo
        # Cursores por canal (Telegram). Van aparte del cursor por fecha del
        # feed: acá el cursor es un id de post, no un `discovered_at`.
        self._cursor_sink = cursor_sink
        self._channel_error_sink = channel_error_sink
        # Colaboradores que el registro no puede construir solo (por ejemplo,
        # qué dominios le toca consultar a Hudson Rock en esta corrida).
        self._feed_deps = feed_deps or FeedDeps()

    def run(
        self,
        specs: Sequence[tuple[FeedSpec, str | None]] | None = None,
        deps: FeedDeps | None = None,
        only: Sequence[str] | None = None,
    ) -> RunReport:
        """Corre todos los feeds habilitados.

        `specs` acota qué fuentes corren y `deps` con qué insumos —por ejemplo
        un solo canal de Telegram—. Los dos son por invocación a propósito: el
        coordinador corre en otro hilo y mutar la configuración compartida para
        acotar una corrida se pisaría con la corrida diaria.

        `only` acota por nombre **después** de resolver el registro, así que un
        sondeo de una sola fuente sigue pasando por las mismas puertas que la
        corrida diaria: si el feed requiere PII y no está habilitada, se saltea
        igual. Acotar la corrida nunca puede ser una forma de saltear un gate.
        """
        pii_habilitado = (
            self._pii_sources_provider() if self._pii_sources_provider is not None else False
        )
        seleccion = (
            list(specs)
            if specs is not None
            else list(resolve_enabled(self._settings, pii_habilitado))
        )
        if only is not None:
            pedidos = set(only)
            seleccion = [par for par in seleccion if par[0].name in pedidos]

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
                resultado, guardados = self._run_one(spec, deps)
                reporte.pii_stored += guardados
            reporte.results.append(resultado)
            self._repository.record_run(resultado)

            # Si la salida dejó de estar permitida a mitad de la corrida, no se
            # sigue con las fuentes que faltan.
            if resultado.status is SourceRunStatus.BLOCKED:
                reporte.blocked_reason = resultado.error
                self._emit(
                    EventKind.EGRESS_BLOCKED,
                    "Corrida interrumpida: la IP de salida dejó de estar permitida",
                    level=EventLevel.ERROR,
                )
                break

        # El catálogo de sitios antes de alertar: una mudanza de dominio es
        # señal por sí sola y conviene tenerla registrada.
        reporte.sites_new = self._collect_sites()

        # La adyacencia después del catálogo y antes de alertar: recalcula
        # los perfiles de actor con lo que se acaba de traer.
        reporte.adjacency_new = self._collect_adjacency()

        # Alertas antes de la retención: avisar es lo urgente.
        reporte.alerts_sent = self._dispatch_alerts()

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

    # -- Adyacencia regional -----------------------------------------------------

    def _collect_adjacency(self) -> int:
        """Trae víctimas regionales y repuntúa los actores. Nunca lanza.

        Es enriquecimiento: si falla, la corrida argentina no se entera. Lo
        único que sí corta es el bloqueo de salida, y eso lo maneja el colector.
        """
        if self._adjacency is None:
            return 0
        try:
            resultado = self._adjacency.collect()
        except Exception as exc:
            logger.warning("La adyacencia falló: %s", type(exc).__name__)
            self._emit(
                EventKind.ADJACENCY,
                f"Adyacencia: falló ({type(exc).__name__})",
                level=EventLevel.WARN,
            )
            return 0

        detalle = (
            f"{resultado.victimas_totales} víctimas regionales "
            f"({resultado.victimas_nuevas} nuevas), {resultado.actores} actores: "
            f"{resultado.confirmados} ya golpearon AR, {resultado.candidatos} todavía no"
        )

        # Lo que amerita interrumpir a alguien no es un actor con score alto
        # —eso es una lista, no una novedad— sino uno que se MOVIÓ.
        self._avisar_saltos()
        if resultado.paises_fallidos:
            detalle += f" · sin respuesta: {', '.join(resultado.paises_fallidos[:5])}"
        self._emit(
            EventKind.ADJACENCY,
            detalle,
            level=EventLevel.WARN if resultado.paises_fallidos else EventLevel.INFO,
        )
        return resultado.victimas_nuevas

    def _avisar_saltos(self) -> None:
        """Avisa de los candidatos cuyo score pegó un salto. Nunca lanza.

        No se avisa por víctima regional: serían 1.353 avisos de cosas que no
        son nuestras. Se avisa por movimiento del perfil, que es la señal.
        """
        if self._adjacency_repo is None or self._alerts is None or not self._alerts.enabled:
            return
        try:
            saltos = self._adjacency_repo.pending_jumps(
                min_jump=self._settings.adjacency_alert_jump,
                min_score=self._settings.adjacency_alert_min_score,
            )
        except Exception as exc:  # pragma: no cover — defensivo
            logger.warning("No se pudieron leer los saltos: %s", type(exc).__name__)
            return
        if not saltos:
            return

        lineas = [
            f"• {p.actor}: {p.score:.0f} (antes {p.score_prev:.0f}, "
            f"{p.variacion:+.0f}) — {p.victims_total} víctimas en {len(p.countries)} países"
            for p in saltos[:10]
        ]
        aviso = (
            "📈 Actores regionales que subieron su probabilidad de apuntar a Argentina:\n"
            + "\n".join(lineas)
            + "\n\nTodavía NO golpearon Argentina. Ver la sección Adyacentes."
        )
        self._alerts.dispatch_notice(aviso)
        self._adjacency_repo.mark_alerted([p.actor for p in saltos])
        self._emit(
            EventKind.ADJACENCY,
            f"Aviso enviado: {len(saltos)} actores saltaron de score",
            level=EventLevel.WARN,
        )

    # -- Catálogo de sitios ------------------------------------------------------

    def _collect_sites(self) -> int:
        """Consolida dónde vive cada sitio de leaks. Nunca lanza."""
        if self._sites is None:
            return 0
        try:
            resultado, fallidos = self._sites.collect()
        except Exception as exc:
            logger.warning("El catálogo de sitios falló: %s", type(exc).__name__)
            self._emit(
                EventKind.SITE_CATALOG,
                f"Catálogo de sitios: falló ({type(exc).__name__})",
                level=EventLevel.WARN,
            )
            return 0

        # Lo que amerita interrumpir a alguien: un grupo que ya golpeó a una
        # entidad argentina estrenando dirección.
        if resultado.moved_ar:
            aviso = "🔀 Grupos con impacto argentino que estrenaron dirección:\n" + "\n".join(
                resultado.moved_ar[:10]
            )
            self._emit(
                EventKind.SITE_CATALOG,
                f"Mudanza de grupo con hallazgos AR: {', '.join(resultado.moved_ar[:3])}",
                level=EventLevel.WARN,
            )
            if self._alerts is not None and self._alerts.enabled:
                self._alerts.dispatch_notice(aviso)

        detalle = f"{resultado.seen} ubicaciones, {resultado.new} nuevas"
        if resultado.moved:
            # Lo interesante: un grupo conocido estrenando dominio.
            detalle += f" — mudanzas: {', '.join(resultado.moved[:3])}"
            if len(resultado.moved) > 3:
                detalle += f" y {len(resultado.moved) - 3} más"
        if fallidos:
            detalle += f" (registros caídos: {', '.join(fallidos)})"

        self._emit(
            EventKind.SITE_CATALOG,
            f"Catálogo de sitios: {detalle}",
            level=EventLevel.WARN if fallidos else EventLevel.INFO,
        )
        return resultado.new

    # -- Alertas ---------------------------------------------------------------

    def _dispatch_alerts(self) -> int:
        """Avisa de los hallazgos pendientes que llegan al umbral.

        Nunca lanza: quedarse sin alertar es malo, pero perder la corrida
        entera por un webhook caído es peor. Lo que no se pudo avisar queda
        pendiente para la próxima.
        """
        if self._alerts is None or not self._alerts.enabled:
            return 0

        pendientes = self._repository.list_pending_alerts(
            min_severity=self._settings.alert_min_severity,
            limit=self._settings.alert_max_per_run,
            max_age_days=self._settings.alert_max_age_days,
        )
        if not pendientes:
            return 0

        # Ensayo: se dice qué se habría mandado y no sale nada. Ni se marca,
        # así que los hallazgos siguen pendientes para cuando haya un canal de
        # verdad. Probar el cableado no puede costar alertas reales.
        if self._settings.alert_dry_run:
            victimas = ", ".join(f.victim_name[:40] for f in pendientes[:5])
            self._emit(
                EventKind.ALERT,
                (
                    f"ENSAYO: se habría avisado de {len(pendientes)} hallazgos "
                    f"por {', '.join(self._alerts.channel_names)} ({victimas}"
                    f"{'…' if len(pendientes) > 5 else ''}). "
                    "No se envió nada y siguen pendientes."
                ),
                level=EventLevel.WARN,
            )
            return 0

        resultado = self._alerts.dispatch(pendientes)

        if not resultado.delivered:
            self._emit(
                EventKind.ALERT,
                (
                    f"No se pudo avisar de {len(pendientes)} hallazgos "
                    f"(canales caídos: {', '.join(resultado.channels_failed) or 'ninguno'}). "
                    "Quedan pendientes para la próxima corrida."
                ),
                level=EventLevel.WARN,
            )
            return 0

        # Solo se marca lo que efectivamente salió por algún canal.
        self._repository.mark_alerted([f.dedup_hash for f in pendientes])
        self._emit(
            EventKind.ALERT,
            (
                f"Alerta enviada por {len(pendientes)} hallazgos "
                f"(≥ {self._settings.alert_min_severity}) "
                f"vía {', '.join(resultado.channels_ok)}"
            ),
        )
        return len(pendientes)

    # -- Bitácora ------------------------------------------------------------

    def _assert_egress_allowed(self) -> None:
        """Barrera previa a CADA request. Lanza si la salida no está permitida.

        El chequeo al arrancar la corrida no alcanza: la IP de salida puede
        cambiar en el medio (una VPN que se reconecta o se cae), y sin esto
        todo lo que falte de esa corrida saldría por la IP nueva. Se pasa al
        cliente HTTP, así que ninguna consulta a un feed puede salir sin una
        lectura fresca que la autorice.
        """
        if self._egress_guard is None:
            return
        decision = self._egress_guard.evaluate()
        if not decision.allowed:
            raise EgressBlockedError(decision.reason)

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

    def _run_one(self, spec: FeedSpec, deps: FeedDeps | None = None) -> tuple[SourceRunResult, int]:
        """Corre un feed. Nunca propaga: el run completo no puede caerse acá.

        `deps` permite acotar la corrida —por ejemplo a un solo canal de
        Telegram— sin tocar la configuración compartida del runner, que corre
        en otro hilo cuando la dispara el coordinador.

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
            adapter, cliente = build_adapter(
                spec,
                self._settings,
                self.emit_event,
                self._assert_egress_allowed,
                deps or self._feed_deps,
            )
            desde = self._repository.get_cursor(spec.name)
            # Sin cursor previo, esta corrida es la importación inicial de la
            # fuente: entra su histórico entero de golpe. Son hallazgos que
            # recién conocemos, no novedades — y sin esta marca dispararían una
            # alerta cada uno.
            es_importacion_inicial = desde is None
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

                hallazgo = self._to_finding(item, spec, backfill=es_importacion_inicial)
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

            # Algunos adapters llevan su propio cursor —Telegram usa el id del
            # último post por canal— porque filtrar por fecha no alcanza: un
            # canal puede republicar y la página siempre trae los últimos 20.
            propios = getattr(adapter, "nuevos_cursores", None)
            if propios and self._cursor_sink is not None:
                self._cursor_sink(dict(propios))

            # Y por qué un canal no aportó nada: muerto, privado o sin novedades
            # son tres cosas distintas y la UI tiene que poder distinguirlas.
            fallos = getattr(adapter, "errores", None)
            if fallos and self._channel_error_sink is not None:
                self._channel_error_sink(dict(fallos))

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

        except EgressBlockedError as exc:
            # No es una falla del feed: es el control de OPSEC cortando.
            estado = SourceRunStatus.BLOCKED
            error = str(exc)[:500]
            logger.error("feed %s abortado por el control de salida: %s", spec.name, error)
            self._emit(
                EventKind.EGRESS_BLOCKED,
                f"{spec.name}: consulta abortada — {error}",
                level=EventLevel.ERROR,
                source=spec.name,
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

    def _to_finding(
        self, item: NormalizedItem, spec: FeedSpec, *, backfill: bool = False
    ) -> Finding | None:
        """Aplica relevancia AR, privacidad y fechado. `None` = no es argentino."""
        veredicto = evaluate(item, self._watchlist, self._enabled_rules)
        if not veredicto.is_match:
            return None

        # El texto libre solo sobrevive si pasa el scrubber. En las fuentes de
        # superficie riesgosa (foros) no se persiste texto libre en absoluto.
        descripcion = None if spec.high_pii_surface else scrub_free_text(item.description)

        # Los enlaces se extraen del texto CRUDO, antes de que el scrubber lo
        # descarte: en las fuentes de foro el cuerpo es justamente donde el
        # publicador pega el magnet y la muestra. Se guarda la referencia, no
        # el contenido.
        # Se combinan los que ya trajo el adapter (que vio el HTML crudo) con
        # los que aparezcan en el texto normalizado.
        enlaces = tuple(
            {
                link.url: link
                for link in (
                    *item.download_links,
                    *extract_download_links(item.description),
                )
            }.values()
        )

        # El título de un thread de foro puede traer una muestra de los datos
        # robados. Se redacta en vez de descartarse: ver privacy/scrub.py.
        nombre = item.victim_name
        if spec.high_pii_surface:
            nombre = redact_pii(nombre) or nombre

        # Cuándo OCURRIÓ, que no es cuándo lo vimos. El adapter puede haberlo
        # resuelto ya; si no, se intenta con el año del título y con lo que
        # haya aportado otra fuente para el mismo dominio. Si no hay nada, el
        # hallazgo queda sin fecha y se dice — no se inventa.
        corroborada = (
            self._repository.earliest_occurrence(item.victim_domain) if item.victim_domain else None
        )
        ocurrido, base = resolve(
            feed_date=item.occurred_at or item.discovered_at,
            texts=(item.victim_name, item.description),
            corroborated=corroborada,
        )

        return Finding(
            **item.model_dump(
                exclude={"description", "victim_name", "download_links", "occurred_at"}
            ),
            victim_name=nombre,
            description=descripcion,
            download_links=enlaces,
            occurred_at=ocurrido,
            occurred_at_basis=base,
            backfill=backfill,
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
