"""Tests del control de IP de salida (OPSEC).

La promesa es fuerte y conviene testearla como tal: **si la salida es desde un
país bloqueado, no se consulta ninguna fuente**. No "se avisa", no "se
registra": no se hace el request.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import respx

from leaks.adapters.egress import EgressInfo, EgressResolver
from leaks.adapters.http import FeedHttpClient
from leaks.config import Settings
from leaks.domain.models import EventKind, SourceRunStatus
from leaks.pipeline.egress_guard import EgressGuard
from leaks.pipeline.runner import PipelineRunner
from leaks.relevance.watchlist import Watchlist
from leaks.storage.repository import SqlAlchemyFindingRepository
from tests.test_pipeline import FakeAdapter, payload_ar, spec_for


class ResolverFalso:
    """Doble del resolver: devuelve la IP que le digamos."""

    def __init__(self, info: EgressInfo | None) -> None:
        self._info = info
        self.llamadas = 0

    def resolve(self, *, force: bool = False) -> EgressInfo | None:
        self.llamadas += 1
        return self._info


def info(country: str | None, ip: str = "1.2.3.4") -> EgressInfo:
    return EgressInfo(ip=ip, country=country, org="ISP", checked_at=datetime.now(UTC))


class TestGuard:
    def test_pais_bloqueado_no_permite(self) -> None:
        decision = EgressGuard(ResolverFalso(info("AR"))).evaluate()  # type: ignore[arg-type]
        assert decision.allowed is False
        assert "AR" in decision.reason

    def test_pais_permitido_permite(self) -> None:
        decision = EgressGuard(ResolverFalso(info("CL"))).evaluate()  # type: ignore[arg-type]
        assert decision.allowed is True

    def test_es_case_insensitive(self) -> None:
        """El ISO-2 llega como venga del proveedor."""
        decision = EgressGuard(ResolverFalso(info("ar"))).evaluate()  # type: ignore[arg-type]
        assert decision.allowed is False

    def test_pais_desconocido_bloquea_por_defecto(self) -> None:
        """Fail-closed: sin país no hay garantía de no estar saliendo por AR."""
        decision = EgressGuard(ResolverFalso(info(None))).evaluate()  # type: ignore[arg-type]
        assert decision.allowed is False

    def test_sin_respuesta_del_proveedor_bloquea(self) -> None:
        decision = EgressGuard(ResolverFalso(None)).evaluate()  # type: ignore[arg-type]
        assert decision.allowed is False

    def test_resolver_que_explota_bloquea(self) -> None:
        class ResolverRoto:
            def resolve(self, *, force: bool = False) -> EgressInfo | None:
                raise RuntimeError("sin red")

        decision = EgressGuard(ResolverRoto()).evaluate()  # type: ignore[arg-type]
        assert decision.allowed is False

    def test_se_puede_permitir_lo_desconocido_por_configuracion(self) -> None:
        """Decisión del operador por entorno, nunca desde la UI."""
        guard = EgressGuard(ResolverFalso(info(None)), block_on_unknown=False)  # type: ignore[arg-type]
        assert guard.evaluate().allowed is True

    def test_sin_verificacion_configurada_bloquea(self) -> None:
        """Apagar el chequeo no debe ser una puerta trasera para saltar el control."""
        assert EgressGuard(None).evaluate().allowed is False


class TestRunnerBloqueado:
    """Lo que de verdad importa: no se hace el request."""

    def _runner(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        pais: str | None,
    ) -> PipelineRunner:
        return PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=settings,
            egress_guard=EgressGuard(ResolverFalso(info(pais) if pais else None)),  # type: ignore[arg-type]
        )

    def test_no_se_consulta_ninguna_fuente(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        adapter = FakeAdapter([payload_ar()])
        runner = self._runner(repository, watchlist, settings, "AR")

        reporte = runner.run([(spec_for(adapter), None)])

        # La prueba de fondo: el adapter nunca fue invocado.
        assert adapter.fetch_calls == 0
        assert reporte.blocked is True
        assert reporte.ok is False
        assert repository.count() == 0

    def test_todas_las_fuentes_quedan_marcadas_bloqueadas(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """Que no se pueda confundir con "no hubo novedades"."""
        runner = self._runner(repository, watchlist, settings, "AR")
        reporte = runner.run([(spec_for(FakeAdapter([])), None), (spec_for(FakeAdapter([])), None)])

        assert all(r.status is SourceRunStatus.BLOCKED for r in reporte.results)
        assert all("BLOQUEADO" in (r.error or "") for r in reporte.results)

    def test_queda_registrado_en_la_bitacora(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        from leaks.domain.models import RunEvent

        capturados: list[RunEvent] = []

        class Sink:
            def emit(self, event: RunEvent) -> None:
                capturados.append(event)

        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=settings,
            event_sink=Sink(),
            egress_guard=EgressGuard(ResolverFalso(info("AR"))),  # type: ignore[arg-type]
        )
        runner.run([(spec_for(FakeAdapter([])), None)])

        bloqueo = next(e for e in capturados if e.kind is EventKind.EGRESS_BLOCKED)
        assert bloqueo.level.value == "error"

    def test_ip_desconocida_tambien_bloquea_el_fetch(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        adapter = FakeAdapter([payload_ar()])
        runner = self._runner(repository, watchlist, settings, None)

        runner.run([(spec_for(adapter), None)])
        assert adapter.fetch_calls == 0

    def test_salida_permitida_deja_correr(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        adapter = FakeAdapter([payload_ar()])
        runner = self._runner(repository, watchlist, settings, "CL")

        reporte = runner.run([(spec_for(adapter), None)])

        assert adapter.fetch_calls == 1
        assert reporte.blocked is False
        assert reporte.total_new == 1


class TestResolver:
    @respx.mock
    def test_usa_el_primer_proveedor_que_responde(self) -> None:
        respx.get("https://proveedor-a.test").mock(return_value=httpx.Response(500))
        respx.get("https://proveedor-b.test").mock(
            return_value=httpx.Response(200, json={"ip": "9.9.9.9", "country": "CL"})
        )

        resolver = EgressResolver(
            FeedHttpClient(
                user_agent="test", max_retries=0, rate_limit_delay=0, sleep=lambda _s: None
            ),
            providers=("https://proveedor-a.test", "https://proveedor-b.test"),
        )
        resultado = resolver.resolve()

        assert resultado is not None
        assert resultado.ip == "9.9.9.9"
        assert resultado.country == "CL"

    @respx.mock
    def test_si_ninguno_responde_devuelve_none(self) -> None:
        respx.get("https://proveedor-a.test").mock(return_value=httpx.Response(500))
        resolver = EgressResolver(
            FeedHttpClient(
                user_agent="test", max_retries=0, rate_limit_delay=0, sleep=lambda _s: None
            ),
            providers=("https://proveedor-a.test",),
        )
        assert resolver.resolve() is None

    @respx.mock
    def test_cachea_el_resultado(self) -> None:
        """El badge se refresca seguido; estos servicios rate-limitean rápido."""
        ruta = respx.get("https://proveedor-a.test").mock(
            return_value=httpx.Response(200, json={"ip": "9.9.9.9", "country": "CL"})
        )
        resolver = EgressResolver(
            FeedHttpClient(
                user_agent="test", max_retries=0, rate_limit_delay=0, sleep=lambda _s: None
            ),
            providers=("https://proveedor-a.test",),
            cache_ttl_seconds=300,
        )
        resolver.resolve()
        resolver.resolve()
        assert ruta.call_count == 1

        # `force` sí vuelve a consultar.
        resolver.resolve(force=True)
        assert ruta.call_count == 2


class TestListasPorEntorno:
    """Regresión: las listas por variable de entorno rompían el arranque.

    pydantic-settings intenta parsear los campos de tipo tupla como JSON antes
    de que corra el validador CSV, así que `LEAKS_EGRESS_BLOCKED_COUNTRIES=AR`
    tiraba un JSONDecodeError y el contenedor entraba en crash-loop. Solo se
    veía al desplegar, no en los tests: por eso este test existe.
    """

    def test_valor_simple_sin_comas(self) -> None:
        import os

        os.environ["LEAKS_EGRESS_BLOCKED_COUNTRIES"] = "AR"
        try:
            assert Settings(_env_file=None).egress_blocked_countries == ("AR",)
        finally:
            del os.environ["LEAKS_EGRESS_BLOCKED_COUNTRIES"]

    def test_lista_separada_por_comas(self) -> None:
        import os

        os.environ["LEAKS_ENABLED_FEEDS"] = "ransomware.live, ransomlook"
        try:
            assert Settings(_env_file=None).enabled_feeds == ("ransomware.live", "ransomlook")
        finally:
            del os.environ["LEAKS_ENABLED_FEEDS"]

    def test_urls_con_barras_y_dos_puntos(self) -> None:
        """Las URLs tampoco son JSON válido."""
        import os

        os.environ["LEAKS_DARKFORUMS_BASE_URLS"] = "https://a.test,https://b.test"
        try:
            assert Settings(_env_file=None).darkforums_base_urls == (
                "https://a.test",
                "https://b.test",
            )
        finally:
            del os.environ["LEAKS_DARKFORUMS_BASE_URLS"]
