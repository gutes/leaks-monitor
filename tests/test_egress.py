"""Tests del control de IP de salida (OPSEC).

La promesa es fuerte y conviene testearla como tal: **si la salida es desde un
país bloqueado, no se consulta ninguna fuente**. No "se avisa", no "se
registra": no se hace el request.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx

from leaks.adapters.egress import EgressInfo, EgressResolver
from leaks.adapters.http import FeedHttpClient
from leaks.config import Settings
from leaks.domain.models import EventKind, SourceRunStatus
from leaks.pipeline.egress_guard import EgressBlockedError, EgressGuard
from leaks.pipeline.runner import PipelineRunner
from leaks.relevance.watchlist import Watchlist
from leaks.storage.repository import SqlAlchemyFindingRepository
from tests.test_pipeline import FakeAdapter, payload_ar, spec_for


class ResolverFalso:
    """Doble del resolver: devuelve la IP que le digamos."""

    def __init__(self, info: EgressInfo | None) -> None:
        self._info = info
        self.llamadas = 0

    def resolve(
        self, *, force: bool = False, max_age_seconds: float | None = None
    ) -> EgressInfo | None:
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
            def resolve(
                self, *, force: bool = False, max_age_seconds: float | None = None
            ) -> EgressInfo | None:
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


class TestElBloqueoNoPuedeFallar:
    """El control tiene que aguantar configuración hostil y cache rancio.

    Cada test de acá corresponde a un agujero concreto que existía y se cerró.
    """

    def test_argentina_no_se_puede_sacar_de_la_lista(self) -> None:
        """Agujero: vaciar la lista por entorno desactivaba el control entero."""
        guard = EgressGuard(ResolverFalso(info("AR")), blocked_countries=())  # type: ignore[arg-type]
        assert guard.evaluate().allowed is False

    def test_configurar_otro_pais_no_desbloquea_argentina(self) -> None:
        """La configuración solo puede AGREGAR países, nunca sacar AR."""
        guard = EgressGuard(ResolverFalso(info("AR")), blocked_countries=("BR",))  # type: ignore[arg-type]
        assert guard.evaluate().allowed is False

    def test_se_pueden_sumar_paises(self) -> None:
        guard = EgressGuard(ResolverFalso(info("BR")), blocked_countries=("BR",))  # type: ignore[arg-type]
        assert guard.evaluate().allowed is False

    def test_no_confia_en_una_lectura_vieja(self) -> None:
        """Agujero: con el cache de 5 min, una VPN caída pasaba desapercibida.

        Si la lectura es más vieja que `max_age`, hay que volver a preguntar.
        """
        vistos: list[float | None] = []

        class ResolverQueRegistra:
            def resolve(
                self, *, force: bool = False, max_age_seconds: float | None = None
            ) -> EgressInfo | None:
                vistos.append(max_age_seconds)
                return info("CL")

        EgressGuard(ResolverQueRegistra(), max_age_seconds=30).evaluate()  # type: ignore[arg-type]

        assert vistos == [30], "el guard tiene que exigir frescura, no aceptar el cache general"

    def test_el_boton_reintentar_fuerza_la_consulta(self) -> None:
        forzados: list[bool] = []

        class ResolverQueRegistra:
            def resolve(
                self, *, force: bool = False, max_age_seconds: float | None = None
            ) -> EgressInfo | None:
                forzados.append(force)
                return info("AR")

        guard = EgressGuard(ResolverQueRegistra())  # type: ignore[arg-type]
        guard.evaluate(force=True)

        assert forzados == [True]

    def test_reintentar_no_es_un_override(self) -> None:
        """Forzar vuelve a preguntar; si sigue saliendo por AR, sigue bloqueado."""
        guard = EgressGuard(ResolverFalso(info("AR")))  # type: ignore[arg-type]
        assert guard.evaluate(force=True).allowed is False


class TestVpnQueSeCaeAMitadDeLaCorrida:
    """Regresión de una falla observada en vivo.

    Con el chequeo únicamente al arrancar, una corrida que empezaba con la VPN
    conectada seguía consultando feeds después de que la salida pasara a ser
    argentina. Se vio de verdad: el pipeline trajo 398 items mientras la IP de
    salida ya era de AR.

    Ahora la verificación va **antes de cada request HTTP**, así que la
    exposición se corta en el instante en que la salida deja de estar
    permitida.
    """

    class ResolverQueCambia:
        """Devuelve CL las primeras `n` veces y AR a partir de ahí."""

        def __init__(self, permitidas: int) -> None:
            self._restantes = permitidas
            self.consultas = 0

        def resolve(
            self, *, force: bool = False, max_age_seconds: float | None = None
        ) -> EgressInfo:
            self.consultas += 1
            if self._restantes > 0:
                self._restantes -= 1
                return info("CL")
            return info("AR")

    @respx.mock
    def test_el_cliente_http_corta_al_cambiar_la_salida(self) -> None:
        resolver = self.ResolverQueCambia(permitidas=1)
        guard = EgressGuard(resolver)  # type: ignore[arg-type]

        ruta = respx.get("https://feed.test/api").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )

        def barrera() -> None:
            decision = guard.evaluate()
            if not decision.allowed:
                raise EgressBlockedError(decision.reason)

        cliente = FeedHttpClient(
            user_agent="test",
            max_retries=0,
            rate_limit_delay=0,
            sleep=lambda _s: None,
            before_request=barrera,
        )

        # El primer request pasa: la salida todavía es CL.
        cliente.get_json("https://feed.test/api")
        assert ruta.call_count == 1

        # La VPN se cayó: el segundo no debe salir.
        with pytest.raises(EgressBlockedError):
            cliente.get_json("https://feed.test/api")
        assert ruta.call_count == 1, "no puede haber salido un segundo request"

    def test_sin_barrera_el_cliente_funciona_igual(self) -> None:
        """La barrera es opcional: los tests de adapters no la necesitan."""
        cliente = FeedHttpClient(user_agent="test", sleep=lambda _s: None)
        assert cliente._before_request is None


class TestElRunnerCableaLaBarrera:
    """El runner tiene que PASARLE la barrera al cliente HTTP.

    Regresión de un agujero real: el mecanismo existía (`before_request` en el
    cliente, parámetro en `build_adapter`) y había un test que lo ejercitaba…
    armando la barrera a mano. El runner nunca la conectaba, así que una VPN
    que se caía a mitad de corrida no se detectaba. El test daba confianza
    falsa: probaba la pieza, no el cableado.
    """

    def _spec_que_captura_el_cliente(self, capturado: dict[str, object]) -> object:
        from leaks.adapters.registry import FeedSpec
        from leaks.domain.models import LeakType

        def factory(_settings: object, client: object, _deps: object) -> object:
            capturado["cliente"] = client
            return FakeAdapter([payload_ar()])

        return FeedSpec(name="fake-feed", leak_type=LeakType.RANSOMWARE, factory=factory)  # type: ignore[arg-type]

    def test_el_cliente_recibe_la_barrera(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        capturado: dict[str, object] = {}
        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=settings,
            egress_guard=EgressGuard(ResolverFalso(info("CL"))),  # type: ignore[arg-type]
        )
        runner.run([(self._spec_que_captura_el_cliente(capturado), None)])  # type: ignore[list-item]

        cliente = capturado.get("cliente")
        assert cliente is not None, "el runner tiene que construir un cliente"
        assert cliente._before_request is not None, (  # type: ignore[attr-defined]
            "el runner tiene que pasarle la barrera de IP de salida al cliente"
        )

    def test_la_barrera_del_runner_lanza_si_la_salida_se_bloquea(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """La barrera que se le pasa al cliente tiene que cortar de verdad."""
        capturado: dict[str, object] = {}
        resolver = ResolverFalso(info("CL"))
        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=settings,
            egress_guard=EgressGuard(resolver),  # type: ignore[arg-type]
        )
        runner.run([(self._spec_que_captura_el_cliente(capturado), None)])

        cliente = capturado["cliente"]
        # La VPN se cae después de que arrancó la corrida.
        resolver._info = info("AR")  # type: ignore[attr-defined]

        with pytest.raises(EgressBlockedError):
            cliente._before_request()  # type: ignore[attr-defined]

    def test_un_bloqueo_a_mitad_corta_las_fuentes_que_faltan(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """La segunda fuente no se consulta si la primera se abortó."""

        class AdapterQueSeBloquea(FakeAdapter):
            def fetch(self, since: object) -> object:
                raise EgressBlockedError("BLOQUEADO: la VPN se cayó")

        segunda = FakeAdapter([payload_ar()])
        segunda.name = "segunda-fuente"

        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=settings,
            egress_guard=EgressGuard(ResolverFalso(info("CL"))),  # type: ignore[arg-type]
        )
        reporte = runner.run(
            [
                (spec_for(AdapterQueSeBloquea([])), None),
                (spec_for(segunda), None),
            ]
        )

        assert reporte.blocked is True
        assert segunda.fetch_calls == 0, "la fuente siguiente no puede consultarse"
        assert reporte.results[0].status is SourceRunStatus.BLOCKED
        # Se corta: la segunda ni siquiera figura como salteada.
        assert len(reporte.results) == 1
