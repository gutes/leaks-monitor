"""Tests del runner: las garantías que el prototipo promete.

Una por una, con un doble de feed en vez de la red:

1. **Aislamiento** — un feed que explota no tumba el run.
2. **Idempotencia** — re-correr no duplica.
3. **Incremental** — la segunda corrida solo procesa lo nuevo.
4. **Privacidad** — sin `STORE_PII` no se escribe PII, ni siquiera si el feed
   la manda inline.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session, sessionmaker

from leaks.adapters.registry import FeedSpec
from leaks.config import Settings
from leaks.domain.models import (
    LeakType,
    NormalizedItem,
    RawItem,
    SourceRunResult,
    SourceRunStatus,
)
from leaks.pipeline.runner import PipelineRunner
from leaks.relevance.watchlist import Watchlist
from leaks.storage.crypto import PiiCipher
from leaks.storage.pii_vault import PiiVault
from leaks.storage.queries import FindingQueryService
from leaks.storage.repository import SqlAlchemyFindingRepository


class FakeAdapter:
    """Doble de feed: devuelve lo que se le dé, o explota si se le pide."""

    name = "fake-feed"
    leak_type = LeakType.RANSOMWARE

    def __init__(self, payloads: list[dict[str, object]], *, explota: bool = False) -> None:
        self._payloads = payloads
        self._explota = explota
        self.fetch_calls = 0
        self.ultimo_since: datetime | None = None

    def fetch(self, since: datetime | None) -> Iterable[RawItem]:
        self.fetch_calls += 1
        self.ultimo_since = since
        if self._explota:
            raise RuntimeError("el feed se cayó")
        for p in self._payloads:
            yield RawItem(source=self.name, payload=p)

    def normalize(self, item: RawItem) -> NormalizedItem | None:
        p = item.payload
        return NormalizedItem(
            source=self.name,
            leak_type=self.leak_type,
            victim_name=str(p["victim"]),
            victim_domain=p.get("domain"),  # type: ignore[arg-type]
            country=p.get("country"),  # type: ignore[arg-type]
            actor=str(p.get("group", "TestGroup")),
            discovered_at=p["discovered"],  # type: ignore[arg-type]
            description=p.get("description"),  # type: ignore[arg-type]
        )


def spec_for(adapter: FakeAdapter, *, requires_pii: bool = False) -> FeedSpec:
    """`FeedSpec` que devuelve siempre el mismo doble ya construido."""
    return FeedSpec(
        name=adapter.name,
        leak_type=adapter.leak_type,
        factory=lambda _s, _c, _d: adapter,
        requires_pii=requires_pii,
    )


def payload_ar(
    victim: str = "Ministerio X",
    domain: str | None = "x.gob.ar",
    *,
    discovered: datetime | None = None,
    **extra: object,
) -> dict[str, object]:
    return {
        "victim": victim,
        "domain": domain,
        "country": "AR",
        "discovered": discovered or datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
        **extra,
    }


class TestAislamiento:
    """Un feed caído no puede tumbar la corrida."""

    def test_un_feed_que_explota_no_frena_a_los_demas(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        roto = FakeAdapter([], explota=True)
        sano = FakeAdapter([payload_ar()])
        sano.name = "feed-sano"

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        reporte = runner.run([(spec_for(roto), None), (spec_for(sano), None)])

        estados = {r.source: r.status for r in reporte.results}
        assert estados["fake-feed"] is SourceRunStatus.FAILED
        assert estados["feed-sano"] is SourceRunStatus.OK
        # El sano persistió igual: el error del otro no lo afectó.
        assert reporte.total_new == 1
        assert reporte.ok

    def test_el_error_queda_registrado_sin_volcar_el_body(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        reporte = runner.run([(spec_for(FakeAdapter([], explota=True)), None)])

        (resultado,) = reporte.results
        assert resultado.error is not None
        assert "RuntimeError" in resultado.error
        assert len(resultado.error) <= 500
        assert reporte.failed_sources == ["fake-feed"]

    def test_feed_salteado_queda_visible(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """Un feed que no corrió tiene que verse, no desaparecer."""
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        reporte = runner.run([(spec_for(FakeAdapter([])), "requiere STORE_PII=true")])

        (resultado,) = reporte.results
        assert resultado.status is SourceRunStatus.SKIPPED
        assert resultado.error == "requiere STORE_PII=true"


class TestCorridaAcotada:
    """`only` acota la corrida, pero no puede saltear ninguna puerta."""

    def test_corre_solo_las_fuentes_pedidas(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """El sondeo no puede arrastrar al resto: es un feed, un request."""
        pedido = FakeAdapter([payload_ar()])
        pedido.name = "efimero"
        otro = FakeAdapter([payload_ar()])
        otro.name = "diario"

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        reporte = runner.run([(spec_for(pedido), None), (spec_for(otro), None)], only=["efimero"])

        assert [r.source for r in reporte.results] == ["efimero"]
        assert pedido.fetch_calls == 1
        assert otro.fetch_calls == 0

    def test_un_sondeo_no_puede_saltear_el_gate_de_pii(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """Acotar por nombre pasa DESPUÉS de resolver el registro.

        Si `only` construyera la selección por su cuenta, sondear una fuente
        `requires_pii` sería la forma de correrla con la PII deshabilitada.
        """
        sin_pii = settings.model_copy(update={"store_pii": False})
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=sin_pii)

        reporte = runner.run(only=["darkforums"])

        (resultado,) = reporte.results
        assert resultado.status is SourceRunStatus.SKIPPED
        assert "PII" in (resultado.error or "")

    def test_un_nombre_que_no_existe_no_corre_nada(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        assert runner.run(only=["no-existe"]).results == []


class TestHuecoDeCobertura:
    """La ventana de un foro es finita: lo que se cae de ella hay que declararlo."""

    def _spec_acotada(self, adapter: FakeAdapter) -> FeedSpec:
        base = spec_for(adapter)
        return replace(base, bounded_window=True)

    def test_declara_el_hueco_cuando_la_ventana_se_corrio(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """El caso real: el pipeline estuvo caído y el foro siguió publicando."""
        cursor = datetime(2026, 8, 25, 18, 0, tzinfo=UTC)
        repository.set_cursor("fake-feed", cursor)
        # Lo más viejo que sigue en la ventana es de una semana después.
        reciente = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
        adapter = FakeAdapter([payload_ar(discovered=reciente)])

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        reporte = runner.run([(self._spec_acotada(adapter), None)])

        (resultado,) = reporte.results
        assert resultado.has_gap
        assert resultado.gap_from == cursor
        assert resultado.gap_to == reciente

    def test_sin_hueco_cuando_la_ventana_solapa(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """Si la ventana todavía alcanza el cursor, no se perdió nada."""
        cursor = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
        repository.set_cursor("fake-feed", cursor)
        adapter = FakeAdapter(
            [
                payload_ar(discovered=datetime(2026, 9, 1, 10, 0, tzinfo=UTC)),
                payload_ar(domain="y.gob.ar", discovered=datetime(2026, 9, 1, 14, 0, tzinfo=UTC)),
            ]
        )

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        reporte = runner.run([(self._spec_acotada(adapter), None)])

        assert not reporte.results[0].has_gap

    def test_la_primera_corrida_no_es_un_hueco(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """Sin cursor previo no hay nada que comparar: es la importación inicial."""
        adapter = FakeAdapter([payload_ar(discovered=datetime(2026, 9, 1, 12, 0, tzinfo=UTC))])

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        reporte = runner.run([(self._spec_acotada(adapter), None)])

        assert not reporte.results[0].has_gap

    def test_una_fuente_de_ventana_abierta_nunca_reporta_hueco(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """En un feed que ya filtra por cursor, el hueco sería un falso positivo
        en cada corrida: lo más viejo siempre es posterior por construcción."""
        repository.set_cursor("fake-feed", datetime(2026, 8, 25, 18, 0, tzinfo=UTC))
        adapter = FakeAdapter([payload_ar(discovered=datetime(2026, 9, 1, 12, 0, tzinfo=UTC))])

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        # `spec_for` deja `bounded_window=False`, que es el default.
        reporte = runner.run([(spec_for(adapter), None)])

        assert not reporte.results[0].has_gap

    def test_el_hueco_queda_en_la_telemetria(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """Tiene que sobrevivir a la corrida: es lo que lee la pantalla Fuentes."""
        cursor = datetime(2026, 8, 25, 18, 0, tzinfo=UTC)
        repository.set_cursor("fake-feed", cursor)
        adapter = FakeAdapter([payload_ar(discovered=datetime(2026, 9, 1, 12, 0, tzinfo=UTC))])

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        runner.run([(self._spec_acotada(adapter), None)])

        queries = FindingQueryService(repository._session_factory)
        (fila,) = queries.latest_runs()
        assert fila["gap_from"] == cursor
        assert fila["gap_to"] is not None


class TestWatchdogEnLaCorrida:
    """Avisar de lo que NO llegó, no solo de lo que llegó."""

    def _runner(self, repository, watchlist, settings, alerts=None):  # type: ignore[no-untyped-def]
        return PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=settings,
            alert_dispatcher=alerts,
        )

    def test_reporta_la_fuente_que_lleva_dias_callada(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        # Una corrida buena vieja: el tablero la mostraría en verde.
        vieja = datetime(2026, 8, 25, 18, 0, tzinfo=UTC)
        repository.record_run(
            SourceRunResult(
                source="fake-feed",
                status=SourceRunStatus.OK,
                started_at=vieja,
                finished_at=vieja,
            )
        )
        adapter = FakeAdapter([], explota=True)
        runner = self._runner(repository, watchlist, settings)

        reporte = runner.run([(spec_for(adapter), None)])

        assert reporte.stale_sources == ("fake-feed",)

    def test_una_fuente_apagada_no_esta_callada(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """Apagada a propósito no es lo mismo que caída.

        Avisar de una fuente que alguien deshabilitó es el ruido que enseña a
        ignorar los avisos, que es exactamente lo que no puede pasar acá.
        """
        adapter = FakeAdapter([])
        runner = self._runner(repository, watchlist, settings)

        reporte = runner.run([(spec_for(adapter), "requiere habilitar las fuentes con PII")])

        assert reporte.stale_sources == ()

    def test_con_el_umbral_en_cero_no_vigila(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        apagado = settings.model_copy(update={"watchdog_max_silence_hours": 0})
        adapter = FakeAdapter([], explota=True)
        runner = self._runner(repository, watchlist, apagado)

        assert runner.run([(spec_for(adapter), None)]).stale_sources == ()

    def test_una_corrida_buena_recien_hecha_lo_apaga(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """La corrida en curso cuenta: si anduvo recién, no está callada."""
        adapter = FakeAdapter([payload_ar()])
        runner = self._runner(repository, watchlist, settings)

        assert runner.run([(spec_for(adapter), None)]).stale_sources == ()


class TestVentanaMedida:
    """Medir la ventana es lo que permite ajustar la cadencia con datos."""

    def test_registra_los_extremos_de_la_ventana(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        viejo = datetime(2026, 9, 1, 0, 0, tzinfo=UTC)
        nuevo = datetime(2026, 9, 1, 20, 30, tzinfo=UTC)
        adapter = FakeAdapter(
            [payload_ar(discovered=viejo), payload_ar(domain="y.gob.ar", discovered=nuevo)]
        )
        spec = replace(spec_for(adapter), bounded_window=True)

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        (resultado,) = runner.run([(spec, None)]).results

        assert resultado.window_from == viejo
        assert resultado.window_to == nuevo
        assert resultado.window_hours == pytest.approx(20.5)

    def test_una_fuente_de_ventana_abierta_no_la_mide(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """En un feed con histórico entero, el span sería la edad del feed."""
        adapter = FakeAdapter([payload_ar()])
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)

        (resultado,) = runner.run([(spec_for(adapter), None)]).results

        assert resultado.window_hours is None


class TestIdempotencia:
    """Re-correr el pipeline no duplica hallazgos."""

    def test_dos_corridas_iguales_no_duplican(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        adapter = FakeAdapter([payload_ar()])
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)

        primera = runner.run([(spec_for(adapter), None)])
        assert primera.total_new == 1

        # Se rearma el doble: la segunda corrida ve exactamente lo mismo.
        adapter2 = FakeAdapter([payload_ar()])
        segunda = runner.run([(spec_for(adapter2), None)])

        assert segunda.total_new == 0
        assert repository.count() == 1

    def test_el_mismo_hallazgo_repetido_en_el_lote_se_deduplica(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """ransomware.live devuelve la misma víctima en sus dos endpoints."""
        adapter = FakeAdapter([payload_ar(), payload_ar()])
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)

        reporte = runner.run([(spec_for(adapter), None)])

        assert reporte.total_matched == 2
        assert reporte.total_new == 1


class TestIncremental:
    """La corrida diaria procesa solo lo nuevo."""

    def test_la_segunda_corrida_arranca_desde_el_cursor(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        ayer = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        hoy = ayer + timedelta(days=1)

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        runner.run([(spec_for(FakeAdapter([payload_ar(discovered=ayer)])), None)])

        assert repository.get_cursor("fake-feed") == ayer

        segundo = FakeAdapter(
            [payload_ar(discovered=ayer), payload_ar("Ministerio Y", "y.gob.ar", discovered=hoy)]
        )
        reporte = runner.run([(spec_for(segundo), None)])

        assert segundo.ultimo_since == ayer
        # El de ayer se descarta por cursor; solo entra el de hoy.
        assert reporte.total_matched == 1
        assert reporte.total_new == 1
        assert repository.get_cursor("fake-feed") == hoy


class TestRelevanciaYPrivacidad:
    """Solo lo argentino se persiste, y sin PII."""

    def test_lo_que_no_es_argentino_se_descarta(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """Caso del enunciado: Acme Corp / acme.com / US no dispara ninguna regla."""
        adapter = FakeAdapter(
            [
                {
                    "victim": "Acme Corp",
                    "domain": "acme.com",
                    "country": "US",
                    "group": "Play",
                    "discovered": datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
                }
            ]
        )
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        reporte = runner.run([(spec_for(adapter), None)])

        assert reporte.total_fetched == 1
        assert reporte.total_matched == 0
        assert repository.count() == 0

    def test_guarda_la_razon_del_match(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        session_factory: sessionmaker[Session],
    ) -> None:
        """La columna auditable es lo que permite tunear falsos positivos."""
        from leaks.storage.models import FindingRow

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        runner.run([(spec_for(FakeAdapter([payload_ar(domain="prevision-ejemplo.gob.ar")])), None)])

        with session_factory() as session:
            fila = session.query(FindingRow).one()
        assert set(fila.ar_match_reason) >= {"watchlist", "tld_ar", "country_ar"}
        assert "prevision-ejemplo.gob.ar" in (fila.ar_match_detail or {})["watchlist"]

    def test_la_descripcion_con_pii_no_se_persiste(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Si el texto libre trae PII se cae entero, no se enmascara."""
        from leaks.storage.models import FindingRow

        adapter = FakeAdapter(
            [payload_ar(description="Contacto: juan.perez@x.gob.ar password: hunter2")]
        )
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        runner.run([(spec_for(adapter), None)])

        with session_factory() as session:
            fila = session.query(FindingRow).one()
        assert fila.description is None

    def test_descripcion_limpia_si_se_persiste(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        session_factory: sessionmaker[Session],
    ) -> None:
        from leaks.storage.models import FindingRow

        adapter = FakeAdapter([payload_ar(description="Organismo público nacional. 1.2 TB.")])
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        runner.run([(spec_for(adapter), None)])

        with session_factory() as session:
            fila = session.query(FindingRow).one()
        assert fila.description == "Organismo público nacional. 1.2 TB."


class TestBovedaPii:
    """El flag STORE_PII es la única puerta a persistir PII."""

    def test_sin_el_flag_la_pii_se_descarta(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Feed que declara PII + vault deshabilitado = no se escribe nada."""
        vault = PiiVault(session_factory, None, 30)
        adapter = FakeAdapter([payload_ar(secreto="persona@gmail.com")])

        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=Settings(store_pii=False),
            pii_vault=vault,
        )
        reporte = runner.run([(spec_for(adapter, requires_pii=True), None)])

        assert reporte.total_new == 1  # el metadata sí entra
        assert reporte.pii_stored == 0  # el crudo no
        assert vault.count() == 0

    def test_con_el_flag_la_pii_va_cifrada_y_recuperable(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        session_factory: sessionmaker[Session],
    ) -> None:
        clave = Fernet.generate_key().decode()
        cipher = PiiCipher(clave)
        vault = PiiVault(session_factory, cipher, 30)
        adapter = FakeAdapter([payload_ar(secreto="persona@gmail.com")])

        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=Settings(store_pii=True, pii_encryption_key=clave),
            pii_vault=vault,
        )
        reporte = runner.run([(spec_for(adapter, requires_pii=True), None)])

        assert reporte.pii_stored == 1
        assert vault.count() == 1

        # El blob en disco no tiene el dato en claro...
        from leaks.storage.models import PiiRecordRow

        with session_factory() as session:
            fila = session.query(PiiRecordRow).one()
        assert b"persona@gmail.com" not in fila.payload_encrypted
        # ...pero con la clave se recupera.
        assert cipher.decrypt(fila.payload_encrypted)["secreto"] == "persona@gmail.com"

    def test_un_feed_sin_pii_no_escribe_en_la_boveda(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Aunque STORE_PII esté activo: solo los feeds marcados usan la bóveda."""
        clave = Fernet.generate_key().decode()
        vault = PiiVault(session_factory, PiiCipher(clave), 30)

        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=Settings(store_pii=True, pii_encryption_key=clave),
            pii_vault=vault,
        )
        reporte = runner.run([(spec_for(FakeAdapter([payload_ar()]), requires_pii=False), None)])

        assert reporte.pii_stored == 0
        assert vault.count() == 0


class TestBitacoraDeActividad:
    """El runner reporta lo que hace, para la consola del frontend."""

    def test_reporta_inicio_fin_y_resultado_por_fuente(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        from leaks.domain.models import EventKind, RunEvent

        capturados: list[RunEvent] = []

        class SinkDePrueba:
            def emit(self, event: RunEvent) -> None:
                capturados.append(event)

        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=settings,
            event_sink=SinkDePrueba(),
        )
        runner.run([(spec_for(FakeAdapter([payload_ar()])), None)])

        tipos = [e.kind for e in capturados]
        assert tipos[0] is EventKind.RUN_START
        assert EventKind.SOURCE_START in tipos
        assert EventKind.SOURCE_DONE in tipos
        assert tipos[-1] is EventKind.RUN_DONE

    def test_reporta_la_fuente_caida(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        from leaks.domain.models import EventKind, EventLevel, RunEvent

        capturados: list[RunEvent] = []

        class SinkDePrueba:
            def emit(self, event: RunEvent) -> None:
                capturados.append(event)

        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=settings,
            event_sink=SinkDePrueba(),
        )
        runner.run([(spec_for(FakeAdapter([], explota=True)), None)])

        fallo = next(e for e in capturados if e.kind is EventKind.SOURCE_FAILED)
        assert fallo.level is EventLevel.ERROR
        assert "RuntimeError" in fallo.message

    def test_un_sink_que_explota_no_tumba_la_corrida(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
    ) -> None:
        """La bitácora es telemetría: su falla no puede costar el monitoreo."""
        from leaks.domain.models import RunEvent

        class SinkRoto:
            def emit(self, event: RunEvent) -> None:
                raise RuntimeError("el sink explotó")

        runner = PipelineRunner(
            repository=repository,
            watchlist=watchlist,
            settings=settings,
            event_sink=SinkRoto(),
        )
        reporte = runner.run([(spec_for(FakeAdapter([payload_ar()])), None)])

        # La corrida termina bien y el hallazgo se persiste igual.
        assert reporte.ok
        assert reporte.total_new == 1


class TestImportacionInicialYFechado:
    """La primera corrida de una fuente trae su histórico entero.

    Son hallazgos que recién conocemos, no que recién pasaron. Sin la marca de
    backfill, cada uno dispararía una alerta el primer día.
    """

    def test_la_primera_corrida_marca_backfill(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        session_factory: sessionmaker[Session],
    ) -> None:
        from leaks.storage.models import FindingRow

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        runner.run([(spec_for(FakeAdapter([payload_ar()])), None)])

        with session_factory() as session:
            fila = session.query(FindingRow).one()
        assert fila.backfill is True, "sin cursor previo = importación inicial"

    def test_la_segunda_corrida_ya_no(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        session_factory: sessionmaker[Session],
    ) -> None:
        from leaks.storage.models import FindingRow

        ayer = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
        hoy = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        runner.run([(spec_for(FakeAdapter([payload_ar(discovered=ayer)])), None)])

        # Ya hay cursor: lo que entra ahora es novedad genuina.
        segundo = FakeAdapter([payload_ar("Ministerio Y", "y.gob.ar", discovered=hoy)])
        runner.run([(spec_for(segundo), None)])

        with session_factory() as session:
            nuevo = session.query(FindingRow).filter(FindingRow.victim_domain == "y.gob.ar").one()
        assert nuevo.backfill is False

    def test_se_fecha_con_lo_que_declara_la_fuente(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        session_factory: sessionmaker[Session],
    ) -> None:
        from leaks.storage.models import FindingRow

        cuando = datetime(2023, 4, 5, tzinfo=UTC)
        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        runner.run([(spec_for(FakeAdapter([payload_ar(discovered=cuando)])), None)])

        with session_factory() as session:
            fila = session.query(FindingRow).one()
        assert fila.occurred_at is not None
        assert fila.occurred_at.year == 2023, "la fecha del evento, no la de importación"
        assert fila.occurred_at_basis == "feed"
