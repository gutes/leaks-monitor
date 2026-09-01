"""Tests de la bitácora de actividad (la consola del frontend).

Lo que importa verificar:

* que el pipeline reporte a qué sitio le pega y qué respondió;
* que la bitácora **nunca** tumbe una corrida si falla;
* que no se filtre PII ni contenido de feeds en los eventos;
* que el frontend pueda pedir "solo lo nuevo" sin repetir líneas.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from sqlalchemy.orm import Session, sessionmaker

from leaks.adapters.http import FeedHttpClient, FeedHttpError, describe_cause
from leaks.domain.models import EventKind, EventLevel, RunEvent
from leaks.storage.event_sink import NullEventSink, SqlAlchemyEventSink
from leaks.storage.queries import FindingQueryService


@pytest.fixture
def sink(session_factory: sessionmaker[Session]) -> SqlAlchemyEventSink:
    return SqlAlchemyEventSink(session_factory, retention_days=14)


@pytest.fixture
def queries(session_factory: sessionmaker[Session]) -> FindingQueryService:
    return FindingQueryService(session_factory)


def evento(**kwargs: object) -> RunEvent:
    base = {
        "occurred_at": datetime.now(UTC),
        "kind": EventKind.HTTP_REQUEST,
        "message": "GET https://ejemplo.test → 200",
    }
    return RunEvent(**{**base, **kwargs})  # type: ignore[arg-type]


class TestSink:
    def test_persiste_y_se_lee_en_orden(
        self, sink: SqlAlchemyEventSink, queries: FindingQueryService
    ) -> None:
        for i in range(3):
            sink.emit(evento(message=f"evento {i}"))

        leidos = queries.list_events()
        assert [e["message"] for e in leidos] == ["evento 0", "evento 1", "evento 2"]

    def test_el_cursor_devuelve_solo_lo_nuevo(
        self, sink: SqlAlchemyEventSink, queries: FindingQueryService
    ) -> None:
        """Es lo que evita que la consola repita líneas en cada poll."""
        sink.emit(evento(message="viejo"))
        primer_lote = queries.list_events()
        ultimo_id = primer_lote[-1]["id"]

        sink.emit(evento(message="nuevo"))
        segundo_lote = queries.list_events(after_id=ultimo_id)

        assert [e["message"] for e in segundo_lote] == ["nuevo"]

    def test_sin_novedades_devuelve_vacio(
        self, sink: SqlAlchemyEventSink, queries: FindingQueryService
    ) -> None:
        sink.emit(evento())
        assert queries.list_events(after_id=queries.last_event_id()) == ()

    def test_el_mensaje_se_trunca(
        self, sink: SqlAlchemyEventSink, queries: FindingQueryService
    ) -> None:
        """La columna tiene tope: un mensaje enorme no puede romper el insert."""
        sink.emit(evento(message="x" * 5000))
        assert len(queries.list_events()[0]["message"]) <= 500

    def test_un_sink_roto_no_propaga(self, session_factory: sessionmaker[Session]) -> None:
        """Perder el monitoreo por culpa del panel que lo muestra sería el colmo."""
        roto = SqlAlchemyEventSink(session_factory)
        roto._session_factory = None  # type: ignore[assignment]
        roto.emit(evento())  # no debe lanzar

    def test_la_retencion_borra_lo_viejo(
        self, sink: SqlAlchemyEventSink, queries: FindingQueryService
    ) -> None:
        sink.emit(evento(occurred_at=datetime.now(UTC) - timedelta(days=30)))
        sink.emit(evento(occurred_at=datetime.now(UTC)))

        assert sink.purge_expired() == 1
        assert len(queries.list_events()) == 1

    def test_null_sink_no_hace_nada(self) -> None:
        NullEventSink().emit(evento())


class TestClienteHttpReporta:
    """El cliente HTTP es el que sabe a qué sitio se le pegó."""

    @respx.mock
    def test_reporta_el_request_con_url_estado_y_tamaño(self) -> None:
        capturados: list[RunEvent] = []
        respx.get("https://feed.test/api").mock(return_value=httpx.Response(200, json={"ok": True}))

        cliente = FeedHttpClient(
            user_agent="leaks-monitor/test",
            rate_limit_delay=0,
            sleep=lambda _s: None,
            emit=capturados.append,
            source="feed-test",
        )
        cliente.get_json("https://feed.test/api")

        (ev,) = capturados
        assert ev.kind is EventKind.HTTP_REQUEST
        assert ev.level is EventLevel.INFO
        assert ev.source == "feed-test"
        assert ev.status_code == 200
        assert "https://feed.test/api" in ev.message
        assert ev.bytes_received is not None and ev.bytes_received > 0
        assert ev.duration_ms is not None

    @respx.mock
    def test_reporta_el_429_y_el_reintento(self) -> None:
        capturados: list[RunEvent] = []
        respx.get("https://feed.test/api").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "1"}),
                httpx.Response(200, json=[]),
            ]
        )

        cliente = FeedHttpClient(
            user_agent="leaks-monitor/test",
            max_retries=2,
            rate_limit_delay=0,
            backoff_base=1,
            sleep=lambda _s: None,
            emit=capturados.append,
            source="feed-test",
        )
        cliente.get_json("https://feed.test/api")

        tipos = [e.kind for e in capturados]
        assert EventKind.HTTP_RETRY in tipos
        assert tipos[-1] is EventKind.HTTP_REQUEST
        assert capturados[0].level is EventLevel.WARN

    @respx.mock
    def test_reporta_el_error_definitivo(self) -> None:
        capturados: list[RunEvent] = []
        respx.get("https://feed.test/api").mock(return_value=httpx.Response(404))

        cliente = FeedHttpClient(
            user_agent="leaks-monitor/test",
            rate_limit_delay=0,
            sleep=lambda _s: None,
            emit=capturados.append,
            source="feed-test",
        )
        with pytest.raises(FeedHttpError):
            cliente.get_json("https://feed.test/api")

        assert capturados[-1].level is EventLevel.ERROR
        assert capturados[-1].status_code == 404

    def test_el_error_final_carga_la_causa(self) -> None:
        """Lo que se guarda en `source_runs` es el texto, no `__cause__`.

        El caso real: darkforums.ru resolvía por DNS pero rechazaba la
        conexión. Sin la causa en el mensaje, la telemetría solo decía "falló
        tras N intentos" y no alcanzaba para saber si el foro se había mudado.
        """
        raiz = httpx.ConnectError("[Errno 111] Connection refused")
        try:
            try:
                raise raiz
            except httpx.ConnectError as exc:
                raise FeedHttpError("https://foro.test/x falló tras 4 intentos") from exc
        except FeedHttpError as exc:
            assert describe_cause(exc) == "ConnectError: [Errno 111] Connection refused"

    def test_la_causa_se_acota(self) -> None:
        """El mensaje no puede arrastrar un body: se trunca."""
        assert len(describe_cause(RuntimeError("x" * 5000))) <= 160

    def test_sin_causa_no_revienta(self) -> None:
        assert describe_cause(None) == "sin causa registrada"

    def test_sin_sink_el_cliente_funciona_igual(self) -> None:
        """La bitácora es opcional: el pipeline no depende de ella."""
        cliente = FeedHttpClient(user_agent="leaks-monitor/test", sleep=lambda _s: None)
        assert cliente._emit is None
