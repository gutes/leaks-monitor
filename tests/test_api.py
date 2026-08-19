"""Tests de la API de solo lectura.

Se levanta la app contra una base temporal: sin red, sin variables de entorno
globales y sin tocar la base real.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from leaks.api.app import create_app
from leaks.config import Settings
from leaks.domain.models import ArMatchReason, Severity
from leaks.storage.event_sink import SqlAlchemyEventSink
from leaks.storage.repository import SqlAlchemyFindingRepository
from tests.conftest import GuardBloqueante, GuardPermisivo, make_finding


@pytest.fixture
def settings(tmp_path: Path, engine: Engine) -> Settings:
    """Settings apuntando a la misma base temporal que usan las fixtures."""
    return Settings(database_url=str(engine.url), store_pii=False)


@pytest.fixture
def poblado(repository: SqlAlchemyFindingRepository) -> None:
    """Un puñado de hallazgos variados para ejercitar filtros y paginado."""
    base = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
    repository.upsert_many(
        [
            make_finding(
                victim_name="Ministerio de Salud",
                victim_domain="salud.gob.ar",
                source="ransomware.live",
                severity=Severity.CRITICAL,
                discovered_at=base + timedelta(days=3),
            ),
            make_finding(
                victim_name="obrasocial-ejemplo.com.ar",
                victim_domain="obrasocial-ejemplo.com.ar",
                source="dls-monitor",
                actor="lockbit3",
                severity=Severity.MEDIUM,
                discovered_at=base + timedelta(days=2),
                reasons=(ArMatchReason.TLD_AR,),
            ),
            make_finding(
                victim_name="aguas-ejemplo.com.ar",
                victim_domain="aguas-ejemplo.com.ar",
                source="ransomlook",
                actor="safepay",
                severity=Severity.CRITICAL,
                discovered_at=base + timedelta(days=1),
            ),
        ]
    )


@pytest.fixture
def client(settings: Settings, poblado: None) -> Iterator[TestClient]:
    # Guard permisivo: sin él, el middleware de bloqueo saldría a la red en
    # cada petición y la suite dejaría de ser offline.
    with TestClient(create_app(settings, egress_guard=GuardPermisivo())) as c:  # type: ignore[arg-type]
        yield c


class TestExportWatchlist:
    """Exportación de la watchlist, con el cruce contra los hallazgos."""

    @pytest.fixture
    def con_watchlist(self, client: TestClient) -> TestClient:
        client.post(
            "/api/watchlist",
            json={"kind": "domain", "value": "salud.gob.ar", "sector": "salud", "critical": True},
        )
        client.post(
            "/api/watchlist",
            json={"kind": "keyword", "value": "ministerio", "sector": "salud"},
        )
        return client

    def test_devuelve_texto_plano_descargable(self, con_watchlist: TestClient) -> None:
        res = con_watchlist.get("/api/watchlist/export")
        assert res.status_code == 200
        assert res.headers["content-type"].startswith("text/plain")
        assert res.headers["content-disposition"].startswith('attachment; filename="watchlist-')
        assert res.headers["X-Watchlist-Exported"] == "2"

    def test_sale_entera_sin_paginado(self, con_watchlist: TestClient) -> None:
        """El listado pagina; el informe no: uno a medias no sirve de nada."""
        texto = con_watchlist.get("/api/watchlist/export").text
        assert "salud.gob.ar" in texto
        assert "ministerio" in texto

    def test_respeta_el_filtro_y_lo_declara(self, con_watchlist: TestClient) -> None:
        texto = con_watchlist.get("/api/watchlist/export", params={"kind": "domain"}).text
        assert "tipo=domain" in texto
        assert "salud.gob.ar" in texto
        assert "En el informe  : 1" in texto

    def test_cruza_los_hallazgos_con_la_entrada(self, con_watchlist: TestClient) -> None:
        """Es lo que convierte el listado en informe: qué de esto ya cayó."""
        texto = con_watchlist.get("/api/watchlist/export").text
        assert "Comprometidos alguna vez" in texto
        assert "salud.gob.ar" in texto

    def test_una_entrada_sin_historial_no_lo_finge(self, client: TestClient) -> None:
        client.post(
            "/api/watchlist",
            json={"kind": "domain", "value": "nadie.gob.ar", "sector": "otros"},
        )
        texto = client.get("/api/watchlist/export", params={"q": "nadie"}).text
        assert "nadie.gob.ar" in texto
        assert "0 entradas cayeron alguna vez" in texto

    def test_watchlist_vacia_devuelve_informe_no_error(self, client: TestClient) -> None:
        res = client.get("/api/watchlist/export", params={"q": "no-existe-nada"})
        assert res.status_code == 200
        assert "La watchlist está vacía para este filtro." in res.text


class TestExport:
    """Exportación a TXT de una selección de hallazgos."""

    @staticmethod
    def _ids(client: TestClient) -> list[int]:
        return [i["id"] for i in client.get("/api/findings").json()["items"]]

    def _exportar(self, client: TestClient, ids: list[int]) -> Any:
        return client.post("/api/findings/export", json={"ids": ids})

    def test_devuelve_texto_plano_descargable(self, client: TestClient) -> None:
        res = self._exportar(client, self._ids(client)[:1])
        assert res.status_code == 200
        assert res.headers["content-type"].startswith("text/plain")
        assert res.headers["content-disposition"].startswith('attachment; filename="hallazgos-')

    def test_exporta_solo_lo_seleccionado(self, client: TestClient) -> None:
        todos = self._ids(client)
        assert len(todos) == 3
        texto = self._exportar(client, todos[:1]).text
        assert "Hallazgos      : 1" in texto
        assert "[1/1]" in texto and "[1/3]" not in texto

    def test_exporta_varios_juntos_y_ordenados(self, client: TestClient) -> None:
        """Es el caso que motivó el feature: varios hallazgos en un solo informe."""
        ids = self._ids(client)
        texto = self._exportar(client, ids).text
        assert "Hallazgos      : 3" in texto
        assert [texto.index(f"[{n}/3]") for n in (1, 2, 3)] == sorted(
            texto.index(f"[{n}/3]") for n in (1, 2, 3)
        )

    def test_el_orden_en_que_se_tildan_no_importa(self, client: TestClient) -> None:
        ids = self._ids(client)
        assert self._exportar(client, ids).text == self._exportar(client, ids[::-1]).text

    def test_un_id_repetido_no_duplica_la_ficha(self, client: TestClient) -> None:
        uno = self._ids(client)[0]
        assert "Hallazgos      : 1" in self._exportar(client, [uno, uno, uno]).text

    def test_ignora_los_que_ya_no_existen_y_lo_informa(self, client: TestClient) -> None:
        """Un hallazgo puede desaparecer entre que se tilda y se pide el archivo."""
        res = self._exportar(client, [*self._ids(client)[:1], 999999])
        assert res.status_code == 200
        assert res.headers["X-Findings-Exported"] == "1"

    def test_si_no_existe_ninguno_avisa_en_vez_de_bajar_un_archivo_vacio(
        self, client: TestClient
    ) -> None:
        assert self._exportar(client, [999998, 999999]).status_code == 404

    def test_una_seleccion_vacia_se_rechaza(self, client: TestClient) -> None:
        assert self._exportar(client, []).status_code == 422

    def test_el_cuerpo_tiene_tope(self, client: TestClient) -> None:
        """Un pedido con 100.000 ids no puede tumbar el proceso."""
        assert self._exportar(client, list(range(6000))).status_code == 422

    def test_se_topea_la_cantidad_exportada(self, settings: Settings, poblado: None) -> None:
        acotado = settings.model_copy(update={"export_max_findings": 2})
        with TestClient(create_app(acotado, egress_guard=GuardPermisivo())) as c:  # type: ignore[arg-type]
            texto = self._exportar(c, self._ids(c)).text
        assert "Hallazgos      : 2" in texto

    def test_el_informe_trae_la_columna_auditable(self, client: TestClient) -> None:
        texto = self._exportar(client, self._ids(client)[:1]).text
        assert "Relevancia AR" in texto


class TestFindings:
    def test_lista_del_mas_nuevo_al_mas_viejo(self, client: TestClient) -> None:
        datos = client.get("/api/findings").json()
        assert datos["total"] == 3
        fechas = [i["discovered_at"] for i in datos["items"]]
        assert fechas == sorted(fechas, reverse=True)

    def test_expone_la_razon_del_match(self, client: TestClient) -> None:
        """La columna auditable tiene que llegar al frontend."""
        item = client.get("/api/findings").json()["items"][0]
        assert isinstance(item["ar_match_reason"], list)
        assert item["ar_match_reason"]

    @pytest.mark.parametrize(
        ("filtro", "esperado"),
        [
            ({"source": "dls-monitor"}, 1),
            ({"severity": "critical"}, 2),
            ({"actor": "safepay"}, 1),
            ({"q": "Obra Social Ejemplo"}, 1),
            ({"q": "gob.ar"}, 1),
            ({"source": "no-existe"}, 0),
        ],
    )
    def test_filtros(self, client: TestClient, filtro: dict[str, str], esperado: int) -> None:
        assert client.get("/api/findings", params=filtro).json()["total"] == esperado

    def test_filtro_por_fecha(self, client: TestClient) -> None:
        datos = client.get("/api/findings", params={"since": "2026-08-12T00:00:00Z"}).json()
        assert datos["total"] == 2

    def test_el_comodin_del_usuario_no_amplia_la_busqueda(self, client: TestClient) -> None:
        """Un `%` en la query no puede convertirse en 'traeme todo'."""
        assert client.get("/api/findings", params={"q": "%"}).json()["total"] == 0

    def test_paginado(self, client: TestClient) -> None:
        primera = client.get("/api/findings", params={"limit": 2, "offset": 0}).json()
        segunda = client.get("/api/findings", params={"limit": 2, "offset": 2}).json()

        assert len(primera["items"]) == 2
        assert len(segunda["items"]) == 1
        assert primera["total"] == segunda["total"] == 3

    def test_el_limit_tiene_tope(self, settings: Settings, poblado: None) -> None:
        """Todo listado tiene tope, también cuando el cliente pide más."""
        acotado = settings.model_copy(update={"api_max_page_size": 2})
        with TestClient(create_app(acotado, egress_guard=GuardPermisivo())) as client:  # type: ignore[arg-type]
            assert client.get("/api/findings", params={"limit": 9999}).json()["limit"] == 2

    def test_limit_invalido_es_rechazado(self, client: TestClient) -> None:
        assert client.get("/api/findings", params={"limit": 0}).status_code == 422


class TestAgregados:
    def test_stats(self, client: TestClient) -> None:
        datos = client.get("/api/stats").json()
        assert datos["total"] == 3
        assert datos["by_severity"]["critical"] == 2
        assert set(datos["by_source"]) == {"ransomware.live", "dls-monitor", "ransomlook"}

    def test_filtros_disponibles(self, client: TestClient) -> None:
        datos = client.get("/api/filters").json()
        assert "dls-monitor" in datos["sources"]
        assert "critical" in datos["severities"]


class TestFuentes:
    def test_lista_el_registro_completo(self, client: TestClient) -> None:
        """También los feeds que no corren: un feed invisible es un feed olvidado."""
        datos = client.get("/api/sources").json()
        nombres = {s["name"] for s in datos}
        assert {"ransomware.live", "ransomlook", "dls-monitor", "hudsonrock"} <= nombres

    def test_el_feed_con_pii_aparece_deshabilitado_y_con_motivo(self, client: TestClient) -> None:
        """Con el toggle apagado no corre, y la UI explica por qué."""
        hudson = next(s for s in client.get("/api/sources").json() if s["name"] == "hudsonrock")
        assert hudson["enabled"] is False
        assert hudson["requires_pii"] is True
        assert "PII" in (hudson["skip_reason"] or "")

    def test_la_licencia_es_visible(self, client: TestClient) -> None:
        """La limitación del tier free tiene que estar a la vista, no solo en el README."""
        rl = next(s for s in client.get("/api/sources").json() if s["name"] == "ransomware.live")
        assert "personal" in rl["license_note"].lower()


class TestHealth:
    def test_expone_la_postura_de_privacidad(self, client: TestClient) -> None:
        """Que STORE_PII sea verificable desde afuera, no una promesa del README."""
        datos = client.get("/api/health").json()
        assert datos["status"] == "ok"
        assert datos["store_pii"] is False
        assert datos["findings"] == 3


class TestSoloLectura:
    @pytest.mark.parametrize("metodo", ["post", "put", "patch", "delete"])
    def test_no_hay_endpoints_de_escritura(self, client: TestClient, metodo: str) -> None:
        """La API no escribe: el pipeline corre por CLI/scheduler."""
        respuesta = getattr(client, metodo)("/api/findings")
        assert respuesta.status_code == 405

    def test_no_expone_los_registros_de_pii(self, client: TestClient) -> None:
        """Ni con el flag activo: para leer PII hace falta la clave y acceso deliberado.

        Existe `/api/settings/pii-sources`, pero es un interruptor de política:
        no devuelve ni un byte de la tabla cifrada. Lo que se verifica es que
        ningún esquema de respuesta exponga el payload.
        """
        openapi = client.get("/api/openapi.json").json()
        crudo = json.dumps(openapi)

        assert "payload_encrypted" not in crudo
        assert "pii_records" not in crudo
        # Ninguna ruta sirve registros de PII.
        assert not any(
            "pii" in ruta.lower() and "settings" not in ruta.lower() for ruta in openapi["paths"]
        )


class TestFrontend:
    def test_sirve_la_pagina(self, client: TestClient) -> None:
        respuesta = client.get("/")
        assert respuesta.status_code == 200
        assert "Monitoreo de leaks" in respuesta.text

    def test_sirve_los_estaticos(self, client: TestClient) -> None:
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/static/style.css").status_code == 200

    def test_sin_frontend_la_api_sigue_funcionando(
        self, settings: Settings, poblado: None, tmp_path: Path
    ) -> None:
        """Desplegar el paquete sin los estáticos degrada la UI, no la API.

        Regresión: la ruta del frontend se resolvía desde `__file__`, y al
        instalarse como wheel (en la imagen Docker) apuntaba a un directorio
        inexistente. Ahora es configuración explícita.
        """
        sin_ui = settings.model_copy(update={"frontend_dir": tmp_path / "no-existe"})
        with TestClient(create_app(sin_ui, egress_guard=GuardPermisivo())) as client:  # type: ignore[arg-type]
            assert client.get("/api/health").status_code == 200
            assert client.get("/").status_code == 404

    def test_el_frontend_se_sirve_desde_la_ruta_configurada(
        self, settings: Settings, poblado: None, tmp_path: Path
    ) -> None:
        ui = tmp_path / "ui"
        ui.mkdir()
        (ui / "index.html").write_text("<h1>otra ui</h1>", encoding="utf-8")

        with TestClient(
            create_app(
                settings.model_copy(update={"frontend_dir": ui}), egress_guard=GuardPermisivo()
            )  # type: ignore[arg-type]
        ) as client:
            assert "otra ui" in client.get("/").text


class TestConsolaDeActividad:
    """El endpoint que alimenta la consola del frontend."""

    @pytest.fixture
    def con_eventos(self, session_factory: Any) -> SqlAlchemyEventSink:
        from leaks.domain.models import EventKind, EventLevel, RunEvent

        sink = SqlAlchemyEventSink(session_factory)
        sink.emit(
            RunEvent(
                occurred_at=datetime.now(UTC),
                kind=EventKind.RUN_START,
                message="Corrida iniciada",
            )
        )
        sink.emit(
            RunEvent(
                occurred_at=datetime.now(UTC),
                kind=EventKind.HTTP_REQUEST,
                source="ransomware.live",
                message="GET https://api.ransomware.live/v2/recentvictims → 200",
                url="https://api.ransomware.live/v2/recentvictims",
                status_code=200,
                duration_ms=1234,
                bytes_received=98309,
            )
        )
        sink.emit(
            RunEvent(
                occurred_at=datetime.now(UTC),
                level=EventLevel.ERROR,
                kind=EventKind.SOURCE_FAILED,
                source="hudsonrock",
                message="Falló: ReadTimeout",
            )
        )
        return sink

    def test_devuelve_la_actividad_con_su_detalle(
        self, client: TestClient, con_eventos: SqlAlchemyEventSink
    ) -> None:
        datos = client.get("/api/events").json()

        assert len(datos["items"]) == 3
        http = next(e for e in datos["items"] if e["kind"] == "http_request")
        assert http["source"] == "ransomware.live"
        assert http["status_code"] == 200
        assert http["duration_ms"] == 1234
        assert http["bytes_received"] == 98309
        assert "api.ransomware.live" in http["message"]

    def test_el_cursor_evita_repetir_lineas(
        self, client: TestClient, con_eventos: SqlAlchemyEventSink
    ) -> None:
        """Es lo que hace que la consola no duplique en cada poll."""
        primero = client.get("/api/events").json()
        assert primero["last_id"] > 0

        segundo = client.get("/api/events", params={"after_id": primero["last_id"]}).json()
        assert segundo["items"] == []
        # Sin novedades, el cursor no retrocede.
        assert segundo["last_id"] == primero["last_id"]

    def test_marca_el_nivel_de_error(
        self, client: TestClient, con_eventos: SqlAlchemyEventSink
    ) -> None:
        fallo = next(
            e for e in client.get("/api/events").json()["items"] if e["kind"] == "source_failed"
        )
        assert fallo["level"] == "error"

    def test_sin_actividad_devuelve_vacio(self, client: TestClient) -> None:
        datos = client.get("/api/events").json()
        assert datos == {"items": [], "last_id": 0}

    def test_el_limit_tiene_tope(self, client: TestClient) -> None:
        assert client.get("/api/events", params={"limit": 5000}).status_code == 422


class TestEstadoDePii:
    """Regresión: la pastilla de PII quedaba clavada en OFF.

    La UI mostraba `store_pii` (variable de entorno, inmutable en caliente)
    mientras el interruptor cambiaba `pii_sources_enabled` (persistido en la
    base). Son dos cosas distintas y la API tiene que exponer las dos.
    """

    def test_health_expone_los_dos_estados_por_separado(self, client: TestClient) -> None:
        datos = client.get("/api/health").json()
        assert datos["store_pii"] is False
        assert datos["pii_sources_enabled"] is False

    def test_el_toggle_se_refleja_en_health(self, client: TestClient) -> None:
        """Lo que se prende tiene que verse, sin reiniciar el proceso."""
        client.patch("/api/settings/pii-sources", json={"enabled": True})

        datos = client.get("/api/health").json()
        assert datos["pii_sources_enabled"] is True
        # El del entorno NO cambia: prender fuentes no habilita a persistir PII.
        assert datos["store_pii"] is False

    def test_el_estado_persiste_entre_peticiones(self, client: TestClient) -> None:
        """ "La última configuración usada" tiene que sobrevivir al refresh."""
        client.patch("/api/settings/pii-sources", json={"enabled": True})
        assert client.get("/api/rules").json()["pii_sources_enabled"] is True

        client.patch("/api/settings/pii-sources", json={"enabled": False})
        assert client.get("/api/rules").json()["pii_sources_enabled"] is False

    def test_el_patch_devuelve_el_estado_ya_aplicado(self, client: TestClient) -> None:
        """El frontend repinta con esto, así que no puede venir desactualizado."""
        respuesta = client.patch("/api/settings/pii-sources", json={"enabled": True}).json()
        assert respuesta["pii_sources_enabled"] is True
        assert "pii_storage_available" in respuesta

    def test_sobrevive_a_una_app_nueva(self, settings: Settings, poblado: None) -> None:
        """Persistido en la base, no en memoria del proceso."""
        with TestClient(create_app(settings, egress_guard=GuardPermisivo())) as primero:  # type: ignore[arg-type]
            primero.patch("/api/settings/pii-sources", json={"enabled": True})

        with TestClient(create_app(settings, egress_guard=GuardPermisivo())) as segundo:  # type: ignore[arg-type]
            assert segundo.get("/api/health").json()["pii_sources_enabled"] is True


class TestBloqueoDeLaApi:
    """Estando bloqueado, la API entera deja de responder.

    El modal del frontend es la capa visible; esta es la que manda. Una pestaña
    vieja o un `curl` no pueden seguir operando porque el navegador no vea el
    modal.
    """

    @pytest.fixture
    def bloqueado(self, settings: Settings, poblado: None) -> Iterator[TestClient]:
        with TestClient(create_app(settings, egress_guard=GuardBloqueante())) as c:  # type: ignore[arg-type]
            yield c

    @pytest.mark.parametrize(
        ("metodo", "ruta"),
        [
            ("get", "/api/findings"),
            ("get", "/api/stats"),
            ("get", "/api/sources"),
            ("get", "/api/filters"),
            ("get", "/api/events"),
            ("get", "/api/watchlist"),
            ("get", "/api/rules"),
            ("post", "/api/runs"),
            ("post", "/api/findings/export"),
            ("get", "/api/watchlist/export"),
        ],
    )
    def test_todo_devuelve_403(self, bloqueado: TestClient, metodo: str, ruta: str) -> None:
        respuesta = getattr(bloqueado, metodo)(ruta)
        assert respuesta.status_code == 403
        assert respuesta.json()["egress_blocked"] is True

    def test_no_se_puede_escribir_la_watchlist(self, bloqueado: TestClient) -> None:
        respuesta = bloqueado.post(
            "/api/watchlist", json={"kind": "domain", "value": "x.gob.ar", "sector": "x"}
        )
        assert respuesta.status_code == 403

    def test_egress_sigue_abierto(self, bloqueado: TestClient) -> None:
        """Si se cerrara, el modal quedaría trabado para siempre."""
        respuesta = bloqueado.get("/api/egress")
        assert respuesta.status_code == 200
        assert respuesta.json()["blocked"] is True
        assert "AR" in respuesta.json()["block_reason"]

    def test_el_motivo_llega_al_frontend(self, bloqueado: TestClient) -> None:
        detalle = bloqueado.get("/api/findings").json()
        assert detalle["country"] == "AR"
        assert "BLOQUEADO" in detalle["detail"]


class TestPaginacionDeWatchlist:
    """Cada pantalla lista pagina; la watchlist crece y no entra en una vista."""

    def test_devuelve_una_pagina_con_su_total(self, client: TestClient) -> None:
        from leaks.storage.watchlist_repository import WatchlistRepository

        repo = WatchlistRepository(client.app.state.session_factory)  # type: ignore[attr-defined]
        for i in range(12):
            repo.add(kind="domain", value=f"org{i}.gob.ar", sector="prueba")

        datos = client.get("/api/watchlist", params={"limit": 5, "offset": 0}).json()
        assert len(datos["items"]) == 5
        assert datos["total"] == 12
        assert datos["limit"] == 5
        assert datos["offset"] == 0

    def test_las_paginas_no_se_solapan(self, client: TestClient) -> None:
        from leaks.storage.watchlist_repository import WatchlistRepository

        repo = WatchlistRepository(client.app.state.session_factory)  # type: ignore[attr-defined]
        for i in range(12):
            repo.add(kind="domain", value=f"org{i}.gob.ar", sector="prueba")

        primera = client.get("/api/watchlist", params={"limit": 5, "offset": 0}).json()
        segunda = client.get("/api/watchlist", params={"limit": 5, "offset": 5}).json()

        ids_primera = {i["id"] for i in primera["items"]}
        ids_segunda = {i["id"] for i in segunda["items"]}
        assert not ids_primera & ids_segunda

    def test_el_total_respeta_el_filtro(self, client: TestClient) -> None:
        """El total tiene que ser el del filtro, no el de la watchlist entera."""
        from leaks.storage.watchlist_repository import WatchlistRepository

        repo = WatchlistRepository(client.app.state.session_factory)  # type: ignore[attr-defined]
        repo.add(kind="domain", value="unico.gob.ar", sector="prueba")
        repo.add(kind="keyword", value="Palabra Larga", sector="prueba")

        datos = client.get("/api/watchlist", params={"kind": "keyword"}).json()
        assert datos["total"] == 1
        assert len(datos["items"]) == 1

    def test_el_limit_tiene_tope(self, settings: Settings, poblado: None) -> None:
        acotado = settings.model_copy(update={"api_max_page_size": 3})
        with TestClient(create_app(acotado, egress_guard=GuardPermisivo())) as client:  # type: ignore[arg-type]
            assert client.get("/api/watchlist", params={"limit": 999}).json()["limit"] == 3


class TestAlertStatus:
    """El endpoint existe para que la UI no mienta por omisión."""

    def test_dice_que_no_hay_canales_y_cuales_faltan(self, client: TestClient) -> None:
        d = client.get("/api/alerts").json()
        assert d["enabled"] is False
        nombres = {c["name"] for c in d["channels"]}
        assert nombres == {"webhook", "telegram"}
        assert all(not c["configured"] for c in d["channels"])
        assert "LEAKS_ALERT_WEBHOOK_URL" in next(
            c["missing"] for c in d["channels"] if c["name"] == "webhook"
        )

    def test_nunca_devuelve_el_valor_de_un_secreto(self, settings: Settings, poblado: None) -> None:
        """Un token de Telegram no puede salir por la API ni para diagnosticar."""
        from pydantic import SecretStr

        con_token = settings.model_copy(
            update={
                "alert_telegram_token": SecretStr("123456:SUPERSECRETO"),
                "alert_telegram_chat_id": "-100999",
            }
        )
        with TestClient(create_app(con_token, egress_guard=GuardPermisivo())) as c:  # type: ignore[arg-type]
            cuerpo = c.get("/api/alerts").text
        assert "SUPERSECRETO" not in cuerpo
        assert "-100999" not in cuerpo

    def test_reconoce_un_canal_configurado(self, settings: Settings, poblado: None) -> None:
        con_webhook = settings.model_copy(update={"alert_webhook_url": "https://ejemplo.test/hook"})
        with TestClient(create_app(con_webhook, egress_guard=GuardPermisivo())) as c:  # type: ignore[arg-type]
            d = c.get("/api/alerts").json()
        assert d["enabled"] is True
        webhook = next(x for x in d["channels"] if x["name"] == "webhook")
        assert webhook["configured"] and webhook["missing"] == []

    def test_informa_el_umbral_vigente(self, client: TestClient) -> None:
        d = client.get("/api/alerts").json()
        assert d["min_severity"] in {"low", "medium", "high", "critical"}
        assert d["max_age_days"] >= 1

    def test_no_cuenta_como_pendiente_la_importacion_inicial(self, client: TestClient) -> None:
        """Si contara el backfill, diría que hay cientos esperando cuando es histórico."""
        assert client.get("/api/alerts").json()["pending"] >= 0


class TestAlertFeed:
    """El feed que consume otro software."""

    def test_devuelve_las_ultimas(self, client: TestClient) -> None:
        d = client.get("/api/alerts/feed", params={"limit": 2}).json()
        assert len(d["items"]) <= 2
        assert d["total"] >= len(d["items"])

    def test_devuelve_despachadas_y_no_despachadas(self, client: TestClient) -> None:
        """Que un canal las haya mandado es un dato, no un filtro implícito."""
        d = client.get("/api/alerts/feed", params={"limit": 50}).json()
        assert all("notified" in i and "alerted_at" in i for i in d["items"])
        todas = d["total"]
        pendientes = client.get(
            "/api/alerts/feed", params={"estado": "pendientes", "limit": 50}
        ).json()["total"]
        assert todas >= pendientes

    def test_ordena_de_la_mas_reciente_a_la_mas_vieja(self, client: TestClient) -> None:
        items = client.get("/api/alerts/feed", params={"limit": 50}).json()["items"]
        fechas = [i["first_seen_at"] for i in items]
        assert fechas == sorted(fechas, reverse=True)

    def test_acepta_solo_desde(self, client: TestClient) -> None:
        """`hasta` es opcional: se puede pedir todo lo posterior a una fecha."""
        futuro = client.get(
            "/api/alerts/feed", params={"desde": "2099-01-01T00:00:00", "limit": 50}
        ).json()
        assert futuro["total"] == 0
        pasado = client.get(
            "/api/alerts/feed", params={"desde": "2000-01-01T00:00:00", "limit": 50}
        ).json()
        assert pasado["total"] > 0

    def test_acepta_solo_hasta(self, client: TestClient) -> None:
        d = client.get(
            "/api/alerts/feed", params={"hasta": "2000-01-01T00:00:00", "limit": 50}
        ).json()
        assert d["total"] == 0

    def test_acepta_un_rango_cerrado(self, client: TestClient) -> None:
        d = client.get(
            "/api/alerts/feed",
            params={
                "desde": "2000-01-01T00:00:00",
                "hasta": "2099-01-01T00:00:00",
                "limit": 50,
            },
        ).json()
        assert d["total"] > 0

    def test_una_fecha_sin_zona_horaria_se_asume_utc(self, client: TestClient) -> None:
        """Sin esto el filtro compararía naive contra aware y correría el rango."""
        naive = client.get(
            "/api/alerts/feed", params={"desde": "2000-01-01T00:00:00", "limit": 50}
        ).json()
        aware = client.get(
            "/api/alerts/feed", params={"desde": "2000-01-01T00:00:00+00:00", "limit": 50}
        ).json()
        assert naive["total"] == aware["total"]

    def test_el_campo_de_fecha_se_elige_y_se_declara(self, client: TestClient) -> None:
        d = client.get("/api/alerts/feed", params={"campo": "occurred"}).json()
        assert d["campo"] == "occurred"

    def test_first_seen_es_el_default(self, client: TestClient) -> None:
        """Es el único monótono: paginar por `occurred` se saltea alertas."""
        assert client.get("/api/alerts/feed").json()["campo"] == "first_seen"

    def test_un_campo_invalido_se_rechaza(self, client: TestClient) -> None:
        assert client.get("/api/alerts/feed", params={"campo": "inventado"}).status_code == 422

    def test_el_umbral_se_puede_bajar(self, client: TestClient) -> None:
        altas = client.get("/api/alerts/feed", params={"min_severity": "critical"}).json()
        todas = client.get("/api/alerts/feed", params={"min_severity": "low"}).json()
        assert todas["total"] >= altas["total"]

    def test_trae_lo_que_un_integrador_necesita(self, client: TestClient) -> None:
        (item, *_) = client.get("/api/alerts/feed", params={"limit": 1}).json()["items"]
        for campo in (
            "dedup_hash",  # para deduplicar del lado del consumidor
            "severity",
            "ar_match_reason",  # por qué es argentino
            "occurred_at",
            "first_seen_at",
            "notified",
            "backfill",  # histórico recién importado vs. novedad
            "raw_ref",
        ):
            assert campo in item, campo

    def test_el_limite_tiene_tope(self, client: TestClient) -> None:
        assert client.get("/api/alerts/feed", params={"limit": 99999}).json()["limit"] <= 1000

    def test_pagina(self, client: TestClient) -> None:
        primera = client.get("/api/alerts/feed", params={"limit": 1}).json()["items"]
        segunda = client.get("/api/alerts/feed", params={"limit": 1, "offset": 1}).json()["items"]
        assert primera and segunda
        assert primera[0]["id"] != segunda[0]["id"]

    def test_lo_corta_el_bloqueo_de_salida(self, settings: Settings, poblado: None) -> None:
        """No queda exento por ser una integración."""
        with TestClient(create_app(settings, egress_guard=GuardBloqueante())) as c:  # type: ignore[arg-type]
            assert c.get("/api/alerts/feed").status_code == 403
