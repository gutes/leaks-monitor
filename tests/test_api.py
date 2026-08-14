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
from tests.conftest import make_finding


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
    with TestClient(create_app(settings)) as c:
        yield c


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
        with TestClient(create_app(acotado)) as client:
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
        hudson = next(s for s in client.get("/api/sources").json() if s["name"] == "hudsonrock")
        assert hudson["enabled"] is False
        assert hudson["requires_pii"] is True
        assert "STORE_PII" in (hudson["skip_reason"] or "")

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
        with TestClient(create_app(sin_ui)) as client:
            assert client.get("/api/health").status_code == 200
            assert client.get("/").status_code == 404

    def test_el_frontend_se_sirve_desde_la_ruta_configurada(
        self, settings: Settings, poblado: None, tmp_path: Path
    ) -> None:
        ui = tmp_path / "ui"
        ui.mkdir()
        (ui / "index.html").write_text("<h1>otra ui</h1>", encoding="utf-8")

        with TestClient(create_app(settings.model_copy(update={"frontend_dir": ui}))) as client:
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
        with TestClient(create_app(settings)) as primero:
            primero.patch("/api/settings/pii-sources", json={"enabled": True})

        with TestClient(create_app(settings)) as segundo:
            assert segundo.get("/api/health").json()["pii_sources_enabled"] is True
