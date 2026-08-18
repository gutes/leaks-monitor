"""Tests de los adapters de feed.

Ningún test toca la red: `respx` intercepta el transporte de httpx y responde
con las fixtures capturadas de cada feed.

Lo que se verifica en todos por igual:

* que el mapeo al schema común sea correcto para las dos formas que devuelve
  cada endpoint;
* que un registro malformado devuelva `None` en vez de romper la ingesta;
* que la PII que traiga el feed **no** llegue al modelo normalizado.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from leaks.adapters.dls_monitor import POSTS_URL, DlsMonitorAdapter
from leaks.adapters.http import FeedHttpClient
from leaks.adapters.hudson_rock import PII_KEYS, HudsonRockAdapter
from leaks.adapters.ransomlook import RansomLookAdapter
from leaks.adapters.ransomware_live import BASE_URL, RansomwareLiveAdapter
from leaks.domain.models import LeakType, RawItem
from tests.conftest import read_fixture


@pytest.fixture
def client() -> FeedHttpClient:
    """Cliente sin esperas: los delays reales harían lentos los tests."""
    return FeedHttpClient(
        user_agent="leaks-monitor/test",
        max_retries=1,
        rate_limit_delay=0,
        sleep=lambda _s: None,
    )


class TestRansomwareLive:
    """Adapter de ransomware.live: dos endpoints con nombres de campo distintos."""

    @respx.mock
    def test_fetch_combina_los_dos_endpoints(self, client: FeedHttpClient) -> None:
        respx.get(f"{BASE_URL}/countryvictims/AR").mock(
            return_value=httpx.Response(
                200, text=read_fixture("ransomware_live_countryvictims_ar.json")
            )
        )
        respx.get(f"{BASE_URL}/recentvictims").mock(
            return_value=httpx.Response(
                200, text=read_fixture("ransomware_live_recentvictims.json")
            )
        )

        items = list(RansomwareLiveAdapter(client).fetch(None))

        # El índice AR es preciso pero incompleto; el global lo complementa.
        assert len(items) == 12
        assert all(i.source == "ransomware.live" for i in items)

    def test_normaliza_la_forma_del_endpoint_ar(self, client: FeedHttpClient) -> None:
        """`countryvictims` usa `group_name`/`post_title`/`website`."""
        payload = json.loads(read_fixture("ransomware_live_countryvictims_ar.json"))[0]
        item = RansomwareLiveAdapter(client).normalize(
            RawItem(source="ransomware.live", payload=payload)
        )

        assert item is not None
        assert item.victim_name == payload["post_title"]
        assert item.actor == payload["group_name"]
        assert item.country == "AR"
        assert item.leak_type is LeakType.RANSOMWARE
        assert item.discovered_at.tzinfo is not None

    def test_normaliza_la_forma_del_endpoint_global(self, client: FeedHttpClient) -> None:
        """`recentvictims` usa `group`/`victim`/`domain`: mismo schema de salida."""
        payload = json.loads(read_fixture("ransomware_live_recentvictims.json"))[0]
        item = RansomwareLiveAdapter(client).normalize(
            RawItem(source="ransomware.live", payload=payload)
        )

        assert item is not None
        assert item.victim_name == payload["victim"]
        assert item.actor == payload["group"]

    @pytest.mark.parametrize(
        ("payload", "motivo"),
        [
            ({"discovered": "2026-08-13T10:00:00Z"}, "sin víctima"),
            ({"victim": "Acme"}, "sin fecha usable"),
            ({}, "vacío"),
        ],
    )
    def test_registro_inservible_devuelve_none(
        self, client: FeedHttpClient, payload: dict[str, object], motivo: str
    ) -> None:
        """Un registro roto se descarta; no puede cortar la ingesta."""
        item = RansomwareLiveAdapter(client).normalize(
            RawItem(source="ransomware.live", payload=payload)
        )
        assert item is None, motivo

    def test_no_copia_la_pii_del_feed(self, client: FeedHttpClient) -> None:
        """`infostealer` y `last_user_compromised` traen emails: nunca se copian."""
        payload = {
            "victim": "Ministerio X",
            "domain": "x.gob.ar",
            "discovered": "2026-08-13T10:00:00Z",
            "infostealer": {
                "last_employee_compromised": "empleado@x.gob.ar",
                "last_user_compromised": "persona@gmail.com",
            },
        }
        item = RansomwareLiveAdapter(client).normalize(
            RawItem(source="ransomware.live", payload=payload)
        )

        assert item is not None
        serializado = item.model_dump_json()
        assert "empleado@x.gob.ar" not in serializado
        assert "persona@gmail.com" not in serializado


class TestRansomLook:
    """Adapter de RansomLook: sin país ni dominio estructurado."""

    @respx.mock
    def test_fetch_devuelve_los_posts_recientes(self, client: FeedHttpClient) -> None:
        respx.get("https://www.ransomlook.io/api/recent").mock(
            return_value=httpx.Response(200, text=read_fixture("ransomlook_recent.json"))
        )
        items = list(RansomLookAdapter(client).fetch(None))
        assert len(items) == 7
        assert all(i.source == "ransomlook" for i in items)

    def test_usa_el_titulo_como_dominio_cuando_lo_es(self, client: FeedHttpClient) -> None:
        """El feed pone el dominio en el título: así lo levanta la regla tld_ar."""
        item = RansomLookAdapter(client).normalize(
            RawItem(
                source="ransomlook",
                payload={
                    "post_title": "aguas-ejemplo.com.ar",
                    "discovered": "2026-08-12 10:15:02.123456",
                    "group_name": "safepay",
                    "link": "/blog/post/aysacomar/",
                },
            )
        )
        assert item is not None
        assert item.victim_domain == "aguas-ejemplo.com.ar"
        assert item.actor == "safepay"
        # El link viene relativo y tiene que salir absoluto para el frontend.
        assert item.raw_ref == "https://www.ransomlook.io/blog/post/aysacomar/"

    def test_titulo_que_no_es_dominio_no_inventa_uno(self, client: FeedHttpClient) -> None:
        item = RansomLookAdapter(client).normalize(
            RawItem(
                source="ransomlook",
                payload={
                    "post_title": "Columbia University Information",
                    "discovered": "2026-08-14 18:34:36.997612",
                },
            )
        )
        assert item is not None
        assert item.victim_domain is None


class TestDlsMonitor:
    """Adapter de dls-monitor: histórico completo, recorte incremental propio."""

    @respx.mock
    def test_sin_cursor_trae_todo(self, client: FeedHttpClient) -> None:
        respx.get(POSTS_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("dls_monitor_posts.json"))
        )
        items = list(DlsMonitorAdapter(client).fetch(None))
        assert len(items) == 10

    @respx.mock
    def test_con_cursor_descarta_lo_viejo_en_el_fetch(self, client: FeedHttpClient) -> None:
        """El recorte va en el fetch: normalizar 14.000 posts por corrida es tirar CPU."""
        respx.get(POSTS_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("dls_monitor_posts.json"))
        )
        desde = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
        items = list(DlsMonitorAdapter(client).fetch(desde))

        assert 0 < len(items) < 10
        for item in items:
            assert item.payload["discovered"] > desde.strftime("%Y-%m-%d %H:%M:%S")

    def test_normaliza_lo_minimo_que_trae(self, client: FeedHttpClient) -> None:
        item = DlsMonitorAdapter(client).normalize(
            RawItem(
                source="dls-monitor",
                payload={
                    "post_title": "obrasocial-ejemplo.com.ar",
                    "group_name": "lockbit3",
                    "discovered": "2026-08-11 09:00:00.000000",
                },
            )
        )
        assert item is not None
        assert item.victim_domain == "obrasocial-ejemplo.com.ar"
        assert item.country is None
        # No hay texto libre en este feed: nada que scrubbear.
        assert item.description is None


class TestHudsonRock:
    """Adapter de infostealers: conteos sí, identidades no."""

    def test_sin_dominios_configurados_no_hace_ningun_request(self, client: FeedHttpClient) -> None:
        """El default es no hablarle al proveedor extranjero."""
        # respx no está activo: si intentara salir a la red, el test fallaría.
        assert list(HudsonRockAdapter(client, domains=()).fetch(None)) == []

    @respx.mock
    def test_consulta_solo_los_dominios_listados_a_mano(self, client: FeedHttpClient) -> None:
        """No lee la watchlist: consultar un dominio es una decisión explícita."""
        ruta = respx.get(url__startswith="https://cavalier.hudsonrock.com").mock(
            return_value=httpx.Response(200, json={"total": 3, "employees": 1, "users": 2})
        )
        items = list(HudsonRockAdapter(client, domains=("prevision-ejemplo.gob.ar",)).fetch(None))

        assert len(items) == 1
        assert ruta.call_count == 1
        assert items[0].payload["_queried_domain"] == "prevision-ejemplo.gob.ar"

    def test_normaliza_a_conteos_sin_identidades(self, client: FeedHttpClient) -> None:
        """La respuesta trae emails; a `findings` solo llegan números."""
        payload = {
            "_queried_domain": "prevision-ejemplo.gob.ar",
            "total": 2,
            "employees": ["empleado@prevision-ejemplo.gob.ar"],
            "users": ["persona@gmail.com"],
            "data": {"credentials": [{"password": "hunter2"}]},
        }
        item = HudsonRockAdapter(client, domains=()).normalize(
            RawItem(source="hudsonrock", payload=payload)
        )

        assert item is not None
        assert item.leak_type is LeakType.INFOSTEALER
        assert item.victim_domain == "prevision-ejemplo.gob.ar"

        serializado = item.model_dump_json()
        for rastro in ("empleado@prevision-ejemplo.gob.ar", "persona@gmail.com", "hunter2"):
            assert rastro not in serializado
        # El conteo sí sobrevive: es la señal, sin la identidad.
        assert "1 empleados" in (item.description or "")

    def test_dominio_limpio_no_genera_hallazgo(self, client: FeedHttpClient) -> None:
        item = HudsonRockAdapter(client, domains=()).normalize(
            RawItem(
                source="hudsonrock",
                payload={"_queried_domain": "prevision-ejemplo.gob.ar", "total": 0},
            )
        )
        assert item is None

    def test_las_claves_con_pii_estan_declaradas(self) -> None:
        """Documenta qué campos se dejan afuera a propósito."""
        assert "employees" in PII_KEYS
        assert "credentials" in PII_KEYS


class TestFechadoDeHudsonRock:
    """Regresión: el adapter fechaba todo con `now()` y su histórico se veía
    como novedad del día. El proveedor sí manda fechas; las ignorábamos."""

    def test_usa_la_fecha_real_del_compromiso(self, client: FeedHttpClient) -> None:
        item = HudsonRockAdapter(client, domains=()).normalize(
            RawItem(
                source="hudsonrock",
                payload={
                    "_queried_domain": "prevision-ejemplo.gob.ar",
                    "total": 5,
                    "last_employee_compromised": "2026-05-26T16:57:25.000Z",
                    "last_user_compromised": "1970-01-01T00:00:00.000Z",
                },
            )
        )
        assert item is not None
        assert item.occurred_at is not None
        assert item.occurred_at.year == 2026
        assert item.occurred_at.month == 5

    def test_el_centinela_epoch_no_fecha_nada(self, client: FeedHttpClient) -> None:
        """1970 es "sin dato" del proveedor, no un leak de los setenta."""
        item = HudsonRockAdapter(client, domains=()).normalize(
            RawItem(
                source="hudsonrock",
                payload={
                    "_queried_domain": "x.gob.ar",
                    "total": 3,
                    "last_employee_compromised": "1970-01-01T00:00:00.000Z",
                    "last_user_compromised": "1970-01-01T00:00:00.000Z",
                },
            )
        )
        assert item is not None
        assert item.occurred_at is None, "sin fecha creíble, se dice sin fecha"

    def test_sin_campos_de_fecha_no_inventa(self, client: FeedHttpClient) -> None:
        """El corazón del bug: antes acá se ponía `now()`."""
        item = HudsonRockAdapter(client, domains=()).normalize(
            RawItem(source="hudsonrock", payload={"_queried_domain": "x.gob.ar", "total": 2})
        )
        assert item is not None
        assert item.occurred_at is None

    def test_los_campos_de_fecha_ya_no_estan_en_pii_keys(self) -> None:
        """Eran timestamps, no identidades: la suposición estaba mal."""
        from leaks.adapters.hudson_rock import DATE_KEYS

        assert "last_employee_compromised" not in PII_KEYS
        assert "last_employee_compromised" in DATE_KEYS
        # Lo que sí es PII sigue estándolo.
        assert "credentials" in PII_KEYS
