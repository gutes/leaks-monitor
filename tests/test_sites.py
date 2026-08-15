"""Tests del catálogo de sitios de leaks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from sqlalchemy.orm import Session, sessionmaker

from leaks.adapters.http import FeedHttpClient
from leaks.sites.collector import SiteCatalogCollector
from leaks.sites.registries import (
    DLS_MONITOR_GROUPS,
    RANSOMWARE_LIVE_GROUPS,
    SiteLocation,
    fetch_dls_monitor,
    fetch_ransomware_live,
)
from leaks.storage.site_repository import LeakSiteRepository

GRUPOS_RW = [
    {
        "name": "AlphaGroup",
        "locations": [
            {"fqdn": "abc123.onion", "available": True, "title": "Blog"},
            {"fqdn": "https://espejo.test/", "available": False},
        ],
    },
    {"name": "SinUbicaciones", "locations": []},
    {"name": "Malformado"},
]


@pytest.fixture
def client() -> FeedHttpClient:
    return FeedHttpClient(
        user_agent="test", max_retries=0, rate_limit_delay=0, sleep=lambda _s: None
    )


@pytest.fixture
def repo(session_factory: sessionmaker[Session]) -> LeakSiteRepository:
    return LeakSiteRepository(session_factory)


class TestLectura:
    @respx.mock
    def test_normaliza_las_ubicaciones(self, client: FeedHttpClient) -> None:
        respx.get(RANSOMWARE_LIVE_GROUPS).mock(return_value=httpx.Response(200, json=GRUPOS_RW))
        ubicaciones = fetch_ransomware_live(client)

        assert len(ubicaciones) == 2
        # El nombre se normaliza y la URL queda como host pelado.
        assert {u.group_name for u in ubicaciones} == {"alphagroup"}
        assert "espejo.test" in {u.fqdn for u in ubicaciones}
        assert all("https://" not in u.fqdn for u in ubicaciones)

    @respx.mock
    def test_un_grupo_malformado_no_rompe(self, client: FeedHttpClient) -> None:
        respx.get(DLS_MONITOR_GROUPS).mock(
            return_value=httpx.Response(200, json=[{"sin": "nombre"}, "texto suelto"])
        )
        assert fetch_dls_monitor(client) == []


class TestConsolidacion:
    def _loc(self, grupo: str, fqdn: str, **extra: object) -> SiteLocation:
        return SiteLocation(group_name=grupo, fqdn=fqdn, source="prueba", **extra)  # type: ignore[arg-type]

    def test_una_ubicacion_reportada_por_dos_registros_es_una_sola_fila(
        self, repo: LeakSiteRepository
    ) -> None:
        resultado = repo.upsert_locations(
            [
                SiteLocation(group_name="akira", fqdn="a.onion", source="ransomware.live"),
                SiteLocation(group_name="akira", fqdn="a.onion", source="dls-monitor"),
            ]
        )
        assert resultado.new == 1

        items, total = repo.list_sites()
        assert total == 1
        assert sorted(items[0]["sources"]) == ["dls-monitor", "ransomware.live"]

    def test_es_idempotente(self, repo: LeakSiteRepository) -> None:
        repo.upsert_locations([self._loc("akira", "a.onion")])
        segunda = repo.upsert_locations([self._loc("akira", "a.onion")])

        assert segunda.new == 0
        assert repo.counts()["total"] == 1

    def test_una_ubicacion_nueva_de_un_grupo_conocido_es_una_mudanza(
        self, repo: LeakSiteRepository
    ) -> None:
        """Es la señal por la que existe el catálogo."""
        repo.upsert_locations([self._loc("akira", "vieja.onion")])
        resultado = repo.upsert_locations([self._loc("akira", "nueva.onion")])

        assert resultado.new == 1
        assert any("akira" in m and "nueva.onion" in m for m in resultado.moved)

    def test_un_grupo_nuevo_no_cuenta_como_mudanza(self, repo: LeakSiteRepository) -> None:
        resultado = repo.upsert_locations([self._loc("recien-visto", "x.onion")])
        assert resultado.new == 1
        assert resultado.moved == ()

    def test_first_seen_no_se_pisa(self, repo: LeakSiteRepository) -> None:
        """Es lo que permite decir "este dominio apareció el martes"."""
        repo.upsert_locations([self._loc("akira", "a.onion")])
        primero = repo.list_sites()[0][0]["first_seen_at"]

        repo.upsert_locations([self._loc("akira", "a.onion", available=True)])
        assert repo.list_sites()[0][0]["first_seen_at"] == primero

    def test_la_disponibilidad_se_actualiza(self, repo: LeakSiteRepository) -> None:
        repo.upsert_locations([self._loc("akira", "a.onion", available=False)])
        repo.upsert_locations([self._loc("akira", "a.onion", available=True)])

        item = repo.list_sites()[0][0]
        assert item["available"] is True
        assert item["last_available_at"] is not None


class TestConsulta:
    def test_filtros_y_paginado(self, repo: LeakSiteRepository) -> None:
        repo.upsert_locations(
            [
                SiteLocation(
                    group_name=f"g{i}", fqdn=f"s{i}.onion", source="x", available=i % 2 == 0
                )
                for i in range(10)
            ]
        )
        _, total = repo.list_sites()
        assert total == 10

        vivos, total_vivos = repo.list_sites(available=True)
        assert total_vivos == 5
        assert all(v["available"] for v in vivos)

        pagina, _ = repo.list_sites(limit=3)
        assert len(pagina) == 3

    def test_busqueda_por_grupo_o_dominio(self, repo: LeakSiteRepository) -> None:
        repo.upsert_locations(
            [
                SiteLocation(group_name="akira", fqdn="uno.onion", source="x"),
                SiteLocation(group_name="lockbit", fqdn="dos.onion", source="x"),
            ]
        )
        assert repo.list_sites(q="akira")[1] == 1
        assert repo.list_sites(q="dos.onion")[1] == 1

    def test_mudanzas_recientes(self, repo: LeakSiteRepository) -> None:
        repo.upsert_locations([SiteLocation(group_name="akira", fqdn="a.onion", source="x")])
        assert len(repo.recent_moves(days=7)) == 1
        # Con una ventana en el futuro no hay nada "reciente" hacia atrás.
        assert repo.recent_moves(days=1) != ()


class TestColector:
    @respx.mock
    def test_un_registro_caido_no_frena_a_los_demas(
        self, repo: LeakSiteRepository, client: FeedHttpClient
    ) -> None:
        respx.get(RANSOMWARE_LIVE_GROUPS).mock(return_value=httpx.Response(500))
        respx.get(DLS_MONITOR_GROUPS).mock(
            return_value=httpx.Response(
                200, json=[{"name": "grupo", "locations": [{"fqdn": "x.onion"}]}]
            )
        )
        respx.get(url__startswith="https://www.ransomlook.io").mock(
            return_value=httpx.Response(200, json=[])
        )

        collector = SiteCatalogCollector(repo, lambda: client)
        resultado, fallidos = collector.collect()

        assert "ransomware.live" in fallidos
        assert resultado.new == 1, "lo que sí respondió tiene que guardarse"

    @respx.mock
    def test_si_fallan_todos_no_lanza(
        self, repo: LeakSiteRepository, client: FeedHttpClient
    ) -> None:
        """El catálogo no puede costar la corrida."""
        respx.get(url__regex=r".*").mock(return_value=httpx.Response(500))

        resultado, fallidos = SiteCatalogCollector(repo, lambda: client).collect()
        assert resultado.new == 0
        assert len(fallidos) == 3


class TestCruceConHallazgosArgentinos:
    """Que un grupo cualquiera se mude es dato; que se mude uno que ya golpeó
    acá es una alerta. Ese es el cruce."""

    def test_cuenta_los_hallazgos_por_actor(
        self, repo: LeakSiteRepository, repository: object
    ) -> None:
        from tests.conftest import make_finding

        repository.upsert_many(  # type: ignore[attr-defined]
            [
                make_finding(victim_name="Uno", victim_domain="uno.gob.ar", actor="LockBit"),
                make_finding(victim_name="Dos", victim_domain="dos.gob.ar", actor="lockbit"),
                make_finding(victim_name="Tres", victim_domain="tres.gob.ar", actor="Akira"),
            ]
        )
        impacto = repo.ar_impact_by_group()

        # Se normaliza a minúsculas: los feeds escriben el nombre como quieren.
        assert impacto["lockbit"] == 2
        assert impacto["akira"] == 1

    def test_una_mudanza_de_grupo_con_impacto_ar_se_distingue(
        self, repo: LeakSiteRepository, repository: object
    ) -> None:
        from tests.conftest import make_finding

        repository.upsert_many(  # type: ignore[attr-defined]
            [make_finding(victim_domain="x.gob.ar", actor="lockbit")]
        )
        # Se conocen dos grupos; solo uno tiene hallazgos argentinos.
        repo.upsert_locations(
            [
                SiteLocation(group_name="lockbit", fqdn="vieja.onion", source="x"),
                SiteLocation(group_name="otrogrupo", fqdn="vieja2.onion", source="x"),
            ]
        )

        resultado = repo.upsert_locations(
            [
                SiteLocation(group_name="lockbit", fqdn="nueva.onion", source="x"),
                SiteLocation(group_name="otrogrupo", fqdn="nueva2.onion", source="x"),
            ]
        )

        assert len(resultado.moved) == 2, "las dos son mudanzas"
        assert len(resultado.moved_ar) == 1, "solo una afecta a Argentina"
        assert "lockbit" in resultado.moved_ar[0]

    def test_el_listado_anota_el_impacto(
        self, repo: LeakSiteRepository, repository: object
    ) -> None:
        from tests.conftest import make_finding

        repository.upsert_many(  # type: ignore[attr-defined]
            [make_finding(victim_domain="x.gob.ar", actor="lockbit")]
        )
        repo.upsert_locations(
            [
                SiteLocation(group_name="lockbit", fqdn="a.onion", source="x"),
                SiteLocation(group_name="otro", fqdn="b.onion", source="x"),
            ]
        )
        items, _ = repo.list_sites()
        por_grupo = {i["group_name"]: i["ar_findings"] for i in items}

        assert por_grupo["lockbit"] == 1
        assert por_grupo["otro"] == 0

    def test_filtro_solo_grupos_con_impacto_ar(
        self, repo: LeakSiteRepository, repository: object
    ) -> None:
        from tests.conftest import make_finding

        repository.upsert_many(  # type: ignore[attr-defined]
            [make_finding(victim_domain="x.gob.ar", actor="lockbit")]
        )
        repo.upsert_locations(
            [
                SiteLocation(group_name="lockbit", fqdn="a.onion", source="x"),
                SiteLocation(group_name="otro", fqdn="b.onion", source="x"),
            ]
        )
        items, total = repo.list_sites(ar_only=True)

        assert total == 1
        assert items[0]["group_name"] == "lockbit"

    def test_sin_hallazgos_el_filtro_no_devuelve_todo(self, repo: LeakSiteRepository) -> None:
        """Sin actores conocidos el filtro tiene que vaciar, no listar todo."""
        repo.upsert_locations([SiteLocation(group_name="otro", fqdn="b.onion", source="x")])
        assert repo.list_sites(ar_only=True)[1] == 0

    def test_las_mudanzas_ar_van_primero(
        self, repo: LeakSiteRepository, repository: object
    ) -> None:
        from tests.conftest import make_finding

        repository.upsert_many(  # type: ignore[attr-defined]
            [make_finding(victim_domain="x.gob.ar", actor="lockbit")]
        )
        repo.upsert_locations(
            [
                SiteLocation(group_name="aaa-primero-alfabetico", fqdn="a.onion", source="x"),
                SiteLocation(group_name="lockbit", fqdn="b.onion", source="x"),
            ]
        )
        recientes = repo.recent_moves(days=7)
        assert recientes[0]["group_name"] == "lockbit"


class TestFrescuraDelEstado:
    """El estado lo reporta el registro; nosotros no verificamos nada."""

    def test_se_guarda_cuando_lo_revisó_el_registro(self, repo: LeakSiteRepository) -> None:
        revisado = datetime.now(UTC) - timedelta(hours=3)
        repo.upsert_locations(
            [
                SiteLocation(
                    group_name="g", fqdn="a.onion", source="dls-monitor", checked_at=revisado
                )
            ]
        )
        assert repo.list_sites()[0][0]["checked_at"] is not None

    def test_sin_fecha_publicada_queda_en_none(self, repo: LeakSiteRepository) -> None:
        """ransomware.live no manda marca de tiempo: no se inventa frescura."""
        repo.upsert_locations(
            [SiteLocation(group_name="g", fqdn="a.onion", source="ransomware.live")]
        )
        assert repo.list_sites()[0][0]["checked_at"] is None
