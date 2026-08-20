"""Tests de la extracción de enlaces a los datos filtrados.

El prototipo guarda la **referencia**, nunca descarga el contenido. Y el
frontend la muestra no clickeable: son punteros a volcados de datos y a
infraestructura de quien los publicó.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from leaks.config import Settings
from leaks.extraction.downloads import MAX_LINKS, DownloadLink, extract_download_links
from leaks.pipeline.runner import PipelineRunner
from leaks.relevance.watchlist import Watchlist
from leaks.storage.models import FindingRow
from leaks.storage.repository import SqlAlchemyFindingRepository

MAGNET = "magnet:?xt=urn:btih:ABCDEF0123456789ABCDEF0123456789ABCDEF01&dn=dump"


class TestClasificacion:
    def test_magnet_es_volcado(self) -> None:
        (link,) = extract_download_links(f"Download: {MAGNET}")
        assert link.kind == "data"

    @pytest.mark.parametrize(
        "url",
        [
            "https://mega.nz/file/xY7z",
            "https://gofile.io/d/abc123",
            "https://pixeldrain.com/u/abcd",
            "https://cdn.test/dump-2026.torrent",
            "https://files.test/base.sql",
        ],
    )
    def test_file_hosts_y_extensiones_son_volcado(self, url: str) -> None:
        (link,) = extract_download_links(f"Mirror: {url}")
        assert link.kind == "data", url

    @pytest.mark.parametrize(
        "url", ["https://i.ibb.co/x/captura.png", "https://imgur.com/abc", "https://prnt.sc/xyz"]
    )
    def test_image_hosts_son_muestra(self, url: str) -> None:
        (link,) = extract_download_links(f"Sample: {url}")
        assert link.kind == "sample", url

    def test_un_enlace_comun_no_entra(self) -> None:
        """El enlace a la publicación ya se guarda en `raw_ref`."""
        assert extract_download_links("Ver https://ejemplo.com.ar/contacto") == ()

    def test_los_volcados_van_primero(self) -> None:
        texto = f"Sample: https://i.ibb.co/x/s.png\nDownload: {MAGNET}"
        enlaces = extract_download_links(texto)
        assert [link.kind for link in enlaces] == ["data", "sample"]

    def test_no_repite_el_mismo_enlace(self) -> None:
        assert len(extract_download_links(f"{MAGNET} y otra vez {MAGNET}")) == 1

    def test_tiene_tope(self) -> None:
        """Un thread puede pegar cincuenta espejos del mismo archivo."""
        texto = " ".join(f"https://mega.nz/file/n{i}" for i in range(40))
        assert len(extract_download_links(texto)) == MAX_LINKS

    def test_texto_vacio(self) -> None:
        assert extract_download_links(None, "") == ()

    def test_el_host_se_deriva(self) -> None:
        link = DownloadLink(url="https://mega.nz/file/xY7z", kind="data")
        assert link.host == "mega.nz"


class TestIntegracionConElPipeline:
    def test_se_extraen_del_cuerpo_aunque_no_se_persista(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        session_factory: object,
    ) -> None:
        """Clave: en los foros el cuerpo se descarta, pero los enlaces se guardan.

        El cuerpo trae las muestras de datos robados y no se persiste; el
        magnet sí, porque es la referencia que el investigador necesita.
        """
        from tests.test_pipeline import FakeAdapter, spec_for

        cuerpo = (
            f"Site: prevision-ejemplo.gob.ar\nDownload: {MAGNET}\nSample: https://i.ibb.co/x/s.png"
        )
        adapter = FakeAdapter(
            [
                {
                    "victim": "[DATABASE] Organismo AR",
                    "domain": None,
                    "country": None,
                    "discovered": datetime(2026, 8, 15, tzinfo=UTC),
                    "description": cuerpo,
                }
            ]
        )
        spec = spec_for(adapter)
        spec = type(spec)(**{**spec.__dict__, "high_pii_surface": True})

        PipelineRunner(repository=repository, watchlist=watchlist, settings=settings).run(
            [(spec, None)]
        )

        with session_factory() as session:  # type: ignore[operator]
            fila = session.query(FindingRow).one()

        # El cuerpo no se guardó...
        assert fila.description is None
        # ...pero los enlaces sí, clasificados.
        tipos = {d["kind"] for d in fila.download_links}
        assert tipos == {"data", "sample"}
        assert any(d["url"].startswith("magnet:") for d in fila.download_links)

    def test_sin_enlaces_queda_en_null(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        session_factory: object,
    ) -> None:
        from tests.test_pipeline import FakeAdapter, payload_ar, spec_for

        PipelineRunner(repository=repository, watchlist=watchlist, settings=settings).run(
            [(spec_for(FakeAdapter([payload_ar()])), None)]
        )
        with session_factory() as session:  # type: ignore[operator]
            assert session.query(FindingRow).one().download_links is None


class TestEnriquecimientoDeHallazgosConocidos:
    """Un hallazgo ya guardado puede adquirir enlaces en una corrida posterior."""

    def _con_enlaces(self, urls: tuple[str, ...]) -> tuple[DownloadLink, ...]:
        return tuple(DownloadLink(url=u, kind="data") for u in urls)

    def test_un_hallazgo_sin_enlaces_los_recibe_despues(
        self, repository: SqlAlchemyFindingRepository, session_factory: object
    ) -> None:
        from tests.conftest import make_finding

        sin = make_finding()
        repository.upsert_many([sin])

        con = make_finding().model_copy(update={"download_links": self._con_enlaces((MAGNET,))})
        # Mismo dedup_hash: es el mismo hallazgo, visto de nuevo.
        assert con.dedup_hash == sin.dedup_hash
        assert repository.upsert_many([con]) == 0, "no debe insertar una fila nueva"

        with session_factory() as session:  # type: ignore[operator]
            fila = session.query(FindingRow).one()
        assert fila.download_links is not None
        assert fila.download_links[0]["url"] == MAGNET

    def test_no_se_pisan_los_enlaces_ya_registrados(
        self, repository: SqlAlchemyFindingRepository, session_factory: object
    ) -> None:
        from tests.conftest import make_finding

        primero = make_finding().model_copy(
            update={"download_links": self._con_enlaces(("magnet:?xt=urn:btih:" + "A" * 32,))}
        )
        repository.upsert_many([primero])

        segundo = make_finding().model_copy(
            update={"download_links": self._con_enlaces(("https://otro.test/x.torrent",))}
        )
        repository.upsert_many([segundo])

        with session_factory() as session:  # type: ignore[operator]
            fila = session.query(FindingRow).one()
        assert fila.download_links[0]["url"].startswith("magnet:")
