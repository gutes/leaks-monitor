"""Tests del descubrimiento de subforos.

Ninguno toca la red: el barrido se hace contra respuestas simuladas.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from leaks.adapters.fid_discovery import (
    as_env_line,
    candidate_fids,
    discover_subforums,
    probe_subforum,
)
from leaks.adapters.http import FeedHttpClient
from leaks.adapters.mybb_forum import SYNDICATION_PATH

BASE = "https://foro.test"
from tests.conftest import read_fixture  # noqa: E402


def url_de(fid: str) -> str:
    return f"{BASE}{SYNDICATION_PATH}&fid={fid}"


@pytest.fixture
def client() -> FeedHttpClient:
    return FeedHttpClient(
        user_agent="leaks-monitor/test", max_retries=0, rate_limit_delay=0, sleep=lambda _s: None
    )


class TestRango:
    def test_arma_los_candidatos(self) -> None:
        assert candidate_fids(1, 4) == ("1", "2", "3", "4")

    def test_un_rango_invalido_no_sale_a_la_red(self) -> None:
        """Se valida antes de pegarle al foro, no en el request número 300."""
        with pytest.raises(ValueError, match="rango"):
            candidate_fids(10, 2)
        with pytest.raises(ValueError, match="rango"):
            candidate_fids(0, 5)


class TestSondeoDeUnSubforo:
    @respx.mock
    def test_devuelve_conteo_y_ventana(self, client: FeedHttpClient) -> None:
        respx.get(url_de("10")).mock(
            return_value=httpx.Response(200, text=read_fixture("darkforums_atom.xml"))
        )
        probe = probe_subforum(client, BASE, "10")

        assert probe is not None
        assert probe.fid == "10"
        assert probe.threads == 6
        assert probe.window_days is not None

    @respx.mock
    def test_un_subforo_vacio_no_se_reporta(self, client: FeedHttpClient) -> None:
        vacio = '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>'
        respx.get(url_de("3")).mock(return_value=httpx.Response(200, text=vacio))

        assert probe_subforum(client, BASE, "3") is None

    @respx.mock
    def test_una_respuesta_que_no_es_atom_no_rompe_el_barrido(self, client: FeedHttpClient) -> None:
        """Los subforos restringidos devuelven HTML. Es un "no", no una falla."""
        respx.get(url_de("17")).mock(
            return_value=httpx.Response(200, text="<html>Checking your browser...</html>")
        )

        assert probe_subforum(client, BASE, "17") is None

    @respx.mock
    def test_un_id_que_no_responde_es_un_no(self, client: FeedHttpClient) -> None:
        respx.get(url_de("99")).mock(return_value=httpx.Response(404))

        assert probe_subforum(client, BASE, "99") is None

    @respx.mock
    def test_el_titulo_de_muestra_va_redactado(self, client: FeedHttpClient) -> None:
        """En estos foros los títulos son avisos de volcados de datos."""
        atom = (
            '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry>'
            "<title>Base con contacto ejemplo@correo.test adentro</title>"
            "<published>2026-09-01T10:00:00Z</published>"
            '<link href="https://foro.test/showthread.php?tid=1"/>'
            "</entry></feed>"
        )
        respx.get(url_de("5")).mock(return_value=httpx.Response(200, text=atom))

        probe = probe_subforum(client, BASE, "5")

        assert probe is not None
        assert "ejemplo@correo.test" not in (probe.sample_title or "")


class TestBarrido:
    @respx.mock
    def test_ordena_por_ventana_descendente(self, client: FeedHttpClient) -> None:
        """Primero el que más historia conserva: es el que más cobertura suma."""

        def atom(desde: str, hasta: str) -> str:
            return (
                '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">'
                f"<entry><title>a</title><published>{desde}</published></entry>"
                f"<entry><title>b</title><published>{hasta}</published></entry>"
                "</feed>"
            )

        respx.get(url_de("1")).mock(
            return_value=httpx.Response(
                200, text=atom("2026-08-30T00:00:00Z", "2026-09-01T00:00:00Z")
            )
        )
        respx.get(url_de("2")).mock(
            return_value=httpx.Response(
                200, text=atom("2024-01-01T00:00:00Z", "2026-09-01T00:00:00Z")
            )
        )
        respx.get(url_de("3")).mock(return_value=httpx.Response(404))

        hallados = discover_subforums(client, BASE, ("1", "2", "3"))

        assert [p.fid for p in hallados] == ["2", "1"]

    def test_la_linea_del_env_sale_lista_para_pegar(self) -> None:
        from leaks.adapters.fid_discovery import SubforumProbe

        probes = (SubforumProbe(fid="10", threads=50), SubforumProbe(fid="25", threads=34))

        assert as_env_line("LEAKS_DARKFORUMS_FIDS", probes) == "LEAKS_DARKFORUMS_FIDS=10,25"
