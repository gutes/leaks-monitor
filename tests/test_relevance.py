"""Tests de la capa de relevancia argentina y de la derivación de severidad."""

from __future__ import annotations

from pathlib import Path

import pytest

from leaks.domain.models import ArMatchReason, LeakType, Severity
from leaks.relevance.rules import evaluate, extract_domains
from leaks.relevance.severity import derive_severity
from leaks.relevance.watchlist import Watchlist, load_watchlist
from tests.conftest import WATCHLIST_DE_PRUEBA, make_normalized


@pytest.fixture(scope="module")
def watchlist() -> Watchlist:
    """La watchlist versionada del repo: se valida el dato, no un doble.

    Es la de EJEMPLO, con dominios ficticios: la real está en `.gitignore`
    porque dice qué organismos vigila la investigación, y la suite tiene que
    pasar en un clon limpio.
    """
    return load_watchlist(WATCHLIST_DE_PRUEBA)


class TestWatchlist:
    def test_carga_los_sectores_del_seed(self, watchlist: Watchlist) -> None:
        nombres = {s.name for s in watchlist.sectors}
        assert {"gobierno_nacional", "energia", "telecomunicaciones"} <= nombres

    def test_matchea_dominio_exacto(self, watchlist: Watchlist) -> None:
        sector = watchlist.match_domain("prevision-ejemplo.gob.ar")
        assert sector is not None
        assert sector.name == "gobierno_nacional"

    def test_matchea_subdominios(self, watchlist: Watchlist) -> None:
        """La regla del bootstrap cubre "y sus subdominios"."""
        sector = watchlist.match_domain("datos.internos.prevision-ejemplo.gob.ar")
        assert sector is not None
        assert sector.name == "gobierno_nacional"

    def test_ignora_www_y_mayusculas(self, watchlist: Watchlist) -> None:
        assert watchlist.match_domain("WWW.Prevision-Ejemplo.GOB.AR") is not None

    def test_no_matchea_un_dominio_ajeno(self, watchlist: Watchlist) -> None:
        assert watchlist.match_domain("acme.com") is None

    def test_no_matchea_por_sufijo_enganoso(self, watchlist: Watchlist) -> None:
        """`noprevision-ejemplo.gob.ar` no es `prevision-ejemplo.gob.ar`."""
        sector = watchlist.match_domain("noprevision-ejemplo.gob.ar")
        assert sector is None or sector.name != "gobierno_nacional"

    def test_keywords_ignoran_acentos(self, watchlist: Watchlist) -> None:
        assert watchlist.match_keywords("filtración de Cancillería Ejemplo")

    def test_keywords_respetan_limite_de_palabra(self, watchlist: Watchlist) -> None:
        """ "ARCA" no debe pegar dentro de "arcade"."""
        matches = watchlist.match_keywords("vendo rejendija y rejero")
        assert [k for k, _ in matches if k == "REJE"] == []

    def test_descarta_keywords_demasiado_cortas(self, tmp_path: Path) -> None:
        yaml_corto = tmp_path / "w.yaml"
        yaml_corto.write_text(
            "version: 1\n"
            "sectors:\n"
            "  - name: t\n"
            "    critical: false\n"
            "    domains: []\n"
            "    keywords: ['AR', 'Prevision Ejemplo']\n",
            encoding="utf-8",
        )
        cargada = load_watchlist(yaml_corto)
        assert cargada.sectors[0].keywords == ("Prevision Ejemplo",)

    def test_falla_si_no_existe(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_watchlist(tmp_path / "no-existe.yaml")


class TestExtraccionDeDominios:
    def test_toma_el_dominio_estructurado(self) -> None:
        item = make_normalized(victim_domain="www.X.GOB.AR")
        assert "x.gob.ar" in extract_domains(item)

    def test_saca_dominios_del_texto_libre(self) -> None:
        """Necesario para foros y RansomLook, que no traen campo `domain`."""
        item = make_normalized(victim_name="Leak de banco.com.ar y otra cosa")
        assert "banco.com.ar" in extract_domains(item)

    def test_deduplica(self) -> None:
        item = make_normalized(
            victim_domain="x.gob.ar",
            victim_name="x.gob.ar dump",
            description="mirror de www.x.gob.ar",
        )
        assert extract_domains(item).count("x.gob.ar") == 1


class TestReglasDeRelevancia:
    def test_ejemplo_1_del_bootstrap_matchea(self, watchlist: Watchlist) -> None:
        """Ministerio X / x.gob.ar / AR -> watchlist + tld_ar + country_ar."""
        item = make_normalized(
            victim_name="Ministerio X",
            victim_domain="x.gob.ar",
            country="AR",
        )
        veredicto = evaluate(item, watchlist)

        assert veredicto.is_match
        assert set(veredicto.reasons) >= {
            ArMatchReason.TLD_AR,
            ArMatchReason.COUNTRY_AR,
        }

    def test_ejemplo_2_del_bootstrap_no_matchea(self, watchlist: Watchlist) -> None:
        """Acme Corp / acme.com / US -> ninguna regla dispara."""
        item = make_normalized(
            victim_name="Acme Corp",
            victim_domain="acme.com",
            country="US",
        )
        veredicto = evaluate(item, watchlist)

        assert not veredicto.is_match
        assert veredicto.reasons == ()

    def test_watchlist_dispara_y_asigna_sector(self, watchlist: Watchlist) -> None:
        item = make_normalized(
            victim_name="Prevision Ejemplo", victim_domain="prevision-ejemplo.gob.ar"
        )
        veredicto = evaluate(item, watchlist)

        assert ArMatchReason.WATCHLIST in veredicto.reasons
        assert veredicto.sector is not None
        assert veredicto.sector.name == "gobierno_nacional"

    @pytest.mark.parametrize(
        "dominio",
        ["algo.com.ar", "cosa.org.ar", "u.edu.ar", "x.mil.ar", "y.gov.ar", "z.ar"],
    )
    def test_cualquier_tld_ar_dispara(self, watchlist: Watchlist, dominio: str) -> None:
        item = make_normalized(victim_domain=dominio)
        assert ArMatchReason.TLD_AR in evaluate(item, watchlist).reasons

    @pytest.mark.parametrize("pais", ["AR", "ar", "ARG", "Argentina", "argentina"])
    def test_variantes_de_pais(self, watchlist: Watchlist, pais: str) -> None:
        item = make_normalized(country=pais)
        assert ArMatchReason.COUNTRY_AR in evaluate(item, watchlist).reasons

    def test_cuit_valido_dispara(self, watchlist: Watchlist) -> None:
        item = make_normalized(description="cliente CUIT 33-69345023-9")
        assert ArMatchReason.CUIT_VALID in evaluate(item, watchlist).reasons

    def test_cuit_invalido_no_dispara(self, watchlist: Watchlist) -> None:
        item = make_normalized(description="ref 33-69345023-1")
        assert ArMatchReason.CUIT_VALID not in evaluate(item, watchlist).reasons

    def test_keyword_dispara_sin_dominio(self, watchlist: Watchlist) -> None:
        """Caso típico de foro: el título nombra al organismo, no al dominio."""
        item = make_normalized(victim_name="Database dump - REGISTRO EJEMPLO 2026")
        veredicto = evaluate(item, watchlist)

        assert ArMatchReason.KEYWORD in veredicto.reasons
        assert "REGISTRO EJEMPLO" in veredicto.matched_keywords


class TestAuditabilidad:
    def test_guarda_la_evidencia_de_cada_regla(self, watchlist: Watchlist) -> None:
        item = make_normalized(
            victim_name="Prevision Ejemplo leak",
            victim_domain="prevision-ejemplo.gob.ar",
            country="AR",
        )
        detalle = evaluate(item, watchlist).detail

        assert detalle["watchlist"] == ["prevision-ejemplo.gob.ar"]
        assert detalle["tld_ar"] == ["prevision-ejemplo.gob.ar"]
        assert detalle["country_ar"] == ["AR"]

    def test_el_cuit_se_guarda_enmascarado(self, watchlist: Watchlist) -> None:
        """El número completo sería PII: en la evidencia va solo el prefijo."""
        item = make_normalized(description="CUIT 33-69345023-9")
        detalle = evaluate(item, watchlist).detail

        assert detalle["cuit_valid"] == ["33-********-*"]
        assert "33693450239" not in str(detalle)


class TestSeveridad:
    def test_gob_ar_es_critica(self, watchlist: Watchlist) -> None:
        item = make_normalized(victim_domain="prevision-ejemplo.gob.ar")
        veredicto = evaluate(item, watchlist)
        assert derive_severity(veredicto, LeakType.RANSOMWARE) is Severity.CRITICAL

    def test_infraestructura_critica_es_critica(self, watchlist: Watchlist) -> None:
        item = make_normalized(
            victim_name="DISTRIBUIDORA EJEMPLO", victim_domain="energia-ejemplo.com.ar"
        )
        veredicto = evaluate(item, watchlist)
        assert derive_severity(veredicto, LeakType.RANSOMWARE) is Severity.CRITICAL

    def test_empresa_ar_fuera_de_watchlist_es_media(self, watchlist: Watchlist) -> None:
        item = make_normalized(victim_name="Pyme", victim_domain="pyme.com.ar")
        veredicto = evaluate(item, watchlist)
        assert derive_severity(veredicto, LeakType.RANSOMWARE) is Severity.MEDIUM

    def test_solo_pais_es_media(self, watchlist: Watchlist) -> None:
        item = make_normalized(victim_name="Sin dominio", country="AR")
        veredicto = evaluate(item, watchlist)
        assert derive_severity(veredicto, LeakType.RANSOMWARE) is Severity.MEDIUM

    def test_infostealer_ar_escala_a_alta(self, watchlist: Watchlist) -> None:
        item = make_normalized(victim_name="Pyme", country="AR")
        veredicto = evaluate(item, watchlist)
        assert derive_severity(veredicto, LeakType.INFOSTEALER) is Severity.HIGH

    def test_solo_keyword_es_baja(self, watchlist: Watchlist) -> None:
        """Match débil: se reporta, pero no compite con un .gob.ar confirmado."""
        item = make_normalized(victim_name="curso sobre Ciencia Ejemplo")
        veredicto = evaluate(item, watchlist)
        assert derive_severity(veredicto, LeakType.FORUM_POST) is Severity.LOW

    def test_keyword_de_sector_critico_sin_corroborar_no_es_critica(
        self, watchlist: Watchlist
    ) -> None:
        """Regresión de un falso positivo real encontrado en la primera corrida.

        El caso original fue una distribuidora eléctrica de otro país que
        comparte nombre con una argentina: matcheaba la keyword del sector
        energía y, como está marcado infraestructura crítica, salía con
        severidad CRITICAL entre organismos argentinos.

        Sin dominio .ar, sin país AR y sin CUIT no hay nada que corrobore que
        la víctima sea argentina: el hallazgo se reporta igual (la keyword
        disparó), pero no puede escalar a la severidad máxima.
        """
        item = make_normalized(
            victim_name="Distribuidora Ejemplo Dominicana",
            victim_domain="distribuidora-ejemplo.com.do",
        )
        veredicto = evaluate(item, watchlist)

        assert ArMatchReason.KEYWORD in veredicto.reasons
        assert derive_severity(veredicto, LeakType.RANSOMWARE) is Severity.LOW

    def test_la_misma_keyword_con_dominio_ar_si_es_critica(self, watchlist: Watchlist) -> None:
        """El contraste: con corroboración argentina, la misma keyword sí es crítica."""
        item = make_normalized(
            victim_name="Distribuidora Ejemplo", victim_domain="energia-ejemplo.com.ar"
        )
        veredicto = evaluate(item, watchlist)
        assert derive_severity(veredicto, LeakType.RANSOMWARE) is Severity.CRITICAL
