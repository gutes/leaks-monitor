"""Tests del cruce watchlist / hallazgos y del informe de watchlist.

El cruce es lo que convierte un listado en un informe: dice, de lo que estamos
vigilando, qué ya cayó alguna vez y dónde lo vimos. Los errores que importan
acá son de correspondencia —relacionar un host con la entrada equivocada— y de
honestidad —inventar una fecha, o truncar en silencio.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

import pytest

from leaks.export.coverage import (
    ORIGEN_SISTEMA,
    ORIGEN_VICTIMA,
    Compromiso,
    cubre,
    host_de,
    relacionar,
)
from leaks.export.watchlist_report import render_watchlist_report, watchlist_filename

AHORA = datetime(2026, 8, 18, 16, 0, tzinfo=UTC)


def hallazgo(**extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": 1,
        "source": "hudsonrock",
        "victim_name": "Comision Nuclear Ejemplo",
        "victim_domain": "nuclear-ejemplo.gob.ar",
        "occurred_at": datetime(2026, 8, 9, tzinfo=UTC),
        "raw_ref": "https://ejemplo.test/Nuclear Ejemplo",
        "exposure_detail": None,
    }
    base.update(extra)
    return base


def entrada(**extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": 1,
        "kind": "domain",
        "value": "nuclear-ejemplo.gob.ar",
        "sector": "ciencia",
        "label": "Comision Nuclear Ejemplo",
        "critical": True,
        "enabled": True,
        "origin": "seed",
    }
    base.update(extra)
    return base


CONTEOS = {"total": 2, "enabled": 2, "disabled": 0, "domains": 1, "keywords": 1}


class TestHostDe:
    @pytest.mark.parametrize(
        ("url", "esperado"),
        [
            ("https://siar.nuclear-ejemplo.gob.ar/sslvpn.shtml", "siar.nuclear-ejemplo.gob.ar"),
            ("http://WWW.Nuclear-Ejemplo.Gob.AR/", "nuclear-ejemplo.gob.ar"),
            ("https://portal.nuclear-ejemplo.gob.ar:8443/x", "portal.nuclear-ejemplo.gob.ar"),
            ("nuclear-ejemplo.gob.ar/algo", "nuclear-ejemplo.gob.ar"),
            ("no es una url", None),
            ("", None),
            (None, None),
        ],
    )
    def test_extrae_el_host(self, url: str | None, esperado: str | None) -> None:
        assert host_de(url) == esperado


class TestCubre:
    def test_cubre_el_dominio_exacto_y_sus_subdominios(self) -> None:
        assert cubre("nuclear-ejemplo.gob.ar", "nuclear-ejemplo.gob.ar")
        assert cubre("nuclear-ejemplo.gob.ar", "siar.nuclear-ejemplo.gob.ar")
        assert cubre("nuclear-ejemplo.gob.ar", "a.b.nuclear-ejemplo.gob.ar")

    def test_no_cubre_un_dominio_que_solo_termina_parecido(self) -> None:
        """`malinuclear-…` no es subdominio de `nuclear-…` aunque lo parezca."""
        assert not cubre("nuclear-ejemplo.gob.ar", "malinuclear-ejemplo.gob.ar")

    def test_no_cubre_hacia_arriba(self) -> None:
        assert not cubre("siar.nuclear-ejemplo.gob.ar", "nuclear-ejemplo.gob.ar")


class TestRelacionar:
    EXPO: ClassVar[dict[str, Any]] = {
        "urls": [
            {"url": "https://siar.nuclear-ejemplo.gob.ar/vpn", "kind": "employee"},
            {"url": "https://portal.nuclear-ejemplo.gob.ar", "kind": "user"},
        ]
    }

    def test_saca_los_subdominios_de_la_exposicion(self) -> None:
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=self.EXPO)])
        sistemas = {c.host for c in mapa["nuclear-ejemplo.gob.ar"][0] if c.origen == ORIGEN_SISTEMA}
        assert sistemas == {"siar.nuclear-ejemplo.gob.ar", "portal.nuclear-ejemplo.gob.ar"}

    def test_conserva_la_url_exacta_con_su_path(self) -> None:
        """Sin el path queda un hostname genérico: `/vpn` es lo que lo identifica."""
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=self.EXPO)])
        urls = {c.url for c in mapa["nuclear-ejemplo.gob.ar"][0] if c.origen == ORIGEN_SISTEMA}
        assert "https://siar.nuclear-ejemplo.gob.ar/vpn" in urls

    def test_el_dominio_de_la_victima_no_se_cuenta_como_sistema(self) -> None:
        """En Hudson Rock ese valor es el dominio que preguntamos nosotros.

        Mezclarlo con los sistemas encontrados haría pasar nuestra propia
        consulta por evidencia de compromiso.
        """
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=self.EXPO)])
        declarados = [c for c in mapa["nuclear-ejemplo.gob.ar"][0] if c.origen == ORIGEN_VICTIMA]
        assert [c.host for c in declarados] == ["nuclear-ejemplo.gob.ar"]
        assert declarados[0].url is None

    def test_sin_exposicion_queda_solo_el_organismo_declarado(self) -> None:
        """Es el caso de ransomware.live: nombra la víctima, no el sistema."""
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(source="ransomware.live")])
        (unico,) = mapa["nuclear-ejemplo.gob.ar"][0]
        assert unico.origen == ORIGEN_VICTIMA

    def test_dos_endpoints_del_mismo_host_son_dos_superficies(self) -> None:
        expo = {
            "urls": [
                {
                    "url": "https://correo.nuclear-ejemplo.gob.ar/owa/auth/logon.aspx",
                    "kind": "employee",
                },
                {"url": "https://correo.nuclear-ejemplo.gob.ar/owa/auth.owa", "kind": "employee"},
            ]
        }
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=expo)])
        urls = {c.url for c in mapa["nuclear-ejemplo.gob.ar"][0] if c.origen == ORIGEN_SISTEMA}
        assert len(urls) == 2

    def test_la_barra_final_no_duplica_el_sistema(self) -> None:
        expo = {
            "urls": [
                {"url": "https://webmail.nuclear-ejemplo.gob.ar", "kind": "employee"},
                {"url": "https://webmail.nuclear-ejemplo.gob.ar/", "kind": "employee"},
            ]
        }
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=expo)])
        sistemas = [c for c in mapa["nuclear-ejemplo.gob.ar"][0] if c.origen == ORIGEN_SISTEMA]
        assert len(sistemas) == 1

    def test_marca_los_de_empleados(self) -> None:
        """Es la distinción que cambia la decisión: acceso interno vs. trámite."""
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=self.EXPO)])
        internos = {c.host for c in mapa["nuclear-ejemplo.gob.ar"][0] if c.empleado}
        assert internos == {"siar.nuclear-ejemplo.gob.ar"}

    def test_una_entrada_sin_hallazgos_no_aparece(self) -> None:
        """Sin historial no se emite una clave vacía: el informe no la imprime."""
        assert relacionar(["tributos-ejemplo.gob.ar"], [hallazgo()]) == {}

    def test_ignora_hosts_que_no_cubre_ninguna_entrada(self) -> None:
        ajeno = hallazgo(victim_domain="otracosa.com")
        assert relacionar(["nuclear-ejemplo.gob.ar"], [ajeno]) == {}

    def test_el_host_va_a_la_entrada_mas_especifica(self) -> None:
        """Con el dominio y su subdominio cargados, gana el más específico."""
        mapa = relacionar(
            ["nuclear-ejemplo.gob.ar", "siar.nuclear-ejemplo.gob.ar"],
            [hallazgo(victim_domain="siar.nuclear-ejemplo.gob.ar")],
        )
        assert "nuclear-ejemplo.gob.ar" not in mapa
        assert [c.host for c in mapa["siar.nuclear-ejemplo.gob.ar"][0]] == [
            "siar.nuclear-ejemplo.gob.ar"
        ]

    def test_dedup_el_mismo_hecho_contado_dos_veces(self) -> None:
        dos = [hallazgo(), hallazgo(id=2)]
        assert len(relacionar(["nuclear-ejemplo.gob.ar"], dos)["nuclear-ejemplo.gob.ar"][0]) == 1

    def test_dos_fuentes_distintas_son_dos_apariciones(self) -> None:
        """El valor está justamente en ver que cayó por más de un lado."""
        mapa = relacionar(
            ["nuclear-ejemplo.gob.ar"], [hallazgo(), hallazgo(id=2, source="ransomware.live")]
        )
        assert {c.source for c in mapa["nuclear-ejemplo.gob.ar"][0]} == {
            "hudsonrock",
            "ransomware.live",
        }

    def test_mas_reciente_primero_y_sin_fecha_al_final(self) -> None:
        mapa = relacionar(
            ["nuclear-ejemplo.gob.ar"],
            [
                hallazgo(id=1, source="a", occurred_at=None),
                hallazgo(id=2, source="b", occurred_at=datetime(2020, 1, 1, tzinfo=UTC)),
                hallazgo(id=3, source="c", occurred_at=datetime(2026, 1, 1, tzinfo=UTC)),
            ],
        )
        assert [c.source for c in mapa["nuclear-ejemplo.gob.ar"][0]] == ["c", "b", "a"]

    def test_no_inventa_fecha_cuando_no_hay(self) -> None:
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(occurred_at=None)])
        assert mapa["nuclear-ejemplo.gob.ar"][0][0].occurred_at is None

    def test_el_tope_cuenta_lo_omitido_en_vez_de_esconderlo(self) -> None:
        muchos = [
            hallazgo(id=i, source=f"fuente{i}", victim_domain=f"h{i}.nuclear-ejemplo.gob.ar")
            for i in range(10)
        ]
        listados, omitidos = relacionar(["nuclear-ejemplo.gob.ar"], muchos, max_por_entrada=3)[
            "nuclear-ejemplo.gob.ar"
        ]
        assert len(listados) == 3
        assert omitidos == 7

    def test_una_exposicion_con_otra_forma_no_rompe(self) -> None:
        assert relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail="basura")])


class TestInforme:
    def test_encabezado_con_los_totales(self) -> None:
        texto = render_watchlist_report([entrada()], counts=CONTEOS, generated_at=AHORA)
        assert "Total cargado  : 2" in texto
        assert "Dominios       : 1" in texto
        assert "Keywords       : 1" in texto

    def test_sin_filtros_lo_dice(self) -> None:
        texto = render_watchlist_report([entrada()], counts=CONTEOS, generated_at=AHORA)
        assert "sin filtro — la watchlist completa" in texto

    def test_con_filtros_declara_cuales(self) -> None:
        """Un TXT parcial no se puede confundir con el total."""
        texto = render_watchlist_report(
            [entrada()],
            counts=CONTEOS,
            generated_at=AHORA,
            filtros={"tipo": "domain", "sector": None},
        )
        assert "tipo=domain" in texto
        assert "sector" not in texto.split("Total cargado")[0].split("Filtro")[1]

    def test_agrupa_por_sector(self) -> None:
        texto = render_watchlist_report(
            [entrada(), entrada(id=2, value="tributos-ejemplo.gob.ar", sector="fiscal")],
            counts=CONTEOS,
            generated_at=AHORA,
        )
        assert "ciencia — 1 entradas" in texto
        assert "fiscal — 1 entradas" in texto

    def test_marca_las_criticas_y_las_deshabilitadas(self) -> None:
        texto = render_watchlist_report(
            [entrada(), entrada(id=2, value="x.gob.ar", enabled=False, critical=False)],
            counts=CONTEOS,
            generated_at=AHORA,
        )
        assert "CRÍTICO" in texto
        assert "inactiva" in texto

    def test_distingue_el_origen(self) -> None:
        texto = render_watchlist_report(
            [entrada(origin="user")], counts=CONTEOS, generated_at=AHORA
        )
        assert "manual" in texto

    def test_lista_los_compromisos_con_fecha_y_url(self) -> None:
        mapa = relacionar(
            ["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=TestRelacionar.EXPO)]
        )
        texto = render_watchlist_report(
            [entrada()], counts=CONTEOS, compromisos=mapa, generated_at=AHORA
        )
        assert "Comprometidos alguna vez: 2 sistemas, 2 URLs (1 de empleados)" in texto
        assert "2026-08-09 · hudsonrock" in texto
        assert "[EMPLEADO]  https://siar.nuclear-ejemplo.gob.ar/vpn" in texto
        assert "visto en: https://ejemplo.test/Nuclear Ejemplo" in texto

    def test_muestra_la_url_exacta_y_no_solo_el_host(self) -> None:
        mapa = relacionar(
            ["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=TestRelacionar.EXPO)]
        )
        texto = render_watchlist_report(
            [entrada()], counts=CONTEOS, compromisos=mapa, generated_at=AHORA
        )
        assert "https://siar.nuclear-ejemplo.gob.ar/vpn" in texto

    def test_rotula_aparte_el_organismo_declarado(self) -> None:
        """No puede leerse como un sistema más: es un dato de otra naturaleza."""
        mapa = relacionar(
            ["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=TestRelacionar.EXPO)]
        )
        texto = render_watchlist_report(
            [entrada()], counts=CONTEOS, compromisos=mapa, generated_at=AHORA
        )
        assert "[organismo señalado por la fuente]  nuclear-ejemplo.gob.ar" in texto

    def test_cuenta_hosts_y_urls_por_separado(self) -> None:
        """Dos endpoints de un servidor son dos superficies de UN sistema."""
        expo = {
            "urls": [
                {
                    "url": "https://siar.nuclear-ejemplo.gob.ar/sslvpn_logon.shtml",
                    "kind": "employee",
                },
                {"url": "https://siar.nuclear-ejemplo.gob.ar/wgcgi.cgi", "kind": "employee"},
            ]
        }
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=expo)])
        texto = render_watchlist_report(
            [entrada()], counts=CONTEOS, compromisos=mapa, generated_at=AHORA
        )
        assert "1 sistemas, 2 URLs (2 de empleados)" in texto

    def test_la_marca_de_empleado_nunca_queda_huerfana(self) -> None:
        """Envuelta a la línea siguiente, no se sabe de qué URL es."""
        larga = "https://teletrabajo.nuclear-ejemplo.gob.ar/" + "a" * 90
        expo = {"urls": [{"url": larga, "kind": "employee"}]}
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=expo)])
        texto = render_watchlist_report(
            [entrada()], counts=CONTEOS, compromisos=mapa, generated_at=AHORA
        )
        (linea,) = [x for x in texto.splitlines() if larga in x]
        assert "[EMPLEADO]" in linea

    def test_sin_sistemas_no_afirma_cuantos_cayeron(self) -> None:
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo(source="ransomware.live")])
        texto = render_watchlist_report(
            [entrada()], counts=CONTEOS, compromisos=mapa, generated_at=AHORA
        )
        assert "Comprometidos alguna vez: sin detalle de sistemas" in texto

    def test_agrupa_los_sistemas_por_hallazgo(self) -> None:
        """La URL aparece una vez por hallazgo, no una vez por subdominio."""
        mapa = relacionar(
            ["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=TestRelacionar.EXPO)]
        )
        texto = render_watchlist_report(
            [entrada()], counts=CONTEOS, compromisos=mapa, generated_at=AHORA
        )
        assert texto.count("https://ejemplo.test/Nuclear Ejemplo") == 1

    def test_cuenta_cuantas_entradas_tienen_historial(self) -> None:
        mapa = relacionar(["nuclear-ejemplo.gob.ar"], [hallazgo()])
        texto = render_watchlist_report(
            [entrada(), entrada(id=2, value="tributos-ejemplo.gob.ar")],
            counts=CONTEOS,
            compromisos=mapa,
            generated_at=AHORA,
        )
        assert "1 entradas cayeron alguna vez" in texto

    def test_sin_historial_no_pone_la_seccion(self) -> None:
        texto = render_watchlist_report([entrada()], counts=CONTEOS, generated_at=AHORA)
        assert "Comprometidos alguna vez" not in texto.split("«Comprometido")[1]

    def test_avisa_lo_que_no_se_listo(self) -> None:
        uno = Compromiso(
            host="nuclear-ejemplo.gob.ar",
            url="https://nuclear-ejemplo.gob.ar/x",
            occurred_at=None,
            source="x",
            ref_url=None,
            victim_name="Comision Nuclear Ejemplo",
        )
        mapa = {"nuclear-ejemplo.gob.ar": ((uno,), 5)}
        texto = render_watchlist_report(
            [entrada()], counts=CONTEOS, compromisos=mapa, generated_at=AHORA
        )
        assert "y 5 más, no listados por espacio" in texto

    def test_dice_que_el_historial_no_prueba_el_estado_actual(self) -> None:
        """Sin esa aclaración el informe afirma algo que no sabe."""
        texto = " ".join(
            render_watchlist_report([entrada()], counts=CONTEOS, generated_at=AHORA).split()
        )
        assert "no significa que siga comprometido hoy" in texto

    def test_watchlist_vacia_no_revienta(self) -> None:
        texto = render_watchlist_report([], counts=CONTEOS, generated_at=AHORA)
        assert "La watchlist está vacía para este filtro." in texto

    def test_ninguna_linea_termina_en_espacios(self) -> None:
        mapa = relacionar(
            ["nuclear-ejemplo.gob.ar"], [hallazgo(exposure_detail=TestRelacionar.EXPO)]
        )
        texto = render_watchlist_report(
            [entrada()], counts=CONTEOS, compromisos=mapa, generated_at=AHORA
        )
        assert not [linea for linea in texto.splitlines() if linea != linea.rstrip()]

    def test_un_valor_hostil_no_fabrica_estructura(self) -> None:
        texto = render_watchlist_report(
            [entrada(value="x.gob.ar\n====\n  falso — 9 entradas")],
            counts=CONTEOS,
            generated_at=AHORA,
        )
        assert texto.count("entradas (") == 1

    def test_nombre_de_archivo(self) -> None:
        assert watchlist_filename(AHORA, 284) == "watchlist-20260818-1600-284.txt"
