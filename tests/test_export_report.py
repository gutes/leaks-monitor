"""Tests del informe TXT.

El formateador son funciones puras: se le pasan los mismos diccionarios que
publica la API y se verifica el texto resultante. No hace falta base ni red.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

from leaks.export.layout import WIDTH
from leaks.export.report import ordenar, render_report, report_filename

AHORA = datetime(2026, 8, 18, 15, 30, tzinfo=UTC)


def plano(texto: str) -> str:
    """Colapsa los espacios para poder afirmar sobre prosa envuelta.

    El informe corta los párrafos a 80 columnas, así que una frase puede
    quedar partida en dos líneas. Buscarla literal ataría el test al ancho.
    """
    return " ".join(texto.split())


def hallazgo(**extra: object) -> dict[str, object]:
    """Un hallazgo con la forma exacta que devuelve `queries._to_dict`."""
    base: dict[str, object] = {
        "id": 1,
        "source": "hudsonrock",
        "leak_type": "infostealer",
        "victim_name": "Comision Nuclear Ejemplo",
        "victim_domain": "nuclear-ejemplo.gob.ar",
        "country": "AR",
        "sector": "Government",
        "actor": None,
        "discovered_at": datetime(2026, 8, 18, 10, 0, tzinfo=UTC),
        "published_at": None,
        "raw_ref": "https://ejemplo.test/x",
        "ar_match_reason": ["watchlist_domain"],
        "ar_match_detail": {"watchlist_domain": ["nuclear-ejemplo.gob.ar"]},
        "severity": "high",
        "description": "Infostealers: 295 equipos comprometidos.",
        "occurred_at": datetime(2026, 8, 9, 0, 0, tzinfo=UTC),
        "occurred_at_basis": "feed",
        "backfill": False,
        "download_links": [],
        "exposure_detail": None,
        "first_seen_at": datetime(2026, 8, 18, 10, 0, tzinfo=UTC),
        "last_seen_at": datetime(2026, 8, 18, 10, 0, tzinfo=UTC),
    }
    base.update(extra)
    return base


class TestOrden:
    def test_mas_reciente_primero(self) -> None:
        viejo = hallazgo(victim_name="Viejo", occurred_at=datetime(2021, 1, 1, tzinfo=UTC))
        nuevo = hallazgo(victim_name="Nuevo", occurred_at=datetime(2026, 1, 1, tzinfo=UTC))
        assert [h["victim_name"] for h in ordenar([viejo, nuevo])] == ["Nuevo", "Viejo"]

    def test_los_sin_fecha_van_al_final(self) -> None:
        """Sin fecha no es 'viejo': es desconocido, y no se puede mezclar."""
        sin = hallazgo(victim_name="Sin fecha", occurred_at=None)
        viejo = hallazgo(victim_name="De 2015", occurred_at=datetime(2015, 6, 1, tzinfo=UTC))
        assert [h["victim_name"] for h in ordenar([sin, viejo])] == ["De 2015", "Sin fecha"]

    def test_los_sin_fecha_se_ordenan_entre_si_por_nombre(self) -> None:
        a = hallazgo(victim_name="Beta", occurred_at=None)
        b = hallazgo(victim_name="Alfa", occurred_at=None)
        assert [h["victim_name"] for h in ordenar([a, b])] == ["Alfa", "Beta"]

    def test_una_fecha_naive_no_rompe_el_orden(self) -> None:
        """La base puede devolver naive; se asume UTC como en todo el proyecto."""
        naive = hallazgo(victim_name="Naive", occurred_at=datetime(2026, 8, 15))
        assert ordenar([hallazgo(), naive])[0]["victim_name"] == "Naive"


class TestEncabezado:
    def test_dice_cuantos_y_desde_cuando(self) -> None:
        texto = render_report(
            [hallazgo(), hallazgo(occurred_at=datetime(2020, 3, 1, tzinfo=UTC))],
            generated_at=AHORA,
        )
        assert "Hallazgos      : 2" in texto
        assert "2020-03-01 → 2026-08-09" in texto

    def test_avisa_cuantos_van_sin_fechar(self) -> None:
        texto = render_report([hallazgo(), hallazgo(occurred_at=None)], generated_at=AHORA)
        assert "Sin fechar     : 1 (van al final)" in texto

    def test_declara_que_no_lleva_credenciales(self) -> None:
        """El informe puede circular: tiene que decir qué contiene y qué no."""
        texto = render_report([hallazgo()], generated_at=AHORA)
        assert "No incluye credenciales" in plano(texto)

    def test_seleccion_vacia_no_revienta(self) -> None:
        texto = render_report([], generated_at=AHORA)
        assert "Ningún hallazgo seleccionado." in texto


class TestFicha:
    def test_lleva_los_datos_del_hallazgo(self) -> None:
        texto = render_report([hallazgo(actor="qilin")], generated_at=AHORA)
        for esperado in (
            "[1/1]  Comision Nuclear Ejemplo",
            "Víctima        : Comision Nuclear Ejemplo",
            "Dominio        : nuclear-ejemplo.gob.ar",
            "Sector         : Government",
            "Actor          : qilin",
            "Severidad      : HIGH",
            "Referencia     : https://ejemplo.test/x",
        ):
            assert esperado in texto, esperado

    def test_la_fuente_dice_de_que_tipo_es(self) -> None:
        texto = render_report([hallazgo()], generated_at=AHORA)
        assert "Fuente         : hudsonrock  (infostealer)" in texto

    def test_separa_ocurrencia_de_descubrimiento(self) -> None:
        """Confundirlas es el bug que motivó toda la cascada de fechado."""
        texto = render_report([hallazgo()], generated_at=AHORA)
        assert "Ocurrencia     : 2026-08-09" in texto
        assert "Declarado      : 2026-08-18  (fecha que informa la fuente)" in texto
        assert "Visto          : 2026-08-18  (cuándo lo detectamos)" in texto

    def test_dice_de_donde_salio_la_fecha(self) -> None:
        texto = render_report([hallazgo(occurred_at_basis="corroboracion")], generated_at=AHORA)
        assert "corroborada con otra fuente" in texto

    def test_sin_fecha_lo_dice_en_vez_de_inventar(self) -> None:
        texto = render_report(
            [hallazgo(occurred_at=None, occurred_at_basis="sin_dato")], generated_at=AHORA
        )
        assert "Ocurrencia     : sin fecha  (sin dato)" in texto
        assert "2026-08-18  (fecha que informa la fuente)" in texto

    def test_marca_reciente_o_historico(self) -> None:
        reciente = render_report([hallazgo()], generated_at=AHORA, fresh_days=30)
        assert "(reciente ·" in reciente
        historico = render_report(
            [hallazgo(occurred_at=datetime(2022, 1, 1, tzinfo=UTC))], generated_at=AHORA
        )
        assert "histórico, hace 1690 días" in historico

    def test_marca_la_importacion_inicial(self) -> None:
        texto = render_report([hallazgo(backfill=True)], generated_at=AHORA)
        assert "importación inicial" in plano(texto)

    def test_incluye_la_evidencia_de_la_relevancia_ar(self) -> None:
        """La columna auditable del prototipo también va al informe."""
        texto = render_report([hallazgo()], generated_at=AHORA)
        assert "Relevancia AR  : watchlist_domain" in texto
        assert "watchlist_domain: nuclear-ejemplo.gob.ar" in texto

    def test_numera_los_hallazgos(self) -> None:
        texto = render_report([hallazgo(), hallazgo(victim_name="Otro")], generated_at=AHORA)
        assert "[1/2]" in texto and "[2/2]" in texto


class TestDatos:
    """La columna de la lupa: es lo que el usuario pidió resumido en el TXT."""

    EXPO: ClassVar[dict[str, Any]] = {
        "urls": [
            {"url": "https://siar.nuclear-ejemplo.gob.ar/sslvpn.shtml", "kind": "employee", "occurrences": 89},
            {"url": "https://portal.nuclear-ejemplo.gob.ar", "kind": "user", "occurrences": 3},
        ],
        "stealer_families": {"RedLine": 23590, "Lumma": 12},
        "weak_password_pct": 63.45,
        "third_party_domains": ["telco-ejemplo.com.ar", "gmail.com"],
    }

    def test_lista_los_sistemas_comprometidos(self) -> None:
        texto = render_report([hallazgo(exposure_detail=self.EXPO)], generated_at=AHORA)
        assert "https://siar.nuclear-ejemplo.gob.ar/sslvpn.shtml" in texto
        assert "[EMPLEADO]" in texto
        assert "[usuario ]" in texto

    def test_resume_arriba_lo_que_importa(self) -> None:
        texto = render_report([hallazgo(exposure_detail=self.EXPO)], generated_at=AHORA)
        assert "2 sistemas comprometidos · 1 de empleados · 63.45% de contraseñas débiles" in texto

    def test_los_conteos_llevan_separador_de_miles(self) -> None:
        texto = render_report([hallazgo(exposure_detail=self.EXPO)], generated_at=AHORA)
        assert "RedLine (23.590)" in texto

    def test_incluye_familias_y_terceros(self) -> None:
        texto = render_report([hallazgo(exposure_detail=self.EXPO)], generated_at=AHORA)
        assert "Familias de malware" in texto
        assert "Otros dominios donde reaparecen esas credenciales" in texto
        assert "telco-ejemplo.com.ar" in texto

    def test_sin_exposicion_no_pone_la_seccion(self) -> None:
        texto = render_report([hallazgo()], generated_at=AHORA)
        assert "Exposición por infostealers" not in texto

    def test_exposicion_vacia_tampoco(self) -> None:
        vacia = {"urls": [], "stealer_families": {}, "third_party_domains": []}
        texto = render_report([hallazgo(exposure_detail=vacia)], generated_at=AHORA)
        assert "Exposición por infostealers" not in texto

    def test_una_exposicion_con_otra_forma_no_rompe(self) -> None:
        """La base es JSON libre: una fila vieja puede no tener la forma nueva."""
        texto = render_report([hallazgo(exposure_detail="basura")], generated_at=AHORA)
        assert "[1/1]  Comision Nuclear Ejemplo" in texto


class TestEnlaces:
    LINKS: ClassVar[list[dict[str, str]]] = [
        {"url": "magnet:?xt=urn:btih:abc", "kind": "data"},
        {"url": "https://ejemplo.test/muestra.zip", "kind": "sample"},
    ]

    def test_lista_los_punteros_a_lo_publicado(self) -> None:
        texto = render_report([hallazgo(download_links=self.LINKS)], generated_at=AHORA)
        assert "magnet:?xt=urn:btih:abc" in texto
        assert "[VOLCADO]" in texto
        assert "[muestra]" in texto

    def test_advierte_que_no_son_para_abrir_de_paso(self) -> None:
        texto = render_report([hallazgo(download_links=self.LINKS)], generated_at=AHORA)
        assert "abrirlos es una decisión deliberada" in plano(texto)

    def test_sin_enlaces_no_pone_la_seccion(self) -> None:
        assert "Enlaces a lo publicado" not in render_report([hallazgo()], generated_at=AHORA)


class TestFormato:
    def test_el_texto_libre_se_envuelve(self) -> None:
        """Una descripción larga no puede desbordar el ancho del informe."""
        largo = "palabra " * 60
        texto = render_report([hallazgo(description=largo)], generated_at=AHORA)
        cuerpo = [
            linea
            for linea in texto.splitlines()
            # Las URLs se dejan enteras a propósito: cortarlas las inutiliza.
            if "http" not in linea and "magnet" not in linea
        ]
        assert max(len(linea) for linea in cuerpo) <= WIDTH

    def test_las_urls_largas_no_se_cortan(self) -> None:
        larga = "https://ejemplo.test/" + "a" * 120
        expo = {"urls": [{"url": larga, "kind": "user", "occurrences": 1}]}
        texto = render_report([hallazgo(exposure_detail=expo)], generated_at=AHORA)
        assert larga in texto

    def test_un_nombre_de_victima_hostil_no_rompe_el_informe(self) -> None:
        """El nombre lo escribe un grupo de ransomware: es texto, no formato."""
        texto = render_report(
            [hallazgo(victim_name="Empresa\n====\n[9/9]  Falso")], generated_at=AHORA
        )
        assert "[1/1]" in texto
        # No se puede fabricar una ficha extra: sigue habiendo un solo hallazgo.
        assert texto.count("Severidad      :") == 1

    def test_termina_con_el_cierre(self) -> None:
        assert "Fin del informe." in render_report([hallazgo()], generated_at=AHORA)


class TestNombreDeArchivo:
    def test_lleva_sello_de_tiempo_y_cantidad(self) -> None:
        assert report_filename(AHORA, 5) == "hallazgos-20260818-1530-5.txt"

    def test_no_lleva_nombres_de_victima(self) -> None:
        """El archivo puede circular por mail: el nombre no filtra a quién mira."""
        assert "Nuclear Ejemplo" not in report_filename(AHORA, 1).lower()


class TestHigiene:
    def test_ninguna_linea_termina_en_espacios(self) -> None:
        """El TXT se pega en un ticket o un mail: el espacio final se nota."""
        texto = render_report([hallazgo(exposure_detail=TestDatos.EXPO)], generated_at=AHORA)
        assert not [linea for linea in texto.splitlines() if linea != linea.rstrip()]

    def test_la_tabla_de_sistemas_dice_que_mide_el_numero(self) -> None:
        texto = render_report([hallazgo(exposure_detail=TestDatos.EXPO)], generated_at=AHORA)
        assert "[ acceso ]   capturas  sistema" in texto
