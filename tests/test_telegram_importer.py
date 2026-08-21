"""Tests del alta masiva de canales.

Lo que se protege: que lo rechazado se REPORTE. Saltear líneas en silencio
haría creer que se están vigilando canales que nunca entraron, que es el error
caro acá — el investigador no tiene forma de notarlo hasta que hace falta.
"""

from __future__ import annotations

import pytest

from leaks.telegram.importer import parsear


class TestFormatos:
    @pytest.mark.parametrize(
        "linea",
        [
            "@canaluno",
            "canaluno",
            "t.me/canaluno",
            "https://t.me/canaluno",
            "https://t.me/s/canaluno",
        ],
    )
    def test_acepta_las_formas_que_uno_pega(self, linea: str) -> None:
        (canal,) = parsear(linea).canales
        assert canal["handle"] == "canaluno"

    def test_acepta_columnas_opcionales(self) -> None:
        (canal,) = parsear("chronusleaks, Chronus Team, data_leak, avisa antes").canales
        assert canal["actor"] == "Chronus Team"
        assert canal["kind"] == "data_leak"
        assert canal["notes"] == "avisa antes"

    @pytest.mark.parametrize("sep", [",", ";", "\t"])
    def test_tolera_cualquier_separador(self, sep: str) -> None:
        """Es lo que sale de pegar desde una planilla o un informe."""
        (canal,) = parsear(f"canaluno{sep}Actor X{sep}ddos").canales
        assert (canal["actor"], canal["kind"]) == ("Actor X", "ddos")

    def test_ignora_comentarios_y_vacías(self) -> None:
        texto = "# los del informe\n\n@canaluno\n\n#  otro comentario\n@canaldos\n"
        assert [c["handle"] for c in parsear(texto).canales] == ["canaluno", "canaldos"]

    def test_columnas_vacías_quedan_en_none(self) -> None:
        (canal,) = parsear("canaluno, , , ").canales
        assert canal["actor"] is None and canal["kind"] is None


class TestLoQueNoEntra:
    def test_reporta_las_invitaciones_privadas_con_el_motivo(self) -> None:
        lectura = parsear("https://t.me/+AbCdEfGh")
        assert lectura.canales == []
        (rechazada,) = lectura.rechazadas
        assert rechazada.numero == 1
        assert "privados" in rechazada.motivo

    def test_reporta_lo_que_no_es_un_handle(self) -> None:
        (rechazada,) = parsear("esto no es nada").rechazadas
        assert "no parece un handle" in rechazada.motivo

    def test_una_línea_mala_no_frena_a_las_buenas(self) -> None:
        lectura = parsear("@buenouno\nbasura!!\n@buenodos")
        assert [c["handle"] for c in lectura.canales] == ["buenouno", "buenodos"]
        assert len(lectura.rechazadas) == 1

    def test_los_números_de_línea_son_los_del_archivo(self) -> None:
        """Sin el número real, encontrar la línea en un archivo de 200 es a ojo."""
        (rechazada,) = parsear("# comentario\n\n@bueno\nbasura!!").rechazadas
        assert rechazada.numero == 4

    def test_cuenta_los_repetidos_dentro_del_texto(self) -> None:
        lectura = parsear("@canaluno\n@CANALUNO\nt.me/canaluno\n@canaldos")
        assert [c["handle"] for c in lectura.canales] == ["canaluno", "canaldos"]
        assert lectura.duplicadas == 2

    def test_el_total_cierra(self) -> None:
        lectura = parsear("@canaluno\n@canaluno\nbasura!!")
        assert lectura.total_leidas == 3

    def test_tiene_tope_de_líneas(self) -> None:
        """Pegar el archivo equivocado no puede encolar miles de canales."""
        texto = "\n".join(f"canal{i}" for i in range(50))
        assert len(parsear(texto, max_lineas=10).canales) == 10

    def test_un_texto_vacío_no_rompe(self) -> None:
        lectura = parsear("\n\n#solo comentarios\n")
        assert lectura.canales == [] and lectura.rechazadas == []
