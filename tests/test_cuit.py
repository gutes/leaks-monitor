"""Tests de detección y validación de CUIT/CUIL."""

from __future__ import annotations

import pytest

from leaks.relevance.cuit import find_valid_cuits, is_valid_cuit


class TestValidacion:
    @pytest.mark.parametrize(
        "cuit",
        [
            "33-69345023-9",  # CUIT público de Tributos Ejemplo
            "33693450239",  # el mismo, sin guiones
            "20-12345678-6",  # verificador calculado a mano: 148 % 11 = 5 -> 6
            "3369345023-9",  # guion parcial
        ],
    )
    def test_acepta_cuits_validos(self, cuit: str) -> None:
        assert is_valid_cuit(cuit)

    @pytest.mark.parametrize(
        ("cuit", "motivo"),
        [
            ("33-69345023-8", "dígito verificador incorrecto"),
            ("20-12345678-9", "dígito verificador incorrecto"),
            ("99-12345678-6", "prefijo inexistente"),
            ("11-11111111-1", "prefijo inexistente"),
            ("2012345678", "diez dígitos"),
            ("201234567890", "doce dígitos"),
            ("20-1234567a-6", "contiene letras"),
            ("", "vacío"),
        ],
    )
    def test_rechaza_invalidos(self, cuit: str, motivo: str) -> None:
        assert not is_valid_cuit(cuit), motivo

    def test_el_prefijo_filtra_numeros_al_azar(self) -> None:
        """Sin filtro de prefijo, ~1 de cada 11 números pasaría el mod-11."""
        colados = [
            n
            for n in ("91234567890", "99999999999", "10000000000", "45678912345")
            if is_valid_cuit(n)
        ]
        assert colados == []


class TestExtraccionEnTexto:
    def test_encuentra_el_cuit_en_una_frase(self) -> None:
        texto = "Dump de la empresa, CUIT 33-69345023-9, 40k registros"
        assert find_valid_cuits(texto) == ("33693450239",)

    def test_descarta_los_candidatos_que_no_validan(self) -> None:
        """La regla del bootstrap: matchea el regex pero se descarta igual."""
        texto = "IDs internos: 33-69345023-1 y 20-12345678-9"
        assert find_valid_cuits(texto) == ()

    def test_deduplica_y_normaliza(self) -> None:
        texto = "33-69345023-9 aparece también como 33693450239"
        assert find_valid_cuits(texto) == ("33693450239",)

    def test_varios_cuits_ordenados(self) -> None:
        texto = "33-69345023-9 y 20-12345678-6"
        assert find_valid_cuits(texto) == ("20123456786", "33693450239")

    def test_no_matchea_dentro_de_un_numero_mas_largo(self) -> None:
        assert find_valid_cuits("ref 9933693450239001") == ()

    @pytest.mark.parametrize("vacio", [None, "", "   "])
    def test_tolera_texto_vacio(self, vacio: str | None) -> None:
        assert find_valid_cuits(vacio) == ()


class TestContexto:
    """Once dígitos sueltos no son un CUIT.

    El 2026-09-15 entraron como hallazgos argentinos una universidad de
    Indonesia (26 "CUIT") y una pasarela peruana (8), todos falsos: eran
    documentos y teléfonos de esos países en el cuerpo del volcado. Con prefijo
    válido y mod-11, ~0,8% de los números de once dígitos pasan por azar, y un
    dump trae miles.
    """

    #: Válido de verdad (mod-11 y prefijo), para probar solo el contexto.
    CRUDO = "20123456786"

    def test_el_numero_pelado_no_cuenta(self) -> None:
        assert is_valid_cuit(self.CRUDO), "el caso de prueba tiene que ser válido"
        assert find_valid_cuits(f"telefono {self.CRUDO} registro") == ()

    def test_con_formato_canonico_cuenta(self) -> None:
        assert find_valid_cuits("20-12345678-6") == ("20123456786",)

    def test_con_la_etiqueta_cerca_cuenta(self) -> None:
        assert find_valid_cuits(f"CUIT {self.CRUDO}") == (self.CRUDO,)
        assert find_valid_cuits(f"CUIL: {self.CRUDO}") == (self.CRUDO,)

    def test_la_etiqueta_lejos_no_cuenta(self) -> None:
        """Si no está pegada, puede ser de otra columna de la misma fila."""
        lejos = "cuit " + "x" * 60 + f" {self.CRUDO}"
        assert find_valid_cuits(lejos) == ()

    def test_un_dump_extranjero_no_entra(self) -> None:
        """El caso real, reducido: documentos que pasan el mod-11 de casualidad."""
        cuerpo = "nik 20123456786 | phone 30123456782 | id 20123456786"
        assert find_valid_cuits(cuerpo) == ()

    def test_un_padron_argentino_sigue_entrando(self) -> None:
        """No se rompe el caso bueno: un padrón real presenta el CUIT como tal."""
        cuerpo = "razon social;CUIT;domicilio\nACME SA;33-69345023-9;Av. Falsa 123"
        assert find_valid_cuits(cuerpo) == ("33693450239",)
