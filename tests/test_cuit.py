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
