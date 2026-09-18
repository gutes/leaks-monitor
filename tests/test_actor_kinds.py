"""Tests del carril de cada actor de la adyacencia."""

from __future__ import annotations

from leaks.adjacency.kinds import KIND_DLS, KIND_FORO, etiqueta, kind_for


def test_una_victima_de_dls_manda():
    assert kind_for(["ransomware.live"]) == KIND_DLS


def test_foros_y_telegram_van_al_otro_carril():
    assert kind_for(["darkforums", "telegram"]) == KIND_FORO


def test_mezclado_cuenta_como_dls():
    """Donde el score está calibrado es la lectura más informativa."""
    assert kind_for(["darkforums", "ransomware.live"]) == KIND_DLS


def test_sin_fuentes_no_es_dls():
    assert kind_for([]) == KIND_FORO


def test_la_etiqueta_cae_al_codigo_si_no_la_conoce():
    assert etiqueta("otro") == "otro"
    assert etiqueta(KIND_DLS) != KIND_DLS
