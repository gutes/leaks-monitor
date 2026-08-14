"""Detección y validación de CUIT/CUIL.

Encontrar "once dígitos" en un texto no significa nada: uno de cada once números
al azar pasa el dígito verificador por pura probabilidad. Por eso se valida
**dígito verificador + prefijo**, que baja los falsos positivos a un orden de
magnitud menos.
"""

from __future__ import annotations

import re

#: Regex del bootstrap: dos dígitos, ocho dígitos y el verificador, con guiones
#: opcionales.
CUIT_PATTERN = re.compile(r"\b\d{2}-?\d{8}-?\d\b")

#: Pesos del algoritmo mod-11 de la agencia tributaria, aplicados a los primeros 10 dígitos.
_WEIGHTS = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)

#: Prefijos asignables. Sin este filtro, cualquier número de 11 dígitos que
#: pase el mod-11 (≈9% de los números al azar) generaría un falso positivo.
_VALID_PREFIXES = frozenset({"20", "23", "24", "25", "26", "27", "30", "33", "34"})


def _check_digit(first_ten: str) -> int:
    """Dígito verificador mod-11 de la agencia tributaria para los primeros 10 dígitos."""
    total = sum(int(d) * w for d, w in zip(first_ten, _WEIGHTS, strict=True))
    remainder = total % 11
    candidate = 11 - remainder
    if candidate == 11:
        return 0
    # resto == 1: la agencia tributaria reasigna el prefijo (23/33) y el verificador queda en 9.
    if candidate == 10:
        return 9
    return candidate


def is_valid_cuit(value: str) -> bool:
    """¿`value` es un CUIT/CUIL válido? Acepta con o sin guiones."""
    digits = value.replace("-", "").replace(".", "").strip()
    if len(digits) != 11 or not digits.isdigit():
        return False
    if digits[:2] not in _VALID_PREFIXES:
        return False
    return int(digits[10]) == _check_digit(digits[:10])


def find_valid_cuits(text: str | None) -> tuple[str, ...]:
    """Devuelve los CUIT/CUIL **válidos** del texto, normalizados sin guiones.

    Los candidatos que no validan se descartan, que es justamente lo que pide
    la regla de relevancia.
    """
    if not text:
        return ()
    encontrados = {
        m.group(0).replace("-", "")
        for m in CUIT_PATTERN.finditer(text)
        if is_valid_cuit(m.group(0))
    }
    return tuple(sorted(encontrados))
