"""Detección y validación de CUIT/CUIL.

Encontrar "once dígitos" en un texto no significa nada: uno de cada once números
al azar pasa el dígito verificador por pura probabilidad. Por eso se valida
**dígito verificador + prefijo**, que baja los falsos positivos a un orden de
magnitud menos.

**Y aun así no alcanza.** Prefijo válido (9 de 100) por mod-11 (1 de 11) deja
~0,8% de los números de once dígitos pasando por azar, y el cuerpo de un volcado
trae miles: el 2026-09-15 entraron como hallazgos argentinos una universidad de
Indonesia y una pasarela de pagos peruana, con 26 y 8 "CUIT" cada una, todos
falsos. Eran documentos y teléfonos de esos países.

Por eso se exige además **contexto**: o el número viene con el formato canónico
`NN-NNNNNNNN-N`, o está acompañado de la palabra CUIT/CUIL. Once dígitos pelados
en medio de un dump son once dígitos, no un identificador fiscal argentino.
"""

from __future__ import annotations

import re

#: Regex del bootstrap: dos dígitos, ocho dígitos y el verificador, con guiones
#: opcionales. Sigue siendo el detector de candidatos; lo que decide cuáles
#: cuentan es `find_valid_cuits`.
CUIT_PATTERN = re.compile(r"\b\d{2}-?\d{8}-?\d\b")

#: Formato canónico. Que alguien lo haya escrito así ya es la señal: nadie
#: puntúa un teléfono indonesio como `20-12345678-6`.
_CUIT_CON_FORMATO = re.compile(r"\b\d{2}[-.]\d{8}[-.]\d\b")

#: La palabra cerca del número. Cubre "CUIT: 20…", "CUIL 27…", "cuit/cuil".
_ETIQUETA = re.compile(r"cui[tl]", re.IGNORECASE)

#: Cuántos caracteres antes del número se miran buscando la etiqueta. Alcanza
#: para "CUIT: ", "CUIL Nº " y similares sin cruzar a la columna de al lado.
_VENTANA_ETIQUETA = 24

#: Pesos del algoritmo mod-11 de Tributos Ejemplo, aplicados a los primeros 10 dígitos.
_WEIGHTS = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)

#: Prefijos asignables. Sin este filtro, cualquier número de 11 dígitos que
#: pase el mod-11 (≈9% de los números al azar) generaría un falso positivo.
_VALID_PREFIXES = frozenset({"20", "23", "24", "25", "26", "27", "30", "33", "34"})


def _check_digit(first_ten: str) -> int:
    """Dígito verificador mod-11 de Tributos Ejemplo para los primeros 10 dígitos."""
    total = sum(int(d) * w for d, w in zip(first_ten, _WEIGHTS, strict=True))
    remainder = total % 11
    candidate = 11 - remainder
    if candidate == 11:
        return 0
    # resto == 1: Tributos Ejemplo reasigna el prefijo (23/33) y el verificador queda en 9.
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


def _tiene_contexto(text: str, match: re.Match[str]) -> bool:
    """¿El número viene presentado como CUIT, o solo son once dígitos?

    Dos formas de contar: el formato canónico con separadores, o la palabra
    CUIT/CUIL justo antes. Sin ninguna de las dos, se descarta.
    """
    if _CUIT_CON_FORMATO.fullmatch(match.group(0)):
        return True
    inicio = max(0, match.start() - _VENTANA_ETIQUETA)
    return _ETIQUETA.search(text[inicio : match.start()]) is not None


def find_valid_cuits(text: str | None) -> tuple[str, ...]:
    """Devuelve los CUIT/CUIL **válidos y presentados como tales**.

    Se descartan los candidatos que no validan y también los que validan por
    azar sin nada que los presente como CUIT. Ver el encabezado del módulo: sin
    esa segunda puerta, un volcado extranjero entra como hallazgo argentino.
    """
    if not text:
        return ()
    encontrados = {
        m.group(0).replace("-", "").replace(".", "")
        for m in CUIT_PATTERN.finditer(text)
        if is_valid_cuit(m.group(0)) and _tiene_contexto(text, m)
    }
    return tuple(sorted(encontrados))
