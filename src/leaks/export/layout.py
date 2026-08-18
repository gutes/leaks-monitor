"""Primitivas de maquetado para los informes en texto plano.

Las comparten el informe de hallazgos y el de watchlist. Están acá y no
duplicadas en cada uno para que los dos documentos se vean igual: mismo ancho,
misma columna de etiquetas, mismos separadores. Un informe que cambia de forma
según qué exportaste se lee como dos herramientas distintas.

Todo son funciones puras sobre strings.
"""

from __future__ import annotations

import textwrap
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

#: Ancho de los informes. 80 columnas: entra en cualquier terminal, en el
#: cuerpo de un mail y en un adjunto impreso sin que se corte.
WIDTH = 80

#: Ancho de la etiqueta en los pares "campo : valor". Fijo para que la columna
#: de valores quede alineada y el informe se pueda leer en diagonal.
LABEL_W = 15

SEP_FUERTE = "=" * WIDTH
SEP_SUAVE = "-" * WIDTH


def num(valor: Any) -> str:
    """Entero con separador de miles a la española: 225375 -> '225.375'."""
    if not isinstance(valor, int):
        return str(valor)
    return f"{valor:,}".replace(",", ".")


def _utc(valor: datetime) -> datetime:
    return (valor if valor.tzinfo else valor.replace(tzinfo=UTC)).astimezone(UTC)


def fecha(valor: Any) -> str:
    """Fecha y hora en UTC. Los naive se asumen UTC, como en toda la base."""
    return _utc(valor).strftime("%Y-%m-%d %H:%M UTC") if isinstance(valor, datetime) else "—"


def dia(valor: Any) -> str:
    return _utc(valor).strftime("%Y-%m-%d") if isinstance(valor, datetime) else "—"


def campo(etiqueta: str, valor: Any, sangria: str = "  ") -> str:
    texto = "—" if valor in (None, "", []) else str(valor)
    return f"{sangria}{etiqueta.ljust(LABEL_W)}: {texto}"


def parrafo(texto: str, sangria: str = "    ") -> list[str]:
    """Envuelve texto libre respetando el ancho. Vacío no produce líneas."""
    if not texto:
        return []
    lineas: list[str] = []
    for cruda in str(texto).splitlines():
        if not cruda.strip():
            lineas.append("")
            continue
        lineas.extend(
            textwrap.wrap(
                cruda.strip(),
                width=WIDTH,
                initial_indent=sangria,
                subsequent_indent=sangria,
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
    return lineas


def lista_envuelta(valores: Iterable[str], sangria: str = "      ") -> list[str]:
    """Una enumeración separada por comas, envuelta al ancho del informe."""
    texto = ", ".join(v for v in valores if v)
    return parrafo(texto, sangria) if texto else []


def sello(generated_at: datetime) -> str:
    """Sello de tiempo para el nombre de archivo: `20260818-1547`."""
    return _utc(generated_at).strftime("%Y%m%d-%H%M")


def unir(lineas: Iterable[str]) -> str:
    """Cierra el documento.

    Ninguna línea termina en espacios: el archivo se pega en tickets y mails,
    donde el espacio final sobrevive y se nota.
    """
    return "\n".join(linea.rstrip() for linea in lineas)
