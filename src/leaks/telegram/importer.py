"""Alta masiva de canales desde un texto pegado o un archivo.

El caso real no es un JSON prolijo: es una lista sacada de un informe, un chat o
una planilla, con formatos mezclados y basura en el medio. Por eso el parser es
tolerante con la forma y **estricto con el resultado**: lo que no se pudo leer
se devuelve con el motivo, en vez de saltearse en silencio.

Formatos que acepta, mezclados en el mismo archivo:

    @canal
    t.me/otro
    https://t.me/s/tercero
    cuarto, Chronus Team, data_leak, avisa antes de atacar
    # esto es un comentario y se ignora

La primera columna es el canal; las tres siguientes, opcionales, son actor, tipo
y nota. Se separa por coma, punto y coma o tabulación — lo que salga de pegar
una planilla.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from leaks.adapters.telegram import normalizar_handle

#: Coma, punto y coma o tabulación. Es lo que produce pegar desde una planilla
#: o desde un informe, y no vale la pena obligar a elegir uno.
_SEPARADOR = re.compile(r"\s*[,;\t]\s*")

#: Tope de líneas por importación. No es una restricción de producto: es para
#: que pegar un archivo equivocado no encole miles de canales.
MAX_LINEAS = 2000


@dataclass(frozen=True)
class LineaRechazada:
    """Una línea que no se pudo interpretar, con el motivo."""

    numero: int
    contenido: str
    motivo: str

    def as_dict(self) -> dict[str, Any]:
        return {"numero": self.numero, "contenido": self.contenido[:120], "motivo": self.motivo}


@dataclass(frozen=True)
class Lectura:
    """Resultado de leer el texto: lo aceptado y lo que no."""

    canales: list[dict[str, Any]] = field(default_factory=list)
    rechazadas: list[LineaRechazada] = field(default_factory=list)
    #: Cuántas líneas venían repetidas dentro del mismo texto.
    duplicadas: int = 0

    @property
    def total_leidas(self) -> int:
        return len(self.canales) + len(self.rechazadas) + self.duplicadas


def _campo(partes: list[str], i: int) -> str | None:
    """Columna opcional de la línea. Vacía cuenta como ausente."""
    valor = partes[i].strip() if len(partes) > i else ""
    return valor or None


def parsear(texto: str, *, max_lineas: int = MAX_LINEAS) -> Lectura:
    """Lee el texto y devuelve los canales, sin tocar la base.

    Es una función pura para que se pueda mostrar lo que va a pasar antes de
    que pase: qué entra, qué se rechaza y por qué.
    """
    canales: list[dict[str, Any]] = []
    rechazadas: list[LineaRechazada] = []
    vistos: set[str] = set()
    duplicadas = 0

    for numero, cruda in enumerate(texto.splitlines()[:max_lineas], start=1):
        linea = cruda.strip()
        if not linea or linea.startswith("#"):
            continue

        partes = _SEPARADOR.split(linea)
        handle = normalizar_handle(partes[0])
        if handle is None:
            rechazadas.append(
                LineaRechazada(
                    numero=numero,
                    contenido=linea,
                    motivo=(
                        "no es un canal público: las invitaciones a grupos privados "
                        "(t.me/+… o /joinchat/) no se pueden leer sin una cuenta"
                        if "+" in partes[0] or "joinchat" in partes[0].lower()
                        else "no parece un handle de Telegram"
                    ),
                )
            )
            continue

        if handle.lower() in vistos:
            duplicadas += 1
            continue
        vistos.add(handle.lower())

        canales.append(
            {
                "handle": handle,
                "actor": _campo(partes, 1),
                "kind": _campo(partes, 2),
                "notes": _campo(partes, 3),
            }
        )

    return Lectura(canales=canales, rechazadas=rechazadas, duplicadas=duplicadas)
