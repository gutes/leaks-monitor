"""Estimación de cuándo ocurrió un leak, no de cuándo lo vimos.

El problema que resuelve: el prototipo confundía **cuándo apareció un hallazgo
en nuestra base** con **cuándo ocurrió el evento**. Una fuente que no fecha su
dato hacía que todo su histórico se viera como novedad del día.

La regla de oro es la misma postura fail-closed del resto del proyecto: **si no
se puede fechar, se dice "sin fecha"**. Nunca `datetime.now()`. Una fecha
ausente y visible es honesta; una inventada y creíble contamina todo lo que se
apoye en ella —el orden del tablero, las alertas, y cualquier cálculo de
recencia.

Todo acá son funciones puras, sin red ni base: se testean solas.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from leaks.adapters.parsing import parse_datetime

#: Antes de esto no había sitios de filtración: una fecha anterior es basura de
#: parseo, no un leak de los noventa.
MIN_YEAR = 2010

#: Centinela de "sin dato" que usa Hudson Rock. Sin este descarte, un dominio
#: sin compromisos quedaría fechado en 1970.
EPOCH_SENTINEL = datetime(1970, 1, 1, tzinfo=UTC)

#: Años plausibles dentro de un título de foro: `[2.1TB][2026] Empresa Database`.
_YEAR_IN_TEXT = re.compile(r"\b(20[0-3]\d)\b")


class DateBasis(StrEnum):
    """De dónde salió la fecha. Se persiste para poder auditarla."""

    #: La declaró la fuente en un campo de fecha.
    FEED = "feed"
    #: Se dedujo de un año embebido en el texto. Precisión: el año.
    TEXTO = "texto"
    #: La aportó otra fuente que ya tenía el mismo hallazgo, con fecha anterior.
    CORROBORACION = "corroboracion"
    #: No se pudo fechar. `occurred_at` queda en NULL.
    SIN_DATO = "sin_dato"


class Freshness(StrEnum):
    """Qué tan reciente es el evento, no el descubrimiento."""

    RECIENTE = "reciente"
    HISTORICO = "historico"
    SIN_FECHA = "sin_fecha"


def is_sane(value: datetime | None, *, now: datetime | None = None) -> bool:
    """¿La fecha es creíble como fecha de un leak?

    Descarta el futuro (un feed con el reloj mal, o un parseo que se comió el
    año), lo anterior a 2010, y el centinela epoch.
    """
    if value is None:
        return False
    momento = now or datetime.now(UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    if value == EPOCH_SENTINEL:
        return False
    if value.year < MIN_YEAR:
        return False
    # Un día de tolerancia: los husos horarios de los feeds no son de fiar.
    return (value - momento).days <= 1


def from_feed(
    payload: dict[str, Any], *fields: str, now: datetime | None = None
) -> datetime | None:
    """Primera fecha creíble entre los campos que declare la fuente.

    El orden de `fields` es la preferencia del adapter: primero el campo que
    mejor representa cuándo ocurrió, después los sustitutos.
    """
    for campo in fields:
        fecha = parse_datetime(payload.get(campo))
        if is_sane(fecha, now=now):
            return fecha
    return None


def newest_sane(*values: Any, now: datetime | None = None) -> datetime | None:
    """La más reciente de varias fechas, descartando las que no son creíbles.

    Lo usa Hudson Rock, que informa el último compromiso de empleados y el de
    usuarios por separado, y deja el centinela epoch en el que no aplica.
    """
    fechas: list[datetime] = []
    for valor in values:
        fecha = parse_datetime(valor)
        if fecha is not None and is_sane(fecha, now=now):
            fechas.append(fecha)
    return max(fechas) if fechas else None


def year_from_text(*textos: str | None, now: datetime | None = None) -> datetime | None:
    """Fecha derivada de un año embebido en el texto.

    Los foros titulan `[2.1TB][2026] Empresa Database`, y ese año suele ser el
    único dato de cuándo se obtuvo la información. Se fecha al 1° de enero: la
    precisión real es el año y no conviene aparentar más.

    Se toma el año **más alto** que sea plausible: un título puede mencionar
    varios (`datos 2019-2024`) y el más reciente es el que fecha el volcado.
    """
    momento = now or datetime.now(UTC)
    candidatos: list[int] = []
    for texto in textos:
        if texto:
            candidatos.extend(int(m.group(1)) for m in _YEAR_IN_TEXT.finditer(texto))

    plausibles = [a for a in candidatos if MIN_YEAR <= a <= momento.year]
    if not plausibles:
        return None
    return datetime(max(plausibles), 1, 1, tzinfo=UTC)


def classify(
    occurred_at: datetime | None, *, fresh_days: int, now: datetime | None = None
) -> Freshness:
    """Reciente, histórico o sin fecha."""
    if occurred_at is None:
        return Freshness.SIN_FECHA
    momento = now or datetime.now(UTC)
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=UTC)
    return Freshness.RECIENTE if (momento - occurred_at).days <= fresh_days else Freshness.HISTORICO


def resolve(
    *,
    feed_date: datetime | None = None,
    texts: tuple[str | None, ...] = (),
    corroborated: datetime | None = None,
    now: datetime | None = None,
) -> tuple[datetime | None, DateBasis]:
    """Cascada completa: devuelve la mejor fecha y de dónde salió.

    Orden de preferencia:

    1. lo que declara la fuente,
    2. el año embebido en el texto,
    3. lo que aportó otra fuente para el mismo hallazgo,
    4. nada.

    La corroboración va **después** del texto porque es la señal más indirecta:
    depende de que el emparejamiento entre fuentes sea correcto.
    """
    if is_sane(feed_date, now=now):
        return feed_date, DateBasis.FEED

    del_texto = year_from_text(*texts, now=now)
    if del_texto is not None:
        return del_texto, DateBasis.TEXTO

    if is_sane(corroborated, now=now):
        return corroborated, DateBasis.CORROBORACION

    return None, DateBasis.SIN_DATO
