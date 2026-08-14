"""Parsing tolerante de los formatos que devuelven los feeds.

Cada feed escribe las fechas a su manera. La regla del proyecto es explícita:
naive vs aware se decide **en el borde**, y de acá para adentro todo es aware
en UTC.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

#: Formatos vistos en los feeds, en orden de frecuencia.
_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",  # ransomlook, dls-monitor
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
)


def parse_datetime(value: Any) -> datetime | None:
    """Convierte lo que venga a un datetime aware en UTC.

    Devuelve `None` si no se puede interpretar: un registro con fecha ilegible
    se descarta, no rompe la ingesta.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None

    texto = value.strip()
    if not texto:
        return None

    # ISO-8601 con offset o 'Z' (ransomware.live, Atom de MyBB).
    try:
        parsed = datetime.fromisoformat(texto.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is not None:
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    for formato in _FORMATS:
        try:
            return datetime.strptime(texto, formato).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def first_str(payload: dict[str, Any], *keys: str) -> str | None:
    """Primer valor de texto no vacío entre varias claves posibles.

    Los feeds cambian nombres de campo entre endpoints (`group` vs `group_name`,
    `victim` vs `post_title`); esto evita repetir el mismo `or` en cada adapter.
    """
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
