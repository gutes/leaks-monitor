"""Cálculo del hash de deduplicación.

Es lo que hace idempotente al pipeline: re-correrlo no duplica filas.

La identidad de un hallazgo son los campos que **no** cambian entre corridas:
fuente, víctima, actor y el **día** en que se descubrió. Se usa el día y no el
timestamp completo a propósito — varios feeds reescriben el `discovered` con
jitter de microsegundos en cada publicación de su índice, y un hash sobre el
timestamp exacto generaría un duplicado nuevo en cada corrida.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _norm(value: str | None) -> str:
    """Normaliza un componente del hash: minúsculas, sin ruido de puntuación."""
    if not value:
        return ""
    return _NON_ALNUM.sub("", value.strip().lower())


def compute_dedup_hash(
    *,
    source: str,
    victim_name: str,
    victim_domain: str | None,
    actor: str | None,
    discovered_at: datetime,
) -> str:
    """Hash estable de la identidad de un hallazgo.

    Se prefiere el dominio sobre el nombre cuando existe: los feeds escriben el
    mismo nombre de víctima de mil formas ("Ministerio X", "MINISTERIO X S.A."),
    pero el dominio es un identificador limpio.
    """
    victim_key = _norm(victim_domain) or _norm(victim_name)
    parts = (
        _norm(source),
        victim_key,
        _norm(actor),
        discovered_at.date().isoformat(),
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
