"""Descubrimiento de subforos por la sindicación abierta.

**Para qué.** Cada subforo de un MyBB publica su propio Atom con SUS últimos
threads, así que sumarlos multiplica la ventana de cobertura: medido el
2026-09-01 contra darkforums, el índice global cubría 20,6 h mientras que los
subforos iban de 1,8 días a más de tres años. Pero el adapter necesita los ids,
y los ids no salen en ningún lado del feed.

**Por qué esto y no un scraper.** El HTML del foro está detrás de un desafío JS;
`syndication.php` no. Pasar ese desafío sería evadir un control de acceso —acá
no se hace—, así que el descubrimiento se apoya en el mismo endpoint abierto
que ya consumimos: un GET por id candidato, leyendo solo cuántos threads trae y
qué período cubre.

**Es una herramienta, no un colector.** No escribe en la base, no persiste
títulos y no corre sola: se dispara a mano cuando el foro se reorganiza o
cambia de dominio. El título de muestra que devuelve va redactado, porque en
estos foros los títulos son avisos de volcados de datos.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from leaks.adapters.http import FeedHttpClient, describe_cause
from leaks.adapters.mybb_forum import SYNDICATION_PATH, parse_atom
from leaks.adapters.parsing import parse_datetime
from leaks.privacy.scrub import redact_pii

logger = logging.getLogger(__name__)

#: Rango por defecto. Los foros MyBB numeran sus secciones desde 1 y no suelen
#: pasar de unas decenas; el tope existe para que esto no sea un barrido largo.
DEFAULT_FIRST_FID = 1
DEFAULT_LAST_FID = 60

#: Cuánto del título se muestra. Alcanza para reconocer la sección y no
#: convierte la salida en un volcado de avisos.
SAMPLE_LENGTH = 60


@dataclass(frozen=True)
class SubforumProbe:
    """Lo que se supo de un subforo con un solo GET."""

    fid: str
    threads: int
    window_from: datetime | None = None
    window_to: datetime | None = None
    sample_title: str | None = None

    @property
    def window_days(self) -> float | None:
        if self.window_from is None or self.window_to is None:
            return None
        return (self.window_to - self.window_from).total_seconds() / 86400

    def as_dict(self) -> dict[str, Any]:
        return {
            "fid": self.fid,
            "threads": self.threads,
            "window_from": self.window_from,
            "window_to": self.window_to,
            "window_days": self.window_days,
            "sample_title": self.sample_title,
        }


def candidate_fids(first: int = DEFAULT_FIRST_FID, last: int = DEFAULT_LAST_FID) -> tuple[str, ...]:
    """Ids a probar. Se valida acá para que un rango absurdo no salga a la red."""
    if first < 1 or last < first:
        raise ValueError(f"rango de fids inválido: {first}..{last}")
    return tuple(str(f) for f in range(first, last + 1))


def probe_subforum(
    client: FeedHttpClient, base_url: str, fid: str, *, path: str = SYNDICATION_PATH
) -> SubforumProbe | None:
    """Consulta un subforo. Devuelve `None` si no existe, está vacío o no parsea.

    Un id que no responde no es un error: la mayoría del rango probado no va a
    existir, y eso es información, no una falla.
    """
    url = f"{base_url.rstrip('/')}{path}&fid={fid}"
    try:
        xml = client.get_text(url)
    except Exception as exc:
        logger.info("fid %s: sin respuesta (%s)", fid, describe_cause(exc))
        return None

    try:
        items = list(parse_atom(xml, source="discovery"))
    except Exception:
        # Los subforos restringidos devuelven algo que no es Atom. Es un "no",
        # no una falla que amerite cortar el barrido.
        logger.info("fid %s: la respuesta no es un Atom legible", fid)
        return None

    if not items:
        return None

    fechas = sorted(
        f
        for f in (
            parse_datetime(str(i.payload.get("published") or i.payload.get("updated") or ""))
            for i in items
        )
        if f is not None
    )
    muestra = redact_pii(str(items[0].payload.get("title") or ""), max_length=SAMPLE_LENGTH)

    return SubforumProbe(
        fid=fid,
        threads=len(items),
        window_from=fechas[0] if fechas else None,
        window_to=fechas[-1] if fechas else None,
        sample_title=muestra or None,
    )


def discover_subforums(
    client: FeedHttpClient,
    base_url: str,
    fids: Iterable[str],
    *,
    path: str = SYNDICATION_PATH,
) -> tuple[SubforumProbe, ...]:
    """Barre los ids candidatos y devuelve solo los que tienen contenido.

    El orden es por ventana descendente: primero el subforo que más historia
    conserva, que es el que más cobertura agrega.

    La autolimitación entre requests la aplica el cliente, igual que en
    cualquier otra consulta del pipeline.
    """
    hallados = [p for fid in fids if (p := probe_subforum(client, base_url, fid, path=path))]
    return tuple(sorted(hallados, key=lambda p: p.window_days or 0.0, reverse=True))


def as_env_line(setting: str, probes: Sequence[SubforumProbe]) -> str:
    """Línea lista para pegar en el `.env`.

    Es el formato de salida a propósito: incorporar un subforo sigue siendo un
    acto explícito del investigador, no algo que la herramienta se auto-aplica.
    """
    return f"{setting}={','.join(p.fid for p in probes)}"
