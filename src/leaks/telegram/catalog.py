"""Importador del catálogo público de canales de actores.

La fuente es **deepdarkCTI** (`fastfire/deepdarkCTI`), un repositorio público en
GitHub que mantiene una tabla markdown de canales de Telegram con el actor
atribuido y el tipo de actividad. Se lee el archivo crudo: sin API key, sin
autenticación y sin depender de la API de GitHub.

Medido el 2026-08-18: 1.025 filas en la tabla, de las cuales solo **390 no
están marcadas como muertas** y **344 son canales públicos únicos** legibles
por `t.me/s/`. El resto son invitaciones a grupos privados (`t.me/+…`), que sin
una cuenta no se pueden leer — y este prototipo no usa una.

Un conteo anterior dio 801 porque filtraba solo `EXPIRED` y dejaba pasar los
`DEAD` y `OFFLINE`. Y aun entre los 344 hay entradas rancias: de 25 canales de
filtración verificados uno por uno, 16 tenían vista previa real.

## Lo que este catálogo NO resuelve

Ninguno de los actores que motivaron el conector está acá: Chronus Team,
Gov.eth, Sherlock, Dictadores y La Pampa Leaks **no figuran**. De las 971 filas
solo 4 son de la región. El catálogo está orientado a hacktivismo DDoS ruso y
de Medio Oriente.

Por eso el alta manual de canales es el mecanismo principal y esto es una
conveniencia. Está anotado acá para que nadie asuma que importar el catálogo
alcanza.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from leaks.adapters.http import FeedHttpClient
from leaks.adapters.telegram import normalizar_handle

logger = logging.getLogger(__name__)

CATALOG_URL = (
    "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/telegram_threat_actors.md"
)

SOURCE_NAME = "deepdarkCTI"

#: Los 4 canales de la región que sí trae el catálogo. Se siembran habilitados
#: porque son pocos y son exactamente el caso de uso; el resto entra apagado.
LATAM_SEED: tuple[dict[str, str], ...] = (
    {
        "handle": "KillnetLATAM",
        "actor": "Killnet LATAM",
        "kind": "ddos",
        "notes": "Rama regional de Killnet. Anuncia objetivos antes de atacar.",
    },
    {
        "handle": "KillnetChatLATAM",
        "actor": "Killnet LATAM",
        "kind": "ddos",
        "notes": "Chat de coordinación de la rama regional.",
    },
    {
        "handle": "MexicanMafiaTheShit",
        "actor": "MexicanMafia",
        "kind": "data_leak",
        "notes": "Filtraciones con foco en México; el patrón MX→AR está medido.",
    },
    {
        "handle": "perunswaroga",
        "actor": "Перун Сварога",
        "kind": "data_leak",
        "notes": "Filtraciones con menciones regionales.",
    },
)


@dataclass(frozen=True)
class CatalogEntry:
    """Una fila del catálogo, ya normalizada."""

    handle: str
    actor: str | None
    kind: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "actor": self.actor,
            "kind": self.kind,
            "notes": f"Importado de {SOURCE_NAME}.",
        }


_EXPIRADO = re.compile(r"expired|dead|offline", re.I)


def parse_catalog(texto: str) -> list[CatalogEntry]:
    """Parsea la tabla markdown. Descarta expirados e invitaciones privadas.

    Formato: `|URL|estado|actor|tipo de ataque|`. Se tolera que falten columnas
    —muchas filas no tienen actor— y que el separador de encabezado aparezca.
    """
    encontrados: list[CatalogEntry] = []
    vistos: set[str] = set()

    for linea in texto.splitlines():
        if not linea.startswith("|"):
            continue
        celdas = [c.strip() for c in linea.strip("|").split("|")]
        if len(celdas) < 2:
            continue
        url = celdas[0]
        if url.lower().startswith(("telegram", "---", ":--")) or not url:
            continue
        if _EXPIRADO.search(celdas[1]):
            continue

        handle = normalizar_handle(url)
        if handle is None or handle in vistos:
            continue
        vistos.add(handle)

        actor = celdas[2] if len(celdas) > 2 and celdas[2] else None
        kind = celdas[3] if len(celdas) > 3 and celdas[3] else None
        encontrados.append(
            CatalogEntry(handle=handle, actor=actor, kind=kind.lower() if kind else None)
        )

    return encontrados


def fetch_catalog(client: FeedHttpClient, url: str = CATALOG_URL) -> list[CatalogEntry]:
    """Baja y parsea el catálogo. Devuelve vacío si la fuente no responde."""
    try:
        crudo = client.get_text(url)
    except Exception as exc:
        logger.warning("El catálogo de canales falló: %s", type(exc).__name__)
        return []
    entradas = parse_catalog(crudo)
    logger.info("%s: %d canales públicos legibles", SOURCE_NAME, len(entradas))
    return entradas
