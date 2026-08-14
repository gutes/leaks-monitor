"""Adapter de dls-monitor (https://github.com/cyberiskvision/dls-monitor).

El proyecto publica su índice como un JSON plano versionado en GitHub, así que
la "API" es el archivo crudo del repo. Ventaja: no hay rate limit propio ni
términos de servicio más allá de los de GitHub. Desventaja: es un **histórico
completo** (~2 MB, miles de posts desde 2020), no un feed incremental.

Por eso el adapter recorta por `since` en el propio `fetch`: normalizar 20.000
posts en cada corrida diaria para tirar el 99,9% sería tirar CPU al pedo. En la
primera corrida no hay cursor y se procesa todo, que es lo correcto — es el
backfill.

Solo trae `post_title`, `group_name` y `discovered`: sin país ni dominio
estructurado. La relevancia argentina sale de `tld_ar` sobre el título y de las
keywords de la watchlist.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from leaks.adapters.http import FeedHttpClient
from leaks.adapters.parsing import first_str, parse_datetime
from leaks.domain.models import LeakType, NormalizedItem, RawItem

POSTS_URL = "https://raw.githubusercontent.com/cyberiskvision/dls-monitor/main/posts.json"

LICENSE_NOTE = "Proyecto open source, self-hosteable. Se consume el posts.json publicado en GitHub."


class DlsMonitorAdapter:
    """Índice histórico de posts de data leak sites."""

    name = "dls-monitor"
    leak_type = LeakType.RANSOMWARE

    def __init__(self, client: FeedHttpClient, posts_url: str = POSTS_URL) -> None:
        self._client = client
        self._posts_url = posts_url

    def fetch(self, since: datetime | None) -> Iterable[RawItem]:
        """Trae el índice completo y descarta lo anterior al cursor.

        El filtro se hace acá y no en el runner porque el volumen lo justifica:
        es la diferencia entre normalizar miles de registros o decenas.
        """
        payload = self._client.get_json(self._posts_url)
        if not isinstance(payload, list):
            return

        for entrada in payload:
            if not isinstance(entrada, dict):
                continue
            if since is not None:
                descubierto = parse_datetime(entrada.get("discovered"))
                if descubierto is not None and descubierto <= since:
                    continue
            yield RawItem(source=self.name, payload=entrada)

    def normalize(self, item: RawItem) -> NormalizedItem | None:
        payload: dict[str, Any] = item.payload

        victim_name = first_str(payload, "post_title")
        if not victim_name:
            return None

        discovered = parse_datetime(payload.get("discovered"))
        if discovered is None:
            return None

        return NormalizedItem(
            source=self.name,
            leak_type=self.leak_type,
            victim_name=victim_name,
            victim_domain=victim_name if "." in victim_name and " " not in victim_name else None,
            country=None,
            sector=None,
            actor=first_str(payload, "group_name"),
            discovered_at=discovered,
            published_at=None,
            raw_ref=None,
            description=None,
        )
