"""Adapter de RansomLook (https://www.ransomlook.io) — open source, API pública.

Cubre los mismos grupos de ransomware que ransomware.live pero con otra
cobertura (incluye Telegram), así que las dos fuentes se complementan: lo que
una pierde, la otra lo suele tener. El dedup las mantiene separadas a propósito
—`source` entra en el hash— porque saber que dos feeds independientes vieron el
mismo hallazgo es señal, no ruido.

Diferencia importante con ransomware.live: **no trae campo `country` ni
`domain` estructurado**. El nombre de la víctima suele SER el dominio
(`granjarinya.com`), así que la relevancia argentina se apoya en `tld_ar` y en
las keywords de la watchlist.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from leaks.adapters.http import FeedHttpClient
from leaks.adapters.parsing import first_str, parse_datetime
from leaks.domain.models import LeakType, NormalizedItem, RawItem

BASE_URL = "https://www.ransomlook.io"

LICENSE_NOTE = "Proyecto open source (AGPL). API pública sin autenticación."


class RansomLookAdapter:
    """Posts recientes de sitios de extorsión. Metadata, sin PII de individuos."""

    name = "ransomlook"
    leak_type = LeakType.RANSOMWARE

    def __init__(self, client: FeedHttpClient, base_url: str = BASE_URL) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    def fetch(self, since: datetime | None) -> Iterable[RawItem]:
        """Trae el índice de posts recientes.

        El endpoint no acepta filtro por fecha: el recorte incremental por
        `since` lo hace el runner sobre el item ya normalizado.
        """
        payload = self._client.get_json(f"{self._base_url}/api/recent")
        if not isinstance(payload, list):
            return
        for entrada in payload:
            if isinstance(entrada, dict):
                yield RawItem(source=self.name, payload=entrada)

    def normalize(self, item: RawItem) -> NormalizedItem | None:
        """Mapea un post al schema común.

        `link` es relativo (`/blog/post/...`): se absolutiza para que
        `raw_ref` sirva como referencia clickeable desde el frontend.
        """
        payload: dict[str, Any] = item.payload

        victim_name = first_str(payload, "post_title")
        if not victim_name:
            return None

        discovered = parse_datetime(payload.get("discovered"))
        if discovered is None:
            return None

        link = first_str(payload, "link")
        raw_ref = f"{self._base_url}{link}" if link and link.startswith("/") else link

        return NormalizedItem(
            source=self.name,
            leak_type=self.leak_type,
            # El feed pone el dominio como título cuando lo conoce; si no es un
            # dominio, `_normalize_domain` + la relevancia lo descartan solos.
            victim_name=victim_name,
            victim_domain=victim_name if "." in victim_name and " " not in victim_name else None,
            country=None,
            sector=None,
            actor=first_str(payload, "group_name"),
            discovered_at=discovered,
            published_at=None,
            raw_ref=raw_ref,
            description=first_str(payload, "description"),
        )
