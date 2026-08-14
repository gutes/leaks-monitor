"""Adapter de ransomware.live (API v2 pública, sin autenticación).

LICENCIA — el tier gratuito es "personal use only, not for corporate/business
use". Alcanza para este prototipo; NO habilita un despliegue institucional
sobre la licencia free. Ver README y docs/feeds.md.

Se consultan dos endpoints a propósito:

* `/v2/countryvictims/AR` — las víctimas que el feed ya etiquetó como
  argentinas. Es barato y preciso.
* `/v2/recentvictims` — el índice global reciente. Hace falta porque el feed
  deja `country` vacío bastante seguido: una víctima con dominio `.com.ar`
  puede no estar etiquetada como AR y se perdería. La capa de relevancia la
  levanta igual por `tld_ar`.

Los dos endpoints devuelven **campos con nombres distintos** para lo mismo
(`group` vs `group_name`, `victim` vs `post_title`), así que `normalize`
contempla ambas formas.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from leaks.adapters.http import FeedHttpClient
from leaks.adapters.parsing import first_str, parse_datetime
from leaks.domain.models import LeakType, NormalizedItem, RawItem

BASE_URL = "https://api.ransomware.live/v2"

LICENSE_NOTE = (
    "Tier gratuito: uso personal únicamente, no corporativo/comercial. "
    "Apto para prototipo, no para producción institucional."
)


class RansomwareLiveAdapter:
    """Víctimas de grupos de ransomware. Metadata, sin PII de individuos."""

    name = "ransomware.live"
    leak_type = LeakType.RANSOMWARE

    def __init__(self, client: FeedHttpClient, base_url: str = BASE_URL) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    def fetch(self, since: datetime | None) -> Iterable[RawItem]:
        """Trae el índice argentino y el global reciente.

        El filtrado incremental por `since` lo hace el runner: el feed no
        expone un parámetro de fecha, así que traemos y descartamos localmente.
        """
        for endpoint in ("countryvictims/AR", "recentvictims"):
            payload = self._client.get_json(f"{self._base_url}/{endpoint}")
            if not isinstance(payload, list):
                continue
            for entrada in payload:
                if isinstance(entrada, dict):
                    yield RawItem(source=self.name, payload=entrada)

    def normalize(self, item: RawItem) -> NormalizedItem | None:
        """Mapea cualquiera de las dos formas del feed al schema común.

        Nótese qué NO se copia: `infostealer.last_employee_compromised` y
        `last_user_compromised` pueden traer el email de una persona física, y
        nunca entran al modelo. Se descartan por construcción, no por filtro.
        """
        payload: dict[str, Any] = item.payload

        victim_name = first_str(payload, "victim", "post_title", "website", "domain")
        if not victim_name:
            return None

        discovered = parse_datetime(payload.get("discovered")) or parse_datetime(
            payload.get("attackdate")
        )
        if discovered is None:
            return None

        return NormalizedItem(
            source=self.name,
            leak_type=self.leak_type,
            victim_name=victim_name,
            victim_domain=first_str(payload, "website", "domain"),
            country=first_str(payload, "country"),
            sector=first_str(payload, "activity"),
            actor=first_str(payload, "group_name", "group"),
            discovered_at=discovered,
            published_at=parse_datetime(payload.get("published"))
            or parse_datetime(payload.get("attackdate")),
            raw_ref=first_str(payload, "post_url", "claim_url", "url"),
            description=first_str(payload, "description"),
        )
