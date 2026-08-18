"""De dónde salen las víctimas regionales.

Hoy hay una sola fuente —ransomware.live, que ya consumimos para Argentina— y
por eso esto es un catálogo declarativo y no un `if`: sumar otra es agregar una
entrada acá.

Se consulta `/v2/countryvictims/<CC>` país por país. Es el mismo endpoint que
usa el adapter argentino con `AR`, así que la forma del payload ya está
verificada y las dos partes normalizan igual.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from leaks.adapters.http import FeedHttpClient
from leaks.adapters.parsing import first_str, parse_datetime
from leaks.extraction.dating import is_sane
from leaks.privacy.scrub import redact_pii

logger = logging.getLogger(__name__)

BASE_URL = "https://api.ransomware.live/v2"

SOURCE_RANSOMWARE_LIVE = "ransomware.live"


@dataclass(frozen=True)
class RegionalVictim:
    """Una víctima regional, ya normalizada. Metadata, nunca PII."""

    actor: str
    country: str
    victim_name: str
    victim_domain: str | None
    sector: str | None
    #: `None` si el feed no la fecha de forma creíble. No se inventa: una
    #: víctima sin fecha no puede sostener recencia ni tendencia.
    occurred_at: datetime | None
    source: str


def _normalizar(entrada: dict[str, object], country: str, source: str) -> RegionalVictim | None:
    """Mapea una entrada del feed. Devuelve `None` si no alcanza para nada."""
    actor = first_str(entrada, "group_name", "group")
    nombre = first_str(entrada, "post_title", "victim", "website", "domain")
    if not actor or not nombre:
        return None

    ocurrido = parse_datetime(entrada.get("discovered")) or parse_datetime(entrada.get("published"))
    if ocurrido is not None and not is_sane(ocurrido):
        # Misma postura que en el pipeline argentino: fecha imposible es
        # ausencia de fecha, no una fecha rara que después ensucia el score.
        ocurrido = None

    dominio = first_str(entrada, "website", "domain")
    sector = first_str(entrada, "activity")

    return RegionalVictim(
        actor=actor.strip().lower(),
        country=country.upper(),
        # El nombre lo escribe un grupo de ransomware: pasa por el redactor
        # igual que del lado argentino.
        victim_name=(redact_pii(nombre) or nombre)[:512],
        victim_domain=dominio.strip().lower()[:255] if dominio else None,
        sector=sector.strip()[:128] if sector else None,
        occurred_at=ocurrido,
        source=source,
    )


def fetch_ransomware_live(
    client: FeedHttpClient, country: str, base_url: str = BASE_URL
) -> list[RegionalVictim]:
    """Víctimas de un país. Un país por request, como el endpoint argentino."""
    payload = client.get_json(f"{base_url.rstrip('/')}/countryvictims/{country.upper()}")
    if not isinstance(payload, list):
        logger.info("countryvictims/%s devolvió algo que no es una lista", country)
        return []

    encontradas: list[RegionalVictim] = []
    for entrada in payload:
        if not isinstance(entrada, dict):
            continue
        victima = _normalizar(entrada, country, SOURCE_RANSOMWARE_LIVE)
        if victima is not None:
            encontradas.append(victima)
    return encontradas


#: Fuentes disponibles: `(nombre, función que trae un país)`.
RegistryFetcher = Callable[[FeedHttpClient, str], Sequence[RegionalVictim]]

REGIONAL_SOURCES: tuple[tuple[str, RegistryFetcher], ...] = (
    (SOURCE_RANSOMWARE_LIVE, fetch_ransomware_live),
)


def ahora() -> datetime:
    return datetime.now(UTC)
