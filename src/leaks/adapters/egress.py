"""Resolución de la IP pública de salida.

Control de operación, no de datos: antes de consultar feeds de este rubro
conviene confirmar que se está saliendo por la VPN que uno cree y no por la
conexión de casa.

Qué se manda afuera: **nada**. Un GET sin cuerpo a un servicio de eco. El
servicio ve nuestra IP, que es exactamente lo que le estamos preguntando —
no viaja la watchlist ni ningún hallazgo.

Se consulta una lista de proveedores en orden y gana el primero que conteste,
porque son gratuitos y se caen o rate-limitean seguido.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from leaks.adapters.http import FeedHttpClient

logger = logging.getLogger(__name__)

#: Proveedores en orden de preferencia. El primero trae `org`, que es lo que
#: permite reconocer al proveedor de VPN de un vistazo.
DEFAULT_PROVIDERS: tuple[str, ...] = (
    "https://ipinfo.io/json",
    "https://ifconfig.co/json",
    "https://ipapi.co/json",
)


@dataclass(frozen=True)
class EgressInfo:
    """Desde dónde sale nuestro tráfico."""

    ip: str
    country: str | None = None
    country_name: str | None = None
    city: str | None = None
    org: str | None = None
    provider: str | None = None
    checked_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_name": self.country_name,
            "city": self.city,
            "org": self.org,
            "provider": self.provider,
            "checked_at": self.checked_at,
        }

    @property
    def label(self) -> str:
        """Una línea para la consola: `149.88.104.6 (CL · Datacamp)`."""
        detalle = " · ".join(p for p in (self.country, self.org) if p)
        return f"{self.ip} ({detalle})" if detalle else self.ip


def _parse(payload: dict[str, Any]) -> EgressInfo | None:
    """Normaliza la respuesta, que cambia de forma según el proveedor."""
    ip = payload.get("ip")
    if not isinstance(ip, str) or not ip:
        return None

    # `country` es ISO-2 en ipinfo/ipapi, pero nombre completo en ifconfig.co.
    country = payload.get("country") or payload.get("country_iso")
    country_name = payload.get("country_name")
    if isinstance(country, str) and len(country) > 2:
        country_name = country_name or country
        country = payload.get("country_iso") or payload.get("country_code")

    return EgressInfo(
        ip=ip,
        country=country if isinstance(country, str) else None,
        country_name=country_name if isinstance(country_name, str) else None,
        city=payload.get("city") if isinstance(payload.get("city"), str) else None,
        # ipinfo usa `org`, ifconfig.co usa `asn_org`.
        org=next(
            (payload[k] for k in ("org", "asn_org") if isinstance(payload.get(k), str)),
            None,
        ),
    )


class EgressResolver:
    """Resuelve la IP de salida y cachea el resultado.

    El cache existe porque el badge se refresca con el tablero y estos
    servicios rate-limitean rápido: la IP de salida no cambia entre dos clicks.
    """

    def __init__(
        self,
        client: FeedHttpClient,
        providers: tuple[str, ...] = DEFAULT_PROVIDERS,
        cache_ttl_seconds: int = 300,
    ) -> None:
        self._client = client
        self._providers = providers
        self._ttl = timedelta(seconds=cache_ttl_seconds)
        self._cached: EgressInfo | None = None

    def resolve(self, *, force: bool = False) -> EgressInfo | None:
        """IP de salida, del cache o consultando. `None` si nadie contestó."""
        ahora = datetime.now(UTC)
        if (
            not force
            and self._cached is not None
            and self._cached.checked_at is not None
            and ahora - self._cached.checked_at < self._ttl
        ):
            return self._cached

        for url in self._providers:
            try:
                payload = self._client.get_json(url)
            except Exception:
                logger.debug("El proveedor de IP %s no respondió", url, exc_info=True)
                continue

            if not isinstance(payload, dict):
                continue
            info = _parse(payload)
            if info is None:
                continue

            self._cached = EgressInfo(**{**info.as_dict(), "provider": url, "checked_at": ahora})
            return self._cached

        # Fail-soft: no saber la IP degrada el badge, no rompe el tablero.
        logger.warning("Ningún proveedor pudo resolver la IP de salida")
        return None
