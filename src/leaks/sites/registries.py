"""Registros que publican dónde vive cada sitio de leaks.

Perseguir dominios que rotan es trabajo que **ya hacen** los proyectos que
consumimos: publican, junto con las víctimas, el catálogo de ubicaciones de
cada grupo y su disponibilidad. Acá solo se lo lee y se lo normaliza.

Verificado el 2026-08-15: ransomware.live expone 782 ubicaciones de 387 grupos
y dls-monitor 367 de 182. No hace falta ni un scraper propio ni una dependencia
nueva.

**Esto es un catálogo, no un colector.** Se registra dónde está cada sitio; no
se lo visita. Los `.onion` de acá nunca se consultan desde el prototipo.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from leaks.adapters.http import FeedHttpClient
from leaks.adapters.parsing import parse_datetime

logger = logging.getLogger(__name__)

RANSOMWARE_LIVE_GROUPS = "https://api.ransomware.live/v2/groups"
DLS_MONITOR_GROUPS = "https://raw.githubusercontent.com/cyberiskvision/dls-monitor/main/groups.json"
RANSOMLOOK_MARKETS = "https://www.ransomlook.io/api/markets"


@dataclass(frozen=True)
class SiteLocation:
    """Una ubicación conocida de un sitio de leaks.

    `available` y `checked_at` son **lo que reporta el registro**, no una
    verificación nuestra: el prototipo no se conecta a estas direcciones.
    """

    group_name: str
    fqdn: str
    kind: str = "ransomware"
    title: str | None = None
    available: bool = False
    source: str = ""
    #: Cuándo lo revisó el registro. `None` si no lo publica.
    checked_at: datetime | None = None


def _normalizar_fqdn(valor: Any) -> str | None:
    """Deja el host solo: sin esquema, sin ruta, en minúsculas."""
    if not isinstance(valor, str):
        return None
    limpio = valor.strip().lower()
    for prefijo in ("https://", "http://"):
        limpio = limpio.removeprefix(prefijo)
    limpio = limpio.split("/", 1)[0].split("?", 1)[0].strip(".")
    return limpio or None


def _ubicaciones(payload: Any, source: str, kind: str = "ransomware") -> Iterable[SiteLocation]:
    """Extrae las ubicaciones de un payload con forma `[{name, locations:[…]}]`.

    Las dos fuentes comparten esta forma, así que un solo parser alcanza.
    """
    if not isinstance(payload, list):
        return

    for grupo in payload:
        if not isinstance(grupo, dict):
            continue
        nombre = grupo.get("name")
        if not isinstance(nombre, str) or not nombre.strip():
            continue

        for ubicacion in grupo.get("locations") or []:
            if not isinstance(ubicacion, dict):
                continue
            fqdn = _normalizar_fqdn(ubicacion.get("fqdn"))
            if not fqdn:
                continue
            titulo = ubicacion.get("title")
            # dls-monitor publica cuándo pasó por ahí; ransomware.live no.
            revisado = parse_datetime(ubicacion.get("lastscrape")) or parse_datetime(
                ubicacion.get("updated")
            )
            yield SiteLocation(
                group_name=nombre.strip().lower(),
                fqdn=fqdn,
                kind=kind,
                title=titulo if isinstance(titulo, str) and titulo.strip() else None,
                available=bool(ubicacion.get("available")),
                source=source,
                checked_at=revisado,
            )


def fetch_ransomware_live(client: FeedHttpClient) -> list[SiteLocation]:
    """Grupos y ubicaciones de ransomware.live."""
    return list(_ubicaciones(client.get_json(RANSOMWARE_LIVE_GROUPS), "ransomware.live"))


def fetch_dls_monitor(client: FeedHttpClient) -> list[SiteLocation]:
    """Grupos y ubicaciones de dls-monitor."""
    return list(_ubicaciones(client.get_json(DLS_MONITOR_GROUPS), "dls-monitor"))


def fetch_ransomlook_markets(client: FeedHttpClient) -> list[SiteLocation]:
    """Mercados que sigue RansomLook.

    Este endpoint devuelve solo los nombres, sin ubicaciones: sirve para saber
    qué mercados existen, no dónde están. Se registra igual, con el nombre como
    entrada, para que aparezcan en el catálogo.
    """
    payload = client.get_json(RANSOMLOOK_MARKETS)
    if not isinstance(payload, list):
        return []
    return [
        SiteLocation(
            group_name=str(nombre).strip().lower(),
            # Sin ubicación conocida: se registra el mercado, no un dominio.
            fqdn="(sin ubicación publicada)",
            kind="market",
            source="ransomlook",
        )
        for nombre in payload
        if isinstance(nombre, str) and nombre.strip()
    ]


#: Catálogo declarativo, igual que los feeds y los canales de alerta.
REGISTRY_SOURCES: tuple[tuple[str, Callable[[FeedHttpClient], list[SiteLocation]]], ...] = (
    ("ransomware.live", fetch_ransomware_live),
    ("dls-monitor", fetch_dls_monitor),
    ("ransomlook", fetch_ransomlook_markets),
)
