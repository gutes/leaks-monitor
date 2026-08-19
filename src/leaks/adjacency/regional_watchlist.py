"""Watchlists regionales: una por país.

Reusa `relevance/watchlist.py` **tal cual**. Ese módulo no tiene nada de
argentino: su `Watchlist` es un value object inmutable con índices de dominios
y keywords, y `build_watchlist` es público. Lo único argentino era el archivo
que se le daba de comer.

## Para qué

Para que el score distinga *"cayó un ministerio chileno"* de *"cayó una PyME
brasileña"*. Sin esto, la afinidad se calcula solo contra el rubro que declara
el feed, que viene vacío bastante seguido.

## Por qué son independientes de la argentina

La watchlist argentina define **qué es un hallazgo nuestro**; éstas solo
ponderan víctimas regionales. Mezclarlas haría que una empresa brasileña
generara un hallazgo argentino, que es exactamente lo que la separación de
subsistemas evita.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from leaks.relevance.watchlist import Watchlist, load_watchlist

logger = logging.getLogger(__name__)

#: Nombre del directorio con un archivo por país (`br.yaml`, `cl.yaml`…).
DIRECTORIO = "watchlist-regional"


@dataclass(frozen=True)
class RegionalWatchlists:
    """Las watchlists por país, ya cargadas e indexadas."""

    por_pais: dict[str, Watchlist]

    def es_critica(self, country: str, domain: str | None) -> bool:
        """Si ese dominio es infraestructura crítica en su país.

        Un país sin watchlist cargada devuelve `False`: no se inventa
        criticidad para lo que no se modeló.
        """
        if not domain:
            return False
        wl = self.por_pais.get(country.upper())
        if wl is None:
            return False
        sector = wl.match_domain(domain)
        return bool(sector and sector.critical)

    def match(self, country: str, domain: str | None) -> str | None:
        """Sector al que pertenece el dominio, o `None`."""
        if not domain:
            return None
        wl = self.por_pais.get(country.upper())
        if wl is None:
            return None
        sector = wl.match_domain(domain)
        return sector.name if sector else None

    @property
    def paises(self) -> tuple[str, ...]:
        return tuple(sorted(self.por_pais))

    def counts(self) -> dict[str, int]:
        """Cuántos dominios se vigilan por país, para mostrarlo en la UI."""
        return {cc: len(wl.all_domains) for cc, wl in sorted(self.por_pais.items())}


def load_regional_watchlists(directorio: Path) -> RegionalWatchlists:
    """Carga un archivo por país. Un archivo roto no cuesta los demás."""
    por_pais: dict[str, Watchlist] = {}
    if not directorio.is_dir():
        logger.info("Sin watchlists regionales en %s", directorio)
        return RegionalWatchlists(por_pais={})

    for archivo in sorted(directorio.glob("*.yaml")):
        codigo = archivo.stem.upper()
        try:
            por_pais[codigo] = load_watchlist(archivo)
        except Exception as exc:
            logger.warning(
                "La watchlist de %s no se pudo cargar (%s); se sigue con las demás",
                codigo,
                type(exc).__name__,
            )
    logger.info("Watchlists regionales cargadas: %s", ", ".join(sorted(por_pais)) or "ninguna")
    return RegionalWatchlists(por_pais=por_pais)
