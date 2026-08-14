"""Carga y consulta de la watchlist argentina.

La watchlist es **dato, no código**: un YAML declarativo que leen todos los
consumidores. Sumar un organismo es agregar una línea, no tocar el pipeline.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

#: Las siglas de menos de 4 caracteres generan demasiados falsos positivos
#: ("ARCA" dentro de "arcade"); las descartamos al cargar y lo avisamos.
MIN_KEYWORD_LENGTH = 4


def normalize_text(value: str) -> str:
    """Minúsculas y sin acentos, para comparar "Cancillería" con "Cancilleria Ejemplo"."""
    descompuesto = unicodedata.normalize("NFKD", value.lower())
    return "".join(c for c in descompuesto if not unicodedata.combining(c))


@dataclass(frozen=True)
class WatchlistSector:
    """Un sector de la watchlist con sus dominios y keywords."""

    name: str
    label: str
    critical: bool
    domains: frozenset[str]
    keywords: tuple[str, ...]


@dataclass(frozen=True)
class Watchlist:
    """Watchlist completa, con índices precalculados para consultar barato."""

    sectors: tuple[WatchlistSector, ...]
    _domain_index: dict[str, WatchlistSector]
    _keyword_index: tuple[tuple[re.Pattern[str], str, WatchlistSector], ...]

    def match_domain(self, domain: str | None) -> WatchlistSector | None:
        """Sector al que pertenece el dominio, cubriendo subdominios.

        `datos.prevision-ejemplo.gob.ar` matchea la entrada `prevision-ejemplo.gob.ar`.
        """
        if not domain:
            return None
        candidato = normalize_text(domain).removeprefix("www.").rstrip(".")
        partes = candidato.split(".")
        for i in range(len(partes) - 1):
            sufijo = ".".join(partes[i:])
            sector = self._domain_index.get(sufijo)
            if sector is not None:
                return sector
        return None

    def match_keywords(self, text: str | None) -> tuple[tuple[str, WatchlistSector], ...]:
        """Keywords de la watchlist presentes en el texto, con su sector."""
        if not text:
            return ()
        normalizado = normalize_text(text)
        return tuple(
            (keyword, sector)
            for patron, keyword, sector in self._keyword_index
            if patron.search(normalizado)
        )

    @property
    def all_domains(self) -> frozenset[str]:
        return frozenset(self._domain_index)


def build_watchlist(sectors: tuple[WatchlistSector, ...]) -> Watchlist:
    """Arma la watchlist y precalcula sus índices.

    Público porque la watchlist ya no viene solo del YAML: también se arma
    desde la base cuando se edita desde la UI.
    """
    domain_index = {
        normalize_text(dominio): sector for sector in sectors for dominio in sector.domains
    }
    keyword_index = tuple(
        (
            # \b sobre el texto ya normalizado: evita que "ARCA" pegue en "arcade".
            re.compile(rf"\b{re.escape(normalize_text(keyword))}\b"),
            keyword,
            sector,
        )
        for sector in sectors
        for keyword in sector.keywords
    )
    return Watchlist(
        sectors=sectors,
        _domain_index=domain_index,
        _keyword_index=keyword_index,
    )


def load_watchlist(path: Path) -> Watchlist:
    """Lee la watchlist del YAML. Falla fuerte si el archivo no está o es inválido."""
    if not path.exists():
        raise FileNotFoundError(
            f"No se encontró la watchlist en {path}. "
            "Es obligatoria: sin ella no hay capa de relevancia argentina."
        )

    crudo = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    definiciones = crudo.get("sectors") or []
    if not definiciones:
        raise ValueError(f"La watchlist {path} no define ningún sector.")

    sectores: list[WatchlistSector] = []
    for definicion in definiciones:
        keywords = tuple(
            k for k in (definicion.get("keywords") or []) if len(k) >= MIN_KEYWORD_LENGTH
        )
        sectores.append(
            WatchlistSector(
                name=definicion["name"],
                label=definicion.get("label", definicion["name"]),
                critical=bool(definicion.get("critical", False)),
                domains=frozenset(normalize_text(d) for d in (definicion.get("domains") or [])),
                keywords=keywords,
            )
        )

    return build_watchlist(tuple(sectores))


@lru_cache(maxsize=4)
def get_watchlist(path: Path) -> Watchlist:
    """Watchlist cacheada por ruta. `get_watchlist.cache_clear()` en tests."""
    return load_watchlist(path)
