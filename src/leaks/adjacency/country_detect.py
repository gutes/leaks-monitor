"""De qué país es una víctima, para el lado regional de la adyacencia.

## Por qué no alcanza con lo que ya hay

`relevance/rules.py` sabe reconocer Argentina, pero la pregunta que contesta es
otra. Allá es *"¿esto nos toca?"*, y conviene pecar de amplio: un falso positivo
cuesta un hallazgo de más que un investigador descarta en diez segundos. Acá la
pregunta es *"¿de qué país es esta víctima?"*, y un falso positivo no se
descarta: se convierte en un actor nuevo en `adjacent_actors`, con score, que
compite por la atención con los 162 actores medidos.

Por eso el criterio es **deliberadamente más estricto** que el argentino.

## El dominio manda

Se emite país sólo con una señal **fuerte**:

* `tld` — un dominio con el sufijo del país (ver `Country.tlds`).
* `watchlist` — un dominio que la watchlist regional de ese país reconoce.

El nombre del país en el texto libre (`nombre`) **corrobora pero nunca dispara
solo**. Un thread que dice "Brasil" en el título puede ser el país de la
víctima, el del vendedor, el de un comprador o parte de una lista de países de
un combo. Sin un dominio que lo ancle, no es evidencia de nada.

## El dominio del propio actor no es una víctima

Medido en el sondeo del 2026-09-18: el canal `breachstars` anunciaba
`breachstars.hn` —"new domain"— y el detector lo leía como una víctima
hondureña. Es infraestructura del vendedor, no alguien a quien atacó. Se
descartan los dominios cuya etiqueta coincide con el handle del actor.

## La ambigüedad se devuelve como nada

Un volcado "LATAM" con dominios de cinco países no es una víctima de cinco
países: es un volcado. Si hay más de un país con señal fuerte y el texto no
desempata, `detect` devuelve `None`. Preferimos perder la fila antes que
inventar de quién es.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from leaks.adjacency.countries import COUNTRIES, Country
from leaks.adjacency.regional_watchlist import RegionalWatchlists
from leaks.domain.models import NormalizedItem
from leaks.relevance.rules import extract_domains
from leaks.relevance.watchlist import normalize_text

#: Un dominio con el ccTLD del país. Señal fuerte.
SIGNAL_TLD = "tld"
#: El dominio está en la watchlist regional de ese país. Señal fuerte.
SIGNAL_WATCHLIST = "watchlist"
#: El país se nombra en el texto. Corrobora; no alcanza por sí sola.
SIGNAL_NOMBRE = "nombre"

_SENALES_FUERTES = frozenset({SIGNAL_TLD, SIGNAL_WATCHLIST})


def _regex_alias(pais: Country) -> re.Pattern[str] | None:
    """Nombres del país como palabra entera, más la forma `[BR]` de los foros."""
    partes = [rf"\b{re.escape(a)}\b" for a in pais.alias]
    partes.append(rf"\[\s*{re.escape(pais.code.lower())}\s*\]")
    return re.compile("|".join(partes)) if partes else None


_ALIAS: dict[str, re.Pattern[str]] = {
    pais.code: patron for pais in COUNTRIES if (patron := _regex_alias(pais)) is not None
}


@dataclass(frozen=True)
class CountryMatch:
    """El país que se le atribuye a un item, con qué se lo atribuyó."""

    code: str
    #: Qué disparó, en orden estable. Se persiste para poder discutir la fila.
    signals: tuple[str, ...]
    #: El dominio que ancló la decisión. `None` sería una señal débil sola, que
    #: este módulo no emite nunca.
    domain: str | None


def _texto(item: NormalizedItem) -> str:
    return normalize_text(" ".join(p for p in (item.victim_name, item.description) if p))


def _slug(valor: str) -> str:
    """Sólo letras y números, para comparar `breachstars` con `breachstars.hn`."""
    return re.sub(r"[^a-z0-9]", "", normalize_text(valor))


def _sin_dominios_del_actor(dominios: tuple[str, ...], actor: str | None) -> tuple[str, ...]:
    """Saca los dominios que son del propio actor.

    Un vendedor que anuncia su dominio nuevo no se está atacando a sí mismo.
    Se compara la **primera etiqueta** del dominio contra el handle:
    `breachstars` contra `breachstars.hn`.

    Deliberadamente no se miran las etiquetas del medio. Con un handle corto o
    genérico —`data`, `combo`— eso descartaría víctimas legítimas que lo lleven
    en el nombre, y perder una víctima real es peor que dejar pasar el caso raro
    de un subdominio propio.
    """
    handle = _slug(actor or "")
    if not handle:
        return dominios
    return tuple(d for d in dominios if _slug(d.split(".")[0]) != handle)


def _dominio_del_pais(pais: Country, dominios: tuple[str, ...]) -> str | None:
    for dominio in dominios:
        if any(dominio.endswith(tld) for tld in pais.tlds):
            return dominio
    return None


def detect(
    item: NormalizedItem,
    *,
    watchlists: RegionalWatchlists | None = None,
) -> CountryMatch | None:
    """El país de la víctima, o `None` si no se puede afirmar.

    `None` no significa "no es regional": significa que con lo que hay no se
    puede decir de quién es. Ver el encabezado del módulo.
    """
    dominios = _sin_dominios_del_actor(extract_domains(item), item.actor)
    texto = _texto(item)

    candidatos: list[CountryMatch] = []
    for pais in COUNTRIES:
        senales: list[str] = []
        ancla: str | None = None

        dominio = _dominio_del_pais(pais, dominios)
        if dominio is not None:
            senales.append(SIGNAL_TLD)
            ancla = dominio

        if watchlists is not None:
            for candidato in dominios:
                if watchlists.match(pais.code, candidato) is not None:
                    senales.append(SIGNAL_WATCHLIST)
                    ancla = ancla or candidato
                    break

        # El nombre sólo se busca si ya hay una señal fuerte: por sí solo no
        # califica a nadie, y salteárselo evita 18 regex por ítem en el 99% de
        # los casos, que no tienen ningún dominio de la región.
        if not _SENALES_FUERTES.intersection(senales):
            continue

        patron = _ALIAS.get(pais.code)
        if patron is not None and patron.search(texto):
            senales.append(SIGNAL_NOMBRE)

        candidatos.append(CountryMatch(pais.code, tuple(senales), ancla))

    if len(candidatos) == 1:
        return candidatos[0]
    if not candidatos:
        return None

    # Empate: el texto desempata sólo si señala a uno y nada más que a uno.
    nombrados = [c for c in candidatos if SIGNAL_NOMBRE in c.signals]
    return nombrados[0] if len(nombrados) == 1 else None
