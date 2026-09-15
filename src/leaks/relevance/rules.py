"""Capa de relevancia argentina.

Cada regla es una función pura que devuelve **su propia razón**. El veredicto
guarda qué disparó y con qué evidencia (`ar_match_detail`), que es lo que
permite tunear falsos positivos sin adivinar.

Un item sin ninguna razón no es un hallazgo argentino: se descarta del pipeline
de alertas y solo cuenta en las métricas globales.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from leaks.domain.models import ArMatchReason, NormalizedItem
from leaks.relevance.cuit import find_valid_cuits
from leaks.relevance.watchlist import Watchlist, WatchlistSector, normalize_text

#: Valores de país que consideramos Argentina.
_AR_COUNTRIES = frozenset({"ar", "arg", "argentina"})

#: País declarado **en el texto**, para las fuentes que no traen el campo.
#:
#: Los foros nunca mandan `country`, pero etiquetan el país en el título con la
#: convención `[ARGENTINA] …` o lo nombran derecho. Sin esto, un thread que
#: dice "Argentina: SIPA 38M [Government]" quedaba sin corroboración de país y
#: caía a severidad `low` — que es exactamente lo que pasó con ese volcado.
#:
#: Se acepta la palabra entera y la forma entre corchetes. **Nunca `ar` suelto**:
#: como sufijo o palabra de dos letras aparece en cualquier lado y convertiría
#: la regla en ruido.
_AR_EN_TEXTO = re.compile(r"\bargentina\b|\[\s*(?:ar|arg|argentina)\s*\]", re.IGNORECASE)

#: Tokens con pinta de dominio dentro de texto libre. Hace falta para las
#: fuentes que no traen un campo `domain` estructurado (títulos de threads de
#: foro, descripciones de RansomLook).
_DOMAIN_IN_TEXT = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b",
    re.IGNORECASE,
)

#: TLDs argentinos de segundo nivel; `.ar` a secas también cuenta.
_AR_TLD_SUFFIX = ".ar"


@dataclass(frozen=True)
class RelevanceVerdict:
    """Resultado de evaluar la relevancia argentina de un item."""

    reasons: tuple[ArMatchReason, ...] = ()
    sector: WatchlistSector | None = None
    matched_domains: tuple[str, ...] = ()
    matched_keywords: tuple[str, ...] = ()
    matched_cuits: tuple[str, ...] = ()
    detail: dict[str, list[str]] = field(default_factory=dict)

    @property
    def is_match(self) -> bool:
        return bool(self.reasons)

    @property
    def is_critical_sector(self) -> bool:
        return self.sector is not None and self.sector.critical


def extract_domains(item: NormalizedItem) -> tuple[str, ...]:
    """Todos los dominios del item: el estructurado más los del texto libre."""
    encontrados: list[str] = []
    if item.victim_domain:
        encontrados.append(item.victim_domain)

    # El nombre de víctima de un foro ES el título del thread; ahí es donde
    # aparece el dominio afectado.
    for texto in (item.victim_name, item.description):
        if not texto:
            continue
        encontrados.extend(m.group(1).lower() for m in _DOMAIN_IN_TEXT.finditer(texto))

    vistos: dict[str, None] = {}
    for dominio in encontrados:
        limpio = dominio.lower().removeprefix("www.").rstrip(".")
        if limpio:
            vistos.setdefault(limpio, None)
    return tuple(vistos)


def _searchable_text(item: NormalizedItem) -> str:
    """Superficie de texto sobre la que corren las reglas de contenido."""
    return " ".join(p for p in (item.victim_name, item.description) if p)


def evaluate(
    item: NormalizedItem,
    watchlist: Watchlist,
    enabled_rules: frozenset[ArMatchReason] | None = None,
) -> RelevanceVerdict:
    """Evalúa las reglas de relevancia activas y arma el veredicto.

    `enabled_rules` viene de la configuración editable: el investigador puede
    apagar una regla (típicamente `keyword`, la más ruidosa) sin tocar código.
    `None` significa "todas", que es el default.
    """
    activas = enabled_rules if enabled_rules is not None else frozenset(ArMatchReason)
    reasons: list[ArMatchReason] = []
    detail: dict[str, list[str]] = {}
    sector: WatchlistSector | None = None

    dominios = extract_domains(item)
    texto = _searchable_text(item)

    # Regla 1 — watchlist (incluye subdominios).
    en_watchlist: list[str] = []
    if ArMatchReason.WATCHLIST in activas:
        for dominio in dominios:
            encontrado = watchlist.match_domain(dominio)
            if encontrado is not None:
                en_watchlist.append(dominio)
                sector = sector or encontrado
    if en_watchlist:
        reasons.append(ArMatchReason.WATCHLIST)
        detail["watchlist"] = en_watchlist

    # Regla 2 — cualquier dominio bajo TLD .ar.
    ar_tld = (
        [d for d in dominios if d.endswith(_AR_TLD_SUFFIX)]
        if ArMatchReason.TLD_AR in activas
        else []
    )
    if ar_tld:
        reasons.append(ArMatchReason.TLD_AR)
        detail["tld_ar"] = ar_tld

    # Regla 3 — el país, declarado en el campo o dicho en el texto.
    if ArMatchReason.COUNTRY_AR in activas:
        evidencia: str | None = None
        if item.country and normalize_text(item.country).strip() in _AR_COUNTRIES:
            evidencia = item.country
        else:
            mencion = _AR_EN_TEXTO.search(normalize_text(texto))
            evidencia = mencion.group(0) if mencion is not None else None
        if evidencia is not None:
            # La evidencia dice de dónde salió: el campo del feed o el texto.
            reasons.append(ArMatchReason.COUNTRY_AR)
            detail["country_ar"] = [evidencia]

    # Regla 4 — CUIT/CUIL con dígito verificador válido.
    cuits = find_valid_cuits(texto) if ArMatchReason.CUIT_VALID in activas else ()
    if cuits:
        reasons.append(ArMatchReason.CUIT_VALID)
        # Se guarda solo el prefijo: el CUIT completo de una persona física es
        # PII, y acá alcanza con saber que disparó y poder auditarlo.
        detail["cuit_valid"] = [f"{c[:2]}-********-*" for c in cuits]

    # Regla 5 — keywords de organismos/empresas.
    keywords = watchlist.match_keywords(texto) if ArMatchReason.KEYWORD in activas else ()
    if keywords:
        reasons.append(ArMatchReason.KEYWORD)
        detail["keyword"] = [k for k, _ in keywords]
        sector = sector or keywords[0][1]

    return RelevanceVerdict(
        reasons=tuple(reasons),
        sector=sector,
        matched_domains=tuple(en_watchlist),
        matched_keywords=tuple(k for k, _ in keywords),
        matched_cuits=cuits,
        detail=detail,
    )
