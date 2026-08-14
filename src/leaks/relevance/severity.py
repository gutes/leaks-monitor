"""Derivación de severidad.

La severidad la calculamos nosotros a partir del veredicto de relevancia; nunca
se toma la que declare el feed, que responde a los intereses del que publica.

Catálogo declarativo, evaluado de mayor a menor: la primera regla que aplica
gana.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from leaks.domain.models import ArMatchReason, LeakType, Severity
from leaks.relevance.rules import RelevanceVerdict


@dataclass(frozen=True)
class SeverityRule:
    """Una regla del catálogo: si el predicado da true, esa es la severidad."""

    severity: Severity
    reason: str
    predicate: Callable[[RelevanceVerdict, LeakType], bool]


#: Reglas que identifican a la entidad por sí solas. Una keyword NO está acá:
#: es la única regla que puede pegar sobre una entidad homónima de otro país.
_REGLAS_FUERTES = frozenset(
    {
        ArMatchReason.WATCHLIST,
        ArMatchReason.TLD_AR,
        ArMatchReason.COUNTRY_AR,
        ArMatchReason.CUIT_VALID,
    }
)


def _es_gob_ar(verdict: RelevanceVerdict) -> bool:
    """Dominio del Estado argentino: .gob.ar, .gov.ar o .mil.ar."""
    return any(
        d.endswith((".gob.ar", ".gov.ar", ".mil.ar"))
        for d in verdict.detail.get("tld_ar", []) + verdict.detail.get("watchlist", [])
    )


def _tiene_corroboracion(verdict: RelevanceVerdict) -> bool:
    """¿Hay alguna regla fuerte, más allá de la keyword?

    Caso real que motivó esto: "Distribuidora Ejemplo Dominicana" (distribuidora dominicana)
    matcheaba la keyword DISTRIBUIDORA EJEMPLO de la watchlist y, como el sector energía está
    marcado crítico, salía como CRITICAL. Sin dominio .ar, sin país AR y sin
    CUIT no hay nada que confirme que la víctima sea argentina, así que un
    match por keyword sola no puede escalar a la máxima severidad.
    """
    return bool(_REGLAS_FUERTES & set(verdict.reasons))


#: Orden importa: se evalúa de arriba hacia abajo.
SEVERITY_RULES: tuple[SeverityRule, ...] = (
    SeverityRule(
        severity=Severity.CRITICAL,
        reason="organismo del Estado o infraestructura crítica, con identidad AR corroborada",
        predicate=lambda v, _t: (_es_gob_ar(v) or v.is_critical_sector) and _tiene_corroboracion(v),
    ),
    SeverityRule(
        severity=Severity.HIGH,
        reason="entidad de la watchlist",
        predicate=lambda v, _t: ArMatchReason.WATCHLIST in v.reasons,
    ),
    SeverityRule(
        severity=Severity.HIGH,
        reason="credenciales expuestas de una entidad argentina",
        predicate=lambda v, t: t is LeakType.INFOSTEALER and v.is_match,
    ),
    SeverityRule(
        severity=Severity.MEDIUM,
        reason="entidad argentina confirmada, fuera de la watchlist",
        predicate=lambda v, _t: (
            ArMatchReason.TLD_AR in v.reasons or ArMatchReason.CUIT_VALID in v.reasons
        ),
    ),
    SeverityRule(
        severity=Severity.MEDIUM,
        reason="el feed declara país Argentina",
        predicate=lambda v, _t: ArMatchReason.COUNTRY_AR in v.reasons,
    ),
)


def derive_severity(verdict: RelevanceVerdict, leak_type: LeakType) -> Severity:
    """Severidad del hallazgo según el catálogo.

    El piso es `LOW`: llega acá solo lo que ya matcheó alguna regla AR, así que
    siempre hay algo que reportar, aunque sea débil. El caso típico de `LOW` es
    justamente el match por keyword sola, sin ninguna regla que corrobore que
    la víctima es argentina.
    """
    for regla in SEVERITY_RULES:
        if regla.predicate(verdict, leak_type):
            return regla.severity
    return Severity.LOW
