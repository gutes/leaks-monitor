"""Sondeo regional: qué pasaría si los foros y Telegram alimentaran la adyacencia.

## Por qué existe este paso

Los items que no son argentinos **nunca se guardaron**: el runner los descarta
en `_to_finding` y no queda rastro. Así que no hay forma de backtestear el
detector de país contra la base — la medición sólo puede salir de traer los
feeds y mirarlos.

Este módulo hace exactamente eso y **no escribe una sola fila**. Sirve para
elegir el umbral con números en la mano en vez de adivinarlo, que es el riesgo
real del cambio: si el criterio queda flojo, `adjacent_actors` pasa de 162
actores medidos a cientos de handles de foro y la sección deja de ser legible.

Es una función pura sobre items ya normalizados: no conoce HTTP ni la base. El
comando `leaks regional-probe` la alimenta; los tests también.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from leaks.adjacency.country_detect import CountryMatch, detect
from leaks.adjacency.regional_watchlist import RegionalWatchlists
from leaks.domain.models import ArMatchReason, NormalizedItem
from leaks.privacy.scrub import redact_pii
from leaks.relevance.rules import evaluate
from leaks.relevance.watchlist import Watchlist

#: Cuántos caracteres del título se muestran. Es para reconocer el item, no
#: para leerlo: el cuerpo de estas fuentes es un volcado con PII.
_LARGO_MUESTRA = 90


@dataclass(frozen=True)
class Muestra:
    """Una fila detectada, para poder juzgar a ojo si el criterio acierta."""

    source: str
    code: str
    signals: tuple[str, ...]
    domain: str | None
    actor: str | None
    #: Título recortado y pasado por el redactor. Nunca el cuerpo.
    titulo: str


@dataclass(frozen=True)
class ProbeReport:
    """Qué se vio en el sondeo. Todo contado, nada persistido."""

    #: Items mirados en total.
    vistos: int = 0
    #: Los que la relevancia argentina reclama. No van al lado regional:
    #: Argentina es el sujeto, no la región.
    argentinos: int = 0
    #: Los que quedaron con un país atribuido.
    detectados: int = 0
    por_pais: dict[str, int] = field(default_factory=dict)
    por_senal: dict[str, int] = field(default_factory=dict)
    por_fuente: dict[str, int] = field(default_factory=dict)
    #: Actores que hoy no están en `adjacent_actors` y entrarían con el cambio.
    actores_nuevos: tuple[str, ...] = ()
    muestras: tuple[Muestra, ...] = ()

    @property
    def descartados(self) -> int:
        """Ni argentinos ni atribuibles: el grueso, y está bien que lo sea."""
        return self.vistos - self.argentinos - self.detectados


def _titulo(item: NormalizedItem) -> str:
    return (redact_pii(item.victim_name) or "")[:_LARGO_MUESTRA]


def probe(
    items: Iterable[tuple[str, NormalizedItem]],
    *,
    watchlist: Watchlist,
    enabled_rules: frozenset[ArMatchReason] | None = None,
    watchlists: RegionalWatchlists | None = None,
    actores_conocidos: frozenset[str] = frozenset(),
    max_muestras: int = 20,
) -> ProbeReport:
    """Clasifica items ya normalizados y devuelve el conteo.

    `items` son pares `(fuente, item)`. `actores_conocidos` son los que ya
    están en `adjacent_actors`, en minúsculas, para contar cuántos se sumarían.
    """
    por_pais: Counter[str] = Counter()
    por_senal: Counter[str] = Counter()
    por_fuente: Counter[str] = Counter()
    muestras: list[Muestra] = []
    nuevos: dict[str, None] = {}
    vistos = argentinos = detectados = 0

    for fuente, item in items:
        vistos += 1

        if evaluate(item, watchlist, enabled_rules).is_match:
            argentinos += 1
            continue

        match: CountryMatch | None = detect(item, watchlists=watchlists)
        if match is None:
            continue

        detectados += 1
        por_pais[match.code] += 1
        por_fuente[fuente] += 1
        for senal in match.signals:
            por_senal[senal] += 1

        actor = (item.actor or "").strip().lower()
        if actor and actor not in actores_conocidos:
            nuevos.setdefault(actor, None)

        if len(muestras) < max_muestras:
            muestras.append(
                Muestra(
                    source=fuente,
                    code=match.code,
                    signals=match.signals,
                    domain=match.domain,
                    actor=item.actor,
                    titulo=_titulo(item),
                )
            )

    return ProbeReport(
        vistos=vistos,
        argentinos=argentinos,
        detectados=detectados,
        por_pais=dict(por_pais.most_common()),
        por_senal=dict(por_senal.most_common()),
        por_fuente=dict(por_fuente.most_common()),
        actores_nuevos=tuple(nuevos),
        muestras=tuple(muestras),
    )
