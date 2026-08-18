"""Score de probabilidad de que un actor apunte a Argentina.

Funciones puras, sin ML y sin llamadas a nadie: entran las víctimas regionales
de un actor y sale un número de 0 a 100 con su desglose. El desglose se
persiste y se muestra, igual que `ar_match_reason` explica por qué un hallazgo
es argentino — un número sin explicación no se puede discutir ni corregir.

## Qué mide y qué no

Mide **precursor regional**: un actor que viene golpeando la región tiene más
chance de cruzar. Medido contra los datos del feed el 2026-08-18:

* De 65 actores que golpearon Argentina, **35 tenían actividad regional previa
  y 30 no**. Para esos 30, Argentina fue su primera víctima latinoamericana
  registrada: el score es **estructuralmente ciego**, no está mal calibrado.
  `thegentlemen` es uno de ellos — golpeó Argentina y Chile el mismo día.
* Y hay un tercer modo de falla que la fórmula tampoco puede tocar: un actor
  que **ninguna fuente nuestra trackea** (Chronus/Cronus Team, verificado
  contra 388 grupos de ransomware.live y 613 de ransomlook). Eso es cobertura,
  no calibración: se arregla sumando una fuente, no ajustando pesos.
* Sobre los 35 que sí se podían ver, el backtest (rankear con datos
  estrictamente anteriores al día del cruce) los dejó en el **percentil 93
  mediano**, con 27 en el top 10 y ninguno en el cuartil inferior.
* La anticipación mediana fue de **105 días**; 86% dieron más de 30.

O sea: sirve para poco más de la mitad de las amenazas, y para esas da unos
tres meses de aviso. Eso hay que decirlo en la UI: la lista es "lo que podemos
ver venir", no "las amenazas".

## Los que ya cruzaron no llevan score

Una probabilidad de que le peguen a Argentina no significa nada para quien ya
lo hizo. Van en su propio grupo, marcados como confirmados.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from leaks.adjacency.countries import COUNTRIES, proximidad

#: Países distintos con los que el alcance se considera máximo. Sale de los
#: datos: los actores más expansivos de la muestra tocan 13-14 países, pero a
#: partir de ~10 el dato deja de discriminar.
PAISES_PARA_ALCANCE_PLENO = 10

#: Vida media de la recencia, en días. Un actor que hace medio año que no
#: aparece pesa la mitad que uno activo esta semana.
RECENCIA_ESCALA_DIAS = 180

#: Volumen con el que se satura la escala logarítmica.
VOLUMEN_PLENO = 30

#: Ventana de la tendencia: se comparan los últimos N días contra los N previos.
VENTANA_TENDENCIA_DIAS = 90

#: Atenuación de los componentes que son ratios, por `n / (n + k)`.
#:
#: Sin esto, un actor con UNA víctima reciente en un país limítrofe y en un
#: sector sensible saturaba recencia, tendencia, proximidad y afinidad —60 de
#: los 100 puntos— y empataba con uno de once víctimas en tres países. Un dato
#: no es una tendencia.
#:
#: El valor sale de un barrido contra el backtest, no de una intuición. La
#: tensión es real: al cruzar a Argentina, la mediana de víctimas regionales
#: previas es 4, así que castigar la poca evidencia castiga también la señal
#: buena. Medido sobre 35 cruces:
#:
#:     k     percentil   top-10   top-5   candidatos flacos en el top 8
#:     0.0        93%     27/35   20/35        5 de 8
#:     1.0        93%     25/35   20/35        0 de 8   ← elegido
#:     3.0        91%     23/35   20/35        0 de 8
#:     5.0        91%     23/35   18/35        0 de 8
#:
#: k=1 saca todo el ruido de una-sola-víctima sin mover el percentil mediano
#: ni el top-5. Subirlo más solo empeora la detección.
CONFIANZA_K = 1.0


@dataclass(frozen=True)
class Pesos:
    """Cuánto aporta cada componente. Suman 100."""

    alcance: float = 25.0
    recencia: float = 25.0
    volumen: float = 15.0
    tendencia: float = 15.0
    proximidad: float = 10.0
    afinidad: float = 10.0

    @property
    def total(self) -> float:
        return (
            self.alcance
            + self.recencia
            + self.volumen
            + self.tendencia
            + self.proximidad
            + self.afinidad
        )


PESOS_POR_DEFECTO = Pesos()


@dataclass(frozen=True)
class VictimaRegional:
    """Lo mínimo que el score necesita de una víctima."""

    country: str
    occurred_at: date
    sector: str = ""


@dataclass(frozen=True)
class Score:
    """El número y por qué. El desglose es lo que lo hace discutible."""

    valor: float
    breakdown: dict[str, float] = field(default_factory=dict)
    #: Cuántas víctimas y países sostienen el número, para poder desconfiar de
    #: un score alto armado con dos datos.
    victimas: int = 0
    paises: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "valor": self.valor,
            "breakdown": dict(self.breakdown),
            "victimas": self.victimas,
            "paises": self.paises,
        }


def _dia(valor: date | datetime) -> date:
    return valor.date() if isinstance(valor, datetime) else valor


def _confianza(cuantas: int) -> float:
    """Cuánto se le cree a los ratios, según cuánta evidencia los sostiene."""
    return cuantas / (cuantas + CONFIANZA_K)


def _alcance(paises: set[str], peso: float) -> float:
    return peso * min(1.0, len(paises) / PAISES_PARA_ALCANCE_PLENO)


def _recencia(ultima: date, hoy: date, peso: float) -> float:
    dias = max(0, (hoy - ultima).days)
    return peso * math.exp(-dias / RECENCIA_ESCALA_DIAS)


def _volumen(cuantas: int, peso: float) -> float:
    return peso * min(1.0, math.log1p(cuantas) / math.log1p(VOLUMEN_PLENO))


def _tendencia(fechas: Sequence[date], hoy: date, peso: float) -> float:
    """Acelerando vs. desacelerando. Sin actividad reciente no aporta nada."""
    corte_reciente = hoy - timedelta(days=VENTANA_TENDENCIA_DIAS)
    corte_previo = hoy - timedelta(days=2 * VENTANA_TENDENCIA_DIAS)
    recientes = sum(1 for f in fechas if f > corte_reciente)
    if not recientes:
        return 0.0
    previas = sum(1 for f in fechas if corte_previo < f <= corte_reciente)
    return peso * min(1.0, recientes / max(1, previas))


def _proximidad(paises: set[str], peso: float) -> float:
    """Promedio ponderado: golpear Brasil no es lo mismo que golpear Cuba."""
    if not paises:
        return 0.0
    return peso * (sum(proximidad(cc) for cc in paises) / len(paises))


def _afinidad(
    victimas: Sequence[VictimaRegional], sectores_ar: frozenset[str], peso: float
) -> float:
    """Qué porción de sus víctimas cae en los sectores que en AR son sensibles."""
    if not victimas or not sectores_ar:
        return 0.0
    afines = sum(1 for v in victimas if v.sector and v.sector in sectores_ar)
    return peso * (afines / len(victimas))


def calcular(
    victimas: Sequence[VictimaRegional],
    *,
    sectores_ar: frozenset[str] = frozenset(),
    hoy: date | datetime | None = None,
    pesos: Pesos = PESOS_POR_DEFECTO,
) -> Score:
    """Puntúa a un actor por sus víctimas regionales.

    `victimas` debe traer SOLO las regionales: pasarle las argentinas haría que
    el actor se puntúe alto por lo que ya hizo acá, que es justo lo que el
    score no quiere medir.
    """
    referencia = _dia(hoy or datetime.now(UTC))
    limpias = [v for v in victimas if v.country and _dia(v.occurred_at) <= referencia]
    if not limpias:
        return Score(valor=0.0, breakdown={}, victimas=0, paises=0)

    fechas = sorted(_dia(v.occurred_at) for v in limpias)
    paises = {v.country.upper() for v in limpias}

    # Alcance y volumen ya crecen con la evidencia; los otros cuatro son
    # ratios que un solo dato satura, así que se atenúan por confianza.
    conf = _confianza(len(limpias))
    desglose = {
        "alcance": round(_alcance(paises, pesos.alcance), 2),
        "volumen": round(_volumen(len(limpias), pesos.volumen), 2),
        "recencia": round(conf * _recencia(fechas[-1], referencia, pesos.recencia), 2),
        "tendencia": round(conf * _tendencia(fechas, referencia, pesos.tendencia), 2),
        "proximidad": round(conf * _proximidad(paises, pesos.proximidad), 2),
        "afinidad": round(conf * _afinidad(limpias, sectores_ar, pesos.afinidad), 2),
    }
    return Score(
        valor=round(sum(desglose.values()), 1),
        # La confianza va en el desglose: un score alto con poca evidencia
        # tiene que poder verse como tal, no esconderse en el número.
        breakdown={**desglose, "confianza": round(conf, 2)},
        victimas=len(limpias),
        paises=len(paises),
    )


def sectores_frecuentes(sectores: Sequence[str], *, tope: int = 8) -> frozenset[str]:
    """Los sectores más golpeados en Argentina, para medir afinidad.

    Sale de los datos y no de una lista escrita a mano: qué sector es sensible
    acá lo dice el histórico, no una opinión.
    """
    conteo: dict[str, int] = {}
    for s in sectores:
        limpio = (s or "").strip()
        if limpio:
            conteo[limpio] = conteo.get(limpio, 0) + 1
    ordenados = sorted(conteo.items(), key=lambda kv: (-kv[1], kv[0]))
    return frozenset(nombre for nombre, _ in ordenados[:tope])


#: Cuántos países se monitorean. Lo usa la UI para explicar el alcance.
TOTAL_PAISES = len(COUNTRIES)
