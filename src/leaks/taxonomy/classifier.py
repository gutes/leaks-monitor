"""Asignación de un tipo de la taxonomía del CERT.ar a cada hallazgo.

Catálogo declarativo evaluado de arriba hacia abajo, igual que la severidad: la
primera regla que aplica gana. Cada regla guarda **por qué** clasificó así
(`basis`), que es lo que hace auditable la decisión — sin eso, una clasificación
mal puesta es imposible de revisar sin reproducir la corrida.

**Lo que clasificamos es lo que observamos, no lo que suponemos.** Un log de
infostealer es evidencia de credenciales de la organización en manos de
terceros: eso es *Compromiso de cuenta*. Que atrás haya habido malware es
probable, pero no lo vemos — y la guía pide clasificar "según aquel que mejor se
ajuste a la situación acontecida que motiva el reporte".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from leaks.domain.models import LeakType, NormalizedItem
from leaks.taxonomy.cert_ar import TipoIncidente, get_tipo

#: Cuando no hay regla que aplique. La guía lo define así: "aquellos incidentes
#: que no puedan ser clasificados dentro de los actuales parámetros".
SLUG_POR_DEFECTO = "sectores_no_criticos"


@dataclass(frozen=True)
class ReglaTaxonomia:
    """Una regla del catálogo: si el predicado da true, ese es el tipo."""

    slug: str
    #: Frase corta que explica la decisión. Se persiste con el hallazgo.
    basis: str
    predicate: Callable[[NormalizedItem], bool]


#: El orden importa: gana la primera que aplica.
REGLAS: tuple[ReglaTaxonomia, ...] = (
    ReglaTaxonomia(
        slug="ransomware",
        basis="el grupo publicó a la víctima en su sitio de extorsión",
        predicate=lambda i: i.leak_type is LeakType.RANSOMWARE,
    ),
    ReglaTaxonomia(
        slug="compromiso_de_cuenta",
        basis="credenciales de la organización expuestas en logs de infostealer",
        predicate=lambda i: i.leak_type is LeakType.INFOSTEALER,
    ),
    ReglaTaxonomia(
        slug="revelacion_de_informacion",
        basis="secreto expuesto en un repositorio público",
        predicate=lambda i: i.leak_type is LeakType.REPO_SECRET,
    ),
    ReglaTaxonomia(
        slug="acceso_no_autorizado",
        basis="datos de la organización publicados o a la venta en un foro",
        predicate=lambda i: i.leak_type in (LeakType.FORUM_POST, LeakType.PASTE),
    ),
)


def classify(item: NormalizedItem) -> tuple[str, str]:
    """Devuelve `(slug, basis)` del tipo que le corresponde al hallazgo.

    Nunca falla: si ninguna regla aplica, cae en el tipo que la propia guía
    reserva para lo no clasificable. Un hallazgo sin taxonomía sería peor que
    uno clasificado como "otros", porque desaparecería de cualquier reporte.
    """
    for regla in REGLAS:
        if regla.predicate(item):
            return regla.slug, regla.basis
    return SLUG_POR_DEFECTO, "no encuadra en ningún tipo de la taxonomía"


def describe(slug: str | None) -> TipoIncidente | None:
    """Atajo para que los consumidores no importen el catálogo entero."""
    return get_tipo(slug)
