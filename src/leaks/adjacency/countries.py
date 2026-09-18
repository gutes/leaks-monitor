"""Catálogo declarativo de países de la región.

Sumar un país es agregar una entrada acá: el colector, el score y la UI lo
leen de esta tabla y no hay que tocar nada más.

`proximidad` pondera cuánto dice la actividad en ese país sobre el riesgo para
Argentina. No es distancia geográfica: es la mezcla de frontera, integración
económica y patrón observado de expansión de los actores. Los limítrofes pesan
el máximo; el resto de Sudamérica, algo menos; México, Centroamérica y el
Caribe, bastante menos, porque un actor que opera ahí suele responder a otro
circuito.

Los conteos son los medidos el 2026-08-18 contra `/v2/countryvictims/<CC>`, y
están para que se note si el feed cambia de cobertura, no como configuración.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Country:
    """Un país monitoreado en la sección de adyacencia."""

    code: str
    name: str
    #: 1.0 limítrofe · 0.6 resto de Sudamérica · 0.3 México/Centroamérica/Caribe.
    proximidad: float
    #: Víctimas que tenía el feed al momento de la medición inicial.
    victimas_medidas: int = 0
    #: Sufijos de dominio que identifican al país **sin ambigüedad**. Casi
    #: siempre es el ccTLD pelado; hay dos excepciones, y las dos están acá
    #: porque el sufijo suelto colisiona con algo de uso masivo:
    #:
    #: * `.co` se vende como genérico en todo el mundo, así que Colombia exige
    #:   el segundo nivel (`.com.co`, `.gov.co`…).
    #: * `.py` es la extensión de los archivos de Python, y el detector de
    #:   dominios en texto libre no distingue `script.py` de un dominio. Sin el
    #:   segundo nivel, cualquier volcado con código adentro sería paraguayo.
    tlds: tuple[str, ...] = ()
    #: Cómo se nombra al país en texto libre, ya en minúsculas y sin acentos.
    #: Corrobora, nunca dispara solo: ver `country_detect`.
    alias: tuple[str, ...] = ()


#: Argentina NO está acá: es el sujeto, no la región. Incluirla haría que el
#: score contara sus propias víctimas argentinas como señal de riesgo.
COUNTRIES: tuple[Country, ...] = (
    # Limítrofes.
    Country("BR", "Brasil", 1.0, 531, (".br",), ("brasil", "brazil", "brazilian", "brasileiro")),
    Country("CL", "Chile", 1.0, 82, (".cl",), ("chile", "chilean", "chileno", "chilena")),
    Country("UY", "Uruguay", 1.0, 18, (".uy",), ("uruguay", "uruguayan", "uruguayo", "uruguaya")),
    Country(
        "PY",
        "Paraguay",
        1.0,
        17,
        (".com.py", ".gov.py", ".edu.py", ".org.py", ".net.py", ".mil.py"),
        ("paraguay", "paraguayan", "paraguayo", "paraguaya"),
    ),
    Country("BO", "Bolivia", 1.0, 15, (".bo",), ("bolivia", "bolivian", "boliviano", "boliviana")),
    # Resto de Sudamérica.
    Country(
        "CO",
        "Colombia",
        0.6,
        142,
        (".com.co", ".gov.co", ".edu.co", ".org.co", ".net.co", ".mil.co"),
        ("colombia", "colombian", "colombiano", "colombiana"),
    ),
    Country("PE", "Perú", 0.6, 81, (".pe",), ("peru", "peruvian", "peruano", "peruana")),
    Country(
        "VE",
        "Venezuela",
        0.6,
        36,
        (".ve",),
        ("venezuela", "venezuelan", "venezolano", "venezolana"),
    ),
    Country(
        "EC", "Ecuador", 0.6, 32, (".ec",), ("ecuador", "ecuadorian", "ecuatoriano", "ecuatoriana")
    ),
    # México, Centroamérica y Caribe hispanohablante.
    Country("MX", "México", 0.3, 285, (".mx",), ("mexico", "mexican", "mexicano", "mexicana")),
    Country(
        "DO",
        "República Dominicana",
        0.3,
        29,
        (".do",),
        ("republica dominicana", "dominican republic", "dominicano", "dominicana"),
    ),
    Country("CR", "Costa Rica", 0.3, 21, (".cr",), ("costa rica", "costa rican", "costarricense")),
    Country("PA", "Panamá", 0.3, 21, (".pa",), ("panama", "panamanian", "panameno", "panamena")),
    Country(
        "GT",
        "Guatemala",
        0.3,
        21,
        (".gt",),
        ("guatemala", "guatemalan", "guatemalteco", "guatemalteca"),
    ),
    Country(
        "SV",
        "El Salvador",
        0.3,
        11,
        (".sv",),
        ("el salvador", "salvadoran", "salvadoreno", "salvadorena"),
    ),
    Country(
        "NI",
        "Nicaragua",
        0.3,
        5,
        (".ni",),
        ("nicaragua", "nicaraguan", "nicaraguense"),
    ),
    Country("HN", "Honduras", 0.3, 4, (".hn",), ("honduras", "honduran", "hondureno", "hondurena")),
    Country("CU", "Cuba", 0.3, 2, (".cu",), ("cuba", "cuban", "cubano", "cubana")),
)


COUNTRY_CODES: tuple[str, ...] = tuple(c.code for c in COUNTRIES)

_POR_CODIGO = {c.code: c for c in COUNTRIES}


def get_country(code: str) -> Country | None:
    return _POR_CODIGO.get(code.strip().upper())


def proximidad(code: str) -> float:
    """Peso del país. Uno desconocido no suma: no se inventa cercanía."""
    pais = get_country(code)
    return pais.proximidad if pais else 0.0
