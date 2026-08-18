"""Informe de la watchlist en texto plano.

Responde dos cosas en un solo documento:

1. **Qué estamos vigilando** — dominios y keywords, por sector, con su estado,
   si son infraestructura crítica y de dónde salió cada entrada.
2. **Qué de eso ya cayó alguna vez** — los sistemas de cada entrada que
   aparecieron en un hallazgo, con la fecha del evento y la URL donde lo
   encontramos.

Lo segundo es lo que convierte el listado en un informe. Ver `prevision-ejemplo.gob.ar` en
una tabla no dice nada; ver que su portal de trámites viene apareciendo en
capturas de infostealers desde hace meses, sí.

Ese cruce vive **solo acá**: en la pantalla, colgarle el historial a cada fila
convertiría la pantalla de administración en otra cosa.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from leaks.export.coverage import ORIGEN_SISTEMA, ORIGEN_VICTIMA, Compromiso
from leaks.export.layout import (
    SEP_FUERTE,
    SEP_SUAVE,
    campo,
    dia,
    fecha,
    num,
    parrafo,
    sello,
    unir,
)

#: Ancho de la columna del valor. Lo que se pase, desborda: cortar un dominio
#: lo inutiliza para copiar y pegar.
VALOR_W = 34

_ORIGEN_LEGIBLE = {"seed": "semilla", "user": "manual"}

_LEYENDA = (
    "Una entrada deshabilitada queda guardada pero no matchea hasta que se la "
    "vuelva a habilitar. Un dominio cubre también sus subdominios. El origen "
    "dice si la entrada vino del archivo semilla o se agregó a mano."
)

_LEYENDA_COMPROMISOS = (
    "«Comprometido alguna vez» lista los sistemas de esa entrada que "
    "aparecieron en algún hallazgo, con la fecha del evento y dónde lo "
    "encontramos. Es histórico acumulado: que figure no significa que siga "
    "comprometido hoy, y que no figure no prueba que esté limpio — solo que no "
    "apareció en las fuentes que miramos."
)

_LEYENDA_PROCEDENCIA = (
    "Las líneas sueltas son la URL exacta que apareció en los datos, con su "
    "path: es la evidencia, y el path suele ser lo que identifica al sistema "
    "(una VPN, un webmail, un GitLab). «Organismo señalado por la fuente» es "
    "otra cosa y por eso va rotulado: ahí la fuente nombró a la organización "
    "sin decir qué sistema suyo cayó, y en las fuentes que se consultan "
    "dominio por dominio ese valor es el dominio que preguntamos nosotros. No "
    "cuenta como sistema comprometido."
)


def _etiqueta(entrada: Mapping[str, Any]) -> str:
    partes = [str(entrada.get("label") or "").strip()]
    if entrada.get("critical"):
        partes.append("CRÍTICO")
    return " · ".join(p for p in partes if p)


def _fila(entrada: Mapping[str, Any]) -> str:
    estado = "activa" if entrada.get("enabled") else "inactiva"
    origen = _ORIGEN_LEGIBLE.get(str(entrada.get("origin") or ""), "—")
    valor = str(entrada.get("value") or "—")
    return f"    {estado:<9} {origen:<8} {valor.ljust(VALOR_W)} {_etiqueta(entrada)}".rstrip()


def _compromisos(items: Sequence[Compromiso], omitidos: int) -> list[str]:
    """El bloque de 'comprometidos alguna vez' de una entrada.

    Se agrupa **por hallazgo** —misma fecha, misma fuente, misma referencia— en
    vez de repetir la URL de origen en cada línea: doce sistemas que salieron
    de un mismo reporte son un hecho, no doce.

    Dentro de cada grupo se separan dos cosas que NO son lo mismo:

    * **Sistemas encontrados** — la URL exacta que apareció en los datos, con
      su path. `/sslvpn_logon.shtml` es lo que identifica al sistema como la
      VPN institucional; sin el path queda un hostname genérico.
    * **Organismo señalado** — el dominio que la fuente nombró como víctima,
      sin decir qué sistema suyo cayó. Para las fuentes que se consultan
      dominio por dominio ese valor es *el dominio que preguntamos nosotros*,
      así que se rotula aparte y nunca se cuenta como sistema comprometido.
    """
    if not items:
        return []

    sistemas = [c for c in items if c.origen == ORIGEN_SISTEMA]
    internos = sum(1 for c in sistemas if c.empleado)

    if sistemas:
        # Hosts y URLs se cuentan por separado: `siar.nuclear-ejemplo.gob.ar/sslvpn_logon`
        # y `siar.nuclear-ejemplo.gob.ar/wgcgi.cgi` son dos superficies de UN sistema, y
        # decir "14 sistemas" cuando son 11 infla el número.
        hosts = len({c.host for c in sistemas})
        titulo = f"Comprometidos alguna vez: {num(hosts)} sistemas, {num(len(sistemas))} URLs"
        if internos:
            titulo += f" ({num(internos)} de empleados)"
    else:
        # Sin URLs no se puede afirmar qué cayó, solo que el organismo figura.
        titulo = "Comprometidos alguna vez: sin detalle de sistemas"

    grupos: dict[tuple[str, str, str], list[Compromiso]] = {}
    for c in items:
        clave = (
            dia(c.occurred_at) if c.occurred_at else "sin fecha",
            c.source,
            c.ref_url or "",
        )
        grupos.setdefault(clave, []).append(c)

    lineas = ["", f"      {titulo}"]
    for (cuando, fuente, ref), propios in grupos.items():
        lineas += ["", f"        {cuando} · {fuente}"]

        propios_sistemas = [c for c in propios if c.origen == ORIGEN_SISTEMA]
        # Los de empleados primero: implican acceso interno. La marca va como
        # PREFIJO y las URLs no se envuelven: envolverlas dejaba el `[EMPLEADO]`
        # colgando en la línea siguiente, donde ya no se sabe de quién es.
        for c in sorted(propios_sistemas, key=lambda x: (not x.empleado, x.evidencia)):
            marca = "EMPLEADO" if c.empleado else "usuario "
            lineas.append(f"          [{marca}]  {c.evidencia}")

        for c in (c for c in propios if c.origen == ORIGEN_VICTIMA):
            lineas.append(f"          [organismo señalado por la fuente]  {c.host}")

        lineas.append(f"          visto en: {ref or 'sin referencia'}")
    if omitidos:
        lineas += ["", f"        … y {num(omitidos)} más, no listados por espacio."]
    lineas.append("")
    return lineas


def _encabezado(
    total: int,
    counts: Mapping[str, Any],
    generated_at: Any,
    filtros: Mapping[str, Any] | None,
    con_historial: int,
) -> list[str]:
    activos = {k: v for k, v in (filtros or {}).items() if v not in (None, "")}
    descripcion = (
        ", ".join(f"{k}={v}" for k, v in sorted(activos.items()))
        if activos
        else "sin filtro — la watchlist completa"
    )

    lineas = [
        SEP_FUERTE,
        "  WATCHLIST MONITOREADA — Monitor de leaks",
        SEP_FUERTE,
        "",
        campo("Generado", fecha(generated_at)),
        campo("En el informe", num(total)),
        campo("Filtro", descripcion),
        "",
        campo("Total cargado", num(counts.get("total", 0))),
        campo("Habilitadas", num(counts.get("enabled", 0))),
        campo("Deshabilitadas", num(counts.get("disabled", 0))),
        campo("Dominios", num(counts.get("domains", 0))),
        campo("Keywords", num(counts.get("keywords", 0))),
        campo("Con historial", f"{num(con_historial)} entradas cayeron alguna vez"),
        "",
        *parrafo(_LEYENDA, "  "),
        "",
        *parrafo(_LEYENDA_COMPROMISOS, "  "),
        "",
        *parrafo(_LEYENDA_PROCEDENCIA, "  "),
        "",
    ]
    return lineas


def render_watchlist_report(
    entries: Sequence[Mapping[str, Any]],
    *,
    counts: Mapping[str, Any],
    compromisos: Mapping[str, tuple[tuple[Compromiso, ...], int]] | None = None,
    generated_at: Any,
    filtros: Mapping[str, Any] | None = None,
) -> str:
    """Arma el informe. `entries` son los dicts que publica la API."""
    mapa = compromisos or {}
    con_historial = sum(1 for e in entries if str(e.get("value") or "") in mapa)

    lineas = _encabezado(len(entries), counts, generated_at, filtros, con_historial)
    if not entries:
        lineas += [SEP_SUAVE, "", "  La watchlist está vacía para este filtro.", ""]

    # Se agrupa por sector conservando el orden que ya trae el repositorio
    # (sector, tipo, valor): los dominios antes que las keywords.
    por_sector: dict[str, list[Mapping[str, Any]]] = {}
    for entrada in entries:
        por_sector.setdefault(str(entrada.get("sector") or "sin_sector"), []).append(entrada)

    for sector, items in por_sector.items():
        activas = sum(1 for e in items if e.get("enabled"))
        lineas += [
            SEP_SUAVE,
            f"  {sector} — {num(len(items))} entradas ({num(activas)} activas)",
            SEP_SUAVE,
            "",
            f"    {'estado':<9} {'origen':<8} {'valor'.ljust(VALOR_W)} etiqueta",
        ]
        for entrada in items:
            lineas.append(_fila(entrada))
            propios, omitidos = mapa.get(str(entrada.get("value") or ""), ((), 0))
            lineas += _compromisos(propios, omitidos)
        lineas.append("")

    lineas += [SEP_FUERTE, "  Fin del informe.", SEP_FUERTE, ""]
    return unir(lineas)


def watchlist_filename(generated_at: Any, count: int) -> str:
    """Nombre del archivo, con sello de tiempo y cantidad."""
    return f"watchlist-{sello(generated_at)}-{count}.txt"
