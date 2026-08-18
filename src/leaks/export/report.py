"""Informe de hallazgos en texto plano.

Por qué TXT y no PDF/HTML: el destino de esto es un informe, un mail o un
ticket. El texto plano se pega en cualquier lado, no arrastra estilos, se
versiona y se puede leer dentro de veinte años. Un PDF sería más lindo y menos
útil.

Todo el módulo son **funciones puras**: entran diccionarios (los mismos que
publica la API) y sale un string. Sin base, sin red, sin reloj propio — la
fecha de generación se inyecta. Eso lo hace testeable carácter por carácter.

Lo que se exporta es lo mismo que se persiste: **metadata**. No hay
credenciales que exportar porque no las guardamos. Las URLs de sistemas
comprometidos y los punteros a los volcados salen tal cual están en la base, ya
pasados por el redactor.
"""

from __future__ import annotations

import textwrap
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

#: Ancho del informe. 80 columnas: entra en cualquier terminal, en el cuerpo de
#: un mail y en un adjunto impreso sin que se corte.
WIDTH = 80

#: Ancho de la etiqueta en los pares "campo : valor". Fijo para que la columna
#: de valores quede alineada y el informe se pueda leer en diagonal.
LABEL_W = 15

_SEP_FUERTE = "=" * WIDTH
_SEP_SUAVE = "-" * WIDTH

#: La clave sale de una constante y no de un literal dentro del diccionario
#: porque el SAST lee el par `"repo_secret": "..."` como una credencial
#: embebida y marcaría el literal entero.
_CLAVE_REPO = "repo_secret"

_TIPO_LEGIBLE = {
    "ransomware": "ransomware",
    "infostealer": "infostealer",
    "forum_post": "publicación en foro",
    "paste": "paste",
    _CLAVE_REPO: "secreto en repositorio",
}

_KIND_LEGIBLE = {"data": "VOLCADO", "sample": "muestra", "unknown": "enlace"}

_BASIS_LEGIBLE = {
    "feed": "la fuente la declara",
    "texto": "año extraído del título",
    "corroboracion": "corroborada con otra fuente",
    "sin_dato": "sin dato",
}

_AVISO_ENLACES = (
    "Los enlaces de esta sección apuntan a datos robados y a la "
    "infraestructura de quien los publicó. Se listan como texto, no como "
    "enlaces: abrirlos es una decisión deliberada, no un click distraído."
)


def _num(valor: Any) -> str:
    """Entero con separador de miles a la española: 225375 -> '225.375'."""
    if not isinstance(valor, int):
        return str(valor)
    return f"{valor:,}".replace(",", ".")


def _fecha(valor: Any) -> str:
    """Fecha en ISO corto y UTC. Los naive se asumen UTC, como en toda la base."""
    if not isinstance(valor, datetime):
        return "—"
    momento = valor if valor.tzinfo else valor.replace(tzinfo=UTC)
    return momento.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _dia(valor: Any) -> str:
    if not isinstance(valor, datetime):
        return "—"
    momento = valor if valor.tzinfo else valor.replace(tzinfo=UTC)
    return momento.astimezone(UTC).strftime("%Y-%m-%d")


def _campo(etiqueta: str, valor: Any, sangria: str = "  ") -> str:
    texto = "—" if valor in (None, "", []) else str(valor)
    return f"{sangria}{etiqueta.ljust(LABEL_W)}: {texto}"


def _parrafo(texto: str, sangria: str = "    ") -> list[str]:
    """Envuelve texto libre respetando el ancho. Vacío no produce líneas."""
    if not texto:
        return []
    lineas: list[str] = []
    for cruda in str(texto).splitlines():
        if not cruda.strip():
            lineas.append("")
            continue
        lineas.extend(
            textwrap.wrap(
                cruda.strip(),
                width=WIDTH,
                initial_indent=sangria,
                subsequent_indent=sangria,
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
    return lineas


def _lista_envuelta(valores: Iterable[str], sangria: str = "      ") -> list[str]:
    """Una enumeración separada por comas, envuelta al ancho del informe."""
    texto = ", ".join(v for v in valores if v)
    return _parrafo(texto, sangria) if texto else []


# -- Ordenamiento -------------------------------------------------------------


def _clave_orden(f: dict[str, Any]) -> tuple[int, float, str]:
    """Más reciente primero; los que no se pudieron fechar, al final.

    Un hallazgo sin fecha no es "viejo": es desconocido. Mezclarlo con los de
    2020 diría algo que no sabemos, así que va en su propio bloque al final.
    """
    ocurrido = f.get("occurred_at")
    if isinstance(ocurrido, datetime):
        momento = ocurrido if ocurrido.tzinfo else ocurrido.replace(tzinfo=UTC)
        return (0, -momento.timestamp(), str(f.get("victim_name") or ""))
    return (1, 0.0, str(f.get("victim_name") or ""))


def ordenar(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Orden del informe: por fecha de ocurrencia, sin fecha al final."""
    return sorted(findings, key=_clave_orden)


def _frescura(ocurrido: Any, ahora: datetime, fresh_days: int) -> str:
    if not isinstance(ocurrido, datetime):
        return "sin fecha"
    momento = ocurrido if ocurrido.tzinfo else ocurrido.replace(tzinfo=UTC)
    dias = (ahora - momento).days
    return "reciente" if dias <= fresh_days else f"histórico, hace {dias} días"


# -- Secciones ----------------------------------------------------------------


def _encabezado(
    findings: Sequence[dict[str, Any]], generated_at: datetime, fresh_days: int
) -> list[str]:
    fechados = [f["occurred_at"] for f in findings if isinstance(f.get("occurred_at"), datetime)]
    sin_fecha = len(findings) - len(fechados)

    lineas = [
        _SEP_FUERTE,
        "  INFORME DE HALLAZGOS — Monitor de leaks",
        _SEP_FUERTE,
        "",
        _campo("Generado", _fecha(generated_at)),
        _campo("Hallazgos", _num(len(findings))),
    ]
    if fechados:
        lineas.append(_campo("Ocurrencias", f"{_dia(min(fechados))} → {_dia(max(fechados))}"))
    if sin_fecha:
        lineas.append(_campo("Sin fechar", f"{_num(sin_fecha)} (van al final)"))
    lineas.append(_campo("Umbral reciente", f"{fresh_days} días"))
    lineas += [
        "",
        *_parrafo(
            "Ordenados por fecha de ocurrencia del evento —no por cuándo lo "
            "importamos—, del más reciente al más antiguo.",
            "  ",
        ),
        "",
        *_parrafo(
            "Contenido: metadata solamente. No incluye credenciales, "
            "contraseñas ni datos de personas físicas, porque no se persisten.",
            "  ",
        ),
        "",
    ]
    return lineas


def _identificacion(f: dict[str, Any], ahora: datetime, fresh_days: int) -> list[str]:
    ocurrido = f.get("occurred_at")
    base = _BASIS_LEGIBLE.get(str(f.get("occurred_at_basis") or ""), "origen desconocido")
    detalle_fecha = (
        f"{_dia(ocurrido)}  ({_frescura(ocurrido, ahora, fresh_days)} · {base})"
        if isinstance(ocurrido, datetime)
        else f"sin fecha  ({base})"
    )

    tipo = str(f.get("leak_type") or "")
    fuente = f"{f.get('source') or '—'}  ({_TIPO_LEGIBLE.get(tipo, tipo or '—')})"

    lineas = [
        _campo("Ocurrencia", detalle_fecha),
        _campo("Declarado", f"{_dia(f.get('discovered_at'))}  (fecha que informa la fuente)"),
        _campo("Visto", f"{_dia(f.get('first_seen_at'))}  (cuándo lo detectamos)"),
    ]
    if f.get("backfill"):
        lineas += _parrafo(
            "Entró con la importación inicial de su fuente: es histórico que "
            "recién conocemos, no una novedad de ese día.",
            "                   ",
        )
    lineas += [
        _campo("Víctima", f.get("victim_name")),
        _campo("Dominio", f.get("victim_domain")),
        _campo("País", f.get("country")),
        _campo("Sector", f.get("sector")),
        _campo("Actor", f.get("actor")),
        _campo("Fuente", fuente),
        _campo("Severidad", str(f.get("severity") or "—").upper()),
    ]

    razones = list(f.get("ar_match_reason") or [])
    lineas.append(_campo("Relevancia AR", ", ".join(razones) if razones else "—"))
    detalles = f.get("ar_match_detail") or {}
    for regla in razones:
        evidencia = detalles.get(regla) or []
        if evidencia:
            lineas += _parrafo(
                f"{regla}: {', '.join(str(e) for e in evidencia)}", "                   "
            )

    lineas.append(_campo("Referencia", f.get("raw_ref")))
    return lineas


def _descripcion(f: dict[str, Any]) -> list[str]:
    texto = f.get("description")
    if not texto:
        return []
    return ["", "  Descripción", *_parrafo(str(texto))]


def _exposicion(f: dict[str, Any]) -> list[str]:
    """La columna 'Datos' (🔎): qué sistemas se comprometieron y con qué."""
    exp = f.get("exposure_detail") or {}
    if not isinstance(exp, dict):
        return []

    urls = [u for u in (exp.get("urls") or []) if isinstance(u, dict)]
    familias = exp.get("stealer_families") or {}
    terceros = [str(d) for d in (exp.get("third_party_domains") or [])]
    debiles = exp.get("weak_password_pct")
    if not (urls or familias or terceros):
        return []

    internos = [u for u in urls if u.get("kind") == "employee"]
    resumen = [f"{_num(len(urls))} sistemas comprometidos"]
    if internos:
        resumen.append(f"{_num(len(internos))} de empleados")
    if debiles:
        resumen.append(f"{debiles}% de contraseñas débiles")

    lineas = ["", "  DATOS · Exposición por infostealers", *_parrafo(" · ".join(resumen))]

    if urls:
        lineas += [
            "",
            "    Sistemas comprometidos",
            *_parrafo(
                "URLs contra las que se estaba autenticando la víctima al "
                "infectarse. Las de empleados van primero: implican acceso "
                "interno, no un trámite público.",
                "      ",
            ),
            "",
            "      [ acceso ]   capturas  sistema",
        ]
        for u in urls:
            marca = "EMPLEADO" if u.get("kind") == "employee" else "usuario"
            veces = u.get("occurrences") or 0
            conteo = _num(veces).rjust(9) if veces else "        —"
            lineas.append(f"      [{marca:<8}] {conteo}  {u.get('url') or '—'}")

    if familias:
        pares = [f"{k} ({_num(v)})" for k, v in familias.items()]
        lineas += ["", "    Familias de malware", *_lista_envuelta(pares)]

    if terceros:
        lineas += [
            "",
            "    Otros dominios donde reaparecen esas credenciales",
            *_lista_envuelta(terceros),
        ]

    return lineas


def _enlaces(f: dict[str, Any]) -> list[str]:
    """La otra mitad de la columna 'Datos' (📎): punteros a lo publicado."""
    enlaces = [e for e in (f.get("download_links") or []) if isinstance(e, dict)]
    if not enlaces:
        return []

    lineas = [
        "",
        "  DATOS · Enlaces a lo publicado",
        *_parrafo(_AVISO_ENLACES),
        "",
    ]
    for e in enlaces:
        marca = _KIND_LEGIBLE.get(str(e.get("kind") or "unknown"), "enlace")
        lineas.append(f"      [{marca:<7}]  {e.get('url') or '—'}")
    return lineas


def _hallazgo(
    f: dict[str, Any], indice: int, total: int, ahora: datetime, fresh_days: int
) -> list[str]:
    titulo = str(f.get("victim_name") or "sin nombre")
    return [
        _SEP_SUAVE,
        f"[{indice}/{total}]  {titulo}",
        _SEP_SUAVE,
        "",
        *_identificacion(f, ahora, fresh_days),
        *_descripcion(f),
        *_exposicion(f),
        *_enlaces(f),
        "",
    ]


def render_report(
    findings: Sequence[dict[str, Any]],
    *,
    generated_at: datetime,
    fresh_days: int = 30,
) -> str:
    """Arma el informe completo. `findings` son los dicts que publica la API."""
    ordenados = ordenar(findings)
    ahora = generated_at if generated_at.tzinfo else generated_at.replace(tzinfo=UTC)

    lineas = _encabezado(ordenados, ahora, fresh_days)
    if not ordenados:
        lineas += [_SEP_SUAVE, "", "  Ningún hallazgo seleccionado.", ""]
    for i, f in enumerate(ordenados, start=1):
        lineas += _hallazgo(f, i, len(ordenados), ahora, fresh_days)

    lineas += [_SEP_FUERTE, "  Fin del informe.", _SEP_FUERTE, ""]
    # Ninguna línea termina en espacios: el archivo se pega en tickets y mails,
    # donde el espacio final sobrevive y se nota.
    return "\n".join(linea.rstrip() for linea in lineas)


def report_filename(generated_at: datetime, count: int) -> str:
    """Nombre del archivo. Sin nombres de víctima: el archivo puede circular."""
    momento = generated_at if generated_at.tzinfo else generated_at.replace(tzinfo=UTC)
    sello = momento.astimezone(UTC).strftime("%Y%m%d-%H%M")
    return f"hallazgos-{sello}-{count}.txt"
