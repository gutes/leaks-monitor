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

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from leaks.export.layout import (
    SEP_FUERTE,
    SEP_SUAVE,
    campo,
    dia,
    fecha,
    lista_envuelta,
    num,
    parrafo,
    sello,
    unir,
)

#: La clave sale de una constante y no de un literal dentro del diccionario
#: porque el SAST lee el par `"repo_secret": "..."` como una credencial
#: embebida y marcaría el literal entero.
_CLAVE_REPO = "repo_secret"

#: Etiquetas y textos propios de este informe. El maquetado (ancho, columnas,
#: separadores) vive en `layout` y lo comparten los dos informes.
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
        SEP_FUERTE,
        "  INFORME DE HALLAZGOS — Monitor de leaks",
        SEP_FUERTE,
        "",
        campo("Generado", fecha(generated_at)),
        campo("Hallazgos", num(len(findings))),
    ]
    if fechados:
        lineas.append(campo("Ocurrencias", f"{dia(min(fechados))} → {dia(max(fechados))}"))
    if sin_fecha:
        lineas.append(campo("Sin fechar", f"{num(sin_fecha)} (van al final)"))
    lineas.append(campo("Umbral reciente", f"{fresh_days} días"))
    lineas += [
        "",
        *parrafo(
            "Ordenados por fecha de ocurrencia del evento —no por cuándo lo "
            "importamos—, del más reciente al más antiguo.",
            "  ",
        ),
        "",
        *parrafo(
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
        f"{dia(ocurrido)}  ({_frescura(ocurrido, ahora, fresh_days)} · {base})"
        if isinstance(ocurrido, datetime)
        else f"sin fecha  ({base})"
    )

    tipo = str(f.get("leak_type") or "")
    fuente = f"{f.get('source') or '—'}  ({_TIPO_LEGIBLE.get(tipo, tipo or '—')})"

    lineas = [
        campo("Ocurrencia", detalle_fecha),
        campo("Declarado", f"{dia(f.get('discovered_at'))}  (fecha que informa la fuente)"),
        campo("Visto", f"{dia(f.get('first_seen_at'))}  (cuándo lo detectamos)"),
    ]
    if f.get("backfill"):
        lineas += parrafo(
            "Entró con la importación inicial de su fuente: es histórico que "
            "recién conocemos, no una novedad de ese día.",
            "                   ",
        )
    lineas += [
        campo("Víctima", f.get("victim_name")),
        campo("Dominio", f.get("victim_domain")),
        campo("País", f.get("country")),
        campo("Sector", f.get("sector")),
        campo("Actor", f.get("actor")),
        campo("Fuente", fuente),
        campo("Severidad", str(f.get("severity") or "—").upper()),
    ]

    razones = list(f.get("ar_match_reason") or [])
    lineas.append(campo("Relevancia AR", ", ".join(razones) if razones else "—"))
    detalles = f.get("ar_match_detail") or {}
    for regla in razones:
        evidencia = detalles.get(regla) or []
        if evidencia:
            lineas += parrafo(
                f"{regla}: {', '.join(str(e) for e in evidencia)}", "                   "
            )

    lineas.append(campo("Referencia", f.get("raw_ref")))
    return lineas


def _descripcion(f: dict[str, Any]) -> list[str]:
    texto = f.get("description")
    if not texto:
        return []
    return ["", "  Descripción", *parrafo(str(texto))]


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
    resumen = [f"{num(len(urls))} sistemas comprometidos"]
    if internos:
        resumen.append(f"{num(len(internos))} de empleados")
    if debiles:
        resumen.append(f"{debiles}% de contraseñas débiles")

    lineas = ["", "  DATOS · Exposición por infostealers", *parrafo(" · ".join(resumen))]

    if urls:
        lineas += [
            "",
            "    Sistemas comprometidos",
            *parrafo(
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
            conteo = num(veces).rjust(9) if veces else "        —"
            lineas.append(f"      [{marca:<8}] {conteo}  {u.get('url') or '—'}")

    if familias:
        pares = [f"{k} ({num(v)})" for k, v in familias.items()]
        lineas += ["", "    Familias de malware", *lista_envuelta(pares)]

    if terceros:
        lineas += [
            "",
            "    Otros dominios donde reaparecen esas credenciales",
            *lista_envuelta(terceros),
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
        *parrafo(_AVISO_ENLACES),
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
        SEP_SUAVE,
        f"[{indice}/{total}]  {titulo}",
        SEP_SUAVE,
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
        lineas += [SEP_SUAVE, "", "  Ningún hallazgo seleccionado.", ""]
    for i, f in enumerate(ordenados, start=1):
        lineas += _hallazgo(f, i, len(ordenados), ahora, fresh_days)

    lineas += [SEP_FUERTE, "  Fin del informe.", SEP_FUERTE, ""]
    return unir(lineas)


def report_filename(generated_at: datetime, count: int) -> str:
    """Nombre del archivo. Sin nombres de víctima: el archivo puede circular."""
    return f"hallazgos-{sello(generated_at)}-{count}.txt"
