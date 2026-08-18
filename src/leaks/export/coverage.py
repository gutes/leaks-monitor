"""Qué sistemas de cada entrada de la watchlist aparecieron comprometidos.

La watchlist dice qué vigilamos; los hallazgos dicen qué encontramos. Cruzarlos
contesta la pregunta que un investigador hace primero: *de lo que estoy
mirando, ¿qué ya cayó alguna vez y dónde lo vimos?*

El cruce vive **solo en la exportación**. En la pantalla sería ruido: la
watchlist se usa para administrar qué se monitorea, y colgarle el historial de
cada dominio la convierte en otra cosa. En un informe, en cambio, es
exactamente lo que se quiere leer.

Dos fuentes de sistemas por hallazgo:

* `victim_domain` — la víctima declarada.
* Las URLs de `exposure_detail` — de ahí salen los subdominios reales
  (`siar.nuclear-ejemplo.gob.ar`, `correo.registro-ejemplo.gob.ar`), que es donde está la señal:
  no es lo mismo "cayó nuclear-ejemplo.gob.ar" que "cayó su VPN".

Funciones puras: entran diccionarios, sale un mapa. Sin base ni red.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

#: Un hostname plausible: etiquetas alfanuméricas separadas por puntos. Sin
#: esto `urlsplit` acepta cualquier texto —"no es una url" sale como host— y el
#: informe listaría basura como si fuera un sistema comprometido.
_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

#: Tope de compromisos listados por entrada. Los que sobran se cuentan, no se
#: esconden: un informe que trunca en silencio miente.
MAX_POR_ENTRADA = 40


def host_de(url: str | None) -> str | None:
    """Hostname de una URL, normalizado. `None` si no se puede sacar."""
    if not url or not isinstance(url, str):
        return None
    try:
        partes = urlsplit(url if "//" in url else f"//{url}")
    except ValueError:
        return None
    host = (partes.hostname or "").strip().lower().removeprefix("www.").rstrip(".")
    return host if _HOSTNAME.match(host) else None


def cubre(dominio: str, host: str) -> bool:
    """Si una entrada de la watchlist cubre ese host.

    Mismo criterio que `Watchlist.match_domain`: la entrada cubre el dominio
    exacto y cualquier subdominio suyo. Se compara por etiquetas y no con un
    `endswith` pelado, porque `malinuclear-ejemplo.gob.ar` no es subdominio de
    `nuclear-ejemplo.gob.ar` aunque termine igual.
    """
    if not dominio or not host:
        return False
    return host == dominio or host.endswith(f".{dominio}")


@dataclass(frozen=True)
class Compromiso:
    """Un sistema de la watchlist que apareció en un hallazgo."""

    #: El host concreto: `siar.nuclear-ejemplo.gob.ar`, no `nuclear-ejemplo.gob.ar`.
    host: str
    #: Cuándo ocurrió el evento. `None` si no se pudo fechar — no se inventa.
    occurred_at: datetime | None
    source: str
    #: Dónde lo encontramos nosotros.
    ref_url: str | None
    victim_name: str
    #: El host salió de una URL de login de empleados: acceso interno.
    empleado: bool = False


def _hosts_del_hallazgo(f: dict[str, Any]) -> list[tuple[str, bool]]:
    """Hosts mencionados por un hallazgo, con si son de empleados."""
    encontrados: dict[str, bool] = {}

    principal = host_de(f.get("victim_domain"))
    if principal:
        encontrados[principal] = False

    exposicion = f.get("exposure_detail")
    if isinstance(exposicion, dict):
        for entrada in exposicion.get("urls") or []:
            if not isinstance(entrada, dict):
                continue
            host = host_de(entrada.get("url"))
            if not host:
                continue
            empleado = entrada.get("kind") == "employee"
            # Si el mismo host aparece como empleado y como usuario, gana
            # empleado: es la lectura que cambia la decisión.
            encontrados[host] = encontrados.get(host, False) or empleado

    return list(encontrados.items())


def _orden(c: Compromiso) -> tuple[int, float, str]:
    """Más reciente primero; los sin fecha al final, como en el otro informe."""
    if c.occurred_at is None:
        return (1, 0.0, c.host)
    momento = c.occurred_at if c.occurred_at.tzinfo else c.occurred_at.replace(tzinfo=UTC)
    return (0, -momento.timestamp(), c.host)


def relacionar(
    dominios: Sequence[str],
    findings: Iterable[dict[str, Any]],
    *,
    max_por_entrada: int = MAX_POR_ENTRADA,
) -> dict[str, tuple[tuple[Compromiso, ...], int]]:
    """Mapa `dominio de la watchlist -> (compromisos, cuántos se omitieron)`.

    Un host puede quedar bajo más de una entrada si la watchlist tiene un
    dominio y su subdominio cargados por separado; se asigna a **la más
    específica**, que es la que el investigador dio de alta a propósito.
    """
    normalizados = [d.strip().lower() for d in dominios if d and d.strip()]
    # Del más específico al más general: gana el primero que cubre.
    por_especificidad = sorted(normalizados, key=lambda d: (-d.count("."), -len(d)))
    acumulado: dict[str, list[Compromiso]] = {d: [] for d in normalizados}
    vistos: dict[str, set[tuple[str, str, str | None]]] = {d: set() for d in normalizados}

    for f in findings:
        fecha = f.get("occurred_at")
        for host, empleado in _hosts_del_hallazgo(f):
            duenio = next((d for d in por_especificidad if cubre(d, host)), None)
            if duenio is None:
                continue
            # Dos hallazgos de la misma fuente sobre el mismo host el mismo día
            # son el mismo hecho contado dos veces.
            clave = (
                host,
                str(f.get("source") or ""),
                fecha.date().isoformat() if isinstance(fecha, datetime) else None,
            )
            if clave in vistos[duenio]:
                continue
            vistos[duenio].add(clave)
            acumulado[duenio].append(
                Compromiso(
                    host=host,
                    occurred_at=fecha if isinstance(fecha, datetime) else None,
                    source=str(f.get("source") or "—"),
                    ref_url=f.get("raw_ref") if isinstance(f.get("raw_ref"), str) else None,
                    victim_name=str(f.get("victim_name") or ""),
                    empleado=empleado,
                )
            )

    salida: dict[str, tuple[tuple[Compromiso, ...], int]] = {}
    for dominio, lista in acumulado.items():
        if not lista:
            continue
        ordenados = sorted(lista, key=_orden)
        salida[dominio] = (
            tuple(ordenados[:max_por_entrada]),
            max(0, len(ordenados) - max_por_entrada),
        )
    return salida
