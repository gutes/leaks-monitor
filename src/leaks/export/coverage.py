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


#: De dónde salió la línea. La distinción no es cosmética: `sistema` es un
#: sistema concreto que apareció en los datos filtrados; `victima` es el
#: organismo que la fuente nombró, sin decir qué sistema suyo cayó.
ORIGEN_SISTEMA = "sistema"
ORIGEN_VICTIMA = "victima"


@dataclass(frozen=True)
class Compromiso:
    """Un sistema de la watchlist que apareció en un hallazgo."""

    #: El host concreto: `siar.nuclear-ejemplo.gob.ar`, no `nuclear-ejemplo.gob.ar`.
    host: str
    #: La URL **exacta** tal como apareció en los datos, con su path. Es la
    #: evidencia: `/sslvpn_logon.shtml` es lo que identifica al sistema como la
    #: VPN. `None` cuando la línea sale del dominio de la víctima y no de una
    #: URL — ahí no hay path que mostrar porque no hubo URL.
    url: str | None
    #: Cuándo ocurrió el evento. `None` si no se pudo fechar — no se inventa.
    occurred_at: datetime | None
    source: str
    #: Dónde lo encontramos nosotros.
    ref_url: str | None
    victim_name: str
    #: El host salió de una URL de login de empleados: acceso interno.
    empleado: bool = False
    origen: str = ORIGEN_SISTEMA

    @property
    def evidencia(self) -> str:
        """Lo que se muestra: la URL exacta si la hay, si no el host."""
        return self.url or self.host


@dataclass(frozen=True)
class _Aparicion:
    """Un host mencionado por un hallazgo, con de dónde salió."""

    host: str
    url: str | None
    empleado: bool
    origen: str


def _normalizar_url(url: str) -> str:
    """Quita la barra final: `https://x/` y `https://x` son el mismo sistema."""
    return url.rstrip("/") if url.count("/") > 2 else url


def _apariciones(f: dict[str, Any]) -> list[_Aparicion]:
    """Hosts mencionados por un hallazgo, sin perder la URL exacta.

    Un mismo host puede aparecer en varias URLs (`/owa/auth/logon.aspx` y
    `/owa/auth.owa` son dos superficies distintas del mismo servidor): se
    devuelven las dos, porque colapsarlas al host perdería justo el detalle que
    hace accionable el hallazgo.
    """
    encontrados: dict[str, _Aparicion] = {}

    exposicion = f.get("exposure_detail")
    if isinstance(exposicion, dict):
        for entrada in exposicion.get("urls") or []:
            if not isinstance(entrada, dict):
                continue
            cruda = entrada.get("url")
            host = host_de(cruda)
            if not host or not isinstance(cruda, str):
                continue
            limpia = _normalizar_url(cruda)
            empleado = entrada.get("kind") == "employee"
            previo = encontrados.get(limpia)
            # Si la misma URL figura como empleado y como usuario, gana
            # empleado: es la lectura que cambia la decisión.
            encontrados[limpia] = _Aparicion(
                host=host,
                url=limpia,
                empleado=empleado or bool(previo and previo.empleado),
                origen=ORIGEN_SISTEMA,
            )

    # El dominio de la víctima va aparte y **último**: para las fuentes que se
    # consultan dominio por dominio (Hudson Rock) es el dominio que nosotros
    # preguntamos, no algo que la fuente haya descubierto. Listarlo junto a los
    # sistemas reales haría pasar nuestra propia consulta por evidencia.
    principal = host_de(f.get("victim_domain"))
    if principal and not any(a.host == principal for a in encontrados.values()):
        encontrados[principal] = _Aparicion(
            host=principal, url=None, empleado=False, origen=ORIGEN_VICTIMA
        )

    return list(encontrados.values())


def _orden(c: Compromiso) -> tuple[int, float, int, str]:
    """Más reciente primero; los sin fecha al final, como en el otro informe.

    Dentro de la misma fecha van primero los sistemas concretos y después el
    organismo declarado, que es el dato más débil.
    """
    rango = 0 if c.origen == ORIGEN_SISTEMA else 1
    if c.occurred_at is None:
        return (1, 0.0, rango, c.evidencia)
    momento = c.occurred_at if c.occurred_at.tzinfo else c.occurred_at.replace(tzinfo=UTC)
    return (0, -momento.timestamp(), rango, c.evidencia)


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
        for ap in _apariciones(f):
            duenio = next((d for d in por_especificidad if cubre(d, ap.host)), None)
            if duenio is None:
                continue
            # Dos hallazgos de la misma fuente sobre la misma URL el mismo día
            # son el mismo hecho contado dos veces. Se deduplica por la URL y no
            # por el host: dos endpoints del mismo servidor son dos superficies.
            clave = (
                ap.url or ap.host,
                str(f.get("source") or ""),
                fecha.date().isoformat() if isinstance(fecha, datetime) else None,
            )
            if clave in vistos[duenio]:
                continue
            vistos[duenio].add(clave)
            acumulado[duenio].append(
                Compromiso(
                    host=ap.host,
                    url=ap.url,
                    occurred_at=fecha if isinstance(fecha, datetime) else None,
                    source=str(f.get("source") or "—"),
                    ref_url=f.get("raw_ref") if isinstance(f.get("raw_ref"), str) else None,
                    victim_name=str(f.get("victim_name") or ""),
                    empleado=ap.empleado,
                    origen=ap.origen,
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
