"""Detalle de exposición por infostealers.

Los feeds de infostealers devuelven mucho más que un conteo, y hasta ahora lo
tirábamos: nos quedábamos con "225.375 equipos comprometidos", que impresiona
pero no dice qué hacer.

Lo que sí es accionable:

* **Qué sistema se comprometió.** Un `ftp.prevision-ejemplo.gob.ar` capturado a un empleado
  pesa distinto que el portal público donde se loguean los ciudadanos.
* **Empleado o usuario.** Es la diferencia entre "alguien de adentro" y "alguien
  que usa el trámite".
* **Qué familia de stealer** predomina, para correlacionar campañas.
* **Qué tan malas son las contraseñas**, que es un hallazgo en sí.

**Nada de esto es PII.** Son URLs de sistemas del propio organismo, nombres de
malware y porcentajes. Las credenciales y los emails no vienen en el tier
gratuito —son el producto comercial del proveedor— y aunque vinieran, no se
persistirían: las URLs igual pasan por el redactor, porque una query string
puede arrastrar un identificador.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from leaks.privacy.scrub import redact_pii

#: Tope de URLs por hallazgo. El feed devuelve decenas y la cola larga no
#: aporta: lo que importa son los sistemas más golpeados.
MAX_URLS = 15

#: Tope de familias de stealer y de dominios de terceros.
MAX_FAMILIES = 8
MAX_THIRD_PARTY = 10

_HTTP = re.compile(r"^https?://", re.IGNORECASE)


class ExposedUrl(BaseModel):
    """Una URL de login capturada por un infostealer."""

    model_config = ConfigDict(frozen=True)

    url: str
    #: `employee` o `user`. Es la distinción operativamente más importante.
    kind: str = "user"
    #: Cuántas capturas registró el proveedor contra esa URL.
    occurrences: int = 0


class ExposureDetail(BaseModel):
    """Cómo se ve la exposición de un dominio, sin identidades."""

    model_config = ConfigDict(frozen=True)

    urls: tuple[ExposedUrl, ...] = ()
    #: Familias de malware y cuántas capturas aporta cada una.
    stealer_families: dict[str, int] = Field(default_factory=dict)
    #: Porcentaje de contraseñas clasificadas como débiles o peores.
    weak_password_pct: float | None = None
    #: Otros dominios donde reaparecen las mismas credenciales.
    third_party_domains: tuple[str, ...] = ()

    @property
    def employee_urls(self) -> tuple[ExposedUrl, ...]:
        """Las de empleados: la señal fuerte de compromiso interno."""
        return tuple(u for u in self.urls if u.kind == "employee")

    def as_dict(self) -> dict[str, Any]:
        return {
            "urls": [
                {"url": u.url, "kind": u.kind, "occurrences": u.occurrences} for u in self.urls
            ],
            "stealer_families": dict(self.stealer_families),
            "weak_password_pct": self.weak_password_pct,
            "third_party_domains": list(self.third_party_domains),
        }

    @property
    def is_empty(self) -> bool:
        return not (self.urls or self.stealer_families or self.third_party_domains)


def _url_entries(valor: Any, kind: str) -> list[ExposedUrl]:
    """Normaliza la lista de URLs del proveedor, que viene en dos formas.

    A veces es `[{"url": ..., "occurrence": N}]` y a veces una lista de strings
    pelados. Se tolera cualquiera y se ignora lo que no se entienda.
    """
    salida: list[ExposedUrl] = []
    if not isinstance(valor, list):
        return salida

    for entrada in valor:
        if isinstance(entrada, str):
            url, veces = entrada, 0
        elif isinstance(entrada, dict):
            url = entrada.get("url") or ""
            crudo = entrada.get("occurrence") or entrada.get("occurrences") or 0
            veces = crudo if isinstance(crudo, int) else 0
        else:
            continue

        if not isinstance(url, str) or not _HTTP.match(url):
            continue

        # Una query string puede arrastrar un identificador: se redacta igual,
        # aunque el proveedor no mande PII en este endpoint.
        limpia = redact_pii(url) or url
        salida.append(ExposedUrl(url=limpia[:500], kind=kind, occurrences=veces))

    return salida


def _weak_pct(passwords: Any) -> float | None:
    """Porcentaje de contraseñas débiles o peores, si el feed lo informa."""
    if not isinstance(passwords, dict):
        return None
    total = 0.0
    for clave in ("too_weak", "weak"):
        tramo = passwords.get(clave)
        if isinstance(tramo, dict) and isinstance(tramo.get("perc"), (int, float)):
            total += float(tramo["perc"])
    return round(total, 2) if total else None


def build_exposure(payload: dict[str, Any]) -> ExposureDetail | None:
    """Arma el detalle a partir del payload de Hudson Rock.

    Devuelve `None` si no hay nada que valga la pena guardar, para no llenar la
    base de estructuras vacías.
    """
    crudo_datos = payload.get("data")
    datos: dict[str, Any] = crudo_datos if isinstance(crudo_datos, dict) else {}

    urls = [
        *_url_entries(datos.get("employees_urls"), "employee"),
        *_url_entries(datos.get("clients_urls"), "user"),
    ]
    # Las de empleados primero, y dentro de cada grupo las más golpeadas: es el
    # orden en que un investigador quiere leerlas.
    urls.sort(key=lambda u: (u.kind != "employee", -u.occurrences))

    familias_crudas = payload.get("stealerFamilies")
    familias: dict[str, int] = {}
    if isinstance(familias_crudas, dict):
        candidatas = {
            k: v
            for k, v in familias_crudas.items()
            # `total` es la suma, no una familia.
            if k != "total" and isinstance(v, int) and v > 0
        }
        familias = dict(sorted(candidatas.items(), key=lambda kv: -kv[1])[:MAX_FAMILIES])

    terceros: list[str] = []
    crudos = payload.get("thirdPartyDomains")
    if isinstance(crudos, list):
        for entrada in crudos:
            dominio = entrada.get("domain") if isinstance(entrada, dict) else entrada
            if isinstance(dominio, str) and dominio.strip():
                terceros.append(dominio.strip().lower())

    detalle = ExposureDetail(
        urls=tuple(urls[:MAX_URLS]),
        stealer_families=familias,
        weak_password_pct=_weak_pct(payload.get("userPasswords"))
        or _weak_pct(payload.get("employeePasswords")),
        third_party_domains=tuple(dict.fromkeys(terceros))[:MAX_THIRD_PARTY],
    )
    return None if detalle.is_empty else detalle
