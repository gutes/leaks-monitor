"""Control de IP de salida: bloqueo de OPSEC.

Regla: **si el tráfico sale desde Argentina, no se consulta ninguna fuente.**

El motivo es operacional, no técnico. El prototipo monitorea filtraciones de
organismos argentinos; consultar los índices de esos mismos leaks desde una IP
argentina expone al investigador y hace atribuible la investigación. La VPN no
es una comodidad: es parte del procedimiento.

Dos decisiones deliberadas:

* **Fail-closed ante lo desconocido.** Si no se puede determinar el país, se
  bloquea igual. El control no promete "no salir por AR salvo que no sepamos":
  promete que no se sale por AR, y una IP sin resolver no da esa garantía.
* **No hay override.** Ni por la UI ni por la API. Un control de OPSEC que se
  puede saltar con un click no es un control, es un cartel.

El bloqueo vive acá, del lado del pipeline, y no en el frontend: el scheduler
corre en otro proceso y seguiría consultando feeds aunque el navegador
estuviera mostrando un modal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from leaks.adapters.egress import EgressInfo, EgressResolver

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EgressDecision:
    """Veredicto del control para una corrida."""

    allowed: bool
    reason: str
    info: EgressInfo | None = None

    @property
    def country(self) -> str | None:
        return self.info.country if self.info else None


class EgressGuard:
    """Decide si se puede consultar fuentes desde la IP de salida actual."""

    def __init__(
        self,
        resolver: EgressResolver | None,
        blocked_countries: tuple[str, ...] = ("AR",),
        block_on_unknown: bool = True,
    ) -> None:
        self._resolver = resolver
        # Se normaliza a mayúsculas: el ISO-2 llega como venga del proveedor.
        self._blocked = frozenset(c.strip().upper() for c in blocked_countries if c.strip())
        self._block_on_unknown = block_on_unknown

    def evaluate(self) -> EgressDecision:
        """Resuelve la IP de salida y decide."""
        if not self._blocked:
            # Sin países bloqueados el control está apagado por configuración
            # del operador (no por la UI). Se deja dicho en el motivo.
            return EgressDecision(True, "Control de IP de salida desactivado")

        if self._resolver is None:
            return self._unknown("La verificación de IP de salida está desactivada")

        try:
            info = self._resolver.resolve()
        except Exception:  # pragma: no cover — fail-closed igual
            logger.warning("Falló la resolución de IP de salida", exc_info=True)
            return self._unknown("No se pudo resolver la IP de salida")

        if info is None or not info.country:
            return self._unknown("No se pudo determinar el país de la IP de salida", info)

        pais = info.country.strip().upper()
        if pais in self._blocked:
            return EgressDecision(
                False,
                (
                    f"BLOQUEADO: el tráfico sale desde {pais} ({info.ip}"
                    f"{', ' + info.org if info.org else ''}). "
                    "Conectate a la VPN antes de consultar fuentes."
                ),
                info,
            )

        return EgressDecision(True, f"Salida verificada: {info.label}", info)

    def _unknown(self, motivo: str, info: EgressInfo | None = None) -> EgressDecision:
        if self._block_on_unknown:
            return EgressDecision(False, f"BLOQUEADO: {motivo}.", info)
        return EgressDecision(True, motivo, info)
