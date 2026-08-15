"""Despacho de alertas.

Qué se alerta: hallazgos **nuevos** cuya severidad llega al umbral. "Nuevo" es
`alerted_at IS NULL`, no "recién insertado" — la diferencia importa: si el envío
falla, el hallazgo queda pendiente y se reintenta en la corrida siguiente en vez
de perderse.

Tres propiedades:

* **No repite.** Un hallazgo se alerta una sola vez; el marcado va después del
  envío exitoso.
* **No tumba la corrida.** Un canal caído se registra y se sigue; el hallazgo
  queda pendiente.
* **No filtra PII.** Sale la misma metadata que se persiste, ni un campo más.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from leaks.alerts.channels import CHANNEL_REGISTRY, ChannelSpec
from leaks.config import Settings
from leaks.domain.models import Finding

logger = logging.getLogger(__name__)


@runtime_checkable
class AlertChannel(Protocol):
    """Un destino de alertas."""

    name: str

    def send(self, findings: Sequence[Finding]) -> None:
        """Manda el aviso. Puede lanzar: el despachador lo aísla."""
        ...


@dataclass
class DispatchResult:
    """Qué pasó al alertar."""

    considered: int = 0
    sent: int = 0
    channels_ok: list[str] = field(default_factory=list)
    channels_failed: list[str] = field(default_factory=list)

    @property
    def delivered(self) -> bool:
        """Solo se marca como alertado si al menos un canal recibió el aviso."""
        return bool(self.channels_ok)

    def as_dict(self) -> dict[str, Any]:
        return {
            "considered": self.considered,
            "sent": self.sent,
            "channels_ok": list(self.channels_ok),
            "channels_failed": list(self.channels_failed),
        }


def build_channels(
    settings: Settings, client_factory: Any, specs: Sequence[ChannelSpec] = CHANNEL_REGISTRY
) -> list[AlertChannel]:
    """Arma los canales que estén configurados.

    Un canal sin credenciales no es un error: es un canal apagado.
    """
    canales: list[AlertChannel] = []
    for spec in specs:
        try:
            canal = spec.factory(settings, client_factory())
        except Exception:
            logger.warning("No se pudo construir el canal %s", spec.name, exc_info=True)
            continue
        if canal is not None:
            canales.append(canal)
    return canales


class AlertDispatcher:
    """Manda los hallazgos pendientes a los canales configurados."""

    def __init__(self, channels: Sequence[AlertChannel]) -> None:
        self._channels = list(channels)

    @property
    def enabled(self) -> bool:
        return bool(self._channels)

    @property
    def channel_names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self._channels)

    def dispatch(self, findings: Sequence[Finding]) -> DispatchResult:
        """Avisa de estos hallazgos. Nunca lanza."""
        resultado = DispatchResult(considered=len(findings))
        if not findings or not self._channels:
            return resultado

        for canal in self._channels:
            try:
                canal.send(findings)
            except Exception as exc:
                # Sin la URL ni el token: el mensaje termina en la bitácora.
                logger.warning("El canal %s falló: %s", canal.name, type(exc).__name__)
                resultado.channels_failed.append(canal.name)
                continue
            resultado.channels_ok.append(canal.name)

        if resultado.delivered:
            resultado.sent = len(findings)
        return resultado
