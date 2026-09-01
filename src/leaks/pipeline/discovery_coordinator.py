"""Coordinador del descubrimiento de subforos disparado desde la UI.

Mismo patrón que `RunCoordinator` y por el mismo motivo: el barrido son decenas
de requests autolimitados, así que tarda más de lo que un navegador espera. Se
lanza en un hilo y el frontend consulta el estado.

Dos garantías, iguales a las de la corrida manual:

* **Uno a la vez.** Dos barridos simultáneos duplicarían los pedidos al foro sin
  aportar nada. El segundo pedido recibe 409.
* **El control de IP de salida se aplica igual.** Lo hace el cliente HTTP, que
  se construye con el mismo `before_request` que el resto del pipeline: pedirlo
  desde la UI no puede saltear el bloqueo.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from leaks.adapters.fid_discovery import (
    SubforumProbe,
    as_env_line,
    candidate_fids,
    discover_subforums,
)
from leaks.adapters.registry import FeedSpec, build_adapter, get_spec
from leaks.config import Settings

logger = logging.getLogger(__name__)

#: Atributo de `Settings` con los fids de cada foro, para armar la línea del
#: `.env` que el investigador tiene que pegar.
_FID_SETTING = {
    "darkforums": "LEAKS_DARKFORUMS_FIDS",
    "breachforums": "LEAKS_BREACHFORUMS_FIDS",
}


@dataclass
class DiscoveryState:
    """Estado del último barrido."""

    running: bool = False
    feed: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    last_error: str | None = None
    probes: tuple[SubforumProbe, ...] = field(default_factory=tuple)
    env_line: str | None = None
    scanned: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "feed": self.feed,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "last_error": self.last_error,
            "scanned": self.scanned,
            "found": [p.as_dict() for p in self.probes],
            "env_line": self.env_line,
        }


class DiscoveryCoordinator:
    """Lanza barridos de subforos sin superponerlos."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._state = DiscoveryState()

    @property
    def state(self) -> DiscoveryState:
        return self._state

    def trigger(self, feed: str, first: int, last: int) -> bool:
        """Arranca un barrido. `False` si ya había uno en curso."""
        with self._lock:
            if self._state.running:
                return False
            self._state = DiscoveryState(running=True, feed=feed, started_at=datetime.now(UTC))

        hilo = threading.Thread(
            target=self._run, args=(feed, first, last), name="descubrir-subforos", daemon=True
        )
        hilo.start()
        return True

    def _run(self, feed: str, first: int, last: int) -> None:
        """Cuerpo del hilo. Nunca propaga: si explota, queda en el estado."""
        cliente = None
        try:
            spec = get_spec(feed)
            if spec is None:
                raise ValueError(f"no existe el feed {feed}")
            base = self._base_url(spec)
            # Se usa `build_adapter` solo por el cliente: trae el User-Agent
            # del feed y el control de IP de salida ya enganchados.
            _adapter, cliente = build_adapter(spec, self._settings)
            fids = candidate_fids(first, last)
            hallados = discover_subforums(cliente, base, fids)

            self._state.probes = hallados
            self._state.scanned = len(fids)
            self._state.env_line = as_env_line(_FID_SETTING.get(feed, "LEAKS_FIDS"), hallados)
            logger.info("descubrimiento en %s: %d subforos con contenido", feed, len(hallados))
        except Exception as exc:
            self._state.last_error = f"{type(exc).__name__}: {exc}"[:300]
            logger.warning("el descubrimiento en %s falló: %s", feed, self._state.last_error)
        finally:
            if cliente is not None:
                cliente.close()
            self._state.finished_at = datetime.now(UTC)
            self._state.running = False

    def _base_url(self, spec: FeedSpec) -> str:
        """Primer dominio configurado del foro. Sin ninguno no hay a dónde ir."""
        atributo = f"{spec.name}_base_urls"
        urls = tuple(getattr(self._settings, atributo, ()) or ())
        if not urls:
            raise ValueError(f"{spec.name} no tiene dominios configurados")
        return str(urls[0])
