"""Coordinador de corridas disparadas a mano.

Existe para que el botón "Correr ahora" del frontend haga lo que dice sin
bloquear la petición: una corrida tarda entre 15 y 80 segundos, así que se
lanza en un hilo aparte y el navegador ve el avance en la consola de actividad,
que ya se actualiza sola.

Dos garantías:

* **Una sola corrida a la vez.** Dos corridas simultáneas sobre la misma SQLite
  se pisarían los cursores y multiplicarían los requests a los feeds. El
  segundo pedido recibe 409, no una segunda corrida.
* **El control de IP de salida se aplica igual.** No se chequea acá: lo hace el
  runner, que es la única puerta. Disparar a mano no puede saltear el bloqueo.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from leaks.adapters.registry import FeedDeps, FeedSpec
from leaks.pipeline.runner import PipelineRunner, RunReport

logger = logging.getLogger(__name__)


@dataclass
class RunState:
    """Estado de la última corrida disparada a mano."""

    running: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None
    last_error: str | None = None
    last_report: RunReport | None = None

    def as_dict(self) -> dict[str, Any]:
        reporte = self.last_report
        return {
            "running": self.running,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "last_error": self.last_error,
            "last_total_new": reporte.total_new if reporte else None,
            "last_blocked_reason": reporte.blocked_reason if reporte else None,
        }


class RunCoordinator:
    """Lanza corridas manuales sin superponerlas."""

    def __init__(self, runner: PipelineRunner) -> None:
        self._runner = runner
        self._lock = threading.Lock()
        self._state = RunState()

    @property
    def state(self) -> RunState:
        return self._state

    def is_running(self) -> bool:
        return self._state.running

    def trigger(
        self,
        specs: Sequence[tuple[FeedSpec, str | None]] | None = None,
        deps: FeedDeps | None = None,
    ) -> bool:
        """Arranca una corrida. Devuelve `False` si ya había una en curso.

        `specs` y `deps` acotan la corrida: sirven para leer un solo canal a
        pedido sin traer todo lo demás. Igual toman el mismo candado, porque
        dos corridas en paralelo sobre la misma SQLite se pisan.
        """
        with self._lock:
            if self._state.running:
                return False
            self._state = RunState(running=True, started_at=datetime.now(UTC))

        hilo = threading.Thread(
            target=self._run, args=(specs, deps), name="corrida-manual", daemon=True
        )
        hilo.start()
        return True

    def _run(
        self,
        specs: Sequence[tuple[FeedSpec, str | None]] | None = None,
        deps: FeedDeps | None = None,
    ) -> None:
        """Cuerpo del hilo. Nunca propaga: si explota, queda en el estado."""
        try:
            reporte = self._runner.run(specs, deps)
            self._state.last_report = reporte
            self._state.last_error = None
        except Exception as exc:  # pragma: no cover — red de seguridad del hilo
            logger.exception("La corrida manual falló")
            self._state.last_error = f"{type(exc).__name__}: {exc}"[:500]
        finally:
            self._state.finished_at = datetime.now(UTC)
            self._state.running = False
