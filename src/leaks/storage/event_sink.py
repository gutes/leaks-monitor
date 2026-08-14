"""Sinks de eventos de actividad.

Dos implementaciones del puerto `EventSink`:

* `SqlAlchemyEventSink` — persiste en `run_events` para que la API (otro
  proceso, otro contenedor) pueda mostrarlos en la consola del frontend.
* `NullEventSink` — descarta. Es el default cuando nadie inyecta un sink, para
  que el pipeline no dependa de que exista bitácora.

Regla de los dos: **nunca propagan excepciones**. Que falle el registro de
actividad no puede tumbar una corrida — sería el colmo perder el monitoreo por
culpa del panel que lo muestra.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete
from sqlalchemy.orm import Session, sessionmaker

from leaks.domain.models import RunEvent
from leaks.storage.models import RunEventRow
from leaks.storage.session import session_scope

logger = logging.getLogger(__name__)

#: Tope del texto libre de un evento. Coincide con la columna.
MAX_MESSAGE_LENGTH = 500


class NullEventSink:
    """Descarta todo. Default cuando no hay bitácora configurada."""

    def emit(self, event: RunEvent) -> None:
        """No hace nada, a propósito."""


class SqlAlchemyEventSink:
    """Persiste los eventos para que el frontend los pueda leer en vivo."""

    def __init__(self, session_factory: sessionmaker[Session], retention_days: int = 14) -> None:
        self._session_factory = session_factory
        self._retention_days = retention_days

    def emit(self, event: RunEvent) -> None:
        """Escribe un evento. Se traga cualquier error: es telemetría, no datos."""
        try:
            with session_scope(self._session_factory) as session:
                session.add(
                    RunEventRow(
                        occurred_at=event.occurred_at,
                        level=str(event.level),
                        kind=str(event.kind),
                        source=event.source,
                        message=event.message[:MAX_MESSAGE_LENGTH],
                        url=event.url,
                        status_code=event.status_code,
                        duration_ms=event.duration_ms,
                        bytes_received=event.bytes_received,
                    )
                )
        except Exception:
            logger.debug("No se pudo registrar el evento de actividad", exc_info=True)

    def purge_expired(self, *, now: datetime | None = None) -> int:
        """Borra la bitácora vieja. La consola es un panel de actividad, no un archivo."""
        limite = (now or datetime.now(UTC)) - timedelta(days=self._retention_days)
        try:
            with session_scope(self._session_factory) as session:
                resultado = cast(
                    CursorResult[Any],
                    session.execute(delete(RunEventRow).where(RunEventRow.occurred_at < limite)),
                )
                return resultado.rowcount or 0
        except Exception:
            logger.debug("No se pudo purgar la bitácora", exc_info=True)
            return 0
