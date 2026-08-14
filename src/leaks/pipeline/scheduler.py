"""Scheduler del run diario.

Un bucle propio y no APScheduler/cron-en-el-contenedor: es una sola tarea a una
hora fija, y una dependencia menos que auditar. La lógica de "cuándo toca" está
separada del bucle (`next_run_at`) justamente para poder testearla sin dejar
correr el reloj.

En producción real conviene igual delegar en el cron del sistema o en el
scheduler del orquestador y usar `leaks run` — está documentado en el README.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime, timedelta

from leaks.pipeline.runner import RunReport

logger = logging.getLogger(__name__)


def parse_daily_time(value: str) -> tuple[int, int]:
    """Convierte "HH:MM" en (hora, minuto). Ya validado por `Settings`."""
    hora, _, minuto = value.partition(":")
    return int(hora), int(minuto)


def next_run_at(now: datetime, daily_at: str) -> datetime:
    """Próxima ocurrencia de `daily_at` estrictamente posterior a `now`.

    Se trabaja en hora local (el `now` que se pasa define el huso): un
    investigador razona en su horario, no en UTC.
    """
    hora, minuto = parse_daily_time(daily_at)
    candidato = now.replace(hour=hora, minute=minuto, second=0, microsecond=0)
    if candidato <= now:
        candidato += timedelta(days=1)
    return candidato


def run_forever(
    run_once: Callable[[], RunReport],
    *,
    daily_at: str,
    now_fn: Callable[[], datetime] = datetime.now,
    sleep_fn: Callable[[float], None] = time.sleep,
    max_iterations: int | None = None,
) -> int:
    """Corre el pipeline una vez por día a la hora indicada.

    `now_fn`/`sleep_fn`/`max_iterations` se inyectan para que el test pueda
    simular días enteros en milisegundos.

    Una corrida que falla no corta el bucle: se registra y se espera a la
    siguiente. Un scheduler que se muere ante el primer error deja de monitorear
    justo cuando más falta hace.
    """
    iteraciones = 0
    while max_iterations is None or iteraciones < max_iterations:
        ahora = now_fn()
        proximo = next_run_at(ahora, daily_at)
        espera = max((proximo - ahora).total_seconds(), 0.0)
        logger.info("Próxima corrida: %s (en %.0f s)", proximo.isoformat(), espera)
        sleep_fn(espera)

        try:
            reporte = run_once()
            logger.info(
                "Corrida terminada: %d traídos, %d relevantes AR, %d nuevos%s",
                reporte.total_fetched,
                reporte.total_matched,
                reporte.total_new,
                f", fuentes caídas: {', '.join(reporte.failed_sources)}"
                if reporte.failed_sources
                else "",
            )
        except Exception:
            logger.exception("La corrida falló entera; se espera a la próxima.")

        iteraciones += 1

    return iteraciones
