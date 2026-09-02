"""Scheduler: la corrida diaria y los sondeos de las fuentes efímeras.

Un bucle propio y no APScheduler/cron-en-el-contenedor: son dos cadencias
simples, y una dependencia menos que auditar. La lógica de "cuándo toca" está
separada del bucle (`next_run_at`, `plan_next`) justamente para poder testearla
sin dejar correr el reloj.

**Por qué dos cadencias.** Algunas fuentes publican mucho más rápido de lo que
dura un día: la sindicación de un foro expone los últimos 15 threads, que en
DarkForums cubren ~3 horas. Verlas una vez por día no es "monitorearlas con
menos resolución": es perder la mayor parte de lo que pasó. Esas fuentes
declaran `poll_interval_minutes` en el registro y se sondean aparte; el resto
sigue entrando solo en la corrida diaria.

En producción real conviene igual delegar en el cron del sistema o en el
scheduler del orquestador y usar `leaks run` — está documentado en el README.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from leaks.pipeline.runner import RunReport

logger = logging.getLogger(__name__)

#: Fecha y hora en el log, en hora local. Va la FECHA además de la hora: sin
#: ella no se distingue la corrida de hoy de la de la semana pasada.
FORMATO_FECHA = "%Y-%m-%d %H:%M:%S %Z"


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


@dataclass(frozen=True)
class ScheduledEvent:
    """Lo próximo que hay que hacer y cuándo."""

    at: datetime
    #: Fuentes a correr. `None` = la corrida completa.
    feeds: tuple[str, ...] | None = None

    @property
    def is_full_run(self) -> bool:
        return self.feeds is None


def plan_next(
    now: datetime,
    daily_at: str,
    next_polls: Mapping[str, datetime],
) -> ScheduledEvent:
    """Elige el evento más próximo entre la corrida diaria y los sondeos.

    Ante un empate gana la corrida completa: hace todo lo que haría el sondeo y
    además el resto, así que sondear en el mismo instante sería trabajo al pedo.
    """
    completa = ScheduledEvent(at=next_run_at(now, daily_at))
    if not next_polls:
        return completa

    cuando = min(next_polls.values())
    if cuando >= completa.at:
        return completa

    # Todo lo que vence en el mismo instante se sondea junto: un solo evento.
    juntos = tuple(sorted(f for f, t in next_polls.items() if t == cuando))
    return ScheduledEvent(at=cuando, feeds=juntos)


class RunCallable(Protocol):
    """Lo que el scheduler necesita del runner: correr todo, o solo unas fuentes."""

    def __call__(self, *, only: Sequence[str] | None = None) -> RunReport: ...


def run_forever(
    run_once: RunCallable,
    *,
    daily_at: str,
    polls: Mapping[str, int] | None = None,
    now_fn: Callable[[], datetime] = datetime.now,
    sleep_fn: Callable[[float], None] = time.sleep,
    max_iterations: int | None = None,
) -> int:
    """Corre el pipeline entero una vez por día, y sondea las fuentes efímeras.

    `polls` mapea nombre de fuente a cada cuántos minutos sondearla; sale del
    registro (`FeedSpec.poll_interval_minutes`), así que sumar una fuente de
    cadencia corta no toca este archivo.

    `now_fn`/`sleep_fn`/`max_iterations` se inyectan para que el test pueda
    simular días enteros en milisegundos.

    Una corrida que falla no corta el bucle: se registra y se espera a la
    siguiente. Un scheduler que se muere ante el primer error deja de monitorear
    justo cuando más falta hace.
    """
    intervalos = dict(polls or {})
    # El primer sondeo recién a un intervalo: al arrancar ya corrió (o va a
    # correr) la corrida completa, y sondear encima sería duplicar el request.
    ahora = now_fn()
    proximos = {f: ahora + timedelta(minutes=m) for f, m in intervalos.items() if m > 0}

    iteraciones = 0
    while max_iterations is None or iteraciones < max_iterations:
        ahora = now_fn()
        evento = plan_next(ahora, daily_at, proximos)
        espera = max((evento.at - ahora).total_seconds(), 0.0)
        que = (
            "corrida completa"
            if evento.is_full_run
            else f"sondeo de {', '.join(evento.feeds or ())}"
        )
        # Fecha completa y en hora local: sin la fecha, mirando el log no se
        # distingue lo de hoy de lo de la semana pasada.
        logger.info(
            "Próximo: %s el %s (en %.0f s)",
            que,
            evento.at.astimezone().strftime(FORMATO_FECHA),
            espera,
        )
        sleep_fn(espera)

        try:
            reporte = run_once(only=evento.feeds)
            logger.info(
                "%s terminada: %d traídos, %d relevantes AR, %d nuevos%s",
                que.capitalize(),
                reporte.total_fetched,
                reporte.total_matched,
                reporte.total_new,
                f", fuentes caídas: {', '.join(reporte.failed_sources)}"
                if reporte.failed_sources
                else "",
            )
        except Exception:
            logger.exception("La corrida falló entera; se espera a la próxima.")

        # Se reprograma SIEMPRE, haya andado o no: una fuente caída no puede
        # quedar fuera del ciclo hasta el próximo reinicio.
        despues = now_fn()
        if evento.is_full_run:
            # La corrida completa ya trajo todas las fuentes: los sondeos
            # arrancan de nuevo desde acá y no se apilan justo detrás.
            for f, m in intervalos.items():
                if m > 0:
                    proximos[f] = despues + timedelta(minutes=m)
        else:
            for f in evento.feeds or ():
                proximos[f] = despues + timedelta(minutes=intervalos[f])

        iteraciones += 1

    return iteraciones
