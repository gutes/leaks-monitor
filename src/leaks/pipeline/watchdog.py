"""Vigilancia del propio monitoreo: qué fuentes dejaron de dar señales.

El caso que motivó esto: el pipeline estuvo caído seis días y nadie se enteró.
Cuando volvió, el tablero mostraba fuentes en verde —porque la última corrida
había andado— sin decir en ningún lado que la última corrida era de la semana
pasada. Un monitoreo que se cae en silencio es peor que no tenerlo: da la
tranquilidad de estar mirando.

La lógica vive acá, pura y sin dependencias, para que se pueda testear con un
reloj de mentira en vez de dejar pasar un día real.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class StaleSource:
    """Una fuente que hace demasiado que no da una corrida buena."""

    source: str
    #: Última corrida OK. `None` = no hay ninguna registrada.
    last_ok_at: datetime | None
    silence: timedelta

    @property
    def silence_hours(self) -> float:
        return self.silence.total_seconds() / 3600

    def describe(self) -> str:
        if self.last_ok_at is None:
            return f"{self.source}: sin ninguna corrida exitosa registrada"
        return (
            f"{self.source}: {self.silence_hours:.0f} h sin una corrida buena "
            f"(última: {self.last_ok_at:%Y-%m-%d %H:%M} UTC)"
        )


def stale_sources(
    last_ok: Mapping[str, datetime | None],
    *,
    now: datetime,
    max_silence: timedelta,
) -> tuple[StaleSource, ...]:
    """Fuentes cuyo último éxito quedó fuera del umbral.

    `last_ok` mapea nombre de fuente a su última corrida OK; el valor `None`
    —fuente habilitada que nunca anduvo— también cuenta como silencio, porque
    "nunca anduvo" es exactamente lo que hay que avisar.

    Se mide contra la última corrida **exitosa**, no contra la última corrida a
    secas: una fuente que falla cada hora hace ruido sin traer nada, y con el
    criterio de "hubo corrida" quedaría en verde para siempre.
    """
    limite = now - max_silence
    vencidas = [
        StaleSource(
            source=nombre,
            last_ok_at=cuando,
            silence=(now - cuando) if cuando is not None else max_silence,
        )
        for nombre, cuando in last_ok.items()
        if cuando is None or cuando < limite
    ]
    # Primero la que más silencio acumula: es por dónde empezar a mirar.
    return tuple(sorted(vencidas, key=lambda s: s.silence, reverse=True))


def build_notice(vencidas: Sequence[StaleSource], max_silence: timedelta) -> str:
    """Texto del aviso. Dice el umbral para que se entienda por qué llegó."""
    horas = max_silence.total_seconds() / 3600
    lineas = "\n".join(f"• {v.describe()}" for v in vencidas)
    return (
        f"🔕 Fuentes sin novedades hace más de {horas:.0f} h:\n{lineas}\n\n"
        "El monitoreo puede estar caído. Revisar la pantalla Fuentes."
    )
