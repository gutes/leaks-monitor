"""Lotes rotativos de dominios para las fuentes que consultan de a uno.

El caso concreto es Hudson Rock: consulta **dominio por dominio** contra un
proveedor extranjero. Mandarle la watchlist entera en cada corrida tiene dos
problemas, y ninguno es teórico:

1. **Disclosure.** Cada consulta le revela qué organismo estás vigilando. Con
   173 dominios le entregás el mapa completo de la investigación de una sola
   vez, todos los días.
2. **Tiempo y cortesía.** Medido el 2026-08-18: ~2 s por dominio y timeouts
   intermitentes. 173 dominios son ~6 minutos de corrida martillando un
   endpoint gratuito.

La rotación resuelve las dos: se consulta un lote por corrida y se avanza un
cursor, así se cubre toda la watchlist en unos días sin publicarla de golpe ni
castigar al proveedor. El cursor se guarda en la base, de modo que la cobertura
sobrevive a los reinicios.

Está **apagado por defecto**: derivar dominios de la watchlist es una decisión
del investigador, no algo que pase solo.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from leaks.storage.settings_store import SettingsStore
from leaks.storage.watchlist_repository import KIND_DOMAIN, WatchlistRepository

logger = logging.getLogger(__name__)

#: Clave del cursor en `app_settings`.
CURSOR_KEY = "hudsonrock_watchlist_cursor"


class WatchlistDomainRotator:
    """Devuelve, en cada corrida, el siguiente lote de dominios a consultar."""

    def __init__(
        self,
        watchlist_repo: WatchlistRepository,
        settings_store: SettingsStore,
        *,
        enabled: bool,
        max_per_run: int,
        cursor_key: str = CURSOR_KEY,
    ) -> None:
        self._watchlist = watchlist_repo
        self._settings = settings_store
        self._enabled = enabled
        self._max_per_run = max(0, max_per_run)
        self._cursor_key = cursor_key

    def next_batch(self) -> tuple[str, ...]:
        """Siguiente lote, avanzando el cursor. Vacío si está apagado."""
        if not self._enabled or self._max_per_run == 0:
            return ()

        # Solo dominios habilitados, y ordenados: el orden estable es lo que
        # hace que el cursor signifique algo entre corridas.
        dominios = sorted(
            e.value for e in self._watchlist.list_entries(kind=KIND_DOMAIN, enabled=True)
        )
        if not dominios:
            return ()

        cursor = self._leer_cursor(len(dominios))
        lote = dominios[cursor : cursor + self._max_per_run]

        # Si el lote se pasa del final, se sigue desde el principio: la
        # cobertura es circular, no se corta en el último dominio.
        if len(lote) < self._max_per_run:
            lote += dominios[: self._max_per_run - len(lote)]

        self._settings.set(self._cursor_key, (cursor + self._max_per_run) % len(dominios))
        logger.info("Lote de dominios %d a %d de %d", cursor, cursor + len(lote), len(dominios))
        return tuple(dict.fromkeys(lote))

    def _leer_cursor(self, total: int) -> int:
        crudo = self._settings.get(self._cursor_key, 0)
        try:
            cursor = int(crudo)
        except (TypeError, ValueError):
            cursor = 0
        # La watchlist puede haberse achicado desde la corrida anterior.
        return cursor % total if total else 0

    def for_feed(self, feed: str) -> Sequence[str]:
        """Adaptador a la interfaz que espera `FeedDeps`."""
        return self.next_batch() if feed == "hudsonrock" else ()
