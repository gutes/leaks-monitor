"""Colector del catálogo de sitios.

Corre dentro de la corrida diaria, después de los feeds. Igual que ellos, va
aislado: un registro caído se anota y se sigue con los demás; el catálogo no
puede costar la corrida.

Pasa por la misma barrera de IP de salida que los feeds — no hay motivo para
que este pedido salga desde una IP bloqueada si los otros no pueden.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence

from leaks.adapters.http import FeedHttpClient
from leaks.sites.registries import REGISTRY_SOURCES, SiteLocation
from leaks.storage.site_repository import LeakSiteRepository, SiteUpsertResult

logger = logging.getLogger(__name__)

RegistrySpec = tuple[str, Callable[[FeedHttpClient], list[SiteLocation]]]


class SiteCatalogCollector:
    """Consolida el catálogo de sitios desde los registros públicos."""

    def __init__(
        self,
        repository: LeakSiteRepository,
        client_factory: Callable[[], FeedHttpClient],
        registries: Sequence[RegistrySpec] = REGISTRY_SOURCES,
    ) -> None:
        self._repository = repository
        self._client_factory = client_factory
        self._registries = list(registries)

    def collect(self) -> tuple[SiteUpsertResult, list[str]]:
        """Trae y consolida. Devuelve el resultado y los registros que fallaron."""
        ubicaciones: list[SiteLocation] = []
        fallidos: list[str] = []

        for nombre, traer in self._registries:
            cliente = self._client_factory()
            try:
                encontradas = traer(cliente)
            except Exception as exc:
                # Un registro caído no puede costar el catálogo entero, ni
                # mucho menos la corrida.
                logger.warning("El registro %s falló: %s", nombre, type(exc).__name__)
                fallidos.append(nombre)
                continue
            finally:
                cliente.close()

            logger.info("%s: %d ubicaciones", nombre, len(encontradas))
            ubicaciones.extend(encontradas)

        return self._repository.upsert_locations(ubicaciones), fallidos
