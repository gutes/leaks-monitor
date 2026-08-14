"""Composition root: el único lugar donde se arma el grafo de objetos.

Todo el resto del código depende de abstracciones y recibe sus colaboradores ya
construidos. Acá —y solo acá— se decide qué implementación concreta se usa:
qué base, qué watchlist, si hay bóveda de PII. Eso es lo que permite que los
tests armen el mismo pipeline contra dobles sin tocar el core.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from leaks.adapters.egress import EgressResolver
from leaks.adapters.http import build_client
from leaks.config import Settings, get_settings
from leaks.pipeline.egress_guard import EgressGuard
from leaks.pipeline.runner import PipelineRunner
from leaks.relevance.watchlist import Watchlist, get_watchlist
from leaks.storage.crypto import build_cipher
from leaks.storage.event_sink import SqlAlchemyEventSink
from leaks.storage.models import Base
from leaks.storage.pii_vault import PiiVault
from leaks.storage.queries import FindingQueryService
from leaks.storage.repository import SqlAlchemyFindingRepository
from leaks.storage.session import create_db_engine, create_session_factory
from leaks.storage.settings_store import SettingsStore
from leaks.storage.watchlist_repository import WatchlistRepository

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Application:
    """Objetos ya cableados de una ejecución."""

    settings: Settings
    engine: Engine
    session_factory: sessionmaker[Session]
    watchlist: Watchlist
    watchlist_repo: WatchlistRepository
    settings_store: SettingsStore
    repository: SqlAlchemyFindingRepository
    queries: FindingQueryService
    pii_vault: PiiVault
    event_sink: SqlAlchemyEventSink
    egress_guard: EgressGuard
    runner: PipelineRunner

    def create_schema(self) -> None:
        """Crea las tablas si faltan y siembra la watchlist.

        Alembic sigue siendo la fuente de verdad para migrar una base con
        datos; esto es el atajo para arrancar de cero con un solo comando.

        La siembra es idempotente y solo corre si la watchlist está vacía: no
        pisa lo que el investigador haya editado desde la UI.
        """
        Base.metadata.create_all(self.engine)
        sembradas = self.watchlist_repo.seed_from_yaml(self.settings.watchlist_path)
        if sembradas:
            logger.info("Watchlist inicial cargada: %d entradas", sembradas)


def build_application(settings: Settings | None = None) -> Application:
    """Arma la aplicación completa a partir de la configuración."""
    config = settings or get_settings()

    engine = create_db_engine(config.database_url)
    session_factory = create_session_factory(engine)

    watchlist_repo = WatchlistRepository(session_factory)
    settings_store = SettingsStore(session_factory)
    # Semilla del YAML para poder construir algo aunque la base esté vacía.
    watchlist = get_watchlist(config.watchlist_path)

    repository = SqlAlchemyFindingRepository(session_factory)
    queries = FindingQueryService(session_factory)

    # `build_cipher` devuelve None salvo que STORE_PII=true y haya clave: el
    # vault deshabilitado descarta la PII en vez de escribirla.
    vault = PiiVault(session_factory, build_cipher(config), config.pii_retention_days)
    if config.store_pii:
        logger.warning(
            "STORE_PII=true: se persistirá PII cifrada con retención de %d días.",
            config.pii_retention_days,
        )

    event_sink = SqlAlchemyEventSink(session_factory, config.event_retention_days)

    egress = (
        EgressResolver(
            build_client(
                user_agent=config.http_user_agent,
                timeout=config.http_timeout_seconds,
                max_retries=1,
                backoff_base=config.http_backoff_base_seconds,
                rate_limit_delay=0,
            ),
            providers=config.egress_providers,
            cache_ttl_seconds=config.egress_cache_seconds,
        )
        if config.egress_check_enabled
        else None
    )

    egress_guard = EgressGuard(
        egress,
        blocked_countries=config.egress_blocked_countries,
        block_on_unknown=config.egress_block_on_unknown,
    )

    runner = PipelineRunner(
        repository=repository,
        watchlist=watchlist,
        settings=config,
        pii_vault=vault,
        event_sink=event_sink,
        egress_guard=egress_guard,
        # La watchlist y las reglas se releen en cada corrida: lo que se edita
        # en la UI aplica en la siguiente sin reiniciar nada.
        watchlist_provider=watchlist_repo.build,
        rules_provider=settings_store.enabled_rules,
        pii_sources_provider=settings_store.pii_sources_enabled,
    )

    return Application(
        settings=config,
        engine=engine,
        session_factory=session_factory,
        watchlist=watchlist,
        watchlist_repo=watchlist_repo,
        settings_store=settings_store,
        repository=repository,
        queries=queries,
        pii_vault=vault,
        event_sink=event_sink,
        egress_guard=egress_guard,
        runner=runner,
    )


def configure_logging(level: str) -> None:
    """Logging estructurado y parejo para CLI, scheduler y API."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
