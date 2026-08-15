"""Composition root: el único lugar donde se arma el grafo de objetos.

Todo el resto del código depende de abstracciones y recibe sus colaboradores ya
construidos. Acá —y solo acá— se decide qué implementación concreta se usa:
qué base, qué watchlist, si hay bóveda de PII. Eso es lo que permite que los
tests armen el mismo pipeline contra dobles sin tocar el core.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from leaks.adapters.egress import EgressResolver
from leaks.adapters.http import build_client
from leaks.alerts.dispatcher import AlertDispatcher, build_channels
from leaks.config import Settings, get_settings
from leaks.pipeline.egress_guard import EgressBlockedError, EgressGuard
from leaks.pipeline.runner import PipelineRunner
from leaks.relevance.watchlist import Watchlist, get_watchlist
from leaks.sites.collector import SiteCatalogCollector
from leaks.storage.crypto import build_cipher
from leaks.storage.event_sink import SqlAlchemyEventSink
from leaks.storage.pii_vault import PiiVault
from leaks.storage.queries import FindingQueryService
from leaks.storage.repository import SqlAlchemyFindingRepository
from leaks.storage.schema import ensure_schema
from leaks.storage.session import create_db_engine, create_session_factory
from leaks.storage.settings_store import SettingsStore
from leaks.storage.site_repository import LeakSiteRepository
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
    alert_dispatcher: AlertDispatcher
    site_repo: LeakSiteRepository
    pii_vault: PiiVault
    event_sink: SqlAlchemyEventSink
    egress_guard: EgressGuard
    runner: PipelineRunner

    def create_schema(self) -> None:
        """Deja la base al día y siembra la watchlist.

        Corre las migraciones de Alembic: `create_all` a secas creaba las
        tablas nuevas pero nunca agregaba una columna a una tabla existente,
        así que un despliegue viejo arrancaba bien y fallaba en el primer
        `SELECT`. Ver `storage/schema.py`.

        La siembra es idempotente y solo corre si la watchlist está vacía: no
        pisa lo que el investigador haya editado desde la UI.
        """
        ensure_schema(self.engine, self.settings.database_url, self.settings)
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

    # Los canales comparten la barrera de IP de salida: una alerta mandada
    # desde una IP bloqueada también sería tráfico atribuible.
    egress_guard_para_alertas = EgressGuard(
        egress,
        blocked_countries=config.egress_blocked_countries,
        block_on_unknown=config.egress_block_on_unknown,
    )

    def _cliente_de_alertas() -> Any:
        def barrera() -> None:
            decision = egress_guard_para_alertas.evaluate()
            if not decision.allowed:
                raise EgressBlockedError(decision.reason)

        return build_client(
            user_agent=config.http_user_agent,
            timeout=config.http_timeout_seconds,
            max_retries=config.http_max_retries,
            backoff_base=config.http_backoff_base_seconds,
            rate_limit_delay=0,
            before_request=barrera,
        )

    site_repo = LeakSiteRepository(session_factory)
    # El colector usa la misma barrera de salida que los feeds: no hay motivo
    # para que este pedido salga desde una IP bloqueada si los otros no pueden.
    site_collector = SiteCatalogCollector(site_repo, _cliente_de_alertas)

    alert_dispatcher = AlertDispatcher(build_channels(config, _cliente_de_alertas))
    if alert_dispatcher.enabled:
        logger.info("Canales de alerta activos: %s", ", ".join(alert_dispatcher.channel_names))
    else:
        logger.info("Sin canales de alerta configurados (ver .env.example)")

    egress_guard = EgressGuard(
        egress,
        blocked_countries=config.egress_blocked_countries,
        block_on_unknown=config.egress_block_on_unknown,
    )

    runner = PipelineRunner(
        repository=repository,
        watchlist=watchlist,
        settings=config,
        alert_dispatcher=alert_dispatcher,
        site_collector=site_collector,
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
        alert_dispatcher=alert_dispatcher,
        site_repo=site_repo,
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
