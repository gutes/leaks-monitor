"""API de solo lectura que alimenta el frontend.

Es deliberadamente chica: cinco endpoints GET y ningún método de escritura. El
pipeline escribe por su lado (CLI/scheduler); la API solo mira. Un endpoint que
dispare una corrida sería una superficie de abuso gratuita en un servicio sin
autenticación.

Sobre autenticación: el prototipo se sirve en `127.0.0.1` y no la trae. Exponer
esto a una red hay que hacerlo detrás de un proxy que autentique — está anotado
en el README y no es un detalle menor: son hallazgos de seguridad de
organismos públicos.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from leaks.adapters.egress import EgressResolver
from leaks.adapters.http import build_client
from leaks.adapters.registry import FEED_REGISTRY, resolve_enabled
from leaks.api.schemas import (
    EgressOut,
    EnabledIn,
    EventOut,
    EventPage,
    FilterOptions,
    FindingOut,
    FindingPage,
    HealthOut,
    RuleOut,
    RulesOut,
    RunStateOut,
    SourceOut,
    SourceRunOut,
    StatsOut,
    WatchlistCountsOut,
    WatchlistEntryIn,
    WatchlistEntryOut,
    WatchlistOut,
)
from leaks.bootstrap import build_application
from leaks.config import Settings, get_settings
from leaks.domain.models import ArMatchReason
from leaks.pipeline.coordinator import RunCoordinator
from leaks.pipeline.egress_guard import EgressGuard
from leaks.storage.queries import FindingFilters, FindingQueryService
from leaks.storage.session import create_db_engine, create_session_factory
from leaks.storage.settings_store import SettingsStore
from leaks.storage.watchlist_repository import (
    WatchlistRepository,
    WatchlistValidationError,
)

logger = logging.getLogger(__name__)

#: Rutas que siguen respondiendo con el bloqueo de OPSEC activo.
#:
#: Son las que hacen falta para *salir* del bloqueo: si se cerrara
#: `/api/egress`, el frontend no tendría cómo enterarse de que ya se puede
#: volver a operar, y el modal quedaría trabado para siempre.
_RUTAS_SIEMPRE_ABIERTAS = ("/api/egress", "/api/health")


def _queries_dep(request: Request) -> FindingQueryService:
    """Servicio de consultas del proceso, guardado en el estado de la app.

    Vive en `app.state` y no en una global para que cada app creada por
    `create_app` (los tests crean varias) tenga la suya.
    """
    servicio = request.app.state.queries
    if not isinstance(servicio, FindingQueryService):  # pragma: no cover — invariante
        # Un `assert` acá desaparecería con `python -O`, justo en producción.
        raise RuntimeError("La app no fue construida con create_app().")
    return servicio


#: Dependencia tipada que inyectan los endpoints.
Queries = Annotated[FindingQueryService, Depends(_queries_dep)]


def build_query_service(settings: Settings) -> FindingQueryService:
    """Servicio de consultas atado a la base configurada."""
    engine = create_db_engine(settings.database_url)
    return FindingQueryService(create_session_factory(engine))


def _watchlist_dep(request: Request) -> WatchlistRepository:
    repo = request.app.state.watchlist_repo
    if not isinstance(repo, WatchlistRepository):  # pragma: no cover — invariante
        raise RuntimeError("La app no fue construida con create_app().")
    return repo


def _settings_store_dep(request: Request) -> SettingsStore:
    store = request.app.state.settings_store
    if not isinstance(store, SettingsStore):  # pragma: no cover — invariante
        raise RuntimeError("La app no fue construida con create_app().")
    return store


WatchlistRepo = Annotated[WatchlistRepository, Depends(_watchlist_dep)]
Store = Annotated[SettingsStore, Depends(_settings_store_dep)]


def create_app(
    settings: Settings | None = None, egress_guard: EgressGuard | None = None
) -> FastAPI:
    """Fábrica de la app.

    Recibe `settings` inyectados para que los tests levanten la API contra una
    base temporal sin tocar variables de entorno globales.

    `egress_guard` se inyecta **solo en tests**: el middleware de bloqueo
    consulta la IP de salida en cada petición, y sin inyectarlo la suite saldría
    a la red. En producción siempre se construye acá adentro, con la
    configuración del proceso.
    """
    config = settings or get_settings()
    engine = create_db_engine(config.database_url)
    session_factory = create_session_factory(engine)
    queries = FindingQueryService(session_factory)

    app = FastAPI(
        title="Monitoreo de leaks — relevancia argentina",
        version="0.1.0",
        summary="Hallazgos de leaks/ransomware con impacto en Argentina. Solo lectura.",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    app.state.queries = queries
    # Se guarda para que los tests puedan sembrar contra la misma base.
    app.state.session_factory = session_factory
    app.state.watchlist_repo = WatchlistRepository(session_factory)
    app.state.settings_store = SettingsStore(session_factory)
    # Coordinador de corridas manuales. Comparte la configuración del proceso,
    # así que el control de IP de salida se le aplica igual que al scheduler.
    app.state.runs = RunCoordinator(build_application(config).runner)

    # Resolver de IP de salida: vive en el estado de la app para que el cache
    # sobreviva entre requests.
    app.state.egress = EgressResolver(
        build_client(
            user_agent=config.http_user_agent,
            timeout=config.http_timeout_seconds,
            max_retries=1,
            backoff_base=config.http_backoff_base_seconds,
            # Sin autolimitación: es un request chico y puntual, no un feed.
            rate_limit_delay=0,
        ),
        providers=config.egress_providers,
        cache_ttl_seconds=config.egress_cache_seconds,
    )
    app.state.egress_guard = egress_guard or EgressGuard(
        app.state.egress if config.egress_check_enabled else None,
        blocked_countries=config.egress_blocked_countries,
        block_on_unknown=config.egress_block_on_unknown,
    )

    # -- Bloqueo de OPSEC a nivel API ---------------------------------------
    #
    # El modal del frontend es la capa visible; esta es la que manda. Estando
    # bloqueado, la API entera deja de responder: una pestaña vieja, un `curl`
    # o un script no pueden seguir operando porque el navegador no vea el modal.
    #
    # Quedan abiertas solo las rutas que hacen falta para *salir* del bloqueo:
    # la que informa la IP de salida y la de salud. Si se cerrara `/api/egress`,
    # el frontend no tendría cómo enterarse de que ya se puede volver.
    @app.middleware("http")
    async def bloquear_si_la_salida_no_esta_permitida(request: Request, call_next: Any) -> Any:
        ruta = request.url.path
        if ruta.startswith("/api/") and not ruta.startswith(_RUTAS_SIEMPRE_ABIERTAS):
            decision = request.app.state.egress_guard.evaluate()
            if not decision.allowed:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "detail": decision.reason,
                        "egress_blocked": True,
                        "country": decision.country,
                    },
                )
        return await call_next(request)

    # -- Hallazgos ----------------------------------------------------------

    @app.get("/api/findings", response_model=FindingPage, tags=["findings"])
    def list_findings(
        queries: Queries,
        source: str | None = None,
        sector: str | None = None,
        severity: str | None = None,
        leak_type: str | None = None,
        actor: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
        limit: Annotated[int, Query(ge=1)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> FindingPage:
        """Lista hallazgos argentinos, del más reciente al más viejo.

        El `limit` se topea contra `api_max_page_size`: todo listado tiene tope,
        también cuando el cliente pide más.
        """
        acotado = min(limit, config.api_max_page_size)
        pagina = queries.list_findings(
            FindingFilters(
                source=source,
                sector=sector,
                severity=severity,
                leak_type=leak_type,
                actor=actor,
                since=since,
                until=until,
                q=q,
            ),
            limit=acotado,
            offset=offset,
        )
        return FindingPage(
            items=[FindingOut.model_validate(i) for i in pagina.items],
            total=pagina.total,
            limit=pagina.limit,
            offset=pagina.offset,
        )

    @app.get("/api/stats", response_model=StatsOut, tags=["findings"])
    def stats(queries: Queries) -> StatsOut:
        """Totales por severidad, fuente, sector y tipo."""
        return StatsOut.model_validate(queries.stats())

    @app.get("/api/filters", response_model=FilterOptions, tags=["findings"])
    def filters(queries: Queries) -> FilterOptions:
        """Valores presentes en la base, para poblar los selectores de la UI."""
        return FilterOptions(
            sources=list(queries.distinct_values("source")),
            sectors=list(queries.distinct_values("sector")),
            severities=list(queries.distinct_values("severity")),
            actors=list(queries.distinct_values("actor")),
            leak_types=list(queries.distinct_values("leak_type")),
        )

    # -- Watchlist ------------------------------------------------------------

    def _require_editing() -> None:
        """Corta si esta instancia no permite editar."""
        if not config.allow_rule_editing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="La edición de reglas está deshabilitada en esta instancia.",
            )

    @app.get("/api/watchlist", response_model=WatchlistOut, tags=["watchlist"])
    def list_watchlist(
        repo: WatchlistRepo,
        kind: str | None = None,
        sector: str | None = None,
        enabled: bool | None = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
        limit: Annotated[int, Query(ge=1)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> WatchlistOut:
        """Todo lo que se está monitoreando: dominios y keywords, con su estado."""
        acotado = min(limit, config.api_max_page_size)
        entradas = repo.list_entries(
            kind=kind, sector=sector, enabled=enabled, q=q, limit=acotado, offset=offset
        )
        return WatchlistOut(
            items=[WatchlistEntryOut.model_validate(e.as_dict()) for e in entradas],
            counts=WatchlistCountsOut.model_validate(repo.counts()),
            sectors=list(repo.sectors()),
            total=repo.count_entries(kind=kind, sector=sector, enabled=enabled, q=q),
            limit=acotado,
            offset=offset,
        )

    @app.post(
        "/api/watchlist",
        response_model=WatchlistEntryOut,
        status_code=status.HTTP_201_CREATED,
        tags=["watchlist"],
    )
    def add_watchlist_entry(repo: WatchlistRepo, payload: WatchlistEntryIn) -> WatchlistEntryOut:
        """Agrega un dominio o una keyword al monitoreo."""
        _require_editing()
        try:
            entrada = repo.add(
                kind=payload.kind,
                value=payload.value,
                sector=payload.sector,
                label=payload.label,
                critical=payload.critical,
            )
        except WatchlistValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc
        return WatchlistEntryOut.model_validate(entrada.as_dict())

    @app.patch("/api/watchlist/{entry_id}", response_model=WatchlistEntryOut, tags=["watchlist"])
    def toggle_watchlist_entry(
        repo: WatchlistRepo, entry_id: int, payload: EnabledIn
    ) -> WatchlistEntryOut:
        """Habilita o deshabilita una entrada.

        Deshabilitar es baja lógica y **persiste**: la entrada deja de matchear
        hasta que se la vuelva a habilitar.
        """
        _require_editing()
        entrada = repo.set_enabled(entry_id, payload.enabled)
        if entrada is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No existe.")
        return WatchlistEntryOut.model_validate(entrada.as_dict())

    @app.delete(
        "/api/watchlist/{entry_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["watchlist"],
    )
    def delete_watchlist_entry(repo: WatchlistRepo, entry_id: int) -> None:
        """Borra una entrada. Para una baja temporal, mejor deshabilitarla."""
        _require_editing()
        if not repo.remove(entry_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No existe.")

    # -- Reglas de relevancia -------------------------------------------------

    @app.get("/api/rules", response_model=RulesOut, tags=["watchlist"])
    def get_rules(store: Store) -> RulesOut:
        """Qué reglas de relevancia argentina están aplicando."""
        return RulesOut(
            rules=[RuleOut.model_validate(r) for r in store.rules_state()],
            pii_sources_enabled=store.pii_sources_enabled(),
            # Persistir PII exige clave en el entorno: el toggle de la UI no
            # puede crearla ni suplirla.
            pii_storage_available=bool(config.store_pii and config.pii_encryption_key),
            editing_allowed=config.allow_rule_editing,
        )

    @app.patch("/api/rules/{rule_name}", response_model=RuleOut, tags=["watchlist"])
    def set_rule(store: Store, rule_name: str, payload: EnabledIn) -> RuleOut:
        """Activa o desactiva una regla de relevancia."""
        _require_editing()
        try:
            regla = ArMatchReason(rule_name)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"Regla desconocida: {rule_name}"
            ) from exc
        store.set_rule_enabled(regla, payload.enabled)
        return RuleOut(
            name=regla.value,
            enabled=payload.enabled,
            description=next(
                (r["description"] for r in store.rules_state() if r["name"] == regla.value), ""
            ),
        )

    @app.patch("/api/settings/pii-sources", response_model=RulesOut, tags=["watchlist"])
    def set_pii_sources(store: Store, payload: EnabledIn) -> RulesOut:
        """Habilita o deshabilita las fuentes que devuelven PII.

        Habilita que esas fuentes **corran**, no que se guarde PII en claro. La
        persistencia sigue exigiendo `LEAKS_STORE_PII=true` y una clave de
        cifrado en el entorno: un toggle de una UI sin autenticación no puede
        crear esa clave ni suplirla.
        """
        _require_editing()
        store.set_pii_sources_enabled(payload.enabled)
        return RulesOut(
            rules=[RuleOut.model_validate(r) for r in store.rules_state()],
            pii_sources_enabled=store.pii_sources_enabled(),
            pii_storage_available=bool(config.store_pii and config.pii_encryption_key),
            editing_allowed=config.allow_rule_editing,
        )

    # -- Corridas manuales ----------------------------------------------------

    @app.post("/api/runs", response_model=RunStateOut, tags=["runs"])
    def trigger_run(request: Request, response: Response) -> RunStateOut:
        """Dispara una corrida del pipeline y vuelve enseguida.

        La corrida sigue en segundo plano; el avance se ve en la consola de
        actividad, que ya se refresca sola.

        No chequea la IP de salida acá a propósito: lo hace el runner, que es la
        única puerta. Disparar a mano no puede saltear el bloqueo.
        """
        coordinador: RunCoordinator = request.app.state.runs
        if not coordinador.trigger():
            # Dos corridas en paralelo sobre la misma SQLite se pisan los
            # cursores y duplican los requests a los feeds.
            response.status_code = status.HTTP_409_CONFLICT
            return RunStateOut.model_validate(coordinador.state.as_dict())

        response.status_code = status.HTTP_202_ACCEPTED
        return RunStateOut.model_validate(coordinador.state.as_dict())

    @app.get("/api/runs/current", response_model=RunStateOut, tags=["runs"])
    def current_run(request: Request) -> RunStateOut:
        """Estado de la corrida manual: si está corriendo y cómo terminó."""
        coordinador: RunCoordinator = request.app.state.runs
        return RunStateOut.model_validate(coordinador.state.as_dict())

    # -- IP de salida ---------------------------------------------------------

    @app.get("/api/egress", response_model=EgressOut, tags=["sources"])
    def egress(request: Request, force: bool = False) -> EgressOut:
        """Desde qué IP pública sale el tráfico, con país y proveedor.

        Sirve para confirmar que se está saliendo por la VPN correcta antes de
        consultar feeds. No manda nada afuera: es un GET a un servicio de eco.
        """
        if not config.egress_check_enabled:
            return EgressOut(enabled=False)

        # El veredicto lo da el mismo guard que usa el pipeline: una sola
        # fuente de verdad para el bloqueo, no dos criterios que se pisen.
        # `force` no es un override: vuelve a preguntar, y solo desbloquea si
        # la IP realmente cambió.
        decision = request.app.state.egress_guard.evaluate(force=force)
        datos = decision.info.as_dict() if decision.info else {}
        return EgressOut(
            enabled=True,
            **datos,
            blocked=not decision.allowed,
            block_reason=None if decision.allowed else decision.reason,
        )

    # -- Consola de actividad -------------------------------------------------

    @app.get("/api/events", response_model=EventPage, tags=["sources"])
    def events(
        queries: Queries,
        after_id: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    ) -> EventPage:
        """Actividad del pipeline posterior a `after_id`.

        Es lo que alimenta la consola: a qué sitio se le pegó, qué respondió y
        cuánto tardó. No incluye PII ni contenido de los feeds.

        El pipeline y la API son procesos distintos (contenedores distintos en
        Docker), así que el canal es la base que ya comparten.
        """
        filas = queries.list_events(after_id=after_id, limit=limit)
        items = [EventOut.model_validate(f) for f in filas]
        return EventPage(items=items, last_id=items[-1].id if items else after_id)

    # -- Salud de las fuentes ------------------------------------------------

    @app.get("/api/sources", response_model=list[SourceOut], tags=["sources"])
    def sources(queries: Queries, store: Store) -> list[SourceOut]:
        """Feeds del registro con su política y el resultado de su última corrida."""
        corridas = {r["source"]: r for r in queries.latest_runs()}
        motivos = {
            spec.name: motivo
            for spec, motivo in resolve_enabled(config, store.pii_sources_enabled())
        }

        salida: list[SourceOut] = []
        for spec in FEED_REGISTRY:
            motivo = motivos.get(spec.name, "no seleccionado en LEAKS_ENABLED_FEEDS")
            ultima = corridas.get(spec.name)
            salida.append(
                SourceOut(
                    name=spec.name,
                    leak_type=str(spec.leak_type),
                    enabled=spec.name in motivos and motivo is None,
                    skip_reason=motivo,
                    requires_pii=spec.requires_pii,
                    license_note=spec.license_note,
                    docs_url=spec.docs_url,
                    tags=list(spec.tags),
                    last_run=SourceRunOut.model_validate(ultima) if ultima else None,
                )
            )
        return salida

    @app.get("/api/health", response_model=HealthOut, tags=["sources"])
    def health(queries: Queries, store: Store) -> HealthOut:
        """Estado del proceso y de la última corrida de cada fuente."""
        corridas = queries.latest_runs()
        return HealthOut(
            status="ok",
            # Se expone a propósito: que la postura de privacidad vigente sea
            # verificable desde afuera, no una promesa del README.
            store_pii=config.store_pii,
            pii_sources_enabled=store.pii_sources_enabled(),
            findings=int(queries.stats()["total"]),
            sources_ok=sum(1 for r in corridas if r["status"] == "ok"),
            sources_failed=sum(1 for r in corridas if r["status"] == "failed"),
        )

    # -- Frontend estático ---------------------------------------------------

    frontend_dir = config.frontend_dir
    if frontend_dir.is_dir():

        @app.get("/", include_in_schema=False)
        def index() -> Any:
            return FileResponse(frontend_dir / "index.html")

        app.mount("/static", StaticFiles(directory=frontend_dir), name="static")
    else:  # pragma: no cover — solo si se despliega el paquete sin el frontend
        logger.warning("No se encontró el frontend en %s; la API queda sin UI", frontend_dir)

    return app
