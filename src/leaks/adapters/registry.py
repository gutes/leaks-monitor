"""Catálogo declarativo de feeds.

Los feeds son **dato**, no cableado. Sumar una fuente es agregar un `FeedSpec`
acá más la clase que implementa `FeedAdapter`: el runner, la API y el frontend
no se tocan.

El registro es también donde vive la política por fuente: si toca PII, si su
superficie de texto es riesgosa, qué licencia tiene y con qué User-Agent se la
consulta.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from leaks.adapters import (
    dls_monitor,
    hudson_rock,
    mybb_forum,
    ransomlook,
    ransomware_live,
    telegram,
)
from leaks.adapters.http import FeedHttpClient, build_client
from leaks.config import Settings
from leaks.domain.models import LeakType, RunEvent
from leaks.domain.ports import FeedAdapter


@dataclass(frozen=True)
class FeedDeps:
    """Colaboradores que el registro no puede construir por su cuenta.

    El registro solo conoce `Settings`; algunas fuentes necesitan algo que se
    resuelve contra la base (por ejemplo, qué dominios consultar en esta
    corrida). Se inyectan acá en vez de que el registro importe storage, que
    invertiría la dirección de las dependencias.
    """

    #: Dado el nombre de un feed, dominios extra a consultar en esta corrida.
    extra_domains: Callable[[str], Sequence[str]] | None = None
    #: Canales de Telegram habilitados. Van aparte de `extra_domains` porque no
    #: son dominios: son *dónde mirar*, no *qué buscar*.
    channels: Callable[[], Sequence[str]] | None = None
    #: Último post visto por canal, para que la lectura sea incremental.
    channel_cursors: Callable[[], dict[str, str]] | None = None

    def domains_for(self, feed: str) -> tuple[str, ...]:
        if self.extra_domains is None:
            return ()
        return tuple(self.extra_domains(feed))

    def channels_enabled(self) -> tuple[str, ...]:
        return () if self.channels is None else tuple(self.channels())

    def cursors(self) -> dict[str, str]:
        return {} if self.channel_cursors is None else dict(self.channel_cursors())


FeedFactory = Callable[[Settings, FeedHttpClient, FeedDeps], FeedAdapter]


@dataclass(frozen=True)
class FeedSpec:
    """Descriptor de un feed: cómo se construye y bajo qué reglas corre."""

    name: str
    leak_type: LeakType
    factory: FeedFactory
    #: Nota de licencia/términos, visible en el README y en la API.
    license_note: str = ""
    docs_url: str = ""
    #: Si arranca habilitado sin que nadie lo pida explícitamente.
    enabled_by_default: bool = True
    #: El feed devuelve datos record-level con PII: solo corre con STORE_PII=true.
    requires_pii: bool = False
    #: El feed no devuelve PII estructurada, pero su texto libre la roza
    #: (títulos de threads de foro). Fuerza el scrubber más estricto.
    high_pii_surface: bool = False
    #: Atributo de `Settings` con el User-Agent a usar para este feed.
    user_agent_setting: str = "http_user_agent"
    #: El feed expone una ventana de tamaño fijo (los últimos N ítems) y no su
    #: histórico. Habilita la detección de huecos: si lo más viejo que trajo
    #: esta corrida es posterior al cursor, algo pasó por el medio sin que lo
    #: viéramos. NO se activa en fuentes cuyo `fetch` ya filtra por cursor —ahí
    #: lo más viejo siempre es posterior y el hueco sería un falso positivo.
    bounded_window: bool = False
    #: Cada cuántos minutos se sondea la fuente, además de la corrida diaria.
    #: `None` = solo en la corrida diaria. Es para fuentes cuya ventana de
    #: publicación es más corta que un día: si el feed solo expone los últimos
    #: N ítems y el foro los rota en horas, una corrida diaria ve una fracción.
    poll_interval_minutes: int | None = None
    #: Motivo por el que el feed viene apagado, para mostrarlo en la UI.
    disabled_reason: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


def _ransomware_live(_settings: Settings, client: FeedHttpClient, _deps: FeedDeps) -> FeedAdapter:
    return ransomware_live.RansomwareLiveAdapter(client)


def _ransomlook(_settings: Settings, client: FeedHttpClient, _deps: FeedDeps) -> FeedAdapter:
    return ransomlook.RansomLookAdapter(client)


def _dls_monitor(_settings: Settings, client: FeedHttpClient, _deps: FeedDeps) -> FeedAdapter:
    return dls_monitor.DlsMonitorAdapter(client)


def _hudson_rock(settings: Settings, client: FeedHttpClient, deps: FeedDeps) -> FeedAdapter:
    # Los explícitos del entorno más el lote que toque en esta corrida. Sin
    # ninguno de los dos no sale un solo request.
    dominios = (*settings.hudsonrock_domains, *deps.domains_for("hudsonrock"))
    return hudson_rock.HudsonRockAdapter(client, dominios)


def _telegram(_settings: Settings, client: FeedHttpClient, deps: FeedDeps) -> FeedAdapter:
    # Sin canales habilitados no sale un solo pedido: importar un catálogo no
    # puede convertirse en cientos de consultas que nadie pidió.
    return telegram.TelegramChannelAdapter(client, deps.channels_enabled(), cursors=deps.cursors())


def _darkforums(settings: Settings, client: FeedHttpClient, _deps: FeedDeps) -> FeedAdapter:
    return mybb_forum.MyBBForumAdapter(
        client, "darkforums", settings.darkforums_base_urls, fids=settings.darkforums_fids
    )


def _breachforums(settings: Settings, client: FeedHttpClient, _deps: FeedDeps) -> FeedAdapter:
    return mybb_forum.MyBBForumAdapter(
        client, "breachforums", settings.breachforums_base_urls, fids=settings.breachforums_fids
    )


#: Registro inmutable. El orden es el de ejecución del run diario.
FEED_REGISTRY: tuple[FeedSpec, ...] = (
    FeedSpec(
        name="ransomware.live",
        leak_type=LeakType.RANSOMWARE,
        factory=_ransomware_live,
        license_note=ransomware_live.LICENSE_NOTE,
        docs_url="https://api.ransomware.live/v2",
        tags=("ransomware", "metadata"),
    ),
    FeedSpec(
        name="ransomlook",
        leak_type=LeakType.RANSOMWARE,
        factory=_ransomlook,
        license_note=ransomlook.LICENSE_NOTE,
        docs_url="https://www.ransomlook.io/api",
        tags=("ransomware", "metadata"),
    ),
    FeedSpec(
        name="dls-monitor",
        leak_type=LeakType.RANSOMWARE,
        factory=_dls_monitor,
        license_note=dls_monitor.LICENSE_NOTE,
        docs_url="https://github.com/cyberiskvision/dls-monitor",
        tags=("ransomware", "metadata", "historico"),
    ),
    FeedSpec(
        name="darkforums",
        leak_type=LeakType.FORUM_POST,
        factory=_darkforums,
        license_note=(
            "Foro público (MyBB) con sindicación Atom abierta. Se lee solo el índice "
            "de threads; no se entra a los posts ni se descargan adjuntos."
        ),
        docs_url="https://darkforums.ru/syndication.php",
        # Queda gobernado ÚNICAMENTE por el toggle de fuentes con PII: su
        # contenido son volcados de datos. `enabled_by_default=False` lo
        # apagaría por un segundo motivo y el toggle no podría encenderlo.
        enabled_by_default=True,
        requires_pii=True,
        # No se persiste texto libre, y el título se redacta.
        high_pii_surface=True,
        bounded_window=True,
        # Medido el 2026-09-01: los 15 threads del Atom cubrían 3,1 horas. Con
        # una sola corrida diaria se pierde la enorme mayoría de lo publicado.
        # Es un GET por sondeo, así que cerrar el agujero sale casi gratis.
        poll_interval_minutes=120,
        tags=("foro", "pii", "metadata"),
    ),
    FeedSpec(
        name="breachforums",
        leak_type=LeakType.FORUM_POST,
        factory=_breachforums,
        license_note="Foro público (MyBB) con sindicación Atom abierta.",
        docs_url="",
        enabled_by_default=False,
        requires_pii=True,
        high_pii_surface=True,
        bounded_window=True,
        disabled_reason=(
            "sin dominio operativo: los conocidos están incautados (verificado 2026-08-14). "
            "Configurar LEAKS_BREACHFORUMS_BASE_URLS cuando reaparezca."
        ),
        tags=("foro", "pii", "metadata", "sin-dominio"),
    ),
    FeedSpec(
        name="telegram",
        leak_type=LeakType.FORUM_POST,
        factory=_telegram,
        license_note=telegram.LICENSE_NOTE,
        docs_url="https://t.me/s/",
        # Gobernado por el toggle de fuentes con PII, igual que los foros: lo
        # que publican estos canales son volcados de datos. Aun habilitado no
        # consulta nada por su cuenta — hacen falta canales dados de alta, así
        # que son dos puertas explícitas y no una.
        enabled_by_default=True,
        requires_pii=True,
        high_pii_surface=True,
        tags=("telegram", "hacktivismo", "pii", "metadata"),
    ),
    FeedSpec(
        name="hudsonrock",
        leak_type=LeakType.INFOSTEALER,
        factory=_hudson_rock,
        license_note=hudson_rock.LICENSE_NOTE,
        docs_url="https://docs.hudsonrock.com/",
        # Verificado el 2026-08-18: el endpoint responde (el 2026-08-14 daba
        # timeout). Queda gobernado por el toggle de fuentes con PII, igual que
        # los foros. Igual no consulta nada por su cuenta: sin dominios en
        # `LEAKS_HUDSONROCK_DOMAINS` no sale un solo request, así que son dos
        # puertas explícitas —habilitar PII y listar dominios— y no una.
        enabled_by_default=True,
        requires_pii=True,
        tags=("infostealer", "pii"),
    ),
)


def get_spec(name: str) -> FeedSpec | None:
    """Busca un feed por nombre."""
    return next((s for s in FEED_REGISTRY if s.name == name), None)


def resolve_enabled(
    settings: Settings, pii_sources_enabled: bool = False
) -> tuple[tuple[FeedSpec, str | None], ...]:
    """Decide qué feeds corren en esta ejecución.

    Devuelve pares `(spec, motivo_de_salteo)`: si el motivo es `None`, el feed
    corre. Se devuelven también los salteados para que queden registrados en la
    telemetría — un feed que no corrió tiene que ser visible, no invisible.
    """
    seleccion = tuple(settings.enabled_feeds)
    resueltos: list[tuple[FeedSpec, str | None]] = []

    for spec in FEED_REGISTRY:
        if seleccion:
            if spec.name not in seleccion:
                continue
            motivo = None
        elif not spec.enabled_by_default:
            motivo = spec.disabled_reason or "deshabilitado por defecto"
            resueltos.append((spec, motivo))
            continue
        else:
            motivo = None

        # Fail-closed: un feed que devuelve PII solo corre si alguien lo
        # habilitó explícitamente — por entorno (`STORE_PII`) o con el toggle
        # de la UI, que se guarda en la base.
        if spec.requires_pii and not (settings.store_pii or pii_sources_enabled):
            motivo = "requiere habilitar las fuentes con PII"

        resueltos.append((spec, motivo))

    return tuple(resueltos)


def build_adapter(
    spec: FeedSpec,
    settings: Settings,
    emit: Callable[[RunEvent], None] | None = None,
    before_request: Callable[[], None] | None = None,
    deps: FeedDeps | None = None,
) -> tuple[FeedAdapter, FeedHttpClient]:
    """Instancia el adapter con el cliente HTTP que le corresponde.

    El User-Agent sale del registro: los feeds legítimos se identifican (ver
    docs/feeds.md). `emit` es opcional: si viene, el cliente reporta cada
    request para la consola de actividad.
    """
    user_agent = str(getattr(settings, spec.user_agent_setting))
    client = build_client(
        user_agent=user_agent,
        timeout=settings.http_timeout_seconds,
        max_retries=settings.http_max_retries,
        backoff_base=settings.http_backoff_base_seconds,
        rate_limit_delay=settings.http_rate_limit_delay_seconds,
        emit=emit,
        source=spec.name,
        before_request=before_request,
    )
    return spec.factory(settings, client, deps or FeedDeps()), client
