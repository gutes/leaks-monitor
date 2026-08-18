"""Catálogo declarativo de feeds.

Los feeds son **dato**, no cableado. Sumar una fuente es agregar un `FeedSpec`
acá más la clase que implementa `FeedAdapter`: el runner, la API y el frontend
no se tocan.

El registro es también donde vive la política por fuente: si toca PII, si su
superficie de texto es riesgosa, qué licencia tiene y con qué User-Agent se la
consulta.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from leaks.adapters import (
    dls_monitor,
    hudson_rock,
    mybb_forum,
    ransomlook,
    ransomware_live,
)
from leaks.adapters.http import FeedHttpClient, build_client
from leaks.config import Settings
from leaks.domain.models import LeakType, RunEvent
from leaks.domain.ports import FeedAdapter

FeedFactory = Callable[[Settings, FeedHttpClient], FeedAdapter]


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
    #: Motivo por el que el feed viene apagado, para mostrarlo en la UI.
    disabled_reason: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


def _ransomware_live(_settings: Settings, client: FeedHttpClient) -> FeedAdapter:
    return ransomware_live.RansomwareLiveAdapter(client)


def _ransomlook(_settings: Settings, client: FeedHttpClient) -> FeedAdapter:
    return ransomlook.RansomLookAdapter(client)


def _dls_monitor(_settings: Settings, client: FeedHttpClient) -> FeedAdapter:
    return dls_monitor.DlsMonitorAdapter(client)


def _hudson_rock(settings: Settings, client: FeedHttpClient) -> FeedAdapter:
    return hudson_rock.HudsonRockAdapter(client, settings.hudsonrock_domains)


def _darkforums(settings: Settings, client: FeedHttpClient) -> FeedAdapter:
    return mybb_forum.MyBBForumAdapter(client, "darkforums", settings.darkforums_base_urls)


def _breachforums(settings: Settings, client: FeedHttpClient) -> FeedAdapter:
    return mybb_forum.MyBBForumAdapter(client, "breachforums", settings.breachforums_base_urls)


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
        disabled_reason=(
            "sin dominio operativo: los conocidos están incautados (verificado 2026-08-14). "
            "Configurar LEAKS_BREACHFORUMS_BASE_URLS cuando reaparezca."
        ),
        tags=("foro", "pii", "metadata", "sin-dominio"),
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
    return spec.factory(settings, client), client
