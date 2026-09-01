"""Contratos de respuesta de la API.

Son modelos explícitos y no `dict` sueltos: el contrato queda versionado en el
código y en el OpenAPI que publica FastAPI, y ningún campo llega al frontend
por accidente. Todo lo que sale de acá es metadata no sensible.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    """Un hallazgo argentino tal como lo ve el frontend."""

    id: int
    source: str
    leak_type: str
    victim_name: str
    victim_domain: str | None = None
    country: str | None = None
    sector: str | None = None
    actor: str | None = None
    discovered_at: datetime
    published_at: datetime | None = None
    raw_ref: str | None = None
    #: Qué reglas de relevancia dispararon. Es la columna auditable.
    ar_match_reason: list[str] = Field(default_factory=list)
    #: Evidencia por regla (CUIT enmascarado).
    ar_match_detail: dict[str, list[str]] = Field(default_factory=dict)
    severity: str
    description: str | None = None
    #: Cuándo ocurrió el evento (mejor estimación), contra `first_seen_at` que
    #: es cuándo lo vimos. `None` = no se pudo fechar, y se dice.
    occurred_at: datetime | None = None
    #: De dónde salió esa fecha: feed, texto, corroboracion o sin_dato.
    occurred_at_basis: str = "sin_dato"
    #: Entró en la importación inicial de su fuente: histórico que recién
    #: conocemos, no una novedad.
    backfill: bool = False
    #: Referencias a los datos filtrados y a las muestras: `[{url, kind}]`.
    #: El frontend las muestra NO clickeables, para copiar y pegar.
    download_links: list[dict[str, str]] = Field(default_factory=list)
    #: Detalle de exposición por infostealers: qué sistemas se comprometieron,
    #: qué malware y qué tan débiles son las contraseñas. Sin credenciales:
    #: el tier gratuito del proveedor no las devuelve.
    exposure_detail: dict[str, Any] | None = None
    first_seen_at: datetime
    last_seen_at: datetime


class ExportIn(BaseModel):
    """Selección a exportar. Solo ids: el contenido sale de la base, no del cliente."""

    #: Ids de los hallazgos tildados. El tope real lo pone `export_max_findings`;
    #: este acota el cuerpo antes de que llegue a la base.
    ids: list[int] = Field(min_length=1, max_length=5000)


class FindingPage(BaseModel):
    """Página de hallazgos con el total, para paginar del lado del cliente."""

    items: list[FindingOut]
    total: int
    limit: int
    offset: int


class StatsOut(BaseModel):
    """Totales del tablero."""

    total: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    by_sector: dict[str, int] = Field(default_factory=dict)
    by_leak_type: dict[str, int] = Field(default_factory=dict)
    latest_discovered_at: datetime | None = None


class SourceRunOut(BaseModel):
    """Última corrida de una fuente."""

    source: str
    status: str
    started_at: datetime
    finished_at: datetime
    items_fetched: int
    items_matched: int
    items_persisted: int
    error: str | None = None
    #: Tramo que la fuente publicó y no llegamos a ver. Nulo = sin hueco.
    gap_from: datetime | None = None
    gap_to: datetime | None = None


class SourceOut(BaseModel):
    """Un feed del registro, con su política y su última corrida."""

    name: str
    leak_type: str
    enabled: bool
    #: Motivo por el que no corre, si no corre.
    skip_reason: str | None = None
    requires_pii: bool
    license_note: str = ""
    docs_url: str = ""
    tags: list[str] = Field(default_factory=list)
    last_run: SourceRunOut | None = None


class FilterOptions(BaseModel):
    """Valores disponibles para poblar los filtros de la UI."""

    sources: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    leak_types: list[str] = Field(default_factory=list)


class HealthOut(BaseModel):
    """Estado del proceso. La postura de PII se expone para que sea auditable.

    Son **dos cosas distintas** y por eso viajan separadas:

    * `store_pii` — si el proceso puede *persistir* PII cifrada. Viene del
      entorno y no cambia sin reiniciar.
    * `pii_sources_enabled` — si las fuentes que devuelven PII *corren*. Es el
      toggle de la UI, se guarda en la base y cambia en caliente.
    """

    status: str
    store_pii: bool
    #: Estado persistido del toggle de fuentes con PII.
    pii_sources_enabled: bool = False
    findings: int
    sources_ok: int
    sources_failed: int


class EventOut(BaseModel):
    """Una línea de la consola de actividad."""

    id: int
    occurred_at: datetime
    level: str
    kind: str
    source: str | None = None
    message: str
    url: str | None = None
    status_code: int | None = None
    duration_ms: int | None = None
    bytes_received: int | None = None


class EventPage(BaseModel):
    """Lote de eventos nuevos. `last_id` es el cursor del próximo poll."""

    items: list[EventOut] = Field(default_factory=list)
    last_id: int


class EgressOut(BaseModel):
    """IP pública de salida, para verificar que se sale por la VPN correcta."""

    #: `False` si la verificación está apagada por configuración.
    enabled: bool = True
    ip: str | None = None
    #: ISO-2 del país (AR, CL, …).
    country: str | None = None
    country_name: str | None = None
    city: str | None = None
    #: Proveedor/ASN — es lo que delata si estás saliendo por la VPN o no.
    org: str | None = None
    #: Servicio que resolvió la consulta.
    provider: str | None = None
    checked_at: datetime | None = None
    #: `True` si el control de OPSEC bloqueó la operación (salida desde un país
    #: bloqueado, o país indeterminable). No se puede overridear.
    blocked: bool = False
    block_reason: str | None = None


class TelegramChannelOut(BaseModel):
    """Un canal de Telegram bajo vigilancia."""

    id: int
    handle: str
    actor: str | None = None
    kind: str | None = None
    notes: str | None = None
    #: `catalog` (importado) o `user` (dado de alta a mano).
    origin: str = "user"
    enabled: bool = False
    #: Último post procesado. Es el cursor incremental.
    last_post_id: str | None = None
    last_fetch_at: datetime | None = None
    last_error: str | None = None
    #: La vista previa pública. Se muestra como texto, nunca enlazada.
    url: str = ""


class TelegramCountsOut(BaseModel):
    total: int = 0
    enabled: int = 0
    disabled: int = 0
    user: int = 0
    catalog: int = 0


class TelegramOut(BaseModel):
    """Página del listado de canales."""

    items: list[TelegramChannelOut] = Field(default_factory=list)
    counts: TelegramCountsOut = Field(default_factory=TelegramCountsOut)
    total: int = 0
    limit: int = 50
    offset: int = 0


class TelegramChannelIn(BaseModel):
    """Alta de un canal. El handle se normaliza y valida en el servidor."""

    #: Acepta `@x`, `t.me/x` o la URL completa; se normaliza a `x`.
    handle: str = Field(min_length=1, max_length=200)
    actor: str | None = Field(default=None, max_length=128)
    kind: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(default=None, max_length=1000)
    enabled: bool = True


class TelegramBulkIn(BaseModel):
    """Alta masiva desde texto pegado."""

    #: Un canal por línea. Acepta `@x`, `t.me/x` o la URL, y columnas
    #: opcionales `actor, tipo, nota` separadas por coma, punto y coma o tab.
    texto: str = Field(min_length=1, max_length=200_000)
    #: Por defecto entran apagados, como el catálogo: dar de alta 200 canales
    #: no puede convertirse en 200 pedidos en la próxima corrida.
    enabled: bool = False


class LineaRechazadaOut(BaseModel):
    """Una línea que no se pudo leer, con el motivo."""

    numero: int
    contenido: str
    motivo: str


class TelegramBulkOut(BaseModel):
    """Resultado del alta masiva. Dice todo lo que NO entró y por qué."""

    imported: int = 0
    #: Estaban dados de alta y no se tocaron.
    ya_estaban: int = 0
    duplicadas: int = 0
    rechazadas: list[LineaRechazadaOut] = Field(default_factory=list)
    total: int = 0


class TelegramImportOut(BaseModel):
    """Resultado de importar el catálogo público."""

    imported: int = 0
    total: int = 0
    #: Cuántos trae la fuente, para que se note si cambió de tamaño.
    available: int = 0
    note: str = ""


class AdjacentActorOut(BaseModel):
    """Un actor de la sección de adyacencia."""

    actor: str
    victims_total: int
    countries: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    #: Ya golpeó Argentina. Parte la lista en dos poblaciones que no se comparan.
    hit_ar: bool = False
    ar_victims: int = 0
    #: 0-100. Siempre 0 para los confirmados: no se les calcula.
    score: float = 0.0
    #: Cuánto aportó cada componente, más `confianza` (que NO suma puntos).
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    score_prev: float | None = None
    #: Cuánto se movió desde la corrida anterior. `None` la primera vez.
    variacion: float | None = None
    score_updated_at: datetime | None = None


class AdjacencyCoverageOut(BaseModel):
    """Qué tan lejos llega esta sección. Va a la vista, no a un README.

    Sin esto la lista se lee como «las amenazas» cuando es «las que nuestras
    fuentes registran y además dejaron rastro regional».
    """

    #: Actores que golpearon AR habiendo dejado rastro regional antes.
    con_precursor: int = 35
    #: Actores para los que AR fue su primera víctima latinoamericana.
    sin_precursor: int = 30
    #: Percentil mediano del backtest.
    percentil_mediano: int = 93
    #: Días de anticipación medianos entre la primera regional y la primera AR.
    anticipacion_mediana_dias: int = 105
    medido_el: str = "2026-08-18"


class AlertChannelOut(BaseModel):
    """Un canal de alerta y si está listo para usarse."""

    name: str
    configured: bool = False
    #: Variables de entorno que le faltan. Es lo que hay que setear.
    missing: list[str] = Field(default_factory=list)


class AlertItemOut(BaseModel):
    """Una alerta, tal como la consume otro software.

    Es un hallazgo que llega al umbral de severidad. Se devuelve haya sido
    despachado o no: `notified` y `alerted_at` dicen en qué estado está, y el
    consumidor decide.
    """

    id: int
    #: Clave estable del hallazgo. Sirve para deduplicar del lado del consumidor.
    dedup_hash: str
    source: str
    leak_type: str
    victim_name: str
    victim_domain: str | None = None
    country: str | None = None
    sector: str | None = None
    actor: str | None = None
    severity: str
    ar_match_reason: list[str] = Field(default_factory=list)
    #: Cuándo ocurrió el evento. `None` si no se pudo fechar — no se inventa.
    occurred_at: datetime | None = None
    occurred_at_basis: str = "sin_dato"
    discovered_at: datetime
    #: Cuándo lo vimos nosotros. Es el único campo **monótono** y el que hay
    #: que usar para paginar incrementalmente.
    first_seen_at: datetime
    alerted_at: datetime | None = None
    #: Si ya salió por algún canal configurado.
    notified: bool = False
    #: Entró con la importación inicial de su fuente: histórico, no novedad.
    backfill: bool = False
    raw_ref: str | None = None


class AlertFeedOut(BaseModel):
    """Página del feed de alertas para integraciones."""

    items: list[AlertItemOut] = Field(default_factory=list)
    #: Total que coincide con el filtro, no el total de alertas.
    total: int = 0
    limit: int = 50
    offset: int = 0
    #: Por qué campo se filtró y ordenó. Va en la respuesta para que el
    #: consumidor no tenga que asumirlo.
    campo: str = "first_seen"
    min_severity: str = "high"


class AlertStatusOut(BaseModel):
    """Estado de las alertas, para que la UI no mienta por omisión.

    Sin canales configurados el pipeline descarta los avisos en silencio. Este
    endpoint existe para que eso se vea: `pending` con `enabled=false` significa
    que hay hallazgos esperando a nadie.
    """

    enabled: bool = False
    channels: list[AlertChannelOut] = Field(default_factory=list)
    #: Severidad mínima que dispara aviso.
    min_severity: str = "high"
    #: No se avisa de eventos más viejos que esto.
    max_age_days: int = 30
    #: Hallazgos que llegan al umbral y todavía no se avisaron.
    pending: int = 0
    sent_total: int = 0
    last_sent_at: datetime | None = None


class RegionalVictimOut(BaseModel):
    """Una víctima regional de infraestructura crítica."""

    actor: str
    country: str
    victim_name: str
    victim_domain: str | None = None
    #: Sector según la watchlist de SU país, no el rubro que declara el feed.
    sector: str | None = None
    occurred_at: datetime | None = None
    source: str = ""
    #: Si ese actor ya golpeó Argentina. Es lo que convierte la fila en señal.
    actor_hit_ar: bool = False


class AdjacencyOut(BaseModel):
    """La sección completa: perfiles más el alcance declarado."""

    confirmados: list[AdjacentActorOut] = Field(default_factory=list)
    candidatos: list[AdjacentActorOut] = Field(default_factory=list)
    total_confirmados: int = 0
    total_candidatos: int = 0
    victimas_regionales: int = 0
    #: De todas las regionales, cuántas son infraestructura crítica.
    victimas_criticas: int = 0
    #: Las críticas más recientes: la lista corta que sí vale leer.
    criticas: list[RegionalVictimOut] = Field(default_factory=list)
    paises: list[str] = Field(default_factory=list)
    cobertura: AdjacencyCoverageOut = Field(default_factory=AdjacencyCoverageOut)
    limit: int = 50
    offset: int = 0


class WatchlistEntryOut(BaseModel):
    """Una entrada de la watchlist tal como la ve la UI."""

    id: int
    #: `domain` o `keyword`.
    kind: str
    value: str
    sector: str
    label: str
    critical: bool
    #: `False` = deshabilitada: no matchea hasta que se rehabilite.
    enabled: bool
    #: `seed` (vino del YAML base) o `user` (agregada a mano).
    origin: str
    created_at: datetime
    updated_at: datetime


class WatchlistCountsOut(BaseModel):
    """Totales de la watchlist, para el encabezado de la sección."""

    total: int = 0
    enabled: int = 0
    disabled: int = 0
    domains: int = 0
    keywords: int = 0


class WatchlistOut(BaseModel):
    """Página del listado, con totales y los sectores disponibles."""

    items: list[WatchlistEntryOut] = Field(default_factory=list)
    counts: WatchlistCountsOut = Field(default_factory=WatchlistCountsOut)
    sectors: list[str] = Field(default_factory=list)
    #: Total que coincide con el filtro (no el total de la watchlist).
    total: int = 0
    limit: int = 50
    offset: int = 0


class WatchlistEntryIn(BaseModel):
    """Alta de una entrada. El valor se normaliza y valida en el servidor."""

    kind: Literal["domain", "keyword"]
    #: Dominio (acepta URL o `*.foo.gob.ar`, se normaliza) o texto de keyword.
    value: str = Field(min_length=1, max_length=255)
    sector: str = Field(default="sin_sector", max_length=64)
    label: str | None = Field(default=None, max_length=128)
    #: Infraestructura crítica: eleva la severidad de sus hallazgos.
    critical: bool = False


class EnabledIn(BaseModel):
    """Cambio de estado habilitado/deshabilitado."""

    enabled: bool


class RuleOut(BaseModel):
    """Una regla de relevancia argentina y si está aplicando."""

    name: str
    enabled: bool
    description: str = ""


class RulesOut(BaseModel):
    """Estado de las reglas y de las fuentes con PII."""

    rules: list[RuleOut] = Field(default_factory=list)
    #: Si corren las fuentes marcadas como portadoras de PII.
    pii_sources_enabled: bool = False
    #: Si además se puede **persistir** PII (exige clave de cifrado en el entorno).
    pii_storage_available: bool = False
    #: Si esta instancia permite editar reglas y watchlist.
    editing_allowed: bool = True


class RunStateOut(BaseModel):
    """Estado de la corrida disparada a mano."""

    running: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None
    last_error: str | None = None
    #: Hallazgos nuevos de la última corrida manual.
    last_total_new: int | None = None
    #: Motivo si el control de IP de salida la bloqueó.
    last_blocked_reason: str | None = None


class LeakSiteOut(BaseModel):
    """Una ubicación conocida de un sitio de leaks."""

    id: int
    group_name: str
    kind: str
    #: Dominio o dirección .onion. El frontend NO lo enlaza.
    fqdn: str
    title: str | None = None
    available: bool = False
    #: Registros que lo reportaron.
    sources: list[str] = Field(default_factory=list)
    #: Un `first_seen_at` reciente es la señal de "este grupo se mudó".
    first_seen_at: datetime
    last_seen_at: datetime
    last_available_at: datetime | None = None
    #: Cuándo lo revisó el registro de origen. `None` si no lo publica
    #: (ransomware.live no manda marca de tiempo). **No es una verificación
    #: nuestra**: el prototipo no se conecta a estas direcciones.
    checked_at: datetime | None = None
    #: Hallazgos argentinos atribuidos a este grupo. `> 0` = ya golpeó acá.
    ar_findings: int = 0


class LeakSiteCountsOut(BaseModel):
    """Totales del catálogo."""

    total: int = 0
    available: int = 0
    offline: int = 0
    groups: int = 0


class LeakSitePage(BaseModel):
    """Página del catálogo con sus totales."""

    items: list[LeakSiteOut] = Field(default_factory=list)
    counts: LeakSiteCountsOut = Field(default_factory=LeakSiteCountsOut)
    #: Ubicaciones vistas por primera vez en los últimos días.
    recent_moves: list[LeakSiteOut] = Field(default_factory=list)
    total: int = 0
    limit: int = 50
    offset: int = 0
