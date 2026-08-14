"""Contratos de respuesta de la API.

Son modelos explícitos y no `dict` sueltos: el contrato queda versionado en el
código y en el OpenAPI que publica FastAPI, y ningún campo llega al frontend
por accidente. Todo lo que sale de acá es metadata no sensible.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

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
    first_seen_at: datetime
    last_seen_at: datetime


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
    """Listado completo con sus totales y los sectores disponibles."""

    items: list[WatchlistEntryOut] = Field(default_factory=list)
    counts: WatchlistCountsOut = Field(default_factory=WatchlistCountsOut)
    sectors: list[str] = Field(default_factory=list)


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
