"""Modelos del dominio.

El núcleo no conoce HTTP, SQLAlchemy ni ningún proveedor: son tipos puros que
viajan entre adapters, relevancia y storage.

Flujo de un hallazgo:

    RawItem            lo que devolvió el feed, tal cual (dict opaco)
      -> NormalizedItem   el adapter lo mapea al schema común
      -> Finding          el pipeline le suma relevancia AR, severidad y dedup
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from leaks.extraction.dating import DateBasis
from leaks.extraction.downloads import DownloadLink
from leaks.extraction.exposure import ExposureDetail


class LeakType(StrEnum):
    """Naturaleza del hallazgo."""

    RANSOMWARE = "ransomware"
    INFOSTEALER = "infostealer"
    FORUM_POST = "forum_post"
    PASTE = "paste"
    REPO_SECRET = "repo_secret"  # nosec B105 — es un tipo de hallazgo, no una clave


class Severity(StrEnum):
    """Severidad derivada por nosotros — nunca la que declare el feed."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Orden de severidad, de menor a mayor. Sirve para comparar contra el umbral
#: de alertas: `SEVERITY_RANK[s] >= SEVERITY_RANK[umbral]`.
SEVERITY_RANK: dict[str, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class ArMatchReason(StrEnum):
    """Qué regla de relevancia argentina disparó.

    Se persiste la lista completa: es lo que hace auditable la capa y permite
    tunear falsos positivos sin adivinar.
    """

    WATCHLIST = "watchlist"
    TLD_AR = "tld_ar"
    COUNTRY_AR = "country_ar"
    CUIT_VALID = "cuit_valid"
    KEYWORD = "keyword"


class RawItem(BaseModel):
    """Un item crudo del feed, antes de normalizar."""

    model_config = ConfigDict(frozen=True)

    source: str
    payload: dict[str, Any]


class NormalizedItem(BaseModel):
    """Item mapeado al schema común, todavía sin relevancia ni dedup.

    `description` y `title_text` son las superficies de texto libre que la capa
    de privacidad tiene que revisar antes de que esto llegue a la DB.
    """

    model_config = ConfigDict(frozen=True)

    source: str
    leak_type: LeakType
    victim_name: str
    victim_domain: str | None = None
    country: str | None = None
    sector: str | None = None
    actor: str | None = None
    discovered_at: datetime
    published_at: datetime | None = None
    raw_ref: str | None = None
    description: str | None = None
    #: Referencias a los datos filtrados (magnet, torrent, file hosts) y a las
    #: muestras. Se guardan como referencia; nunca se descarga el contenido.
    download_links: tuple[DownloadLink, ...] = ()
    #: Cuándo ocurrió el evento, no cuándo lo vimos. `None` = no se pudo
    #: fechar, y eso se dice: nunca se rellena con la fecha de la consulta.
    occurred_at: datetime | None = None
    #: Detalle de exposición por infostealers: qué sistemas se comprometieron,
    #: si fueron de empleados o de usuarios, qué malware. Metadata, sin PII.
    exposure: ExposureDetail | None = None

    @field_validator("discovered_at", "published_at", "occurred_at")
    @classmethod
    def _require_aware_utc(cls, value: datetime | None) -> datetime | None:
        """El borde decide: acá adentro todo es aware en UTC, sin excepción."""
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("las fechas deben ser timezone-aware (UTC)")
        return value

    @field_validator("victim_domain")
    @classmethod
    def _normalize_domain(cls, value: str | None) -> str | None:
        """Normaliza el dominio para que el dedup y el match sean estables."""
        if not value:
            return None
        domain = value.strip().lower()
        for prefix in ("https://", "http://"):
            domain = domain.removeprefix(prefix)
        domain = domain.split("/", 1)[0].split(":", 1)[0]
        domain = domain.removeprefix("www.").rstrip(".")
        return domain or None


class Finding(NormalizedItem):
    """Hallazgo listo para persistir: item normalizado + veredicto AR."""

    ar_match_reason: tuple[ArMatchReason, ...] = Field(min_length=1)
    #: Evidencia de cada regla (qué dominio, qué keyword). Es lo que hace
    #: tuneables los falsos positivos sin tener que reproducir el run.
    #: Los CUIT van enmascarados: el número completo sería PII.
    ar_match_detail: dict[str, list[str]] = Field(default_factory=dict)
    severity: Severity
    dedup_hash: str
    #: De dónde salió `occurred_at`, para poder auditar la estimación.
    occurred_at_basis: DateBasis = DateBasis.SIN_DATO
    #: El hallazgo entró en la importación inicial de su fuente: es histórico
    #: que recién conocemos, no una novedad. No dispara alertas.
    backfill: bool = False


class EventLevel(StrEnum):
    """Severidad de una línea de la consola de actividad."""

    INFO = "info"
    WARN = "warn"
    ERROR = "error"


class EventKind(StrEnum):
    """Qué está pasando. La consola del frontend colorea según esto."""

    RUN_START = "run_start"
    RUN_DONE = "run_done"
    SOURCE_START = "source_start"
    SOURCE_DONE = "source_done"
    SOURCE_FAILED = "source_failed"
    SOURCE_SKIPPED = "source_skipped"
    SOURCE_GAP = "source_gap"
    HTTP_REQUEST = "http_request"
    HTTP_RETRY = "http_retry"
    RETENTION = "retention"
    EGRESS = "egress"
    EGRESS_BLOCKED = "egress_blocked"
    ALERT = "alert"
    SITE_CATALOG = "site_catalog"
    ADJACENCY = "adjacency"


class RunEvent(BaseModel):
    """Una línea de actividad del pipeline.

    Es lo que alimenta la consola del frontend: a qué sitio se le pegó, qué
    respondió y cuánto tardó.

    NO lleva PII ni contenido de los feeds: solo URL, código de estado y
    conteos. El `message` se trunca y nunca incluye el body de una respuesta.
    """

    model_config = ConfigDict(frozen=True)

    occurred_at: datetime
    level: EventLevel = EventLevel.INFO
    kind: EventKind
    source: str | None = None
    message: str
    url: str | None = None
    status_code: int | None = None
    duration_ms: int | None = None
    bytes_received: int | None = None


class SourceRunStatus(StrEnum):
    """Resultado de correr un feed dentro de un run."""

    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"
    #: No se consultó por el control de IP de salida.
    BLOCKED = "blocked"


class SourceRunResult(BaseModel):
    """Telemetría por feed de una corrida.

    Es lo que hace visible que "un feed caído no tumba el run": cada fuente
    reporta su propio resultado y el frontend lo muestra.
    """

    model_config = ConfigDict(frozen=True)

    source: str
    status: SourceRunStatus
    started_at: datetime
    finished_at: datetime
    items_fetched: int = 0
    items_matched: int = 0
    items_persisted: int = 0
    error: str | None = None
    #: Tramo que la fuente publicó y nosotros no llegamos a ver: va del cursor
    #: anterior a lo más viejo que trajo esta corrida. Se registra en vez de
    #: perderse en silencio — una pérdida conocida y fechada se puede auditar;
    #: una invisible parece "no hubo novedades".
    gap_from: datetime | None = None
    gap_to: datetime | None = None

    @property
    def has_gap(self) -> bool:
        return self.gap_from is not None and self.gap_to is not None
