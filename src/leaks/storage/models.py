"""Tablas SQLAlchemy 2.0.

Separación deliberada: `findings` es metadata no sensible y es lo único que se
escribe por defecto. `pii_records` es una tabla **aparte**, con el payload
cifrado, y solo existe contenido ahí si `STORE_PII=true`.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base declarativa del proyecto."""


class FindingRow(Base):
    """Hallazgo argentino: SOLO metadata no sensible.

    Nada de credenciales, contraseñas, emails de personas, cookies, tokens ni
    contenido de dumps. `description` únicamente si pasó el scrubber de PII.
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Identidad / idempotencia
    dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Schema normalizado común
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    leak_type: Mapped[str] = mapped_column(String(32), nullable=False)
    victim_name: Mapped[str] = mapped_column(String(512), nullable=False)
    victim_domain: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(64))
    sector: Mapped[str | None] = mapped_column(String(128))
    actor: Mapped[str | None] = mapped_column(String(128))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_ref: Mapped[str | None] = mapped_column(Text)

    # Veredicto de la capa de relevancia — auditable
    ar_match_reason: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    ar_match_detail: Mapped[dict[str, list[str]] | None] = mapped_column(JSON)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)

    # Texto libre: solo si sobrevivió al scrubber
    description: Mapped[str | None] = mapped_column(Text)

    # Trazabilidad del run
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    #: Cuándo se avisó de este hallazgo. `NULL` = pendiente de alertar.
    #: Es lo que hace que no se alerte dos veces lo mismo, y que una alerta que
    #: falló se reintente en la corrida siguiente en vez de perderse.
    alerted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("dedup_hash", name="uq_findings_dedup_hash"),
        Index("ix_findings_discovered_at", "discovered_at"),
        Index("ix_findings_source", "source"),
        Index("ix_findings_sector", "sector"),
        Index("ix_findings_actor", "actor"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_alerted_at", "alerted_at"),
    )


class SourceRunRow(Base):
    """Telemetría por feed de cada corrida: salud de las fuentes."""

    __tablename__ = "source_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    items_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    items_matched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    items_persisted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Mensaje de error truncado: nunca se vuelca el body de la respuesta acá,
    # podría arrastrar PII o secretos a los logs.
    error: Mapped[str | None] = mapped_column(String(500))

    __table_args__ = (Index("ix_source_runs_source_started", "source", "started_at"),)


class SourceStateRow(Base):
    """Cursor incremental por fuente: hasta dónde llegó la última corrida."""

    __tablename__ = "source_state"

    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    cursor: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WatchlistEntryRow(Base):
    """Una entrada de la watchlist: un dominio o una keyword bajo vigilancia.

    La watchlist vive en la base y no solo en el YAML porque se edita desde la
    UI, y el contenedor corre con el filesystem de solo lectura. El YAML pasa a
    ser la **semilla**: se importa la primera vez y queda como respaldo
    versionado.

    `enabled=False` es una baja lógica: la entrada deja de matchear pero no se
    pierde, y se puede volver a habilitar cuando se quiera.
    """

    __tablename__ = "watchlist_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: `domain` o `keyword`.
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    #: El dominio (cubre subdominios) o el texto de la keyword.
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    sector: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    #: Infraestructura crítica: eleva la severidad del hallazgo.
    critical: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: `seed` (vino del YAML) o `user` (se agregó desde la UI).
    origin: Mapped[str] = mapped_column(String(16), default="user", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        # Un mismo valor no puede estar dos veces con el mismo tipo.
        UniqueConstraint("kind", "value", name="uq_watchlist_kind_value"),
        Index("ix_watchlist_sector", "sector"),
        Index("ix_watchlist_enabled", "enabled"),
    )


class AppSettingRow(Base):
    """Configuración que se cambia en caliente desde la UI.

    Deliberadamente **no** reemplaza al entorno: las credenciales y la clave de
    cifrado siguen viniendo por variable de entorno. Acá viven solo decisiones
    operativas del investigador (qué reglas aplican, si corren las fuentes con
    PII), que necesitan cambiarse sin reiniciar el proceso.
    """

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RunEventRow(Base):
    """Bitácora de actividad del pipeline: lo que muestra la consola del frontend.

    Vive en la base y no solo en el log del proceso porque el pipeline y la API
    corren en procesos (y contenedores) distintos: la base es el canal que ya
    comparten.

    Nunca guarda PII ni contenido de feeds: URL, código de estado y conteos.
    """

    __tablename__ = "run_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    url: Mapped[str | None] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    bytes_received: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        # El frontend pagina por id ascendente desde el último que vio.
        Index("ix_run_events_id_desc", "id"),
        Index("ix_run_events_occurred_at", "occurred_at"),
    )


class PiiRecordRow(Base):
    """Registro con PII, cifrado en reposo. Solo se escribe con STORE_PII=true.

    El payload va como blob cifrado (Fernet); ni el tipo ni el contenido se
    pueden leer sin la clave. `expires_at` implementa la retención configurable.
    """

    __tablename__ = "pii_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_pii_records_finding", "finding_id"),
        Index("ix_pii_records_expires", "expires_at"),
    )
