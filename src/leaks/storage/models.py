"""Tablas SQLAlchemy 2.0.

Separación deliberada: `findings` es metadata no sensible y es lo único que se
escribe por defecto. `pii_records` es una tabla **aparte**, con el payload
cifrado, y solo existe contenido ahí si `STORE_PII=true`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
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

    #: Detalle de exposición por infostealers: URLs comprometidas, familias de
    #: malware, fortaleza de contraseñas. Metadata agregada, nunca credenciales
    #: (el tier gratuito del proveedor no las devuelve, y no las querríamos).
    exposure_detail: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    #: Enlaces a los datos filtrados y a las muestras: `[{url, kind}]`.
    #: Son referencias, no datos: el prototipo nunca descarga el contenido.
    download_links: Mapped[list[dict[str, str]] | None] = mapped_column(JSON)

    # Trazabilidad del run
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    #: Cuándo ocurrió el evento (mejor estimación), contra `first_seen_at` que
    #: es cuándo lo vimos nosotros. `NULL` = no se pudo fechar, y se muestra
    #: como tal en vez de aparentar una fecha.
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: De dónde salió esa fecha: `feed`, `texto`, `corroboracion`, `sin_dato`.
    occurred_at_basis: Mapped[str | None] = mapped_column(String(16))
    #: Entró en la importación inicial de su fuente: histórico que recién
    #: conocemos. No dispara alertas.
    backfill: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

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
        Index("ix_findings_occurred_at", "occurred_at"),
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


class LeakSiteRow(Base):
    """Dónde vive cada sitio de leaks, y desde cuándo.

    Los grupos de ransomware rotan de dominio permanentemente (bloqueos,
    incautaciones, mudanzas). Los feeds que ya consumimos publican ese catálogo
    con su disponibilidad, así que acá se lo consolida en vez de rastrearlo por
    nuestra cuenta.

    Sirve para dos cosas:

    * **No perder una fuente** cuando se muda.
    * **Señal por sí sola**: un grupo que estrena dominio suele estar por
      publicar.

    Es un catálogo: se registra dónde está cada sitio, **no se lo visita**. Los
    `.onion` de acá no se consultan desde el prototipo.
    """

    __tablename__ = "leak_sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Nombre del grupo o mercado, normalizado en minúsculas.
    group_name: Mapped[str] = mapped_column(String(128), nullable=False)
    #: `ransomware`, `market` o lo que declare el registro de origen.
    kind: Mapped[str] = mapped_column(String(32), default="ransomware", nullable=False)
    #: Dominio o dirección .onion.
    fqdn: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255))
    #: Última disponibilidad informada por el registro de origen.
    available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Qué registros lo reportaron: `["ransomware.live", "dls-monitor"]`.
    sources: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    #: Cuándo lo vimos por primera vez. Un `first_seen_at` reciente es
    #: exactamente la señal de "este grupo se acaba de mudar".
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: Última vez que se lo reportó disponible.
    last_available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Cuándo lo revisó el registro de origen, **según el registro**.
    #: Nosotros no verificamos ninguna de estas direcciones: no nos conectamos
    #: a `.onion`. dls-monitor publica `lastscrape`; ransomware.live no manda
    #: marca de tiempo, así que ahí queda en `NULL` y la UI lo dice.
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("group_name", "fqdn", name="uq_leak_sites_group_fqdn"),
        Index("ix_leak_sites_group", "group_name"),
        Index("ix_leak_sites_first_seen", "first_seen_at"),
        Index("ix_leak_sites_available", "available"),
    )


class RegionalVictimRow(Base):
    """Una víctima de la región. **No es un hallazgo argentino.**

    Vive en su propia tabla y no en `findings` por tres razones concretas, no
    por prolijidad:

    * `findings.dedup_hash` tiene unique global: mezclarlas colisionaría.
    * `Finding.ar_match_reason` exige `min_length=1`. Un hallazgo argentino
      **no puede existir** sin una razón argentina, y estas no la tienen.
    * `queries.stats()` y `list_pending_alerts()` recorren la tabla entera. Con
      una columna `scope` habría que acordarse del filtro en cada consulta, y
      olvidarse una sola vez mezcla los datos en silencio.

    Es insumo del perfil de actor, no algo para mirar de a una: son ~1.500
    filas de empresas que no son argentinas. Metadata solamente.
    """

    __tablename__ = "regional_victims"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Nombre del grupo en minúsculas. `lockbit3` y `lockbit5` cuentan
    #: separado: son campañas distintas y el feed las nombra distinto.
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    #: ISO-3166 alfa-2. Siempre uno del catálogo de `adjacency/countries.py`.
    country: Mapped[str] = mapped_column(String(2), nullable=False)
    victim_name: Mapped[str] = mapped_column(String(512), nullable=False)
    victim_domain: Mapped[str | None] = mapped_column(String(255))
    #: Rubro tal como lo declara el feed, sin normalizar: se usa para medir
    #: afinidad sectorial contra lo que se golpea en Argentina.
    sector: Mapped[str | None] = mapped_column(String(128))
    #: Cuándo ocurrió, con la misma postura que en `findings`: si no se puede
    #: fechar, no se inventa. Sin fecha la víctima no puntúa.
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        # Clave natural. El feed republica lo mismo en cada corrida, así que
        # sin esto la tabla crecería sola en cada pasada.
        UniqueConstraint(
            "actor", "country", "victim_name", "occurred_at", name="uq_regional_victim"
        ),
        Index("ix_regional_victims_actor", "actor"),
        Index("ix_regional_victims_country", "country"),
        Index("ix_regional_victims_occurred", "occurred_at"),
    )


class AdjacentActorRow(Base):
    """El perfil de un actor: el producto de la sección de adyacencia.

    La unidad es el **actor**, no la víctima. Las víctimas regionales son el
    insumo; esto es lo que se mira.

    `hit_ar` parte la tabla en dos poblaciones que no se comparan entre sí:

    * **Confirmados** (`hit_ar=True`): ya golpearon Argentina. No llevan score
      — una probabilidad de que le peguen a AR no significa nada para quien ya
      lo hizo. Se ordenan por actividad reciente.
    * **Candidatos** (`hit_ar=False`): todavía no. Son los únicos puntuados.
    """

    __tablename__ = "adjacent_actors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    victims_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Códigos de país donde tiene víctimas: `["BR", "CL"]`.
    countries: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Ya golpeó Argentina. Se deriva de `findings`, que es donde vive eso.
    hit_ar: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ar_victims: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: 0-100. Siempre 0 para los confirmados: no se les calcula.
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    #: Cuánto aportó cada componente, más la confianza. Es lo que hace al
    #: número discutible en vez de un veredicto opaco.
    score_breakdown: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False)
    #: El score de la corrida anterior. Es lo que hace el score *vivo*: permite
    #: mostrar la variación y alertar por salto, no solo por umbral absoluto.
    score_prev: Mapped[float | None] = mapped_column(Float)
    score_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Última vez que se avisó por este actor, para no repetir el aviso.
    alerted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_adjacent_actors_score", "score"),
        Index("ix_adjacent_actors_hit_ar", "hit_ar"),
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
