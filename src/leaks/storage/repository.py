"""Adaptador de persistencia sobre SQLAlchemy.

Implementa el puerto `FindingRepository`. El pipeline depende del puerto, no de
esta clase: cambiar de motor no obliga a reescribir el core.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session, sessionmaker

from leaks.domain.models import (
    SEVERITY_RANK,
    ArMatchReason,
    Finding,
    LeakType,
    Severity,
    SourceRunResult,
)
from leaks.storage.models import FindingRow, SourceRunRow, SourceStateRow
from leaks.storage.session import session_scope


def _as_utc(value: datetime) -> datetime:
    """SQLite no guarda offset: al leer, reponemos el UTC que escribimos."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class SqlAlchemyFindingRepository:
    """Persistencia idempotente de hallazgos."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Hallazgos ----------------------------------------------------------

    def upsert_many(self, findings: Sequence[Finding]) -> int:
        """Inserta los nuevos y refresca `last_seen_at` de los ya conocidos.

        Devuelve solo la cantidad de **nuevos**, que es lo que hace que correr
        el pipeline dos veces seguidas reporte 0 la segunda vez.
        """
        if not findings:
            return 0

        # Dedup dentro del propio lote: un mismo hallazgo puede venir repetido
        # en la misma respuesta del feed (p. ej. índice global + por país).
        unique: dict[str, Finding] = {f.dedup_hash: f for f in findings}
        now = datetime.now(UTC)
        inserted = 0

        with session_scope(self._session_factory) as session:
            existing = set(
                session.scalars(
                    select(FindingRow.dedup_hash).where(FindingRow.dedup_hash.in_(list(unique)))
                ).all()
            )

            for dedup_hash, finding in unique.items():
                if dedup_hash in existing:
                    session.execute(
                        update(FindingRow)
                        .where(FindingRow.dedup_hash == dedup_hash)
                        .values(last_seen_at=now)
                    )
                    continue
                session.add(self._to_row(finding, now))
                inserted += 1

        return inserted

    @staticmethod
    def _to_row(finding: Finding, now: datetime) -> FindingRow:
        return FindingRow(
            dedup_hash=finding.dedup_hash,
            source=finding.source,
            leak_type=str(finding.leak_type),
            victim_name=finding.victim_name,
            victim_domain=finding.victim_domain,
            country=finding.country,
            sector=finding.sector,
            actor=finding.actor,
            discovered_at=finding.discovered_at,
            published_at=finding.published_at,
            raw_ref=finding.raw_ref,
            ar_match_reason=[str(r) for r in finding.ar_match_reason],
            ar_match_detail=finding.ar_match_detail or None,
            severity=str(finding.severity),
            description=finding.description,
            first_seen_at=now,
            last_seen_at=now,
        )

    def count(self) -> int:
        """Total de hallazgos persistidos (para tests y métricas)."""
        with session_scope(self._session_factory) as session:
            return len(session.scalars(select(FindingRow.id)).all())

    # -- Alertas -------------------------------------------------------------

    def list_pending_alerts(self, *, min_severity: str, limit: int) -> list[Finding]:
        """Hallazgos que llegan al umbral y todavía no se avisaron.

        El criterio es `alerted_at IS NULL`, no "insertado en esta corrida": si
        un envío falla, el hallazgo sigue pendiente y se reintenta en la
        corrida siguiente en vez de perderse.
        """
        piso = SEVERITY_RANK.get(min_severity.lower(), 0)
        alcanzan = [s for s, rango in SEVERITY_RANK.items() if rango >= piso]

        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(FindingRow)
                .where(
                    FindingRow.alerted_at.is_(None),
                    FindingRow.severity.in_(alcanzan),
                )
                .order_by(FindingRow.discovered_at.desc())
                .limit(limit)
            ).all()
            return [self._to_finding(f) for f in filas]

    def mark_alerted(self, dedup_hashes: Sequence[str]) -> int:
        """Marca los hallazgos como avisados. Devuelve cuántos marcó."""
        if not dedup_hashes:
            return 0
        now = datetime.now(UTC)
        with session_scope(self._session_factory) as session:
            resultado = cast(
                CursorResult[Any],
                session.execute(
                    update(FindingRow)
                    .where(FindingRow.dedup_hash.in_(list(dedup_hashes)))
                    .values(alerted_at=now)
                ),
            )
            return int(resultado.rowcount or 0)

    @staticmethod
    def _to_finding(row: FindingRow) -> Finding:
        """Reconstruye el modelo de dominio desde la fila."""
        return Finding(
            source=row.source,
            leak_type=LeakType(row.leak_type),
            victim_name=row.victim_name,
            victim_domain=row.victim_domain,
            country=row.country,
            sector=row.sector,
            actor=row.actor,
            discovered_at=_as_utc(row.discovered_at),
            published_at=_as_utc(row.published_at) if row.published_at else None,
            raw_ref=row.raw_ref,
            description=row.description,
            ar_match_reason=tuple(ArMatchReason(r) for r in row.ar_match_reason),
            ar_match_detail=row.ar_match_detail or {},
            severity=Severity(row.severity),
            dedup_hash=row.dedup_hash,
        )

    # -- Telemetría por fuente ----------------------------------------------

    def record_run(self, result: SourceRunResult) -> None:
        with session_scope(self._session_factory) as session:
            session.add(
                SourceRunRow(
                    source=result.source,
                    status=str(result.status),
                    started_at=result.started_at,
                    finished_at=result.finished_at,
                    items_fetched=result.items_fetched,
                    items_matched=result.items_matched,
                    items_persisted=result.items_persisted,
                    # Truncado: el error nunca debe arrastrar un body completo.
                    error=result.error[:500] if result.error else None,
                )
            )

    # -- Cursor incremental --------------------------------------------------

    def get_cursor(self, source: str) -> datetime | None:
        with session_scope(self._session_factory) as session:
            row = session.get(SourceStateRow, source)
            return _as_utc(row.cursor) if row else None

    def set_cursor(self, source: str, value: datetime) -> None:
        now = datetime.now(UTC)
        with session_scope(self._session_factory) as session:
            row = session.get(SourceStateRow, source)
            if row is None:
                session.add(SourceStateRow(source=source, cursor=value, updated_at=now))
                return
            # Nunca retrocede: si una corrida trae datos viejos, el cursor queda.
            if value > _as_utc(row.cursor):
                row.cursor = value
                row.updated_at = now
