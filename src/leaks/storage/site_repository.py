"""Persistencia del catálogo de sitios de leaks."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, sessionmaker

from leaks.sites.registries import SiteLocation
from leaks.storage.models import LeakSiteRow
from leaks.storage.session import session_scope

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SiteUpsertResult:
    """Qué cambió al consolidar el catálogo."""

    seen: int = 0
    new: int = 0
    #: Ubicaciones nuevas de grupos que ya conocíamos: son las mudanzas.
    moved: tuple[str, ...] = ()


class LeakSiteRepository:
    """Consolida y consulta dónde vive cada sitio de leaks."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Escritura -----------------------------------------------------------

    def upsert_locations(self, locations: list[SiteLocation]) -> SiteUpsertResult:
        """Consolida lo que reportaron los registros.

        Una misma ubicación puede venir de varias fuentes: se guarda una sola
        fila por `(grupo, fqdn)` acumulando de dónde salió. `first_seen_at` no
        se toca nunca una vez puesto — es lo que permite decir "este dominio
        apareció el martes".
        """
        if not locations:
            return SiteUpsertResult()

        ahora = datetime.now(UTC)
        # Dedup dentro del lote: dos registros pueden reportar lo mismo.
        unicas: dict[tuple[str, str], SiteLocation] = {}
        fuentes: dict[tuple[str, str], set[str]] = {}
        for loc in locations:
            clave = (loc.group_name, loc.fqdn)
            previa = unicas.get(clave)
            if previa is None or (loc.available and not previa.available):
                unicas[clave] = loc
            fuentes.setdefault(clave, set()).add(loc.source)

        nuevas = 0
        mudanzas: list[str] = []

        with session_scope(self._session_factory) as session:
            existentes = {
                (fila.group_name, fila.fqdn): fila
                for fila in session.scalars(
                    select(LeakSiteRow).where(LeakSiteRow.group_name.in_({g for g, _ in unicas}))
                ).all()
            }
            grupos_conocidos = {g for g, _ in existentes}

            for clave, loc in unicas.items():
                fila = existentes.get(clave)
                origen = sorted(fuentes[clave])

                if fila is not None:
                    fila.last_seen_at = ahora
                    fila.available = loc.available
                    fila.title = loc.title or fila.title
                    fila.sources = sorted(set(fila.sources) | set(origen))
                    if loc.available:
                        fila.last_available_at = ahora
                    continue

                session.add(
                    LeakSiteRow(
                        group_name=loc.group_name,
                        kind=loc.kind,
                        fqdn=loc.fqdn,
                        title=loc.title,
                        available=loc.available,
                        sources=origen,
                        first_seen_at=ahora,
                        last_seen_at=ahora,
                        last_available_at=ahora if loc.available else None,
                    )
                )
                nuevas += 1
                # Ubicación nueva de un grupo que ya teníamos = se mudó.
                if loc.group_name in grupos_conocidos:
                    mudanzas.append(f"{loc.group_name} → {loc.fqdn}")

        return SiteUpsertResult(seen=len(unicas), new=nuevas, moved=tuple(mudanzas))

    # -- Lectura -------------------------------------------------------------

    @staticmethod
    def _apply(
        stmt: Select[Any], *, kind: str | None, available: bool | None, q: str | None
    ) -> Select[Any]:
        if kind:
            stmt = stmt.where(LeakSiteRow.kind == kind)
        if available is not None:
            stmt = stmt.where(LeakSiteRow.available == available)
        if q:
            patron = "%{}%".format(q.strip().replace("%", r"\%").replace("_", r"\_"))
            stmt = stmt.where(
                LeakSiteRow.group_name.ilike(patron, escape="\\")
                | LeakSiteRow.fqdn.ilike(patron, escape="\\")
            )
        return stmt

    def list_sites(
        self,
        *,
        kind: str | None = None,
        available: bool | None = None,
        q: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[tuple[dict[str, Any], ...], int]:
        """Página del catálogo, con el total del filtro.

        Ordena por `first_seen_at` descendente: lo que apareció recién arriba,
        que es la señal útil.
        """
        with session_scope(self._session_factory) as session:
            total = session.scalar(
                self._apply(
                    select(func.count()).select_from(LeakSiteRow),
                    kind=kind,
                    available=available,
                    q=q,
                )
            )
            filas = session.scalars(
                self._apply(select(LeakSiteRow), kind=kind, available=available, q=q)
                .order_by(LeakSiteRow.first_seen_at.desc(), LeakSiteRow.group_name)
                .limit(limit)
                .offset(offset)
            ).all()
            return tuple(self._to_dict(f) for f in filas), int(total or 0)

    def recent_moves(self, *, days: int = 7, limit: int = 50) -> tuple[dict[str, Any], ...]:
        """Ubicaciones vistas por primera vez en los últimos `days` días."""
        desde = datetime.now(UTC) - timedelta(days=days)
        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(LeakSiteRow)
                .where(LeakSiteRow.first_seen_at >= desde)
                .order_by(LeakSiteRow.first_seen_at.desc())
                .limit(limit)
            ).all()
            return tuple(self._to_dict(f) for f in filas)

    def counts(self) -> dict[str, int]:
        with session_scope(self._session_factory) as session:
            total = session.scalar(select(func.count()).select_from(LeakSiteRow)) or 0
            vivas = (
                session.scalar(
                    select(func.count())
                    .select_from(LeakSiteRow)
                    .where(LeakSiteRow.available.is_(True))
                )
                or 0
            )
            grupos = session.scalar(select(func.count(func.distinct(LeakSiteRow.group_name)))) or 0
            return {
                "total": int(total),
                "available": int(vivas),
                "offline": int(total) - int(vivas),
                "groups": int(grupos),
            }

    @staticmethod
    def _to_dict(row: LeakSiteRow) -> dict[str, Any]:
        def _utc(v: datetime | None) -> datetime | None:
            if v is None:
                return None
            return v if v.tzinfo is not None else v.replace(tzinfo=UTC)

        return {
            "id": row.id,
            "group_name": row.group_name,
            "kind": row.kind,
            "fqdn": row.fqdn,
            "title": row.title,
            "available": row.available,
            "sources": list(row.sources or []),
            "first_seen_at": _utc(row.first_seen_at),
            "last_seen_at": _utc(row.last_seen_at),
            "last_available_at": _utc(row.last_available_at),
        }
