"""Canales de Telegram bajo vigilancia: alta, baja, estado y cursor."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from leaks.adapters.telegram import normalizar_handle
from leaks.storage.models import TelegramChannelRow
from leaks.storage.session import session_scope

logger = logging.getLogger(__name__)

ORIGEN_CATALOGO = "catalog"
ORIGEN_USUARIO = "user"


class TelegramValidationError(ValueError):
    """El handle no es un canal público legible."""


@dataclass(frozen=True)
class TelegramChannel:
    """Un canal tal como lo ve la API."""

    id: int
    handle: str
    actor: str | None
    kind: str | None
    notes: str | None
    origin: str
    enabled: bool
    last_post_id: str | None
    last_fetch_at: datetime | None
    last_error: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "handle": self.handle,
            "actor": self.actor,
            "kind": self.kind,
            "notes": self.notes,
            "origin": self.origin,
            "enabled": self.enabled,
            "last_post_id": self.last_post_id,
            "last_fetch_at": self.last_fetch_at,
            "last_error": self.last_error,
            "url": f"https://t.me/s/{self.handle}",
        }


def _to_channel(fila: TelegramChannelRow) -> TelegramChannel:
    return TelegramChannel(
        id=fila.id,
        handle=fila.handle,
        actor=fila.actor,
        kind=fila.kind,
        notes=fila.notes,
        origin=fila.origin,
        enabled=bool(fila.enabled),
        last_post_id=fila.last_post_id,
        last_fetch_at=fila.last_fetch_at,
        last_error=fila.last_error,
    )


class TelegramChannelRepository:
    """CRUD de canales, más el cursor que hace incremental la lectura."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Lectura -------------------------------------------------------------

    def list_channels(
        self,
        *,
        enabled: bool | None = None,
        origin: str | None = None,
        q: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> tuple[TelegramChannel, ...]:
        with session_scope(self._session_factory) as session:
            stmt = self._filtrar(select(TelegramChannelRow), enabled, origin, q)
            stmt = stmt.order_by(TelegramChannelRow.enabled.desc(), TelegramChannelRow.handle)
            if limit is not None:
                stmt = stmt.limit(limit).offset(offset)
            return tuple(_to_channel(f) for f in session.scalars(stmt).all())

    def count_channels(
        self, *, enabled: bool | None = None, origin: str | None = None, q: str | None = None
    ) -> int:
        with session_scope(self._session_factory) as session:
            stmt = self._filtrar(
                select(func.count()).select_from(TelegramChannelRow), enabled, origin, q
            )
            return int(session.scalar(stmt) or 0)

    @staticmethod
    def _filtrar(stmt: Any, enabled: bool | None, origin: str | None, q: str | None) -> Any:
        if enabled is not None:
            stmt = stmt.where(TelegramChannelRow.enabled == enabled)
        if origin:
            stmt = stmt.where(TelegramChannelRow.origin == origin)
        if q:
            patron = "%{}%".format(q.strip().replace("%", r"\%").replace("_", r"\_"))
            stmt = stmt.where(
                TelegramChannelRow.handle.ilike(patron, escape="\\")
                | TelegramChannelRow.actor.ilike(patron, escape="\\")
            )
        return stmt

    def counts(self) -> dict[str, int]:
        with session_scope(self._session_factory) as session:
            total = session.scalar(select(func.count()).select_from(TelegramChannelRow)) or 0
            activos = (
                session.scalar(
                    select(func.count())
                    .select_from(TelegramChannelRow)
                    .where(TelegramChannelRow.enabled.is_(True))
                )
                or 0
            )
            manuales = (
                session.scalar(
                    select(func.count())
                    .select_from(TelegramChannelRow)
                    .where(TelegramChannelRow.origin == ORIGEN_USUARIO)
                )
                or 0
            )
            return {
                "total": int(total),
                "enabled": int(activos),
                "disabled": int(total) - int(activos),
                "user": int(manuales),
                "catalog": int(total) - int(manuales),
            }

    def enabled_handles(self) -> tuple[str, ...]:
        """Los que se consultan en esta corrida. Sin habilitados, cero pedidos."""
        with session_scope(self._session_factory) as session:
            filas = session.scalars(
                select(TelegramChannelRow.handle).where(TelegramChannelRow.enabled.is_(True))
            ).all()
        return tuple(filas)

    def cursors(self) -> dict[str, str]:
        """Último post visto por canal, para no reprocesar la página entera."""
        with session_scope(self._session_factory) as session:
            filas = session.execute(
                select(TelegramChannelRow.handle, TelegramChannelRow.last_post_id).where(
                    TelegramChannelRow.last_post_id.is_not(None)
                )
            ).all()
        return {h: c for h, c in filas if c}

    # -- Escritura -----------------------------------------------------------

    def add(
        self,
        handle: str,
        *,
        actor: str | None = None,
        kind: str | None = None,
        notes: str | None = None,
        enabled: bool = True,
        origin: str = ORIGEN_USUARIO,
    ) -> TelegramChannel:
        """Da de alta un canal. Rechaza lo que no se pueda leer en público."""
        limpio = normalizar_handle(handle)
        if limpio is None:
            raise TelegramValidationError(
                "No es un canal público de Telegram. Las invitaciones a grupos privados "
                "(t.me/+…) no se pueden leer sin una cuenta, y este prototipo no usa una."
            )

        ahora = datetime.now(UTC)
        with session_scope(self._session_factory) as session:
            fila = session.scalar(
                select(TelegramChannelRow).where(TelegramChannelRow.handle == limpio)
            )
            if fila is not None:
                # Re-alta: se actualiza lo que venga y se respeta lo ya cargado.
                fila.actor = actor or fila.actor
                fila.kind = kind or fila.kind
                fila.notes = notes or fila.notes
                fila.enabled = enabled
                # Si lo da de alta una persona, pasa a ser suyo aunque haya
                # llegado con el catálogo: el filtro "cargados a mano" quiere
                # decir "los que decidí yo", y este ahora lo es.
                if origin == ORIGEN_USUARIO:
                    fila.origin = ORIGEN_USUARIO
                fila.updated_at = ahora
                session.flush()
                return _to_channel(fila)

            nueva = TelegramChannelRow(
                handle=limpio,
                actor=actor,
                kind=kind,
                notes=notes,
                origin=origin,
                enabled=enabled,
                created_at=ahora,
                updated_at=ahora,
            )
            session.add(nueva)
            session.flush()
            return _to_channel(nueva)

    def set_enabled(self, channel_id: int, enabled: bool) -> TelegramChannel | None:
        with session_scope(self._session_factory) as session:
            fila = session.get(TelegramChannelRow, channel_id)
            if fila is None:
                return None
            fila.enabled = enabled
            fila.updated_at = datetime.now(UTC)
            session.flush()
            return _to_channel(fila)

    def remove(self, channel_id: int) -> bool:
        with session_scope(self._session_factory) as session:
            fila = session.get(TelegramChannelRow, channel_id)
            if fila is None:
                return False
            session.delete(fila)
            return True

    def save_cursors(self, cursores: dict[str, str]) -> None:
        """Guarda el último post visto por canal, al final de la corrida."""
        if not cursores:
            return
        ahora = datetime.now(UTC)
        with session_scope(self._session_factory) as session:
            for fila in session.scalars(
                select(TelegramChannelRow).where(TelegramChannelRow.handle.in_(list(cursores)))
            ).all():
                fila.last_post_id = cursores[fila.handle]
                fila.last_fetch_at = ahora
                fila.last_error = None
                fila.updated_at = ahora

    def save_errors(self, errores: dict[str, str]) -> None:
        """Anota por qué un canal no aportó nada.

        Sin esto un canal muerto se ve igual que uno sin novedades, y el
        investigador no se entera nunca de que está vigilando humo.
        """
        if not errores:
            return
        ahora = datetime.now(UTC)
        with session_scope(self._session_factory) as session:
            for fila in session.scalars(
                select(TelegramChannelRow).where(TelegramChannelRow.handle.in_(list(errores)))
            ).all():
                fila.last_error = errores[fila.handle][:255]
                fila.last_fetch_at = ahora
                fila.updated_at = ahora

    def import_many(self, canales: Iterable[dict[str, Any]], *, enabled: bool = False) -> int:
        """Importa un catálogo. Deshabilitados salvo que se pida lo contrario.

        Nunca pisa lo que el investigador ya tocó: un canal que ya existe se
        deja como está, incluido su estado.
        """
        ahora = datetime.now(UTC)
        nuevos = 0
        with session_scope(self._session_factory) as session:
            existentes = {h for (h,) in session.execute(select(TelegramChannelRow.handle)).all()}
            vistos: set[str] = set()
            for entrada in canales:
                limpio = normalizar_handle(str(entrada.get("handle") or ""))
                if limpio is None or limpio in existentes or limpio in vistos:
                    continue
                vistos.add(limpio)
                session.add(
                    TelegramChannelRow(
                        handle=limpio,
                        actor=entrada.get("actor") or None,
                        kind=entrada.get("kind") or None,
                        notes=entrada.get("notes") or None,
                        origin=ORIGEN_CATALOGO,
                        enabled=enabled,
                        created_at=ahora,
                        updated_at=ahora,
                    )
                )
                nuevos += 1
        return nuevos

    def seed(self, canales: Sequence[dict[str, Any]]) -> int:
        """Siembra inicial. Solo corre si la tabla está vacía."""
        with session_scope(self._session_factory) as session:
            if session.scalar(select(func.count()).select_from(TelegramChannelRow)):
                return 0
        return self.import_many(canales, enabled=True)
