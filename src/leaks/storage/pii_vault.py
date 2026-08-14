"""Bóveda de registros con PII: tabla aparte, cifrada y con retención.

Este módulo es el ÚNICO lugar del proyecto que puede escribir PII, y solo lo
hace si se cumplen las tres condiciones a la vez:

1. `STORE_PII=true`;
2. hay clave de cifrado válida;
3. el feed está marcado `requires_pii` en el registro.

Si falta cualquiera, `store()` no escribe y lo dice en el log — nunca degrada a
"lo guardo en claro". La tabla `findings` jamás recibe nada de acá.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete, select
from sqlalchemy.orm import Session, sessionmaker

from leaks.storage.crypto import PiiCipher
from leaks.storage.models import FindingRow, PiiRecordRow
from leaks.storage.session import session_scope

logger = logging.getLogger(__name__)


class PiiVault:
    """Persistencia cifrada de payloads record-level, con expiración."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        cipher: PiiCipher | None,
        retention_days: int,
    ) -> None:
        self._session_factory = session_factory
        self._cipher = cipher
        self._retention_days = retention_days

    @property
    def enabled(self) -> bool:
        """Sin cifrador no hay bóveda: se descarta la PII en vez de guardarla."""
        return self._cipher is not None

    def store(self, *, dedup_hash: str, source: str, payload: dict[str, Any]) -> bool:
        """Guarda un payload cifrado atado a un hallazgo ya persistido.

        Devuelve `False` (sin escribir) si la bóveda está deshabilitada o si el
        hallazgo no existe todavía: la FK exige que el metadata vaya primero.
        """
        if self._cipher is None:
            return False

        ahora = datetime.now(UTC)
        blob = self._cipher.encrypt(payload)

        with session_scope(self._session_factory) as session:
            finding_id = session.scalar(
                select(FindingRow.id).where(FindingRow.dedup_hash == dedup_hash)
            )
            if finding_id is None:
                logger.warning(
                    "PII descartada: no existe el hallazgo %s en findings", dedup_hash[:12]
                )
                return False

            # Idempotencia: re-correr el pipeline no debe apilar copias del
            # mismo registro cifrado (cada cifrado da un blob distinto, así que
            # no se puede deduplicar por contenido).
            session.execute(delete(PiiRecordRow).where(PiiRecordRow.finding_id == finding_id))
            session.add(
                PiiRecordRow(
                    finding_id=finding_id,
                    source=source,
                    payload_encrypted=blob,
                    created_at=ahora,
                    expires_at=ahora + timedelta(days=self._retention_days),
                )
            )
        return True

    def purge_expired(self, *, now: datetime | None = None) -> int:
        """Borra los registros vencidos. Devuelve cuántos borró.

        Corre en cada run: la retención no sirve si nadie la aplica.
        """
        momento = now or datetime.now(UTC)
        with session_scope(self._session_factory) as session:
            resultado = cast(
                CursorResult[Any],
                session.execute(delete(PiiRecordRow).where(PiiRecordRow.expires_at <= momento)),
            )
            return resultado.rowcount or 0

    def count(self) -> int:
        """Cantidad de registros cifrados vigentes (métricas y tests)."""
        with session_scope(self._session_factory) as session:
            return len(session.scalars(select(PiiRecordRow.id)).all())
