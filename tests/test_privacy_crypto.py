"""Tests de cifrado, bóveda y retención de PII."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session, sessionmaker

from leaks.config import Settings
from leaks.storage.crypto import PiiCipher, PiiCipherError, build_cipher
from leaks.storage.models import FindingRow, PiiRecordRow
from leaks.storage.pii_vault import PiiVault
from leaks.storage.repository import SqlAlchemyFindingRepository
from tests.conftest import make_finding


@pytest.fixture
def clave() -> str:
    return Fernet.generate_key().decode()


class TestCifrado:
    def test_ida_y_vuelta(self, clave: str) -> None:
        cipher = PiiCipher(clave)
        payload = {"email": "persona@example.com", "password": "hunter2"}
        assert cipher.decrypt(cipher.encrypt(payload)) == payload

    def test_el_blob_no_deja_ver_el_contenido(self, clave: str) -> None:
        blob = PiiCipher(clave).encrypt({"email": "persona@example.com"})
        assert b"persona@example.com" not in blob

    def test_clave_invalida_falla_al_construir(self) -> None:
        """Fail-closed: no se degrada a guardar en claro."""
        with pytest.raises(PiiCipherError):
            PiiCipher("esto-no-es-una-clave-fernet")

    def test_otra_clave_no_puede_descifrar(self, clave: str) -> None:
        blob = PiiCipher(clave).encrypt({"a": 1})
        with pytest.raises(PiiCipherError):
            PiiCipher(Fernet.generate_key().decode()).decrypt(blob)

    def test_blob_manipulado_se_detecta(self, clave: str) -> None:
        """Fernet es autenticado: el ciphertext tocado no pasa."""
        cipher = PiiCipher(clave)
        blob = bytearray(cipher.encrypt({"a": 1}))
        blob[-5] = blob[-5] ^ 0xFF
        with pytest.raises(PiiCipherError):
            cipher.decrypt(bytes(blob))


class TestBuildCipher:
    def test_sin_store_pii_no_hay_cifrador(self) -> None:
        assert build_cipher(Settings(store_pii=False)) is None

    def test_con_store_pii_y_clave_hay_cifrador(self, clave: str) -> None:
        assert build_cipher(Settings(store_pii=True, pii_encryption_key=clave)) is not None

    def test_store_pii_sin_clave_no_arranca(self) -> None:
        """La validación vive en Settings: el proceso ni levanta."""
        with pytest.raises(ValueError, match="PII_ENCRYPTION_KEY"):
            Settings(store_pii=True, pii_encryption_key=None)


class TestBoveda:
    @pytest.fixture
    def hallazgo_persistido(self, repository: SqlAlchemyFindingRepository) -> str:
        finding = make_finding()
        repository.upsert_many([finding])
        return finding.dedup_hash

    def test_deshabilitada_no_escribe(
        self, session_factory: sessionmaker[Session], hallazgo_persistido: str
    ) -> None:
        vault = PiiVault(session_factory, None, 30)
        assert vault.enabled is False
        assert vault.store(dedup_hash=hallazgo_persistido, source="x", payload={"a": 1}) is False
        assert vault.count() == 0

    def test_sin_hallazgo_previo_no_escribe(
        self, session_factory: sessionmaker[Session], clave: str
    ) -> None:
        """La FK exige que el metadata vaya primero."""
        vault = PiiVault(session_factory, PiiCipher(clave), 30)
        assert vault.store(dedup_hash="inexistente", source="x", payload={"a": 1}) is False
        assert vault.count() == 0

    def test_guardar_dos_veces_no_apila_copias(
        self, session_factory: sessionmaker[Session], clave: str, hallazgo_persistido: str
    ) -> None:
        """Cada cifrado da un blob distinto: hay que deduplicar por hallazgo."""
        vault = PiiVault(session_factory, PiiCipher(clave), 30)
        for _ in range(3):
            vault.store(dedup_hash=hallazgo_persistido, source="x", payload={"a": 1})
        assert vault.count() == 1

    def test_la_retencion_borra_lo_vencido(
        self,
        session_factory: sessionmaker[Session],
        clave: str,
        hallazgo_persistido: str,
    ) -> None:
        vault = PiiVault(session_factory, PiiCipher(clave), retention_days=30)
        vault.store(dedup_hash=hallazgo_persistido, source="x", payload={"a": 1})
        assert vault.count() == 1

        # Antes del vencimiento no se toca nada.
        assert vault.purge_expired(now=datetime.now(UTC) + timedelta(days=29)) == 0
        assert vault.count() == 1

        # Pasada la retención, se borra.
        assert vault.purge_expired(now=datetime.now(UTC) + timedelta(days=31)) == 1
        assert vault.count() == 0

    def test_borrar_el_hallazgo_arrastra_su_pii(
        self,
        session_factory: sessionmaker[Session],
        clave: str,
        hallazgo_persistido: str,
    ) -> None:
        """El ON DELETE CASCADE necesita PRAGMA foreign_keys=ON en SQLite."""
        vault = PiiVault(session_factory, PiiCipher(clave), 30)
        vault.store(dedup_hash=hallazgo_persistido, source="x", payload={"a": 1})

        with session_factory() as session:
            session.query(FindingRow).delete()
            session.commit()
            assert session.query(PiiRecordRow).count() == 0
