"""Cifrado en reposo de la tabla de PII.

Solo se usa cuando `STORE_PII=true`. La postura es fail-closed en los dos
sentidos:

* sin clave, `Settings` ni siquiera deja arrancar el proceso (ver `config.py`);
* sin cifrador, el vault se niega a escribir en lugar de guardar en claro.

Se usa Fernet (AES-128-CBC + HMAC-SHA256, del paquete `cryptography`) en vez de
armar el esquema a mano: es una primitiva autenticada, estándar y probada, que
detecta el ciphertext manipulado al descifrar.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from leaks.config import Settings


class PiiCipherError(RuntimeError):
    """Falla de cifrado/descifrado de un registro con PII."""


class PiiCipher:
    """Cifra y descifra los payloads record-level que tocan PII."""

    def __init__(self, key: str) -> None:
        try:
            self._fernet = Fernet(key.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise PiiCipherError(
                "LEAKS_PII_ENCRYPTION_KEY no es una clave Fernet válida. "
                'Generar con: python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            ) from exc

    def encrypt(self, payload: dict[str, Any]) -> bytes:
        """Serializa y cifra un payload. El resultado es opaco sin la clave."""
        crudo = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return self._fernet.encrypt(crudo.encode("utf-8"))

    def decrypt(self, blob: bytes) -> dict[str, Any]:
        """Descifra un payload. Lanza si el blob fue manipulado o la clave no es la misma."""
        try:
            crudo = self._fernet.decrypt(blob)
        except InvalidToken as exc:
            raise PiiCipherError(
                "No se pudo descifrar el registro: clave incorrecta o dato manipulado."
            ) from exc
        parsed: Any = json.loads(crudo.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise PiiCipherError("El payload descifrado no es un objeto JSON.")
        return parsed


def build_cipher(settings: Settings) -> PiiCipher | None:
    """Cifrador del proceso, o `None` si no corresponde guardar PII.

    Devolver `None` no es un error: es el caso por defecto (`STORE_PII=false`),
    y el vault lo interpreta como "no escribas nada".
    """
    if not settings.store_pii or settings.pii_encryption_key is None:
        return None
    return PiiCipher(settings.pii_encryption_key.get_secret_value())
