"""Capa de privacidad: qué texto puede llegar a la base y qué no.

Postura **fail-closed**: ante la duda, se descarta. Un campo de texto libre que
contenga cualquier rastro de PII no se guarda truncado ni parcialmente
enmascarado — se descarta entero. Perder contexto es barato; persistir el email
de una persona física no.

Con `STORE_PII=true` el pipeline no usa estas funciones para *descartar*, sino
que manda el payload a la tabla cifrada aparte (ver `storage/crypto.py`).
"""

from __future__ import annotations

import hashlib
import re

#: Longitud máxima del texto libre que sí se persiste.
MAX_DESCRIPTION_LENGTH = 600

_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
#: Par `email:contraseña`, el formato más común de combolist.
#:
#: Hace falta aparte de `_COMBO_LINE`, que exige tres campos (`url:user:pass`):
#: un par de dos campos no lo dispara. Y tiene que ir ANTES que `_EMAIL` en el
#: orden de redacción, porque si primero se tapa el email, la contraseña queda
#: suelta a la derecha de los dos puntos.
_EMAIL_PASS = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+:\S+")
#: Password/credencial en formatos típicos de combolist: `user:pass`, `URL:LOG:PASS`.
_CREDENTIAL = re.compile(
    r"(?i)\b(?:pass(?:word)?|contrase[nñ]a|passwd|pwd|token|api[_-]?key|secret)\b\s*[:=]\s*\S+"
)
_COMBO_LINE = re.compile(r"\S+:\S+:\S+")
#: Hashes de password sueltos (md5/sha1/sha256 en hex) y bcrypt.
_HASH = re.compile(r"\b[a-f0-9]{32,64}\b|\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
#: Tarjetas y documentos de persona física.
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_DNI = re.compile(r"(?i)\bDNI\s*[:.\s]?\s*\d{7,8}\b")
#: CUIT/CUIL: la regla de relevancia ya lo registró enmascarado en
#: `ar_match_detail`; el número en claro no tiene por qué quedar además acá.
_CUIT = re.compile(r"\b\d{2}-?\d{8}-?\d\b")

#: El orden importa para la redacción: lo más específico primero.
_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email_pass", _EMAIL_PASS),
    ("email", _EMAIL),
    ("credential", _CREDENTIAL),
    ("combo", _COMBO_LINE),
    ("hash", _HASH),
    ("card", _CARD),
    ("dni", _DNI),
    ("cuit", _CUIT),
)


def find_pii_kinds(text: str | None) -> tuple[str, ...]:
    """Qué clases de PII aparecen en el texto. Vacío = limpio."""
    if not text:
        return ()
    return tuple(nombre for nombre, patron in _PII_PATTERNS if patron.search(text))


def contains_pii(text: str | None) -> bool:
    """¿El texto tiene algo que no podemos persistir?"""
    return bool(find_pii_kinds(text))


def scrub_free_text(text: str | None, *, max_length: int = MAX_DESCRIPTION_LENGTH) -> str | None:
    """Devuelve el texto apto para persistir, o `None` si no lo es.

    No enmascara ni recorta la parte sensible: si hay PII, se cae el campo
    completo. Enmascarar deja demasiado margen a que algo se filtre por un
    patrón que no previmos.
    """
    if not text:
        return None
    limpio = " ".join(text.split())
    if not limpio:
        return None
    if contains_pii(limpio):
        return None
    return limpio[:max_length]


def redact_pii(text: str | None, *, max_length: int = MAX_DESCRIPTION_LENGTH) -> str | None:
    """Reemplaza la PII por `[redactado]` en lugar de tirar el campo entero.

    Es la excepción deliberada a la regla de `scrub_free_text`, y aplica solo al
    **nombre de la víctima** de las fuentes de superficie riesgosa (títulos de
    threads de foro).

    El razonamiento: en `description` tirar el campo cuesta contexto, y por eso
    conviene tirarlo. En `victim_name` tirar el campo cuesta **el hallazgo
    entero** — un thread titulado "Prevision Ejemplo dump juan@x.gob.ar" desaparecería del
    monitoreo justo por ser el más grave. Redactado sigue siendo identificable,
    y el thread original queda referenciado en `raw_ref` para quien tenga que
    ir a verlo.
    """
    if not text:
        return None
    limpio = " ".join(text.split())
    if not limpio:
        return None
    for _nombre, patron in _PII_PATTERNS:
        limpio = patron.sub("[redactado]", limpio)
    return limpio[:max_length] or None


def hash_identifier(value: str, *, salt: str = "") -> str:
    """Hash estable de un identificador, para correlacionar sin guardarlo.

    Se usa cuando un feed devuelve PII inline y hace falta poder decir "este
    hallazgo es el mismo de ayer" sin persistir el dato en claro.
    """
    return hashlib.sha256(f"{salt}{value.strip().lower()}".encode()).hexdigest()
