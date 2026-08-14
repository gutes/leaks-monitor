"""Configuración operativa que se cambia en caliente desde la UI.

Deliberadamente **no** reemplaza al entorno. La separación es:

* **Entorno / secrets manager** — credenciales, clave de cifrado, países
  bloqueados. Son decisiones de despliegue y de seguridad; no se tocan desde
  una interfaz sin autenticación.
* **Base (este módulo)** — decisiones operativas del investigador: qué reglas
  de relevancia aplican, si corren las fuentes que traen PII. Cambian seguido y
  necesitan aplicarse sin reiniciar el proceso.

Los valores se guardan como JSON para no inventar un formato de serialización.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from leaks.domain.models import ArMatchReason
from leaks.storage.models import AppSettingRow
from leaks.storage.session import session_scope

logger = logging.getLogger(__name__)

#: Prefijo de las claves de las reglas de relevancia.
RULE_PREFIX = "rule."

#: Habilita las fuentes marcadas `requires_pii`. Ojo: habilita que **corran**,
#: no que se persista PII en claro — eso sigue exigiendo clave de cifrado.
KEY_PII_SOURCES = "pii_sources_enabled"

#: Descripción de cada regla, para que la UI no tenga que hardcodearlas.
RULE_DESCRIPTIONS: dict[ArMatchReason, str] = {
    ArMatchReason.WATCHLIST: ("El dominio de la víctima está en la watchlist (cubre subdominios)."),
    ArMatchReason.TLD_AR: "Cualquier dominio bajo el TLD .ar (.gob.ar, .com.ar, etc.).",
    ArMatchReason.COUNTRY_AR: "El feed declara que el país de la víctima es Argentina.",
    ArMatchReason.CUIT_VALID: ("Aparece un CUIT/CUIL con dígito verificador válido en el texto."),
    ArMatchReason.KEYWORD: (
        "Aparece el nombre de un organismo o empresa de la watchlist. "
        "Es la regla más propensa a falsos positivos (entidades homónimas de otros países)."
    ),
}


class SettingsStore:
    """Lectura y escritura de la configuración operativa."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Genérico ------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        with session_scope(self._session_factory) as session:
            fila = session.get(AppSettingRow, key)
            if fila is None:
                return default
            try:
                return json.loads(fila.value)
            except json.JSONDecodeError:
                logger.warning("Valor ilegible en app_settings[%s]; se usa el default", key)
                return default

    def set(self, key: str, value: Any) -> None:
        ahora = datetime.now(UTC)
        serializado = json.dumps(value)
        with session_scope(self._session_factory) as session:
            fila = session.get(AppSettingRow, key)
            if fila is None:
                session.add(AppSettingRow(key=key, value=serializado, updated_at=ahora))
                return
            fila.value = serializado
            fila.updated_at = ahora

    def all_values(self) -> dict[str, Any]:
        with session_scope(self._session_factory) as session:
            filas = session.scalars(select(AppSettingRow)).all()
            salida: dict[str, Any] = {}
            for fila in filas:
                try:
                    salida[fila.key] = json.loads(fila.value)
                except json.JSONDecodeError:
                    continue
            return salida

    # -- Reglas de relevancia ------------------------------------------------

    def rule_enabled(self, rule: ArMatchReason) -> bool:
        """¿Aplica esta regla? Por defecto sí: la watchlist completa es el default."""
        valor = self.get(f"{RULE_PREFIX}{rule.value}")
        return True if valor is None else bool(valor)

    def set_rule_enabled(self, rule: ArMatchReason, enabled: bool) -> None:
        self.set(f"{RULE_PREFIX}{rule.value}", bool(enabled))

    def enabled_rules(self) -> frozenset[ArMatchReason]:
        """Conjunto de reglas activas, que es lo que consume la capa de relevancia."""
        guardados = self.all_values()
        return frozenset(
            regla
            for regla in ArMatchReason
            if bool(guardados.get(f"{RULE_PREFIX}{regla.value}", True))
        )

    def rules_state(self) -> tuple[dict[str, Any], ...]:
        """Estado de las 5 reglas, con su descripción, para la UI."""
        guardados = self.all_values()
        return tuple(
            {
                "name": regla.value,
                "enabled": bool(guardados.get(f"{RULE_PREFIX}{regla.value}", True)),
                "description": RULE_DESCRIPTIONS.get(regla, ""),
            }
            for regla in ArMatchReason
        )

    # -- Fuentes con PII -----------------------------------------------------

    def pii_sources_enabled(self) -> bool:
        """¿Corren las fuentes marcadas `requires_pii`? Default: no (fail-closed)."""
        return bool(self.get(KEY_PII_SOURCES, False))

    def set_pii_sources_enabled(self, enabled: bool) -> None:
        self.set(KEY_PII_SOURCES, bool(enabled))
