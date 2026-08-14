"""Adapter de Hudson Rock Cavalier (infostealers) — endpoints OSINT gratuitos.

⚠️ ESTADO: NO VERIFICADO. Al 2026-08-14 el endpoint
`cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain` no responde
(timeout a los 60 s, cero bytes). El adapter queda implementado contra la forma
documentada del payload, pero **viene deshabilitado** y hay que confirmar el
modelo de acceso antes de habilitarlo. Ver docs/feeds.md.

Dos razones para que este feed sea opt-in y no corra en el run diario:

1. **Toca PII.** Es record-level: habla de credenciales de personas físicas
   comprometidas por infostealers. Por eso `requires_pii=True` — sin
   `STORE_PII=true` el registro ni lo instancia.

2. **Es un pedido saliente a un tercero extranjero.** A diferencia del resto de
   los feeds (que se bajan enteros y se filtran acá), acá hay que *mandarle* un
   dominio al proveedor. La regla del proyecto es no filtrar la watchlist a
   servicios de terceros, así que este adapter NO lee la watchlist: consulta
   únicamente los dominios que se listen a mano en
   `LEAKS_HUDSONROCK_DOMAINS`. Consultar es una decisión explícita por dominio,
   no un efecto secundario de agregar una entrada a la watchlist.

Lo que se persiste en `findings` son CONTEOS, nunca identidades: cuántos
empleados y cuántos usuarios aparecen comprometidos. Los emails y credenciales
que devuelva el proveedor viajan al vault cifrado y solo si `STORE_PII=true`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from leaks.adapters.http import FeedHttpClient
from leaks.domain.models import LeakType, NormalizedItem, RawItem

BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

LICENSE_NOTE = (
    "Endpoints OSINT gratuitos de un proveedor comercial extranjero. "
    "Enriquecimiento, nunca columna vertebral. Verificar términos antes de usarlo en serio."
)

#: Claves del payload que NUNCA se copian al modelo: son PII de personas
#: físicas. Se listan explícitas para que quede escrito qué estamos dejando
#: afuera a propósito, y para poder testearlo.
PII_KEYS = frozenset(
    {
        "employees",
        "users",
        "third_parties",
        "stealers",
        "data",
        "logs",
        "credentials",
        "last_employee_compromised",
        "last_user_compromised",
    }
)


def _as_count(value: Any) -> int | None:
    """Interpreta un campo del proveedor como conteo, sea número o lista."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return len(value)
    return None


class HudsonRockAdapter:
    """Exposición por infostealers de dominios explícitamente configurados."""

    name = "hudsonrock"
    leak_type = LeakType.INFOSTEALER

    def __init__(
        self,
        client: FeedHttpClient,
        domains: Sequence[str],
        base_url: str = BASE_URL,
    ) -> None:
        self._client = client
        self._domains = tuple(d.strip().lower() for d in domains if d.strip())
        self._base_url = base_url.rstrip("/")

    def fetch(self, since: datetime | None) -> Iterable[RawItem]:
        """Consulta uno por uno los dominios configurados a mano.

        Sin dominios configurados no sale ni un request: el default es no
        hablar con el proveedor.
        """
        for dominio in self._domains:
            payload = self._client.get_json(
                f"{self._base_url}/search-by-domain", params={"domain": dominio}
            )
            if isinstance(payload, dict):
                # Se anota el dominio consultado: la respuesta no siempre lo
                # repite y sin él no se puede normalizar.
                yield RawItem(source=self.name, payload={**payload, "_queried_domain": dominio})

    def normalize(self, item: RawItem) -> NormalizedItem | None:
        """Reduce la respuesta a conteos agregados. La PII no entra al modelo."""
        payload: dict[str, Any] = item.payload

        dominio = payload.get("_queried_domain")
        if not isinstance(dominio, str) or not dominio:
            return None

        empleados = _as_count(payload.get("employees")) or 0
        usuarios = _as_count(payload.get("users")) or 0
        total = _as_count(payload.get("total")) or (empleados + usuarios)
        if total <= 0:
            # Dominio limpio: no es un hallazgo, no se persiste nada.
            return None

        return NormalizedItem(
            source=self.name,
            leak_type=self.leak_type,
            victim_name=dominio,
            victim_domain=dominio,
            country=None,
            sector=None,
            actor=None,
            # El proveedor no fecha el agregado: la fecha es la de la consulta.
            discovered_at=datetime.now(UTC),
            published_at=None,
            raw_ref=f"{self._base_url}/search-by-domain?domain={dominio}",
            # Texto derivado por nosotros a partir de conteos: sin PII por
            # construcción, no por filtrado.
            description=(
                f"Infostealers: {total} equipos comprometidos "
                f"({empleados} empleados, {usuarios} usuarios)."
            ),
        )
