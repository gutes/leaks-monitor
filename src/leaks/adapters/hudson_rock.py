"""Adapter de Hudson Rock Cavalier (infostealers) — endpoints OSINT gratuitos.

ESTADO: verificado el 2026-08-18 (el 2026-08-14 daba timeout, no era el
adapter). ~2 s por dominio, con timeouts intermitentes.

Dos razones para que este feed sea opt-in y no corra sin que nadie lo pida:

1. **Toca PII.** Es record-level: habla de credenciales de personas físicas
   comprometidas por infostealers. Por eso `requires_pii=True` — sin habilitar
   las fuentes con PII, el registro ni lo instancia.

2. **Es un pedido saliente a un tercero extranjero.** A diferencia del resto de
   los feeds (que se bajan enteros y se filtran acá), acá hay que *mandarle* un
   dominio al proveedor: cada consulta le revela qué organismo estás vigilando.

Por eso el adapter **no lee la watchlist por su cuenta**: recibe una lista ya
resuelta. Quién la arma es una decisión de quien despliega, y hay dos caminos:

* `LEAKS_HUDSONROCK_DOMAINS` — los dominios a mano, siempre los mismos.
* La rotación por lotes (`pipeline/domain_rotation.py`), apagada por defecto,
  que recorre la watchlist de a poco en vez de publicarla entera de una.

Lo que se persiste en `findings` son CONTEOS, nunca identidades: cuántos
empleados y cuántos usuarios aparecen comprometidos. Los emails y credenciales
que devuelva el proveedor viajan al vault cifrado y solo si `STORE_PII=true`.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from leaks.adapters.http import FeedHttpClient
from leaks.domain.models import LeakType, NormalizedItem, RawItem
from leaks.extraction.dating import newest_sane
from leaks.extraction.exposure import ExposureDetail, build_exposure
from leaks.pipeline.egress_guard import EgressBlockedError

BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

logger = logging.getLogger(__name__)

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
    }
)

#: Campos de fecha del proveedor. Estuvieron en `PII_KEYS` por una suposición
#: equivocada —el nombre sugiere una identidad, pero el valor es un timestamp
#: ISO— y por eso el adapter fechaba todo con `now()` y el histórico se veía
#: como novedad del día. Se usan para fechar, nunca se persisten como texto.
DATE_KEYS = ("last_employee_compromised", "last_user_compromised")


def _describir(total: int, empleados: int, usuarios: int, exposicion: ExposureDetail | None) -> str:
    """Resumen legible. Destaca los sistemas de empleados, que es lo grave."""
    partes = [
        f"Infostealers: {total} equipos comprometidos ({empleados} empleados, {usuarios} usuarios)."
    ]
    if exposicion:
        internos = exposicion.employee_urls
        if internos:
            partes.append(f"{len(internos)} sistemas con credenciales de empleados.")
        if exposicion.weak_password_pct:
            partes.append(f"{exposicion.weak_password_pct}% de contraseñas débiles.")
    return " ".join(partes)


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
        """Consulta uno por uno los dominios configurados.

        Sin dominios configurados no sale ni un request: el default es no
        hablar con el proveedor.

        Cada dominio va aislado. El endpoint tiene timeouts intermitentes
        (medido el 2026-08-18: uno de cada cinco), y sin esto una consulta
        lenta se llevaría puesto todo el lote — justamente lo que la rotación
        intenta evitar.
        """
        for dominio in self._domains:
            try:
                payload = self._client.get_json(
                    f"{self._base_url}/search-by-domain", params={"domain": dominio}
                )
            except EgressBlockedError:
                # El control de OPSEC corta la corrida entera, no un dominio.
                raise
            except Exception as exc:
                logger.info(
                    "hudsonrock: %s no respondió (%s); se sigue con el resto",
                    dominio,
                    type(exc).__name__,
                )
                continue

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

        # El proveedor SÍ fecha: informa el último compromiso de empleados y el
        # de usuarios por separado, y deja el centinela epoch en el que no
        # aplica. Se toma el más reciente de los dos. Si no hay ninguno
        # creíble, el hallazgo queda sin fecha de evento — nunca `now()`, que
        # es lo que hacía ver todo el histórico como nuevo.
        ocurrido = newest_sane(*(payload.get(k) for k in DATE_KEYS))

        # Lo que hace accionable el hallazgo: qué sistemas se comprometieron y
        # cuáles eran de empleados. Sin esto queda solo un número grande.
        exposicion = build_exposure(payload)

        return NormalizedItem(
            source=self.name,
            leak_type=self.leak_type,
            victim_name=dominio,
            victim_domain=dominio,
            country=None,
            sector=None,
            actor=None,
            # `discovered_at` es cuándo lo supimos: la consulta es hoy.
            discovered_at=datetime.now(UTC),
            occurred_at=ocurrido,
            exposure=exposicion,
            published_at=None,
            raw_ref=f"{self._base_url}/search-by-domain?domain={dominio}",
            # Texto derivado por nosotros a partir de conteos: sin PII por
            # construcción, no por filtrado.
            description=_describir(total, empleados, usuarios, exposicion),
        )
