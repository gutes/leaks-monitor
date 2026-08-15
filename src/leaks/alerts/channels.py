"""Canales de alerta: catálogo declarativo, igual que los feeds.

Sumar un canal es implementar `AlertChannel` y agregar un `ChannelSpec`. El
despachador no se toca.

**Qué viaja en una alerta.** Solo metadata: organismo, dominio, actor, fuente,
severidad, fecha y el enlace a la publicación. Nunca PII, nunca contenido de
volcados — lo mismo que se persiste, ni un campo más. Un canal de alertas es un
tercero (Slack, Telegram, un webhook propio), así que vale la misma regla que
para los feeds.

**Los secretos van por entorno.** Ni tokens ni URLs con credenciales en el
código o en la base.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from leaks.adapters.http import FeedHttpClient
from leaks.config import Settings
from leaks.domain.models import Finding

logger = logging.getLogger(__name__)

#: Tope de hallazgos que se detallan en un mensaje. Más que esto se resume:
#: una alerta con 300 líneas no la lee nadie y encima puede pasarse del límite
#: de tamaño del canal.
MAX_DETALLE = 10


def _titulo(findings: Sequence[Finding]) -> str:
    criticos = sum(1 for f in findings if f.severity == "critical")
    if criticos:
        return f"🚨 {len(findings)} hallazgos AR nuevos ({criticos} críticos)"
    return f"⚠️ {len(findings)} hallazgos AR nuevos"


def _linea(f: Finding) -> str:
    partes = [f"[{f.severity.upper()}] {f.victim_name}"]
    if f.victim_domain:
        partes.append(f"({f.victim_domain})")
    if f.actor:
        partes.append(f"— {f.actor}")
    partes.append(f"· {f.source}")
    partes.append(f"· {f.discovered_at:%Y-%m-%d}")
    return " ".join(partes)


def format_text(findings: Sequence[Finding]) -> str:
    """Mensaje en texto plano, común a todos los canales."""
    lineas = [_titulo(findings), ""]
    lineas.extend(_linea(f) for f in findings[:MAX_DETALLE])
    if len(findings) > MAX_DETALLE:
        lineas.append(f"…y {len(findings) - MAX_DETALLE} más.")
    return "\n".join(lineas)


class WebhookChannel:
    """POST de un JSON a una URL. Sirve para Slack, Discord, n8n o uno propio.

    Se manda `text` (lo que muestran Slack y Discord sin configurar nada) y
    además `findings` estructurado, para quien quiera procesarlo.
    """

    name = "webhook"

    def __init__(self, client: FeedHttpClient, url: str) -> None:
        self._client = client
        self._url = url

    def send(self, findings: Sequence[Finding]) -> None:
        cuerpo: dict[str, Any] = {
            "text": format_text(findings),
            "count": len(findings),
            "findings": [
                {
                    "victim_name": f.victim_name,
                    "victim_domain": f.victim_domain,
                    "sector": f.sector,
                    "actor": f.actor,
                    "source": f.source,
                    "severity": str(f.severity),
                    "discovered_at": f.discovered_at.isoformat(),
                    "ar_match_reason": [str(r) for r in f.ar_match_reason],
                    "raw_ref": f.raw_ref,
                }
                for f in findings
            ],
        }
        self._client.post_json(self._url, cuerpo)


class TelegramChannel:
    """Mensaje a un chat de Telegram por la Bot API."""

    name = "telegram"

    def __init__(self, client: FeedHttpClient, token: str, chat_id: str) -> None:
        self._client = client
        self._token = token
        self._chat_id = chat_id

    def send(self, findings: Sequence[Finding]) -> None:
        # El token va en la URL porque así es la Bot API; por eso nunca se
        # loguea la URL de este canal (ver `dispatcher`).
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        self._client.post_json(
            url,
            {
                "chat_id": self._chat_id,
                "text": format_text(findings),
                "disable_web_page_preview": True,
            },
        )


@dataclass(frozen=True)
class ChannelSpec:
    """Descriptor de un canal: cómo se construye y si está configurado."""

    name: str
    #: Devuelve el canal, o `None` si le faltan credenciales.
    factory: Callable[[Settings, FeedHttpClient], Any]
    #: Qué variables de entorno hacen falta, para poder explicarlo en la UI.
    requires: tuple[str, ...]


def _webhook(settings: Settings, client: FeedHttpClient) -> WebhookChannel | None:
    url = settings.alert_webhook_url
    return WebhookChannel(client, url) if url else None


def _telegram(settings: Settings, client: FeedHttpClient) -> TelegramChannel | None:
    token = settings.alert_telegram_token
    chat = settings.alert_telegram_chat_id
    if not token or not chat:
        return None
    return TelegramChannel(client, token.get_secret_value(), chat)


#: Registro inmutable de canales.
CHANNEL_REGISTRY: tuple[ChannelSpec, ...] = (
    ChannelSpec("webhook", _webhook, ("LEAKS_ALERT_WEBHOOK_URL",)),
    ChannelSpec(
        "telegram",
        _telegram,
        ("LEAKS_ALERT_TELEGRAM_TOKEN", "LEAKS_ALERT_TELEGRAM_CHAT_ID"),
    ),
)
