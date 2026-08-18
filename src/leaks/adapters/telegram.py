"""Adapter de canales públicos de Telegram, vía la vista previa web.

## Por qué existe

Medido el 2026-08-18 sobre el caso Chronus Team: las tres fuentes de ransomware
que consumimos indexan **data leak sites de bandas de ransomware**, y los
colectivos hacktivistas que van contra el sector público argentino publican por
**Telegram**. No es que se nos pasaban: no podían aparecer. Chronus golpeó
México el 2026-01-30 y Argentina el 2026-03-30 —el banco central, ministerios, Suprema
Corte de Buenos Aires, una obra social provincial— y nuestra base no tenía ni una fila. Ver
`docs/hueco-hacktivistas.md`.

Además esta clase de actor **anuncia sus objetivos antes de atacar**: Chronus
declaró en su canal que "le va a llegar el turno a Argentina" con un mes de
anticipación. Eso es aviso previo, no post-mortem.

## Cómo se lee, y qué se descartó

`https://t.me/s/<handle>` es la vista previa pública del canal: HTML renderizado
del lado del servidor, **sin cuenta, sin API key y sin Tor**. Verificado: 20
mensajes por página, con `datetime` real y `data-post` que sirve de cursor.

Se descartó **MTProto/Telethon** a propósito, aunque dé más: exige `api_id` y un
número de teléfono, o sea una identidad que quemar y una cuenta que se puede
banear. Para leer canales públicos no hace falta.

Se descartó la **Bot API** porque no sirve: un bot solo lee canales de los que
es miembro.

## Privacidad

Estos canales publican volcados con PII masiva. El adapter va marcado
`requires_pii` y `high_pii_surface`:

* A `findings` solo entra **metadata**: canal, fecha, URL del post y un título
  corto que pasa por el redactor.
* El **cuerpo completo** viaja en `RawItem.payload`, que el runner manda al
  vault cifrado y **solo si `STORE_PII=true`**. Sin clave de cifrado se
  descarta; nunca se degrada a guardarlo en claro.

El cuerpo sí se usa en memoria para decidir relevancia argentina —ahí es donde
el actor escribe el organismo afectado— y se descarta enseguida.
"""

from __future__ import annotations

import html
import logging
import re
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from leaks.adapters.http import FeedHttpClient
from leaks.adapters.parsing import parse_datetime
from leaks.domain.models import LeakType, NormalizedItem, RawItem
from leaks.extraction.downloads import extract_download_links
from leaks.pipeline.egress_guard import EgressBlockedError

logger = logging.getLogger(__name__)

BASE_URL = "https://t.me/s"

LICENSE_NOTE = (
    "Vista previa pública de canales de Telegram (t.me/s/<canal>). Sin cuenta ni "
    "API key. Se lee lo que el canal publica en abierto; no se entra a grupos "
    "privados ni se resuelven invitaciones."
)

#: Un handle público válido. Los `t.me/+AbCd...` son invitaciones a grupos
#: privados y NO se pueden leer así: se rechazan en vez de pedirlos y fallar.
HANDLE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")

#: Primeros segmentos de `t.me/` que NO son canales: son rutas del propio
#: Telegram, y pedirlas es garantía de no encontrar nada.
_NO_SON_CANALES = frozenset({"joinchat", "addstickers", "share", "proxy", "socks", "iv"})

#: Máximo de mensajes que se procesan por canal y corrida. La página trae ~20;
#: el tope está para que un canal que cambie de formato no dispare un bucle.
MAX_MENSAJES = 40

#: Largo del título derivado que llega a `findings`.
MAX_TITULO = 300

#: Telegram responde 200 para cualquier handle. Un canal inexistente devuelve
#: la página de "Contact", y uno privado la de "View/Join": las dos traen cero
#: mensajes. Distinguirlas importa — si no, un canal muerto se ve igual que uno
#: tranquilo y el investigador no se entera nunca.
SIN_PREVIA = "el canal no tiene vista previa pública (privado, o no existe)"
NO_EXISTE = "el canal no existe"
_ES_CONTACTO = re.compile(r"<title>\s*Telegram:\s*Contact\s*@", re.I)

_MSG_ABRE = r'<div class="tgme_widget_message\b'
_BLOQUE = re.compile(
    _MSG_ABRE + r"(?P<attrs>[^>]*)>(?P<cuerpo>.*?)(?=" + _MSG_ABRE + r"|\Z)",
    re.S,
)
_POST_ID = re.compile(r'data-post="([^"]+)"')
_FECHA = re.compile(r'<time[^>]*datetime="([^"]+)"')
_TEXTO = re.compile(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', re.S)
_BR = re.compile(r"<br\s*/?>", re.I)
_TAGS = re.compile(r"<[^>]+>")


def normalizar_handle(valor: str) -> str | None:
    """Acepta `@x`, `t.me/x`, `https://t.me/s/x` y devuelve `x`.

    Devuelve `None` si no es un canal público legible: una invitación
    (`t.me/+...`) o un handle imposible. Rechazar acá es mejor que descubrirlo
    con un 404 por corrida.
    """
    if not valor:
        return None
    limpio = valor.strip().strip("@").rstrip("/")
    limpio = re.sub(r"^https?://", "", limpio, flags=re.I)
    limpio = re.sub(r"^t\.me/(s/)?", "", limpio, flags=re.I)
    limpio = limpio.split("/")[0].split("?")[0]
    # `t.me/joinchat/AAA` es una invitación igual que `t.me/+AAA`, pero el
    # primer segmento es un handle válido y se colaba: generaba un pedido por
    # corrida contra una URL que nunca va a devolver mensajes.
    if limpio.lower() in _NO_SON_CANALES:
        return None
    return limpio if HANDLE.match(limpio) else None


def _a_texto(fragmento: str) -> str:
    """HTML de un mensaje a texto plano, conservando los saltos de línea."""
    con_saltos = _BR.sub("\n", fragmento)
    sin_tags = _TAGS.sub(" ", con_saltos)
    lineas = [" ".join(x.split()) for x in html.unescape(sin_tags).splitlines()]
    return "\n".join(x for x in lineas if x)


class TelegramChannelAdapter:
    """Mensajes públicos de los canales configurados."""

    name = "telegram"
    leak_type = LeakType.FORUM_POST

    def __init__(
        self,
        client: FeedHttpClient,
        channels: Sequence[str],
        base_url: str = BASE_URL,
        cursors: dict[str, str] | None = None,
    ) -> None:
        # Se normaliza acá y no en la base: así un handle inválido no llega a
        # generar un pedido, venga de donde venga.
        self._channels = tuple(h for h in (normalizar_handle(c) for c in channels) if h is not None)
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._cursors = dict(cursors or {})
        #: Último post visto por canal en esta corrida, para que el repositorio
        #: guarde el cursor después.
        self.nuevos_cursores: dict[str, str] = {}
        #: Por qué un canal no aportó nada. Se persiste y se muestra: un canal
        #: muerto tiene que verse distinto de uno sin novedades.
        self.errores: dict[str, str] = {}

    def fetch(self, since: datetime | None) -> Iterable[RawItem]:
        """Un pedido por canal. Sin canales habilitados no sale ninguno."""
        for canal in self._channels:
            try:
                html_crudo = self._client.get_text(f"{self._base_url}/{canal}")
            except EgressBlockedError:
                # OPSEC corta la corrida entera, no un canal.
                raise
            except Exception as exc:
                logger.info(
                    "telegram: %s no respondió (%s); se sigue con el resto",
                    canal,
                    type(exc).__name__,
                )
                self.errores[canal] = f"no respondió ({type(exc).__name__})"
                continue

            mensajes = self._parsear(html_crudo, canal)
            if not mensajes and canal not in self.nuevos_cursores:
                # Ni un mensaje y nunca se vio uno: no es que no haya novedades,
                # es que no se puede leer.
                self.errores[canal] = NO_EXISTE if _ES_CONTACTO.search(html_crudo) else SIN_PREVIA
                logger.info("telegram: %s — %s", canal, self.errores[canal])
                continue

            for mensaje in mensajes:
                yield RawItem(source=self.name, payload=mensaje)

    def _parsear(self, html_crudo: str, canal: str) -> list[dict[str, Any]]:
        """Extrae los mensajes de la página, del más viejo al más nuevo.

        Se corta en el cursor guardado: lo ya visto no se reprocesa, que es lo
        que hace la corrida incremental de verdad.
        """
        visto = self._cursors.get(canal)
        encontrados: list[dict[str, Any]] = []
        ultimo_visto: str | None = None

        for bloque in _BLOQUE.finditer(html_crudo):
            attrs, cuerpo = bloque.group("attrs"), bloque.group("cuerpo")
            m_id = _POST_ID.search(attrs) or _POST_ID.search(cuerpo)
            if not m_id:
                continue
            post_id = m_id.group(1)

            # El cursor avanza sobre TODO lo visto, no solo sobre lo que se
            # queda: si no, un mensaje sin texto al final del canal se
            # reprocesa en cada corrida para siempre.
            ultimo_visto = post_id

            m_texto = _TEXTO.search(cuerpo)
            texto = _a_texto(m_texto.group(1)) if m_texto else ""
            if not texto:
                # Un mensaje que es solo una imagen no aporta nada que analizar.
                continue

            m_fecha = _FECHA.search(cuerpo)
            encontrados.append(
                {
                    "channel": canal,
                    "post_id": post_id,
                    "url": f"https://t.me/{post_id}",
                    "published": m_fecha.group(1) if m_fecha else None,
                    # El cuerpo completo: va al vault cifrado, nunca a findings.
                    "text": texto,
                }
            )

        if ultimo_visto is not None:
            self.nuevos_cursores[canal] = ultimo_visto

        if visto:
            # Todo lo anterior al último post visto ya se procesó.
            for i, m in enumerate(encontrados):
                if m["post_id"] == visto:
                    encontrados = encontrados[i + 1 :]
                    break
        return encontrados[:MAX_MENSAJES]

    def normalize(self, item: RawItem) -> NormalizedItem | None:
        """Metadata para `findings`. El cuerpo NO se copia acá."""
        payload: dict[str, Any] = item.payload
        canal = payload.get("channel")
        texto = payload.get("text")
        if not isinstance(canal, str) or not isinstance(texto, str) or not texto:
            return None

        publicado = parse_datetime(payload.get("published"))

        # El título es la primera línea con contenido, recortada. Es lo único
        # del mensaje que puede llegar a persistirse, y aun así pasa por el
        # scrubber del pipeline porque el feed es `high_pii_surface`.
        primera = next((x for x in texto.splitlines() if x.strip()), "")

        return NormalizedItem(
            source=self.name,
            leak_type=self.leak_type,
            # El "nombre de víctima" de un canal es el título del post: es ahí
            # donde el actor escribe a quién dice haber golpeado.
            victim_name=primera[:MAX_TITULO] or f"@{canal}",
            victim_domain=None,
            country=None,
            sector=None,
            # El canal ES el actor, cuando se sabe quién lo opera. La
            # atribución fina vive en la tabla de canales, no acá.
            actor=canal,
            discovered_at=publicado or datetime.now(UTC),
            occurred_at=publicado,
            published_at=publicado,
            raw_ref=payload.get("url"),
            # El cuerpo entero se usa en memoria para decidir relevancia y
            # extraer punteros; lo que se persiste lo decide el pipeline.
            description=texto[:MAX_TITULO],
            download_links=tuple(extract_download_links(texto)),
        )
