"""Adapter de foros MyBB vía su sindicación Atom pública.

Cubre DarkForums y BreachForums: los dos corren MyBB y publican
`/syndication.php`, así que es un solo adapter parametrizado por dominio.

**Qué se consume y qué no.** Se lee el índice público de threads: título, autor,
fecha y URL. No se entra a los threads, no se descarga ningún adjunto y no se
persiste el cuerpo del post. El cuerpo sí se usa **en memoria** para decidir si
el thread es relevante para Argentina (ahí es donde el foro escribe
`Location: Argentina` o el dominio afectado) y se descarta enseguida.

**Por qué son fuentes con PII.** El contenido de estos threads son literalmente
volcados de datos: muestras con emails, documentos y contraseñas. Por eso los
dos van marcados `requires_pii` —no corren salvo que se habiliten a propósito—
y `high_pii_surface`, que impide persistir texto libre.

**User-Agent identificable.** Se los consulta con el UA del proyecto, igual que
a cualquier otro feed. Si un foro bloquea a una herramienta identificada, la
respuesta correcta es registrar el bloqueo, no disfrazarse de navegador.

**Dominios rotativos.** Estos foros cambian de dominio seguido (incautaciones,
bloqueos). Por eso se configura una lista de candidatos y se usa el primero que
responda; si no responde ninguno, el adapter falla y el runner lo aísla como a
cualquier otra fuente caída.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from defusedxml import ElementTree as DefusedET

from leaks.adapters.http import FeedHttpClient
from leaks.adapters.parsing import parse_datetime
from leaks.domain.models import LeakType, NormalizedItem, RawItem

logger = logging.getLogger(__name__)

_ATOM = "{http://www.w3.org/2005/Atom}"

#: Ruta de sindicación estándar de MyBB.
SYNDICATION_PATH = "/syndication.php?type=atom1.0"

#: El autor viene envuelto en HTML (`<a href=...>usuario</a>`).
_TAGS = re.compile(r"<[^>]+>")


def _texto(elemento: Any) -> str:
    """Texto plano de un nodo, sin el HTML que MyBB mete en los CDATA."""
    if elemento is None or not elemento.text:
        return ""
    return " ".join(_TAGS.sub(" ", elemento.text).split())


class MyBBForumAdapter:
    """Índice de threads recientes de un foro MyBB."""

    leak_type = LeakType.FORUM_POST

    def __init__(
        self,
        client: FeedHttpClient,
        name: str,
        base_urls: Sequence[str],
        syndication_path: str = SYNDICATION_PATH,
    ) -> None:
        self.name = name
        self._client = client
        self._base_urls = tuple(u.rstrip("/") for u in base_urls if u.strip())
        self._path = syndication_path
        #: Dominio que respondió, para absolutizar enlaces relativos.
        self._active_base: str | None = None

    def fetch(self, since: datetime | None) -> Iterable[RawItem]:
        """Trae el índice del primer dominio que responda.

        El recorte incremental lo hace el runner sobre el item normalizado: el
        feed devuelve unas decenas de threads, no hace falta filtrar antes.
        """
        if not self._base_urls:
            return

        ultimo_error: Exception | None = None
        for base in self._base_urls:
            try:
                xml = self._client.get_text(f"{base}{self._path}")
            except Exception as exc:
                logger.info("El dominio %s no respondió: %s", base, type(exc).__name__)
                ultimo_error = exc
                continue

            self._active_base = base
            yield from self._parse(xml)
            return

        raise RuntimeError(
            f"Ningún dominio de {self.name} respondió "
            f"({', '.join(self._base_urls)}). ¿Cambió de dominio o fue incautado?"
        ) from ultimo_error

    def _parse(self, xml: str) -> Iterable[RawItem]:
        """Parsea el Atom. XML de fuente hostil: se usa defusedxml."""
        try:
            raiz = DefusedET.fromstring(xml)
        except Exception as exc:
            raise RuntimeError(f"{self.name} devolvió un Atom ilegible") from exc

        for entrada in raiz.iter(f"{_ATOM}entry"):
            enlace = entrada.find(f"{_ATOM}link")
            autor = entrada.find(f"{_ATOM}author/{_ATOM}name")
            yield RawItem(
                source=self.name,
                payload={
                    "title": _texto(entrada.find(f"{_ATOM}title")),
                    "author": _texto(autor),
                    "published": (entrada.findtext(f"{_ATOM}published") or "").strip(),
                    "updated": (entrada.findtext(f"{_ATOM}updated") or "").strip(),
                    "link": enlace.get("href") if enlace is not None else None,
                    # El cuerpo se usa para matchear y NO se persiste: es donde
                    # el foro declara país y dominio afectado, pero también
                    # donde pega las muestras de datos robados.
                    "content": _texto(entrada.find(f"{_ATOM}content")),
                },
            )

    def normalize(self, item: RawItem) -> NormalizedItem | None:
        payload: dict[str, Any] = item.payload

        titulo = payload.get("title")
        if not isinstance(titulo, str) or not titulo.strip():
            return None

        publicado = parse_datetime(payload.get("published")) or parse_datetime(
            payload.get("updated")
        )
        if publicado is None:
            return None

        return NormalizedItem(
            source=self.name,
            leak_type=self.leak_type,
            # El título del thread ES el identificador del hallazgo.
            victim_name=titulo,
            victim_domain=None,
            country=None,
            sector=None,
            # El handle de quien publica: es el actor, igual que el nombre de un
            # grupo de ransomware. Es un seudónimo público, no la identidad de
            # una persona.
            actor=payload.get("author") or None,
            discovered_at=publicado,
            published_at=publicado,
            raw_ref=payload.get("link"),
            # Se pasa el cuerpo para que la capa de relevancia lo mire. El
            # runner lo descarta antes de persistir porque la fuente está
            # marcada `high_pii_surface`.
            description=payload.get("content") or None,
        )
