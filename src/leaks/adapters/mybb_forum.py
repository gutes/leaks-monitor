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

from leaks.adapters.http import FeedHttpClient, describe_cause
from leaks.adapters.parsing import parse_datetime
from leaks.domain.models import LeakType, NormalizedItem, RawItem
from leaks.extraction.downloads import extract_download_links

logger = logging.getLogger(__name__)

_ATOM = "{http://www.w3.org/2005/Atom}"

#: Ruta de sindicación estándar de MyBB.
#:
#: `limit` es la diferencia entre ver el foro y perdérselo. Medido el
#: 2026-09-01 contra darkforums: sin el parámetro son 15 threads y una ventana
#: de 3,3 h; con `limit=50` son 50 threads y **20,6 h**, en el mismo request.
#: MyBB topea en 50 —pedir 100 o 200 devuelve 50 igual—, así que 50 es el
#: máximo de historia que la sindicación puede dar.
SYNDICATION_PATH = "/syndication.php?type=atom1.0&limit=50"

#: El autor viene envuelto en HTML (`<a href=...>usuario</a>`).
_TAGS = re.compile(r"<[^>]+>")


def _texto(elemento: Any) -> str:
    """Texto plano de un nodo, sin el HTML que MyBB mete en los CDATA."""
    if elemento is None or not elemento.text:
        return ""
    return " ".join(_TAGS.sub(" ", elemento.text).split())


def parse_atom(xml: str, *, source: str) -> Iterable[RawItem]:
    """Parsea el Atom. XML de fuente hostil: se usa defusedxml.

    Se recorta el arranque antes de parsear: la declaración `<?xml…?>` tiene que
    ser el primer byte, y un despliegue de MyBB que deje un espacio o un salto
    de línea colados antes —o un BOM— produce XML inválido. Le pasa a BreachForums
    en bf.st, que sirve un Atom perfectamente bueno detrás de un espacio.
    Rechazarlo por eso sería perder la fuente entera por un byte de más.
    """
    try:
        raiz = DefusedET.fromstring(xml.lstrip("\ufeff \t\r\n"))
    except Exception as exc:
        raise RuntimeError(f"{source} devolvió un Atom ilegible") from exc

    for entrada in raiz.iter(f"{_ATOM}entry"):
        enlace = entrada.find(f"{_ATOM}link")
        autor = entrada.find(f"{_ATOM}author/{_ATOM}name")
        contenido = entrada.find(f"{_ATOM}content")
        yield RawItem(
            source=source,
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
                # El HTML sin tocar: los enlaces al volcado viven en los
                # atributos (`href`, `src`), y quitar las etiquetas se los
                # lleva puestos. Tampoco se persiste.
                "content_html": (
                    contenido.text or ""
                    if (contenido := entrada.find(f"{_ATOM}content")) is not None
                    else ""
                ),
            },
        )


class MyBBForumAdapter:
    """Índice de threads recientes de un foro MyBB."""

    leak_type = LeakType.FORUM_POST

    def __init__(
        self,
        client: FeedHttpClient,
        name: str,
        base_urls: Sequence[str],
        syndication_path: str = SYNDICATION_PATH,
        fids: Sequence[str] = (),
    ) -> None:
        self.name = name
        self._client = client
        self._base_urls = tuple(u.rstrip("/") for u in base_urls if u.strip())
        self._path = syndication_path
        #: Subforos a consultar además del índice global. Cada uno trae SUS
        #: últimos 50 threads, así que suman ventana en vez de repetirla.
        self._fids = tuple(f.strip() for f in fids if f.strip())
        #: Dominio que respondió, para absolutizar enlaces relativos.
        self._active_base: str | None = None

    def fetch(self, since: datetime | None) -> Iterable[RawItem]:
        """Trae el índice global y, si hay subforos configurados, los de cada uno.

        El recorte incremental lo hace el runner sobre el item normalizado: el
        feed devuelve unas decenas de threads, no hace falta filtrar antes.
        """
        if not self._base_urls:
            return

        ultimo_error: Exception | None = None
        fallas: list[str] = []
        for base in self._base_urls:
            try:
                xml = self._client.get_text(f"{base}{self._path}")
            except Exception as exc:
                motivo = describe_cause(exc)
                logger.warning("El dominio %s no respondió: %s", base, motivo)
                fallas.append(f"{base} → {motivo}")
                ultimo_error = exc
                continue

            self._active_base = base
            # Un thread aparece en el índice global y otra vez en el de su
            # subforo. Se deduplica acá y no en el storage para que la
            # telemetría diga cuántos threads distintos vimos, no cuántas
            # veces los vimos.
            vistos: set[str] = set()
            for item in self._parse(xml):
                clave = self._clave(item)
                if clave in vistos:
                    continue
                vistos.add(clave)
                yield item

            yield from self._fetch_subforos(base, vistos)
            return

        # Se detalla candidato por candidato: "no respondió ninguno" no alcanza
        # para decidir si el foro se mudó (rechazo/DNS) o si nos bloquearon
        # (403), y es la diferencia entre buscar dominio nuevo o no.
        raise RuntimeError(
            f"Ningún dominio de {self.name} respondió. {'; '.join(fallas)}. "
            "¿Cambió de dominio o fue incautado?"
        ) from ultimo_error

    @staticmethod
    def _clave(item: RawItem) -> str:
        """Identidad del thread. La URL es lo único estable entre feeds."""
        payload = item.payload
        return str(payload.get("link") or payload.get("id") or payload.get("title") or "")

    def _fetch_subforos(self, base: str, vistos: set[str]) -> Iterable[RawItem]:
        """Suma la ventana de cada subforo configurado.

        Cada subforo trae sus últimos 50 threads: uno activo cubre días donde
        el índice global cubre horas, y uno tranquilo, años.

        Un subforo que falla **no tumba la fuente**: se registra y se sigue con
        los demás, igual que un feed caído no tumba la corrida. Los ids se
        cargan a mano y pueden quedar viejos si el foro reordena sus secciones.
        """
        for fid in self._fids:
            url = f"{base}{self._path}&fid={fid}"
            try:
                xml = self._client.get_text(url)
            except Exception as exc:
                logger.warning(
                    "El subforo %s de %s no respondió: %s", fid, self.name, describe_cause(exc)
                )
                continue

            for item in self._parse(xml):
                clave = self._clave(item)
                if clave in vistos:
                    continue
                vistos.add(clave)
                yield item

    def _parse(self, xml: str) -> Iterable[RawItem]:
        """Parsea el Atom de este foro."""
        return parse_atom(xml, source=self.name)

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
            # Los enlaces salen del HTML crudo, no del texto plano.
            download_links=extract_download_links(
                payload.get("content_html"), payload.get("content")
            ),
            # Se pasa el cuerpo para que la capa de relevancia lo mire. El
            # runner lo descarta antes de persistir porque la fuente está
            # marcada `high_pii_surface`.
            description=payload.get("content") or None,
        )
