"""Extracción de enlaces a los datos filtrados.

Qué se busca: dónde dice el publicador que está el volcado —un magnet, un
`.torrent`, un archivo en un file host— y dónde puso la muestra.

**Nada de esto se descarga.** El prototipo solo registra la referencia para que
el investigador sepa dónde mirar; bajar el contenido es una decisión aparte,
con sus implicancias legales y de custodia, y no la toma una herramienta
automática.

Se clasifican en:

* `data`   — apunta al volcado completo (magnet, torrent, file host).
* `sample`  — apunta a una muestra (capturas que los foros suben a image hosts).
* `unknown` — parece una descarga pero no se puede afirmar cuál de las dos.

El frontend los muestra **no clickeables**: la URL es para copiar y pegar
deliberadamente, no para navegar de un click a un sitio de extorsión o a un
archivo con datos de terceros.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict

DownloadKind = Literal["data", "sample", "unknown"]

#: Tope de enlaces por hallazgo. Un thread puede pegar cincuenta espejos del
#: mismo archivo y no aportan nada.
MAX_LINKS = 12

#: Magnet: es inequívocamente el volcado.
_MAGNET = re.compile(r"magnet:\?xt=urn:[a-z0-9]+:[a-zA-Z0-9]{20,}[^\s\"'<>]*")

#: URLs http(s) comunes.
_URL = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)

#: File hosts donde se publica el volcado.
_DATA_HOSTS = (
    "mega.nz",
    "mega.io",
    "mediafire.com",
    "anonfiles.com",
    "gofile.io",
    "pixeldrain.com",
    "file.io",
    "bayfiles.com",
    "dropmefiles.com",
    "1fichier.com",
    "send.cm",
    "krakenfiles.com",
    "workupload.com",
    "temp.sh",
    "transfer.sh",
    "filetransfer.io",
    "buzzheavier.com",
)

#: Image hosts: lo que se sube ahí son capturas de muestra.
_SAMPLE_HOSTS = (
    "ibb.co",
    "imgur.com",
    "postimg.cc",
    "imgbb.com",
    "prnt.sc",
    "gyazo.com",
    "snipboard.io",
    "files.catbox.moe",
)

#: Extensiones que delatan un archivo de datos.
_DATA_EXTENSIONS = (".torrent", ".7z", ".zip", ".rar", ".tar.gz", ".sql", ".csv.gz")


class DownloadLink(BaseModel):
    """Una referencia a los datos filtrados. Se guarda, no se descarga."""

    model_config = ConfigDict(frozen=True)

    url: str
    kind: DownloadKind = "unknown"

    @property
    def host(self) -> str:
        """Host, para agrupar y para mostrar sin la URL entera."""
        sin_esquema = re.sub(r"^[a-z]+://", "", self.url, flags=re.IGNORECASE)
        return sin_esquema.split("/", 1)[0].split("?", 1)[0] or "—"


def _clasificar(url: str) -> DownloadKind:
    minuscula = url.lower()
    if minuscula.startswith("magnet:"):
        return "data"
    if any(host in minuscula for host in _SAMPLE_HOSTS):
        return "sample"
    if any(host in minuscula for host in _DATA_HOSTS):
        return "data"
    if any(minuscula.split("?")[0].endswith(ext) for ext in _DATA_EXTENSIONS):
        return "data"
    return "unknown"


def _es_interesante(url: str, kind: DownloadKind) -> bool:
    """Descarta el ruido: enlaces al propio foro, perfiles, imágenes de estilo."""
    # Un http suelto sin pinta de descarga no aporta: el enlace a la
    # publicación ya se guarda en `raw_ref`.
    return kind != "unknown"


def extract_download_links(*textos: str | None) -> tuple[DownloadLink, ...]:
    """Enlaces a datos o muestras encontrados en los textos dados.

    Se pasa el contenido crudo del feed (que después no se persiste). El
    resultado sí se guarda: son referencias, no datos.
    """
    encontrados: dict[str, DownloadLink] = {}

    for texto in textos:
        if not texto:
            continue

        for m in _MAGNET.finditer(texto):
            url = m.group(0)
            encontrados.setdefault(url, DownloadLink(url=url, kind="data"))

        for m in _URL.finditer(texto):
            url = m.group(0).rstrip(".,;")
            if url in encontrados:
                continue
            kind = _clasificar(url)
            if _es_interesante(url, kind):
                encontrados.setdefault(url, DownloadLink(url=url, kind=kind))

    # Los `data` primero: es lo que el investigador busca.
    ordenados = sorted(
        encontrados.values(), key=lambda link: (link.kind != "data", link.kind != "sample")
    )
    return tuple(ordenados[:MAX_LINKS])
