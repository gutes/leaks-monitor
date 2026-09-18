"""Los dos carriles de la adyacencia.

## Por qué hay dos

`adjacent_actors` tuvo una sola población hasta el 2026-09-18: bandas de
ransomware con data leak site, que es lo único que trae ransomware.live. El
score está calibrado sobre esa cadencia —volumen y tendencia suponen un goteo
de víctimas publicadas— y el backtest que lo valida se corrió sobre ella.

Los foros y Telegram traen otra cosa: brokers de acceso y grupos hacktivistas.
Un post vendiendo acceso a cinco sistemas es **un post**, no cinco víctimas, y
un grupo que defacea treinta sitios en una tarde no está "acelerando" en el
sentido que el score mide.

Mezclarlos en un ranking único haría que un vendedor ruidoso le ganara a
LockBit, y que el mismo número significara cosas distintas según la fila. Por
eso se separan: la UI los muestra aparte y cada carril se lee con su propia
vara.

## Cómo se decide

Por la fuente de las víctimas, no por el nombre del actor. Un actor con al
menos una víctima publicada en un DLS es `dls` aunque también venda en un foro:
ahí el score sí está calibrado y es la lectura más informativa.
"""

from __future__ import annotations

from collections.abc import Iterable

from leaks.adjacency.registries import SOURCE_RANSOMWARE_LIVE

#: Banda con data leak site. El universo donde el score está medido.
KIND_DLS = "dls"
#: Broker de acceso, vendedor de foro o grupo hacktivista.
KIND_FORO = "foro"

#: Fuentes que publican víctimas al modo DLS.
FUENTES_DLS = frozenset({SOURCE_RANSOMWARE_LIVE})

ETIQUETAS: dict[str, str] = {
    KIND_DLS: "Banda con sitio de extorsión",
    KIND_FORO: "Foro / Telegram",
}


def kind_for(sources: Iterable[str]) -> str:
    """El carril de un actor, dadas las fuentes de sus víctimas."""
    return KIND_DLS if FUENTES_DLS.intersection(sources) else KIND_FORO


def etiqueta(kind: str) -> str:
    return ETIQUETAS.get(kind, kind)
