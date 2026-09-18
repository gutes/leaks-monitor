"""Tests del sondeo regional.

Función pura sobre items ya normalizados: ni red ni base. Lo que se verifica es
el reparto — argentino, regional, sin atribuir — y que las muestras no filtren
nada.
"""

from __future__ import annotations

from datetime import UTC, datetime

from leaks.adjacency.probe import probe
from leaks.domain.models import LeakType, NormalizedItem
from leaks.relevance.watchlist import build_watchlist

AHORA = datetime(2026, 9, 18, tzinfo=UTC)
WATCHLIST = build_watchlist(())


def item(nombre: str, *, actor: str | None = None) -> NormalizedItem:
    return NormalizedItem(
        source="darkforums",
        leak_type=LeakType.FORUM_POST,
        victim_name=nombre,
        discovered_at=AHORA,
        actor=actor,
    )


def test_reparte_entre_argentino_regional_y_resto():
    reporte = probe(
        [
            ("darkforums", item("dump de anses.gob.ar")),
            ("darkforums", item("acceso a sii.cl")),
            ("telegram", item("selling fresh combos 2026")),
        ],
        watchlist=WATCHLIST,
    )
    assert reporte.vistos == 3
    assert reporte.argentinos == 1
    assert reporte.detectados == 1
    assert reporte.descartados == 1


def test_un_item_argentino_nunca_cuenta_como_regional():
    """Argentina es el sujeto, no la región: no puede entrar por las dos puertas."""
    reporte = probe(
        [("darkforums", item("leak de anses.gob.ar y de sii.cl"))],
        watchlist=WATCHLIST,
    )
    assert reporte.argentinos == 1
    assert reporte.detectados == 0
    assert reporte.por_pais == {}


def test_cuenta_por_pais_fuente_y_senal():
    reporte = probe(
        [
            ("darkforums", item("dump de banco.com.br")),
            ("telegram", item("Brasil: acceso a prefeitura.gov.br")),
            ("telegram", item("dump de sii.cl")),
        ],
        watchlist=WATCHLIST,
    )
    assert reporte.por_pais == {"BR": 2, "CL": 1}
    assert reporte.por_fuente == {"telegram": 2, "darkforums": 1}
    assert reporte.por_senal["tld"] == 3
    assert reporte.por_senal["nombre"] == 1


def test_solo_cuenta_actores_que_no_estan_en_la_tabla():
    reporte = probe(
        [
            ("darkforums", item("dump de banco.com.br", actor="LockBit")),
            ("darkforums", item("dump de sii.cl", actor="vendedor_nuevo")),
        ],
        watchlist=WATCHLIST,
        actores_conocidos=frozenset({"lockbit"}),
    )
    assert reporte.actores_nuevos == ("vendedor_nuevo",)


def test_las_muestras_se_topean():
    items = [("darkforums", item(f"dump{i} de sii.cl")) for i in range(30)]
    reporte = probe(items, watchlist=WATCHLIST, max_muestras=5)
    assert reporte.detectados == 30
    assert len(reporte.muestras) == 5


def test_la_muestra_pasa_por_el_redactor():
    reporte = probe(
        [("darkforums", item("dump de sii.cl contacto juan@ejemplo.cl"))],
        watchlist=WATCHLIST,
    )
    assert "juan@ejemplo.cl" not in reporte.muestras[0].titulo


def test_sin_items_no_explota():
    reporte = probe([], watchlist=WATCHLIST)
    assert reporte.vistos == 0
    assert reporte.descartados == 0
