"""Tests de la detección de país para la adyacencia.

El criterio bajo prueba es el que separa esta capa de la relevancia argentina:
**una señal débil no alcanza**. La mayoría de estos tests son negativos a
propósito — lo que hay que garantizar no es que detecte Brasil, que es fácil,
sino que NO invente un país cuando sólo hay una palabra suelta.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from leaks.adjacency.country_detect import (
    SIGNAL_NOMBRE,
    SIGNAL_TLD,
    SIGNAL_WATCHLIST,
    detect,
)
from leaks.adjacency.regional_watchlist import RegionalWatchlists
from leaks.domain.models import LeakType, NormalizedItem
from leaks.relevance.watchlist import WatchlistSector, build_watchlist

AHORA = datetime(2026, 9, 18, tzinfo=UTC)


def item(nombre: str, *, descripcion: str | None = None, dominio: str | None = None):
    return NormalizedItem(
        source="darkforums",
        leak_type=LeakType.FORUM_POST,
        victim_name=nombre,
        victim_domain=dominio,
        discovered_at=AHORA,
        description=descripcion,
    )


# -- Lo que sí se detecta ---------------------------------------------------


def test_dominio_con_cctld_alcanza_solo():
    match = detect(item("Database leak", dominio="ministerio.gov.br"))
    assert match is not None
    assert match.code == "BR"
    assert match.signals == (SIGNAL_TLD,)
    assert match.domain == "ministerio.gov.br"


def test_dominio_en_texto_libre_tambien_cuenta():
    # Los foros no traen `victim_domain`: el dominio vive en el título.
    match = detect(item("Selling access to sii.cl full database"))
    assert match is not None
    assert match.code == "CL"


def test_el_nombre_corrobora_y_queda_registrado():
    match = detect(item("[MEXICO] leak de gob.mx", descripcion="dump mexicano"))
    assert match is not None
    assert match.code == "MX"
    assert set(match.signals) == {SIGNAL_TLD, SIGNAL_NOMBRE}


def test_la_watchlist_regional_es_senal_fuerte_sin_cctld():
    # Un dominio `.com` puede ser de infraestructura crítica de un país: si la
    # watchlist de ese país lo declara, eso ancla igual que el ccTLD.
    sector = WatchlistSector(
        name="energia",
        label="Energía",
        critical=True,
        domains=frozenset({"electrica-ejemplo.com"}),
        keywords=(),
    )
    wls = RegionalWatchlists({"BR": build_watchlist((sector,))})
    match = detect(item("dump de electrica-ejemplo.com"), watchlists=wls)
    assert match is not None
    assert match.code == "BR"
    assert SIGNAL_WATCHLIST in match.signals


# -- Lo que NO se detecta, que es el punto ----------------------------------


def test_el_nombre_del_pais_solo_no_alcanza():
    """El caso que inunda la tabla si se afloja."""
    assert detect(item("Selling fresh combos from Brasil and Chile")) is None


def test_etiqueta_de_foro_sola_tampoco():
    assert detect(item("[BRAZIL] 2M lines fresh")) is None


def test_dominios_de_varios_paises_es_ambiguo():
    # Un combo LATAM no es una víctima por país: es un combo.
    assert detect(item("combo: banco.com.br, sii.cl, sat.gob.mx")) is None


def test_el_texto_desempata_cuando_senala_a_uno_solo():
    match = detect(item("Brasil: dump de banco.com.br con backup en sii.cl"))
    assert match is not None
    assert match.code == "BR"


def test_un_archivo_python_no_es_paraguay():
    """`.py` colisiona con la extensión de Python; por eso PY exige 2do nivel."""
    assert detect(item("leaked source: exploit.py and dumper.py")) is None


def test_paraguay_con_segundo_nivel_si():
    match = detect(item("access to hacienda.gov.py"))
    assert match is not None
    assert match.code == "PY"


def test_punto_co_generico_no_es_colombia():
    """`.co` se vende como genérico: sin segundo nivel no prueba nada."""
    assert detect(item("database from startup.co")) is None


def test_colombia_con_segundo_nivel_si():
    match = detect(item("dump de dian.gov.co"))
    assert match is not None
    assert match.code == "CO"


def test_argentina_no_es_region():
    """Argentina es el sujeto, no la región: no está en el catálogo."""
    assert detect(item("SIPA 38M databases de anses.gob.ar")) is None


def test_item_sin_nada_no_inventa():
    assert detect(item("Selling fresh database 2026")) is None


@pytest.mark.parametrize(
    ("texto", "esperado"),
    [
        ("dump de sunat.gob.pe", "PE"),
        ("acceso a impuestos.gob.bo", "BO"),
        ("base de dgii.gov.do", "DO"),
        ("leak de hacienda.go.cr", "CR"),
        ("datos de mef.gob.pa", "PA"),
        ("dump de sat.gob.gt", "GT"),
        ("acceso a mh.gob.sv", "SV"),
        ("base de inss.gob.ni", "NI"),
        ("leak de sar.gob.hn", "HN"),
        ("datos de aduana.gob.cu", "CU"),
        ("dump de seniat.gob.ve", "VE"),
        ("base de sri.gob.ec", "EC"),
        ("acceso a dgi.gub.uy", "UY"),
    ],
)
def test_cada_pais_del_catalogo_se_reconoce(texto: str, esperado: str):
    match = detect(item(texto))
    assert match is not None and match.code == esperado


# -- El dominio del propio actor --------------------------------------------


def _con_actor(nombre: str, actor: str) -> NormalizedItem:
    return NormalizedItem(
        source="telegram",
        leak_type=LeakType.FORUM_POST,
        victim_name=nombre,
        discovered_at=AHORA,
        actor=actor,
    )


def test_el_dominio_propio_del_actor_no_es_victima():
    """Caso real del sondeo: el canal breachstars anunciando breachstars.hn."""
    assert detect(_con_actor("new domain: breachstars.hn", "breachstars")) is None


def test_pero_si_ataca_a_otro_del_mismo_pais_si_cuenta():
    match = detect(_con_actor("breachstars.hn y tambien sar.gob.hn", "breachstars"))
    assert match is not None and match.code == "HN"


def test_sin_actor_no_se_filtra_nada():
    match = detect(item("dump de sar.gob.hn"))
    assert match is not None and match.code == "HN"
