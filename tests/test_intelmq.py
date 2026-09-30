"""Tests de la exportación al formato de datos de IntelMQ.

El test que más importa es el del vocabulario: si mañana se suma un tipo a la
taxonomía del CERT.ar y nadie lo mapea, el evento sale con un
`classification.type` que IntelMQ rechaza —y se descubre del lado del CERT, no
acá—. Ese caso falla en esta suite.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from leaks.export.intelmq import (
    CERT_A_RSIT,
    RSIT_TAXONOMIAS,
    RSIT_TIPOS,
    SIN_CLASIFICAR,
    clasificar,
    to_intelmq,
    to_ndjson,
)
from leaks.taxonomy.cert_ar import TAXONOMIA

#: La regla que IntelMQ aplica a los nombres de campo, incluido `extra.`.
CLAVE_VALIDA = re.compile(r"^[a-z_][a-z_0-9]+(\.[a-z_0-9]+)*$")

AHORA = datetime(2026, 9, 30, 14, 5, 30, tzinfo=UTC)


class Alerta:
    """Doble de `AlertItemOut`: los mismos campos, sin arrastrar la API."""

    def __init__(self, **campos: object) -> None:
        base: dict[str, object] = {
            "dedup_hash": "abc123",
            "source": "darkforums",
            "leak_type": "forum_post",
            "victim_name": "Organismo Ejemplo",
            "victim_domain": "organismo-ejemplo.gob.ar",
            "sector": "gobierno_nacional",
            "actor": "LockBit3",
            "severity": "critical",
            "ar_match_reason": ["watchlist", "tld_ar"],
            "occurred_at": datetime(2026, 9, 28, 10, 0, tzinfo=UTC),
            "occurred_at_basis": "feed",
            "first_seen_at": AHORA,
            "backfill": False,
            "raw_ref": "https://ejemplo.test/thread-123",
            "taxonomy_type": "acceso_no_autorizado",
        }
        base.update(campos)
        for k, v in base.items():
            setattr(self, k, v)


# -- El vocabulario, que es lo que no puede romperse -------------------------


def test_todos_los_tipos_del_cert_tienen_mapeo():
    """Sumar un tipo a la taxonomía sin mapearlo tiene que fallar acá."""
    slugs = {t.slug for t in TAXONOMIA}
    assert slugs - set(CERT_A_RSIT) == set(), "hay tipos del CERT.ar sin par RSIT"


def test_no_hay_mapeos_de_tipos_que_ya_no_existen():
    slugs = {t.slug for t in TAXONOMIA}
    assert set(CERT_A_RSIT) - slugs == set(), "sobran entradas en el mapeo"


@pytest.mark.parametrize("slug", sorted(CERT_A_RSIT))
def test_cada_par_esta_dentro_del_vocabulario_de_intelmq(slug: str):
    rsit = CERT_A_RSIT[slug]
    assert rsit.taxonomy in RSIT_TAXONOMIAS, f"{slug}: taxonomía inválida"
    assert rsit.type in RSIT_TIPOS, f"{slug}: tipo inválido"


def test_ransomware_va_como_data_leak():
    """Decisión del líder técnico: IntelMQ no tiene un tipo `ransomware`.

    Lo que observamos es la publicación de datos robados, no una infección que
    detectamos. El par es canónico en RSIT, así que ningún bot de la cadena lo
    va a reescribir.
    """
    rsit = clasificar("ransomware")
    assert (rsit.taxonomy, rsit.type) == ("information-content-security", "data-leak")


def test_un_slug_desconocido_no_explota():
    """Un tipo sin mapear no puede cortar la exportación entera."""
    assert clasificar("algo_que_no_existe") == SIN_CLASIFICAR
    assert clasificar(None) == SIN_CLASIFICAR


# -- La forma del evento -----------------------------------------------------


def test_los_campos_van_a_su_lugar_de_rsit():
    evento = to_intelmq(Alerta())
    assert evento["classification.taxonomy"] == "information-content-security"
    assert evento["classification.type"] == "unauthorised-information-access"
    # El identificador va en minúsculas, como pide la especificación.
    assert evento["classification.identifier"] == "lockbit3"
    assert evento["source.fqdn"] == "organismo-ejemplo.gob.ar"
    # "the target (organization) of an attack".
    assert evento["event_description.target"] == "Organismo Ejemplo"
    assert evento["event_description.url"] == "https://ejemplo.test/thread-123"
    assert evento["source.geolocation.cc"] == "AR"
    assert evento["feed.name"] == "leaks-monitor"


def test_las_fechas_van_en_utc_con_el_formato_exigido():
    evento = to_intelmq(Alerta())
    assert evento["time.observation"] == "2026-09-30T14:05:30+00:00"
    assert evento["time.source"] == "2026-09-28T10:00:00+00:00"
    # Ida y vuelta como lo haría un consumidor: ISO-8601 con zona.
    # `FORMATO_FECHA` lleva el `+00:00` literal y no `%z` a propósito —UTC es la
    # única zona que IntelMQ acepta—, así que el que reconstruye el aware es
    # `fromisoformat`, no `strptime` con ese mismo formato.
    vuelta = datetime.fromisoformat(evento["time.observation"])
    assert vuelta.tzinfo is not None and vuelta.utcoffset() == timedelta(0)
    assert vuelta == AHORA


def test_una_fecha_en_otra_zona_se_normaliza_a_utc():
    art = timezone(timedelta(hours=-3))
    evento = to_intelmq(Alerta(first_seen_at=datetime(2026, 9, 30, 11, 5, 30, tzinfo=art)))
    assert evento["time.observation"] == "2026-09-30T14:05:30+00:00"


def test_sin_fecha_de_ocurrencia_el_campo_no_viaja():
    """La postura del pipeline es no inventar fechas; acá tampoco."""
    evento = to_intelmq(Alerta(occurred_at=None))
    assert "time.source" not in evento
    assert "extra.occurred_at_basis" not in evento


def test_un_nombre_que_no_es_dominio_no_va_a_source_fqdn():
    """IntelMQ valida el campo y rechazaría el evento entero."""
    evento = to_intelmq(Alerta(victim_domain=None))
    assert "source.fqdn" not in evento
    evento = to_intelmq(Alerta(victim_domain="Ministerio de Algo"))
    assert "source.fqdn" not in evento


def test_una_referencia_que_no_es_url_no_va():
    evento = to_intelmq(Alerta(raw_ref="thread-123"))
    assert "event_description.url" not in evento


def test_nunca_se_emite_raw():
    """Se define como base64 de la línea original, y la nuestra es un volcado."""
    evento = to_intelmq(Alerta())
    assert "raw" not in evento


def test_el_slug_del_cert_viaja_aunque_la_taxonomia_se_corra():
    """El par canónico puede mover el evento de taxonomía; el dato no se pierde."""
    evento = to_intelmq(Alerta(taxonomy_type="ransomware"))
    assert evento["classification.taxonomy"] == "information-content-security"
    assert evento["extra.taxonomy_cert"] == "ransomware"


def test_las_claves_extra_cumplen_la_regla_de_intelmq():
    evento = to_intelmq(Alerta())
    malas = [k for k in evento if not CLAVE_VALIDA.match(k)]
    assert malas == [], f"claves que IntelMQ rechazaría: {malas}"


def test_ningun_valor_viaja_en_null():
    """Un campo ausente se omite: un `null` falla la validación del tipo."""
    evento = to_intelmq(Alerta(occurred_at=None, actor=None, sector=None, victim_domain=None))
    assert [k for k, v in evento.items() if v is None] == []


# -- NDJSON ------------------------------------------------------------------


def test_ndjson_es_un_evento_por_linea():
    salida = to_ndjson([Alerta(dedup_hash="a"), Alerta(dedup_hash="b")])
    lineas = salida.strip().split("\n")
    assert len(lineas) == 2
    assert [json.loads(x)["extra.dedup_hash"] for x in lineas] == ["a", "b"]


def test_ndjson_vacio_no_deja_una_linea_en_blanco():
    assert to_ndjson([]) == ""


def test_ndjson_no_escapa_los_acentos():
    salida = to_ndjson([Alerta(victim_name="Comisión Ejemplo")])
    assert "Comisión" in salida
