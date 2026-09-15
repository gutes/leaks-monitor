"""Tests de la taxonomía del CERT.ar y su clasificador.

La taxonomía es **transcripción** de la guía (IF-2023-69993929-APN-SSTI#JGM),
no criterio nuestro: estos tests la fijan contra el documento para que un
cambio accidental se note.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from leaks.domain.models import LeakType, NormalizedItem
from leaks.taxonomy.cert_ar import (
    CRITICIDAD_RANK,
    TAXONOMIA,
    CriticidadCert,
    get_tipo,
)
from leaks.taxonomy.classifier import REGLAS, SLUG_POR_DEFECTO, classify


def item(leak_type: LeakType, nombre: str = "Ministerio X") -> NormalizedItem:
    return NormalizedItem(
        source="prueba",
        leak_type=leak_type,
        victim_name=nombre,
        discovered_at=datetime(2026, 9, 15, tzinfo=UTC),
    )


class TestCatalogo:
    def test_tiene_la_taxonomia_completa(self) -> None:
        """31 tipos en 9 clasificaciones, como la tabla de la sección 4."""
        assert len(TAXONOMIA) == 31
        assert len({t.clasificacion for t in TAXONOMIA}) == 9

    def test_los_slugs_son_unicos(self) -> None:
        """El slug es lo que se persiste: dos iguales corromperían el dato."""
        slugs = [t.slug for t in TAXONOMIA]
        assert len(slugs) == len(set(slugs))

    @pytest.mark.parametrize(
        ("slug", "criticidad"),
        [
            # Muestreo de la tabla 5.1.1, un nivel de cada uno.
            ("apt", CriticidadCert.CRITICO),
            ("ransomware", CriticidadCert.ALTO),
            ("acceso_no_autorizado", CriticidadCert.ALTO),
            ("compromiso_de_cuenta", CriticidadCert.MEDIO),
            ("revelacion_de_informacion", CriticidadCert.MEDIO),
            ("spam", CriticidadCert.BAJO),
            ("sectores_no_criticos", CriticidadCert.BAJO),
        ],
    )
    def test_los_niveles_son_los_de_la_guia(self, slug: str, criticidad: CriticidadCert) -> None:
        tipo = get_tipo(slug)
        assert tipo is not None, f"falta el tipo {slug}"
        assert tipo.criticidad is criticidad

    def test_apt_es_el_unico_critico(self) -> None:
        """La guía reserva "Crítico" para un solo tipo."""
        criticos = [t.slug for t in TAXONOMIA if t.criticidad is CriticidadCert.CRITICO]
        assert criticos == ["apt"]

    def test_los_niveles_se_pueden_ordenar(self) -> None:
        assert CRITICIDAD_RANK["critico"] > CRITICIDAD_RANK["alto"] > CRITICIDAD_RANK["bajo"]

    def test_un_slug_desconocido_no_revienta(self) -> None:
        assert get_tipo("no-existe") is None
        assert get_tipo(None) is None


class TestClasificador:
    def test_ransomware(self) -> None:
        slug, base = classify(item(LeakType.RANSOMWARE))
        assert slug == "ransomware"
        assert base

    def test_infostealer_es_compromiso_de_cuenta(self) -> None:
        """Decisión del líder técnico: se clasifica lo que observamos.

        Un log de stealer es evidencia de credenciales de la organización en
        manos de terceros. Que atrás haya habido malware es probable, pero no
        lo vemos — y la guía pide clasificar según lo que motiva el reporte.
        """
        assert classify(item(LeakType.INFOSTEALER))[0] == "compromiso_de_cuenta"

    def test_foro_y_paste_son_acceso_no_autorizado(self) -> None:
        """ "Robo" no aplica: la guía lo define como intrusión FÍSICA."""
        assert classify(item(LeakType.FORUM_POST))[0] == "acceso_no_autorizado"
        assert classify(item(LeakType.PASTE))[0] == "acceso_no_autorizado"

    def test_repo_secret_es_revelacion_de_informacion(self) -> None:
        assert classify(item(LeakType.REPO_SECRET))[0] == "revelacion_de_informacion"

    def test_todas_las_reglas_apuntan_a_un_tipo_real(self) -> None:
        """Una regla con un slug inventado dejaría hallazgos sin clasificación."""
        for regla in REGLAS:
            assert get_tipo(regla.slug) is not None, f"{regla.slug} no está en la taxonomía"
        assert get_tipo(SLUG_POR_DEFECTO) is not None

    def test_todo_leak_type_queda_clasificado(self) -> None:
        """Ningún hallazgo puede quedar sin tipo: desaparecería del reporte."""
        for lt in LeakType:
            slug, base = classify(item(lt))
            assert get_tipo(slug) is not None
            assert base, "siempre hay que decir por qué"

    def test_la_clasificacion_explica_por_que(self) -> None:
        """Sin el motivo, revisar una clasificación dudosa es imposible."""
        _, base = classify(item(LeakType.INFOSTEALER))
        assert "credenciales" in base.lower()
