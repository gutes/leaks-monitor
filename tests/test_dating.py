"""Tests del fechado: cuándo ocurrió un leak, no cuándo lo vimos.

La regla que se protege acá es una sola: **si no se puede fechar, se dice "sin
fecha"**. Una fecha inventada contamina el orden del tablero, las alertas y
cualquier cálculo de recencia, y encima es creíble.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from leaks.extraction.dating import (
    EPOCH_SENTINEL,
    MIN_YEAR,
    DateBasis,
    Freshness,
    classify,
    from_feed,
    is_sane,
    newest_sane,
    resolve,
    year_from_text,
)

AHORA = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


class TestGuardas:
    def test_el_futuro_no_es_creible(self) -> None:
        """Un feed con el reloj mal, o un parseo que se comió el año."""
        assert is_sane(AHORA + timedelta(days=30), now=AHORA) is False

    def test_un_dia_de_tolerancia(self) -> None:
        """Los husos horarios de los feeds no son de fiar."""
        assert is_sane(AHORA + timedelta(hours=12), now=AHORA) is True

    def test_lo_anterior_a_2010_es_basura_de_parseo(self) -> None:
        assert is_sane(datetime(2009, 12, 31, tzinfo=UTC), now=AHORA) is False
        assert is_sane(datetime(MIN_YEAR, 1, 1, tzinfo=UTC), now=AHORA) is True

    def test_el_centinela_epoch_se_descarta(self) -> None:
        """Hudson Rock manda 1970-01-01 cuando no tiene el dato."""
        assert is_sane(EPOCH_SENTINEL, now=AHORA) is False

    def test_none_no_es_creible(self) -> None:
        assert is_sane(None, now=AHORA) is False


class TestFechaDelFeed:
    def test_toma_el_primer_campo_creible(self) -> None:
        payload = {"published": None, "discovered": "2026-05-01T00:00:00Z"}
        assert from_feed(payload, "published", "discovered", now=AHORA) == datetime(
            2026, 5, 1, tzinfo=UTC
        )

    def test_saltea_los_no_creibles(self) -> None:
        """El orden es la preferencia del adapter, pero la guarda manda."""
        payload = {"attackdate": "2030-01-01T00:00:00Z", "discovered": "2026-05-01T00:00:00Z"}
        assert from_feed(payload, "attackdate", "discovered", now=AHORA) == datetime(
            2026, 5, 1, tzinfo=UTC
        )

    def test_sin_campos_usables(self) -> None:
        assert from_feed({"otro": "x"}, "discovered", now=AHORA) is None


class TestMasReciente:
    def test_gana_la_mas_nueva(self) -> None:
        assert newest_sane("2024-01-01T00:00:00Z", "2026-05-26T16:57:25Z", now=AHORA) == datetime(
            2026, 5, 26, 16, 57, 25, tzinfo=UTC
        )

    def test_el_centinela_no_gana_ni_estorba(self) -> None:
        """El caso real de Hudson Rock: usuarios en epoch, empleados con fecha."""
        assert newest_sane(
            "1970-01-01T00:00:00.000Z", "2026-05-26T16:57:25.000Z", now=AHORA
        ) == datetime(2026, 5, 26, 16, 57, 25, tzinfo=UTC)

    def test_solo_centinelas_es_sin_fecha(self) -> None:
        assert newest_sane("1970-01-01T00:00:00.000Z", now=AHORA) is None


class TestAnioEnElTexto:
    def test_titulo_de_foro(self) -> None:
        """`[2.1TB][2026] Empresa Database` — el patrón que usan los foros."""
        assert year_from_text("[2.1TB][2026] Empresa Database", now=AHORA) == datetime(
            2026, 1, 1, tzinfo=UTC
        )

    def test_ante_un_rango_gana_el_mas_reciente(self) -> None:
        """`datos 2019-2024` — el año alto es el que fecha el volcado."""
        assert year_from_text("mix datos 2019-2024", now=AHORA) == datetime(2024, 1, 1, tzinfo=UTC)

    def test_ignora_años_imposibles(self) -> None:
        assert year_from_text("archivo 1998 legacy", now=AHORA) is None
        assert year_from_text("proyeccion 2031", now=AHORA) is None

    def test_sin_año_no_inventa(self) -> None:
        assert year_from_text("Empresa Database", None, now=AHORA) is None


class TestCascada:
    def test_gana_el_feed(self) -> None:
        fecha, base = resolve(feed_date=datetime(2025, 3, 1, tzinfo=UTC), now=AHORA)
        assert base is DateBasis.FEED
        assert fecha == datetime(2025, 3, 1, tzinfo=UTC)

    def test_sin_feed_usa_el_texto(self) -> None:
        fecha, base = resolve(texts=("[2024] Empresa dump",), now=AHORA)
        assert base is DateBasis.TEXTO
        assert fecha == datetime(2024, 1, 1, tzinfo=UTC)

    def test_la_corroboracion_va_ultima(self) -> None:
        """Es la señal más indirecta: depende de emparejar bien entre fuentes."""
        fecha, base = resolve(corroborated=datetime(2023, 6, 1, tzinfo=UTC), now=AHORA)
        assert base is DateBasis.CORROBORACION
        assert fecha == datetime(2023, 6, 1, tzinfo=UTC)

    def test_el_texto_le_gana_a_la_corroboracion(self) -> None:
        _, base = resolve(
            texts=("[2024] dump",), corroborated=datetime(2023, 6, 1, tzinfo=UTC), now=AHORA
        )
        assert base is DateBasis.TEXTO

    def test_sin_nada_no_inventa(self) -> None:
        """El corazón del arreglo: nunca `now()`."""
        fecha, base = resolve(now=AHORA)
        assert fecha is None
        assert base is DateBasis.SIN_DATO

    def test_una_fecha_de_feed_no_creible_cae_a_la_siguiente_señal(self) -> None:
        fecha, base = resolve(feed_date=EPOCH_SENTINEL, texts=("[2025] dump",), now=AHORA)
        assert base is DateBasis.TEXTO
        assert fecha == datetime(2025, 1, 1, tzinfo=UTC)


class TestClasificacion:
    @pytest.mark.parametrize(
        ("dias", "esperado"),
        [(0, Freshness.RECIENTE), (29, Freshness.RECIENTE), (31, Freshness.HISTORICO)],
    )
    def test_umbral(self, dias: int, esperado: Freshness) -> None:
        assert classify(AHORA - timedelta(days=dias), fresh_days=30, now=AHORA) is esperado

    def test_sin_fecha_no_es_ni_reciente_ni_historico(self) -> None:
        """La tercera categoría existe porque fingir cualquiera de las otras miente."""
        assert classify(None, fresh_days=30, now=AHORA) is Freshness.SIN_FECHA


class TestUnHallazgoSinFechaLaAdquiere:
    """La migración limpió las fechas inventadas de Hudson Rock. Sin esto,
    esas filas quedaban sin fecha para siempre: el upsert solo refresca
    `last_seen_at` y nunca volvía a fecharlas."""

    def test_adquiere_la_fecha_en_una_corrida_posterior(
        self, repository: object, session_factory: object
    ) -> None:
        from leaks.storage.models import FindingRow
        from tests.conftest import make_finding

        sin_fecha = make_finding().model_copy(update={"occurred_at": None})
        repository.upsert_many([sin_fecha])  # type: ignore[attr-defined]

        con_fecha = make_finding().model_copy(
            update={
                "occurred_at": datetime(2026, 5, 26, tzinfo=UTC),
                "occurred_at_basis": DateBasis.FEED,
            }
        )
        assert con_fecha.dedup_hash == sin_fecha.dedup_hash
        repository.upsert_many([con_fecha])  # type: ignore[attr-defined]

        with session_factory() as session:  # type: ignore[operator]
            fila = session.query(FindingRow).one()
        assert fila.occurred_at is not None
        assert fila.occurred_at.year == 2026
        assert fila.occurred_at_basis == "feed"

    def test_no_pisa_una_fecha_que_ya_estaba(
        self, repository: object, session_factory: object
    ) -> None:
        from leaks.storage.models import FindingRow
        from tests.conftest import make_finding

        primera = make_finding().model_copy(
            update={"occurred_at": datetime(2023, 1, 1, tzinfo=UTC)}
        )
        repository.upsert_many([primera])  # type: ignore[attr-defined]

        segunda = make_finding().model_copy(
            update={"occurred_at": datetime(2026, 1, 1, tzinfo=UTC)}
        )
        repository.upsert_many([segunda])  # type: ignore[attr-defined]

        with session_factory() as session:  # type: ignore[operator]
            fila = session.query(FindingRow).one()
        assert fila.occurred_at.year == 2023, "la primera fecha manda"
