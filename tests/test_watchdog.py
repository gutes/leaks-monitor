"""Tests del watchdog: avisar cuando el propio monitoreo se calla.

El caso que motivó el módulo: el pipeline estuvo seis días caído y el tablero
seguía en verde, porque la última corrida —de la semana anterior— había andado.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from leaks.pipeline.watchdog import StaleSource, build_notice, stale_sources

AHORA = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
UMBRAL = timedelta(hours=26)


class TestDeteccion:
    def test_una_fuente_al_dia_no_se_reporta(self) -> None:
        ultimos = {"ransomware.live": AHORA - timedelta(hours=3)}
        assert stale_sources(ultimos, now=AHORA, max_silence=UMBRAL) == ()

    def test_una_fuente_callada_se_reporta(self) -> None:
        """El caso real: seis días sin correr y el tablero en verde."""
        ultimos = {"darkforums": datetime(2026, 8, 25, 18, 0, tzinfo=UTC)}
        (vencida,) = stale_sources(ultimos, now=AHORA, max_silence=UMBRAL)

        assert vencida.source == "darkforums"
        assert vencida.silence_hours == 162.0

    def test_justo_en_el_umbral_todavia_no_avisa(self) -> None:
        """26 h y no 24 para que una corrida diaria un rato tarde no sea falla."""
        ultimos = {"ransomlook": AHORA - UMBRAL}
        assert stale_sources(ultimos, now=AHORA, max_silence=UMBRAL) == ()

    def test_pasado_el_umbral_avisa(self) -> None:
        ultimos = {"ransomlook": AHORA - UMBRAL - timedelta(minutes=1)}
        assert len(stale_sources(ultimos, now=AHORA, max_silence=UMBRAL)) == 1

    def test_una_fuente_que_nunca_anduvo_cuenta_como_callada(self) -> None:
        """ "Nunca anduvo" es justamente lo que hay que avisar, no ignorar."""
        (vencida,) = stale_sources({"breachforums": None}, now=AHORA, max_silence=UMBRAL)

        assert vencida.last_ok_at is None
        assert "sin ninguna corrida exitosa" in vencida.describe()

    def test_ordena_por_silencio_acumulado(self) -> None:
        ultimos = {
            "a": AHORA - timedelta(hours=30),
            "b": AHORA - timedelta(days=7),
            "c": AHORA - timedelta(hours=48),
        }
        assert [v.source for v in stale_sources(ultimos, now=AHORA, max_silence=UMBRAL)] == [
            "b",
            "c",
            "a",
        ]


class TestAviso:
    def test_el_aviso_dice_el_umbral_y_las_fuentes(self) -> None:
        """Sin el umbral, quien lo recibe no sabe por qué le llegó."""
        vencidas = (
            StaleSource(
                source="darkforums",
                last_ok_at=datetime(2026, 8, 25, 18, 0, tzinfo=UTC),
                silence=timedelta(hours=162),
            ),
        )
        texto = build_notice(vencidas, UMBRAL)

        assert "26 h" in texto
        assert "darkforums" in texto
        assert "2026-08-25 18:00" in texto
