"""Tests del scheduler: la lógica de "cuándo toca", sin dejar correr el reloj."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from leaks.config import Settings
from leaks.pipeline.runner import RunReport
from leaks.pipeline.scheduler import next_run_at, run_forever


class TestNextRunAt:
    def test_si_todavia_no_paso_la_hora_es_hoy(self) -> None:
        ahora = datetime(2026, 8, 14, 1, 0, tzinfo=UTC)
        assert next_run_at(ahora, "03:00") == datetime(2026, 8, 14, 3, 0, tzinfo=UTC)

    def test_si_ya_paso_la_hora_es_mañana(self) -> None:
        ahora = datetime(2026, 8, 14, 5, 0, tzinfo=UTC)
        assert next_run_at(ahora, "03:00") == datetime(2026, 8, 15, 3, 0, tzinfo=UTC)

    def test_justo_a_la_hora_va_al_dia_siguiente(self) -> None:
        """Evita correr dos veces si el bucle vuelve en el mismo segundo."""
        ahora = datetime(2026, 8, 14, 3, 0, tzinfo=UTC)
        assert next_run_at(ahora, "03:00") == datetime(2026, 8, 15, 3, 0, tzinfo=UTC)


class TestRunForever:
    def _reporte(self) -> RunReport:
        ahora = datetime.now(UTC)
        return RunReport(started_at=ahora, finished_at=ahora)

    def test_corre_una_vez_por_dia(self) -> None:
        corridas: list[int] = []
        dormidas: list[float] = []
        instante = datetime(2026, 8, 14, 1, 0, tzinfo=UTC)

        def now_fn() -> datetime:
            # Cada iteración avanza el reloj hasta después de la corrida.
            nonlocal instante
            return instante

        def sleep_fn(segundos: float) -> None:
            nonlocal instante
            dormidas.append(segundos)
            instante += timedelta(seconds=segundos + 1)

        def run_once() -> RunReport:
            corridas.append(1)
            return self._reporte()

        run_forever(run_once, daily_at="03:00", now_fn=now_fn, sleep_fn=sleep_fn, max_iterations=3)

        assert len(corridas) == 3
        # La primera espera 2 h; las siguientes, un día completo.
        assert dormidas[0] == pytest.approx(2 * 3600)
        assert dormidas[1] == pytest.approx(24 * 3600 - 1)

    def test_una_corrida_que_falla_no_corta_el_bucle(self) -> None:
        """Un scheduler que se muere deja de monitorear justo cuando hace falta."""
        intentos: list[int] = []

        def run_once() -> RunReport:
            intentos.append(1)
            raise RuntimeError("la corrida explotó")

        iteraciones = run_forever(
            run_once,
            daily_at="03:00",
            now_fn=lambda: datetime(2026, 8, 14, 1, 0, tzinfo=UTC),
            sleep_fn=lambda _s: None,
            max_iterations=2,
        )

        assert iteraciones == 2
        assert len(intentos) == 2


class TestValidacionDeHora:
    @pytest.mark.parametrize("valor", ["25:00", "03:99", "tres", "3", ""])
    def test_hora_invalida_no_arranca(self, valor: str) -> None:
        """Falla al arrancar, no a las 3 AM del primer run."""
        with pytest.raises(ValueError, match="daily_run_at"):
            Settings(daily_run_at=valor)

    def test_hora_valida(self) -> None:
        assert Settings(daily_run_at="23:59").daily_run_at == "23:59"
