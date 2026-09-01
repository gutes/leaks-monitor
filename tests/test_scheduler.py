"""Tests del scheduler: la lógica de "cuándo toca", sin dejar correr el reloj."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest

from leaks.config import Settings
from leaks.pipeline.runner import RunReport
from leaks.pipeline.scheduler import next_run_at, plan_next, run_forever


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

        def run_once(*, only: Sequence[str] | None = None) -> RunReport:
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

        def run_once(*, only: Sequence[str] | None = None) -> RunReport:
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


class TestPlanNext:
    """Elegir el evento más próximo entre la corrida diaria y los sondeos."""

    AHORA = datetime(2026, 9, 1, 10, 0, tzinfo=UTC)

    def test_sin_sondeos_es_la_corrida_diaria(self) -> None:
        evento = plan_next(self.AHORA, "03:00", {})
        assert evento.is_full_run
        assert evento.at == datetime(2026, 9, 2, 3, 0, tzinfo=UTC)

    def test_un_sondeo_antes_de_la_diaria_gana(self) -> None:
        polls = {"darkforums": self.AHORA + timedelta(hours=2)}
        evento = plan_next(self.AHORA, "03:00", polls)
        assert evento.feeds == ("darkforums",)
        assert evento.at == self.AHORA + timedelta(hours=2)

    def test_un_sondeo_despues_de_la_diaria_no_gana(self) -> None:
        """La corrida completa incluye a la fuente: sondear después es al pedo."""
        polls = {"darkforums": datetime(2026, 9, 2, 5, 0, tzinfo=UTC)}
        assert plan_next(self.AHORA, "03:00", polls).is_full_run

    def test_empate_gana_la_corrida_completa(self) -> None:
        polls = {"darkforums": datetime(2026, 9, 2, 3, 0, tzinfo=UTC)}
        assert plan_next(self.AHORA, "03:00", polls).is_full_run

    def test_los_que_vencen_juntos_van_en_un_solo_evento(self) -> None:
        cuando = self.AHORA + timedelta(hours=1)
        polls = {"darkforums": cuando, "breachforums": cuando}
        evento = plan_next(self.AHORA, "03:00", polls)
        assert evento.feeds == ("breachforums", "darkforums")


class TestSondeos:
    """El bucle con dos cadencias."""

    def _reloj(self, inicio: datetime) -> tuple[object, object, list[float]]:
        instante = inicio
        dormidas: list[float] = []

        def now_fn() -> datetime:
            return instante

        def sleep_fn(segundos: float) -> None:
            nonlocal instante
            dormidas.append(segundos)
            instante += timedelta(seconds=segundos)

        return now_fn, sleep_fn, dormidas

    def test_sondea_entre_corridas_diarias(self) -> None:
        """El caso real: el foro rota su ventana en horas, la diaria no alcanza."""
        # 22:00, con la corrida completa a las 03:00: entran dos sondeos antes.
        now_fn, sleep_fn, dormidas = self._reloj(datetime(2026, 9, 1, 22, 0, tzinfo=UTC))
        pedidos: list[tuple[str, ...] | None] = []

        def run_once(*, only: Sequence[str] | None = None) -> RunReport:
            pedidos.append(tuple(only) if only is not None else None)
            inicio = datetime(2026, 9, 1, tzinfo=UTC)
            return RunReport(started_at=inicio, finished_at=inicio)

        run_forever(
            run_once,
            daily_at="03:00",
            polls={"darkforums": 120},
            now_fn=now_fn,  # type: ignore[arg-type]
            sleep_fn=sleep_fn,  # type: ignore[arg-type]
            max_iterations=3,
        )

        # Dos sondeos de 2 h y recién después la corrida completa de las 03:00.
        assert pedidos == [("darkforums",), ("darkforums",), None]
        assert dormidas[0] == pytest.approx(2 * 3600)

    def test_la_corrida_completa_reprograma_los_sondeos(self) -> None:
        """Ya trajo la fuente: sondearla enseguida sería un request duplicado."""
        now_fn, sleep_fn, dormidas = self._reloj(datetime(2026, 9, 1, 2, 0, tzinfo=UTC))

        def run_once(*, only: Sequence[str] | None = None) -> RunReport:
            inicio = datetime(2026, 9, 1, tzinfo=UTC)
            return RunReport(started_at=inicio, finished_at=inicio)

        run_forever(
            run_once,
            daily_at="03:00",
            polls={"darkforums": 120},
            now_fn=now_fn,  # type: ignore[arg-type]
            sleep_fn=sleep_fn,  # type: ignore[arg-type]
            max_iterations=2,
        )

        # 1 h hasta la corrida completa; después 2 h enteras, no lo que quedaba.
        assert dormidas[0] == pytest.approx(3600)
        assert dormidas[1] == pytest.approx(2 * 3600)

    def test_una_fuente_caida_se_sigue_sondeando(self) -> None:
        """Si no se reprograma, una falla la saca del ciclo hasta el reinicio."""
        now_fn, sleep_fn, _ = self._reloj(datetime(2026, 9, 1, 10, 0, tzinfo=UTC))
        intentos: list[int] = []

        def run_once(*, only: Sequence[str] | None = None) -> RunReport:
            intentos.append(1)
            raise RuntimeError("el foro se cayó")

        run_forever(
            run_once,
            daily_at="03:00",
            polls={"darkforums": 120},
            now_fn=now_fn,  # type: ignore[arg-type]
            sleep_fn=sleep_fn,  # type: ignore[arg-type]
            max_iterations=3,
        )

        assert len(intentos) == 3


class TestCadenciaDelRegistro:
    """La cadencia es dato del registro, no cableado del scheduler."""

    def test_darkforums_declara_su_ventana_corta(self) -> None:
        from leaks.adapters.registry import get_spec

        spec = get_spec("darkforums")
        assert spec is not None
        assert spec.poll_interval_minutes == 120

    def test_las_fuentes_diarias_no_declaran_sondeo(self) -> None:
        """Los feeds de ransomware publican por día: sondearlos sería ruido."""
        from leaks.adapters.registry import get_spec

        for nombre in ("ransomware.live", "ransomlook", "dls-monitor"):
            spec = get_spec(nombre)
            assert spec is not None
            assert spec.poll_interval_minutes is None
