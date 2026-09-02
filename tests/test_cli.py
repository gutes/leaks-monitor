"""Tests de la capa de entrada CLI.

Se ejercita que cada comando delegue donde corresponde y traduzca bien el
resultado a un código de salida. La lógica de negocio se testea en sus propios
módulos: acá interesa el cableado.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from leaks.cli import main
from leaks.config import get_settings
from leaks.domain.models import SourceRunResult, SourceRunStatus
from leaks.pipeline.runner import RunReport


@pytest.fixture(autouse=True)
def entorno_aislado(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Cada test corre contra su propia base y sin leer el .env del repo."""
    for var in list(dict(__import__("os").environ)):
        if var.startswith("LEAKS_"):
            monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LEAKS_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    # `_env_file=None` no se puede pasar desde el CLI: se apunta a uno vacío.
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _reporte(*, ok: bool) -> RunReport:
    ahora = datetime.now(UTC)
    estado = SourceRunStatus.OK if ok else SourceRunStatus.FAILED
    return RunReport(
        started_at=ahora,
        finished_at=ahora,
        results=[
            SourceRunResult(
                source="ransomware.live",
                status=estado,
                started_at=ahora,
                finished_at=ahora,
                items_fetched=10,
                items_matched=2,
                items_persisted=2,
                error=None if ok else "boom",
            )
        ],
    )


class TestFeeds:
    def test_lista_los_feeds_con_su_politica(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["feeds"]) == 0
        salida = capsys.readouterr().out
        assert "ransomware.live" in salida
        assert "hudsonrock" in salida
        # La limitación de licencia tiene que estar a la vista.
        assert "personal" in salida.lower()


class TestInitDb:
    def test_crea_el_schema(self, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
        assert main(["init-db"]) == 0
        assert (tmp_path / "cli.db").exists()
        assert "Schema listo" in capsys.readouterr().out


class TestRun:
    def test_run_exitoso_devuelve_cero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            "leaks.pipeline.runner.PipelineRunner.run", lambda *_a, **_k: _reporte(ok=True)
        )
        assert main(["run"]) == 0
        salida = capsys.readouterr().out
        assert "Corrida terminada" in salida
        assert "ransomware.live" in salida

    def test_el_resumen_lleva_fecha_y_no_solo_hora(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Sin la fecha no se distingue la corrida de hoy de la de la semana pasada.

        El log del scheduler es un chorro continuo de corridas: la hora sola no
        alcanza para saber cuál es cuál.
        """
        monkeypatch.setattr(
            "leaks.pipeline.runner.PipelineRunner.run", lambda *_a, **_k: _reporte(ok=True)
        )
        main(["run"])
        salida = capsys.readouterr().out

        assert re.search(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", salida), salida[:200]

    def test_si_no_respondio_ninguna_fuente_devuelve_uno(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Fail-closed en el exit code: el cron tiene que enterarse."""
        monkeypatch.setattr(
            "leaks.pipeline.runner.PipelineRunner.run", lambda *_a, **_k: _reporte(ok=False)
        )
        assert main(["run"]) == 1
        assert "Fuentes caídas" in capsys.readouterr().out


class TestPurgePii:
    def test_purga_y_reporta(self, capsys: pytest.CaptureFixture[str]) -> None:
        main(["init-db"])
        assert main(["purge-pii"]) == 0
        assert "vencidos borrados: 0" in capsys.readouterr().out


class TestParser:
    def test_comando_desconocido_falla(self) -> None:
        with pytest.raises(SystemExit):
            main(["no-existe"])

    def test_sin_comando_falla(self) -> None:
        with pytest.raises(SystemExit):
            main([])
