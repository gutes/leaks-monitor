"""Tests de persistencia: idempotencia, cursor y telemetría por fuente."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, inspect, text

from leaks.domain.models import SourceRunResult, SourceRunStatus
from leaks.storage.dedup import compute_dedup_hash
from leaks.storage.repository import SqlAlchemyFindingRepository
from tests.conftest import make_finding


class TestDedupHash:
    def test_es_estable_entre_llamadas(self) -> None:
        args = {
            "source": "ransomware.live",
            "victim_name": "Ministerio X",
            "victim_domain": "x.gob.ar",
            "actor": "LockBit",
            "discovered_at": datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
        }
        assert compute_dedup_hash(**args) == compute_dedup_hash(**args)  # type: ignore[arg-type]

    def test_ignora_jitter_de_timestamp_dentro_del_mismo_dia(self) -> None:
        """Varios feeds reescriben `discovered` con microsegundos distintos."""
        base = {
            "source": "ransomware.live",
            "victim_name": "Ministerio X",
            "victim_domain": "x.gob.ar",
            "actor": "LockBit",
        }
        manana = compute_dedup_hash(
            **base,  # type: ignore[arg-type]
            discovered_at=datetime(2026, 8, 13, 9, 15, 1, 123, tzinfo=UTC),
        )
        tarde = compute_dedup_hash(
            **base,  # type: ignore[arg-type]
            discovered_at=datetime(2026, 8, 13, 21, 59, 59, 999, tzinfo=UTC),
        )
        assert manana == tarde

    def test_distingue_dias_distintos(self) -> None:
        base = {
            "source": "ransomware.live",
            "victim_name": "Ministerio X",
            "victim_domain": "x.gob.ar",
            "actor": "LockBit",
        }
        assert compute_dedup_hash(
            **base,  # type: ignore[arg-type]
            discovered_at=datetime(2026, 8, 13, tzinfo=UTC),
        ) != compute_dedup_hash(
            **base,  # type: ignore[arg-type]
            discovered_at=datetime(2026, 8, 14, tzinfo=UTC),
        )

    def test_el_dominio_manda_sobre_el_nombre(self) -> None:
        """El mismo dominio escrito con nombres distintos es un solo hallazgo."""
        a = compute_dedup_hash(
            source="s",
            victim_name="Ministerio X",
            victim_domain="x.gob.ar",
            actor="LockBit",
            discovered_at=datetime(2026, 8, 13, tzinfo=UTC),
        )
        b = compute_dedup_hash(
            source="s",
            victim_name="MINISTERIO X S.A.",
            victim_domain="x.gob.ar",
            actor="LockBit",
            discovered_at=datetime(2026, 8, 13, tzinfo=UTC),
        )
        assert a == b


class TestUpsertIdempotente:
    def test_reinsertar_no_duplica(self, repository: SqlAlchemyFindingRepository) -> None:
        finding = make_finding()

        assert repository.upsert_many([finding]) == 1
        assert repository.upsert_many([finding]) == 0
        assert repository.count() == 1

    def test_deduplica_dentro_del_mismo_lote(self, repository: SqlAlchemyFindingRepository) -> None:
        finding = make_finding()
        assert repository.upsert_many([finding, finding, finding]) == 1
        assert repository.count() == 1

    def test_refresca_last_seen_sin_tocar_first_seen(
        self, repository: SqlAlchemyFindingRepository, engine: Engine
    ) -> None:
        finding = make_finding()
        repository.upsert_many([finding])

        with engine.connect() as conn:
            first, last = conn.execute(
                text("SELECT first_seen_at, last_seen_at FROM findings")
            ).one()

        repository.upsert_many([finding])

        with engine.connect() as conn:
            first_2, last_2 = conn.execute(
                text("SELECT first_seen_at, last_seen_at FROM findings")
            ).one()

        assert first_2 == first, "first_seen_at no debe moverse"
        assert last_2 >= last, "last_seen_at debe refrescarse"

    def test_victimas_distintas_conviven(self, repository: SqlAlchemyFindingRepository) -> None:
        repository.upsert_many(
            [
                make_finding(victim_name="Uno", victim_domain="uno.gob.ar"),
                make_finding(victim_name="Dos", victim_domain="dos.gob.ar"),
            ]
        )
        assert repository.count() == 2

    def test_lote_vacio_es_no_op(self, repository: SqlAlchemyFindingRepository) -> None:
        assert repository.upsert_many([]) == 0


class TestCursorIncremental:
    def test_arranca_vacio(self, repository: SqlAlchemyFindingRepository) -> None:
        assert repository.get_cursor("ransomware.live") is None

    def test_guarda_y_recupera_en_utc(self, repository: SqlAlchemyFindingRepository) -> None:
        momento = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        repository.set_cursor("ransomware.live", momento)

        recuperado = repository.get_cursor("ransomware.live")
        assert recuperado is not None
        assert recuperado.tzinfo is not None, "el cursor debe volver aware"
        assert recuperado == momento

    def test_nunca_retrocede(self, repository: SqlAlchemyFindingRepository) -> None:
        """Una corrida que trae datos viejos no debe rebobinar el incremental."""
        nuevo = datetime(2026, 8, 13, tzinfo=UTC)
        viejo = datetime(2026, 1, 1, tzinfo=UTC)

        repository.set_cursor("f", nuevo)
        repository.set_cursor("f", viejo)

        assert repository.get_cursor("f") == nuevo

    def test_cursores_independientes_por_fuente(
        self, repository: SqlAlchemyFindingRepository
    ) -> None:
        repository.set_cursor("a", datetime(2026, 8, 1, tzinfo=UTC))
        repository.set_cursor("b", datetime(2026, 8, 2, tzinfo=UTC))
        assert repository.get_cursor("a") != repository.get_cursor("b")


class TestTelemetriaDeFuente:
    def test_registra_el_error_truncado(
        self, repository: SqlAlchemyFindingRepository, engine: Engine
    ) -> None:
        ahora = datetime(2026, 8, 14, tzinfo=UTC)
        repository.record_run(
            SourceRunResult(
                source="feed-caido",
                status=SourceRunStatus.FAILED,
                started_at=ahora,
                finished_at=ahora,
                error="x" * 2000,
            )
        )

        with engine.connect() as conn:
            status, error = conn.execute(text("SELECT status, error FROM source_runs")).one()

        assert status == "failed"
        assert len(error) == 500, "el error se trunca para no volcar bodies"


class TestSchema:
    def test_la_migracion_coincide_con_los_modelos(self, tmp_path: object) -> None:
        """Guarda contra drift entre `storage/models.py` y `alembic/versions/`."""
        import subprocess
        import sys
        from pathlib import Path

        from leaks.storage.models import Base
        from leaks.storage.session import create_db_engine

        db = Path(str(tmp_path)) / "alembic.db"
        subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "alembic",
                "-x",
                f"db_url=sqlite:///{db}",
                "upgrade",
                "head",
            ],
            check=True,
            capture_output=True,
        )

        migrated = inspect(create_db_engine(f"sqlite:///{db}"))
        assert set(migrated.get_table_names()) >= set(Base.metadata.tables)

        for table_name, table in Base.metadata.tables.items():
            de_migracion = {c["name"] for c in migrated.get_columns(table_name)}
            de_modelo = {c.name for c in table.columns}
            assert de_migracion == de_modelo, f"drift en la tabla {table_name}"


class TestPuestaAlDiaDelEsquema:
    """Regresión: una columna nueva rompía las instalaciones ya desplegadas.

    `create_all` crea tablas que faltan pero **no** agrega columnas a tablas
    existentes. El proceso arrancaba bien y fallaba en el primer `SELECT` que
    tocaba la columna nueva.
    """

    def test_base_nueva_queda_sellada(self, tmp_path: Path) -> None:
        from sqlalchemy import inspect

        from leaks.storage.schema import ensure_schema
        from leaks.storage.session import create_db_engine

        url = f"sqlite:///{tmp_path / 'nueva.db'}"
        engine = create_db_engine(url)
        ensure_schema(engine, url)

        tablas = set(inspect(engine).get_table_names())
        assert "findings" in tablas
        # Sellada: a partir de acá manda Alembic.
        assert "alembic_version" in tablas

    def test_base_vieja_recibe_las_columnas_que_faltan(self, tmp_path: Path) -> None:
        """El caso real: base creada antes de Alembic, sin las columnas nuevas."""
        import sqlite3

        from sqlalchemy import inspect

        from leaks.storage.schema import ensure_schema
        from leaks.storage.session import create_db_engine

        ruta = tmp_path / "vieja.db"
        # Se simula una base vieja: la tabla sin las columnas agregadas después.
        con = sqlite3.connect(ruta)
        con.execute(
            "CREATE TABLE findings ("
            " id INTEGER PRIMARY KEY, dedup_hash VARCHAR(64) NOT NULL,"
            " source VARCHAR(64) NOT NULL, leak_type VARCHAR(32) NOT NULL,"
            " victim_name VARCHAR(512) NOT NULL, ar_match_reason JSON NOT NULL,"
            " severity VARCHAR(16) NOT NULL, discovered_at DATETIME NOT NULL,"
            " first_seen_at DATETIME NOT NULL, last_seen_at DATETIME NOT NULL)"
        )
        con.commit()
        con.close()

        url = f"sqlite:///{ruta}"
        engine = create_db_engine(url)
        ensure_schema(engine, url)

        columnas = {c["name"] for c in inspect(engine).get_columns("findings")}
        assert "alerted_at" in columnas, "la columna de alertas tiene que aparecer"
        assert "download_links" in columnas, "la columna de enlaces tiene que aparecer"
        assert "alembic_version" in set(inspect(engine).get_table_names())

    def test_es_idempotente(self, tmp_path: Path) -> None:
        from leaks.storage.schema import ensure_schema
        from leaks.storage.session import create_db_engine

        url = f"sqlite:///{tmp_path / 'repetida.db'}"
        engine = create_db_engine(url)
        ensure_schema(engine, url)
        ensure_schema(engine, url)  # no debe lanzar


class TestSincronizacionDeLaWatchlist:
    """Importar novedades del YAML sin pisar lo que se editó desde la UI."""

    def _repo(self, session_factory: object) -> object:
        from leaks.storage.watchlist_repository import WatchlistRepository

        return WatchlistRepository(session_factory)  # type: ignore[arg-type]

    def _yaml(self, tmp_path: Path, dominios: list[str]) -> Path:
        import yaml

        ruta = tmp_path / "wl.yaml"
        ruta.write_text(
            yaml.safe_dump(
                {
                    "sectors": [
                        {
                            "name": "prueba",
                            "label": "Prueba",
                            "critical": False,
                            "domains": dominios,
                            "keywords": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return ruta

    def test_por_defecto_no_toca_una_base_poblada(
        self, session_factory: object, tmp_path: Path
    ) -> None:
        """Sembrar en cada arranque resucitaría lo que se borró a mano."""
        repo = self._repo(session_factory)
        repo.seed_from_yaml(self._yaml(tmp_path, ["uno.gob.ar"]))  # type: ignore[attr-defined]

        # Un YAML con más entradas no entra si no se pide explícitamente.
        agregadas = repo.seed_from_yaml(self._yaml(tmp_path, ["uno.gob.ar", "dos.gob.ar"]))  # type: ignore[attr-defined]
        assert agregadas == 0

    def test_con_allow_updates_importa_solo_lo_nuevo(
        self, session_factory: object, tmp_path: Path
    ) -> None:
        repo = self._repo(session_factory)
        repo.seed_from_yaml(self._yaml(tmp_path, ["uno.gob.ar"]))  # type: ignore[attr-defined]

        agregadas = repo.seed_from_yaml(  # type: ignore[attr-defined]
            self._yaml(tmp_path, ["uno.gob.ar", "dos.gob.ar", "tres.gob.ar"]),
            allow_updates=True,
        )
        assert agregadas == 2
        assert repo.counts()["total"] == 3  # type: ignore[attr-defined]

    def test_no_revive_el_estado_deshabilitado(
        self, session_factory: object, tmp_path: Path
    ) -> None:
        """Deshabilitar es una decisión del investigador: sincronizar la respeta."""
        repo = self._repo(session_factory)
        repo.seed_from_yaml(self._yaml(tmp_path, ["uno.gob.ar"]))  # type: ignore[attr-defined]

        entrada = repo.list_entries()[0]  # type: ignore[attr-defined]
        repo.set_enabled(entrada.id, False)  # type: ignore[attr-defined]

        repo.seed_from_yaml(  # type: ignore[attr-defined]
            self._yaml(tmp_path, ["uno.gob.ar", "dos.gob.ar"]), allow_updates=True
        )
        sigue = next(e for e in repo.list_entries() if e.value == "uno.gob.ar")  # type: ignore[attr-defined]
        assert sigue.enabled is False, "no puede rehabilitarse solo"


class TestRebobinarCursor:
    """Retroceder la marca es una operación legítima, pero acotada."""

    def test_retrocede_y_devuelve_el_anterior(
        self, repository: SqlAlchemyFindingRepository
    ) -> None:
        """`set_cursor` nunca retrocede; sumar subforos lo necesita."""
        original = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
        repository.set_cursor("darkforums", original)

        anterior = repository.rewind_cursor("darkforums", datetime(2026, 9, 6, tzinfo=UTC))

        assert anterior == original
        assert repository.get_cursor("darkforums") == datetime(2026, 9, 6, tzinfo=UTC)

    def test_set_cursor_sigue_sin_retroceder(self, repository: SqlAlchemyFindingRepository) -> None:
        """La corrida normal no puede retroceder por accidente."""
        repository.set_cursor("darkforums", datetime(2026, 9, 15, tzinfo=UTC))
        repository.set_cursor("darkforums", datetime(2026, 9, 1, tzinfo=UTC))

        assert repository.get_cursor("darkforums") == datetime(2026, 9, 15, tzinfo=UTC)

    def test_sobre_una_fuente_sin_cursor_no_falla(
        self, repository: SqlAlchemyFindingRepository
    ) -> None:
        anterior = repository.rewind_cursor("nueva", datetime(2026, 9, 6, tzinfo=UTC))

        assert anterior is None
        assert repository.get_cursor("nueva") == datetime(2026, 9, 6, tzinfo=UTC)
