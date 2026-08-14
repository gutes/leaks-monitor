"""Fixtures compartidas.

Regla del proyecto: **ningún test toca la red**. Los adapters se ejercitan
contra fixtures JSON/XML capturadas en `tests/fixtures/`.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from leaks.adapters.egress import EgressInfo
from leaks.config import PROJECT_ROOT, Settings
from leaks.domain.models import (
    ArMatchReason,
    Finding,
    LeakType,
    NormalizedItem,
    Severity,
)
from leaks.pipeline.egress_guard import EgressDecision
from leaks.relevance.watchlist import Watchlist, load_watchlist
from leaks.storage.dedup import compute_dedup_hash
from leaks.storage.models import Base
from leaks.storage.repository import SqlAlchemyFindingRepository
from leaks.storage.session import create_db_engine, create_session_factory

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    """Base SQLite descartable, con el schema creado desde los modelos."""
    db_engine = create_db_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(db_engine)
    yield db_engine
    db_engine.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return create_session_factory(engine)


@pytest.fixture
def repository(session_factory: sessionmaker[Session]) -> SqlAlchemyFindingRepository:
    return SqlAlchemyFindingRepository(session_factory)


@pytest.fixture
def watchlist() -> Watchlist:
    """La watchlist real del repo: los tests de relevancia valen más con ella."""
    return load_watchlist(PROJECT_ROOT / "data" / "watchlist.yaml")


@pytest.fixture
def settings() -> Settings:
    """Configuración por defecto, con la postura de privacidad cerrada."""
    return Settings(store_pii=False)


def make_finding(
    *,
    source: str = "ransomware.live",
    victim_name: str = "Ministerio X",
    victim_domain: str | None = "x.gob.ar",
    actor: str | None = "LockBit",
    discovered_at: datetime | None = None,
    reasons: tuple[ArMatchReason, ...] = (ArMatchReason.WATCHLIST,),
    severity: Severity = Severity.HIGH,
    description: str | None = None,
) -> Finding:
    """Constructor de hallazgos para tests, con dedup_hash coherente."""
    discovered = discovered_at or datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
    return Finding(
        source=source,
        leak_type=LeakType.RANSOMWARE,
        victim_name=victim_name,
        victim_domain=victim_domain,
        country="AR",
        sector="Government",
        actor=actor,
        discovered_at=discovered,
        raw_ref="http://example.onion/x",
        description=description,
        ar_match_reason=reasons,
        severity=severity,
        dedup_hash=compute_dedup_hash(
            source=source,
            victim_name=victim_name,
            victim_domain=victim_domain,
            actor=actor,
            discovered_at=discovered,
        ),
    )


def make_normalized(
    *,
    source: str = "test-feed",
    victim_name: str = "Acme",
    victim_domain: str | None = None,
    country: str | None = None,
    description: str | None = None,
    discovered_at: datetime | None = None,
    leak_type: LeakType = LeakType.RANSOMWARE,
) -> NormalizedItem:
    """Item normalizado mínimo para ejercitar la capa de relevancia."""
    return NormalizedItem(
        source=source,
        leak_type=leak_type,
        victim_name=victim_name,
        victim_domain=victim_domain,
        country=country,
        description=description,
        discovered_at=discovered_at or datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
    )


def read_fixture(name: str) -> str:
    """Lee una respuesta capturada de un feed."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


class GuardPermisivo:
    """Guard de test que siempre deja pasar.

    Los tests **no tocan la red**: sin esto, el middleware de bloqueo resolvería
    la IP de salida contra un servicio externo en cada petición.
    """

    def evaluate(self, *, force: bool = False) -> EgressDecision:
        return EgressDecision(True, "control desactivado en tests")


class GuardBloqueante:
    """Guard de test que bloquea, para ejercitar el corte de la API."""

    def __init__(self, country: str = "AR") -> None:
        self._country = country

    def evaluate(self, *, force: bool = False) -> EgressDecision:
        return EgressDecision(
            False,
            f"BLOQUEADO: el tráfico sale desde {self._country}.",
            EgressInfo(ip="200.1.2.3", country=self._country, checked_at=datetime.now(UTC)),
        )
