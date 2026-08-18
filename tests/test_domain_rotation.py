"""Tests de la rotación de dominios para Hudson Rock.

Por qué existe la rotación: cada consulta le revela a un proveedor extranjero
qué organismo estás vigilando, y son ~2 s por dominio. Mandar la watchlist
entera todos los días publica el mapa completo y castiga un endpoint gratuito.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from leaks.pipeline.domain_rotation import CURSOR_KEY, WatchlistDomainRotator
from leaks.storage.settings_store import SettingsStore
from leaks.storage.watchlist_repository import WatchlistRepository


@pytest.fixture
def watchlist(session_factory: sessionmaker[Session]) -> WatchlistRepository:
    repo = WatchlistRepository(session_factory)
    for i in range(10):
        repo.add(kind="domain", value=f"org{i:02d}.gob.ar", sector="prueba")
    # Una keyword y un dominio deshabilitado: ninguno debe entrar en los lotes.
    repo.add(kind="keyword", value="Organismo de Prueba", sector="prueba")
    apagado = repo.add(kind="domain", value="apagado.gob.ar", sector="prueba")
    repo.set_enabled(apagado.id, False)
    return repo


@pytest.fixture
def store(session_factory: sessionmaker[Session]) -> SettingsStore:
    return SettingsStore(session_factory)


def rotator(
    watchlist: WatchlistRepository,
    store: SettingsStore,
    *,
    enabled: bool = True,
    max_per_run: int = 4,
) -> WatchlistDomainRotator:
    return WatchlistDomainRotator(watchlist, store, enabled=enabled, max_per_run=max_per_run)


class TestApagadoPorDefecto:
    def test_deshabilitado_no_devuelve_nada(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        """Derivar dominios de la watchlist es una decisión, no un default."""
        assert rotator(watchlist, store, enabled=False).next_batch() == ()

    def test_tope_en_cero_no_devuelve_nada(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        assert rotator(watchlist, store, max_per_run=0).next_batch() == ()

    def test_sin_dominios_no_falla(self, session_factory: sessionmaker[Session]) -> None:
        vacia = WatchlistRepository(session_factory)
        assert rotator(vacia, SettingsStore(session_factory)).next_batch() == ()


class TestRotacion:
    def test_devuelve_un_lote_del_tamaño_pedido(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        assert len(rotator(watchlist, store, max_per_run=4).next_batch()) == 4

    def test_la_corrida_siguiente_toma_los_que_faltan(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        r = rotator(watchlist, store, max_per_run=4)
        primero, segundo = r.next_batch(), r.next_batch()

        assert set(primero) & set(segundo) == set(), "no puede repetir en la corrida siguiente"

    def test_cubre_toda_la_watchlist_y_vuelve_a_empezar(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        """La cobertura es circular: no se corta en el último dominio."""
        r = rotator(watchlist, store, max_per_run=4)
        vistos: set[str] = set()
        for _ in range(3):  # 3 lotes de 4 sobre 10 dominios
            vistos |= set(r.next_batch())

        assert len(vistos) == 10, "en tres corridas tiene que haber visto los diez"

    def test_solo_dominios_habilitados(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        """Deshabilitar una entrada también la saca de las consultas salientes."""
        r = rotator(watchlist, store, max_per_run=20)
        assert "apagado.gob.ar" not in r.next_batch()

    def test_no_incluye_keywords(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        lote = rotator(watchlist, store, max_per_run=20).next_batch()
        assert all(d.endswith(".gob.ar") for d in lote)
        assert "Organismo de Prueba" not in lote

    def test_no_repite_dentro_del_lote(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        """Con el tope mayor que la watchlist, el wrap no puede duplicar."""
        lote = rotator(watchlist, store, max_per_run=25).next_batch()
        assert len(lote) == len(set(lote))


class TestCursor:
    def test_el_cursor_persiste(self, watchlist: WatchlistRepository, store: SettingsStore) -> None:
        """La cobertura tiene que sobrevivir a un reinicio del proceso."""
        rotator(watchlist, store, max_per_run=4).next_batch()
        assert store.get(CURSOR_KEY) == 4

        # Un rotador nuevo (proceso nuevo) sigue donde quedó el anterior.
        segundo = rotator(watchlist, store, max_per_run=4).next_batch()
        assert store.get(CURSOR_KEY) == 8
        assert segundo

    def test_un_cursor_corrupto_no_rompe(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        store.set(CURSOR_KEY, "no es un número")
        assert len(rotator(watchlist, store, max_per_run=4).next_batch()) == 4

    def test_si_la_watchlist_se_achica_el_cursor_se_acomoda(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        """Borrar dominios no puede dejar el cursor apuntando al vacío."""
        store.set(CURSOR_KEY, 500)
        assert len(rotator(watchlist, store, max_per_run=4).next_batch()) == 4


class TestIntegracionConElRegistro:
    def test_solo_le_da_dominios_a_hudsonrock(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        r = rotator(watchlist, store)
        assert r.for_feed("hudsonrock")
        assert r.for_feed("ransomware.live") == ()

    def test_el_registro_suma_los_explicitos_y_el_lote(
        self, watchlist: WatchlistRepository, store: SettingsStore
    ) -> None:
        from leaks.adapters.registry import FeedDeps, build_adapter, get_spec
        from leaks.config import Settings

        spec = get_spec("hudsonrock")
        assert spec is not None

        adapter, cliente = build_adapter(
            spec,
            Settings(hudsonrock_domains=("explicito.gob.ar",)),
            deps=FeedDeps(extra_domains=rotator(watchlist, store, max_per_run=3).for_feed),
        )
        cliente.close()

        dominios = adapter._domains  # type: ignore[attr-defined]
        assert "explicito.gob.ar" in dominios, "los del entorno tienen que seguir"
        assert len(dominios) == 4, "más el lote rotativo"

    def test_sin_rotador_solo_quedan_los_explicitos(self) -> None:
        from leaks.adapters.registry import build_adapter, get_spec
        from leaks.config import Settings

        spec = get_spec("hudsonrock")
        assert spec is not None

        adapter, cliente = build_adapter(spec, Settings(hudsonrock_domains=("uno.gob.ar",)))
        cliente.close()
        assert adapter._domains == ("uno.gob.ar",)  # type: ignore[attr-defined]
