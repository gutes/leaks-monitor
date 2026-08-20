"""Tests del paquete de datos que se reparte al equipo.

Lo que se protege acá:

* que el paquete incluya lo que está en el WAL — es la razón de existir del
  comando, y copiar el archivo a mano fallaba justo ahí, en silencio;
* que NUNCA viaje el vault de PII;
* que importar no pise datos por accidente ni deje una instalación a medias.
"""

from __future__ import annotations

import sqlite3
import tarfile
from pathlib import Path

import pytest

from leaks.bundle import (
    BundleError,
    exportar,
    importar,
    leer_manifiesto,
)


def base_con_datos(ruta: Path, *, filas: int = 3, dejar_en_wal: bool = False) -> None:
    """Crea una base mínima. Con `dejar_en_wal` no hace checkpoint."""
    con = sqlite3.connect(ruta)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, victim_name TEXT)")
    con.execute("CREATE TABLE pii_records (id INTEGER PRIMARY KEY, secreto TEXT)")
    con.execute("CREATE TABLE alembic_version (version_num TEXT)")
    con.execute("INSERT INTO alembic_version VALUES ('0013')")
    con.executemany(
        "INSERT INTO findings (victim_name) VALUES (?)",
        [(f"victima-{i}",) for i in range(filas)],
    )
    con.execute("INSERT INTO pii_records (secreto) VALUES ('no-debe-viajar')")
    con.commit()
    if not dejar_en_wal:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()


@pytest.fixture
def entorno(tmp_path: Path) -> dict[str, Path]:
    base = tmp_path / "origen" / "leaks.db"
    base.parent.mkdir()
    base_con_datos(base)

    wl = tmp_path / "origen" / "watchlist.yaml"
    wl.write_text("version: 1\nsectors: []\n", encoding="utf-8")
    reg = tmp_path / "origen" / "regional"
    reg.mkdir()
    (reg / "br.yaml").write_text("version: 1\ncountry: BR\nsectors: []\n", encoding="utf-8")
    (reg / "cl.yaml").write_text("version: 1\ncountry: CL\nsectors: []\n", encoding="utf-8")

    return {"base": base, "watchlist": wl, "regional": reg, "raiz": tmp_path}


class TestExportar:
    def test_arma_el_paquete(self, entorno: dict[str, Path]) -> None:
        destino = entorno["raiz"] / "p.tar.gz"
        manifiesto = exportar(
            database_url=f"sqlite:///{entorno['base']}",
            watchlist_path=entorno["watchlist"],
            regional_dir=entorno["regional"],
            destino=destino,
        )
        assert destino.exists()
        assert manifiesto.conteos["findings"] == 3
        assert manifiesto.incluye_watchlist
        assert manifiesto.incluye_regionales == 2
        assert manifiesto.revision_esquema == "0013"

    def test_incluye_lo_que_esta_en_el_wal(self, tmp_path: Path) -> None:
        """La razón de existir del comando.

        En modo WAL lo recién escrito no está en el `.db`. Copiar el archivo a
        mano entregaba una base incompleta sin ningún error que lo delatara:
        medido en producción, 1,8 MB de base contra 4,3 MB de WAL.
        """
        base = tmp_path / "leaks.db"
        base_con_datos(base, filas=5, dejar_en_wal=True)

        # El `.db` todavía no tiene las filas; el WAL sí.
        destino = tmp_path / "p.tar.gz"
        manifiesto = exportar(
            database_url=f"sqlite:///{base}",
            watchlist_path=tmp_path / "no-existe.yaml",
            regional_dir=tmp_path / "tampoco",
            destino=destino,
        )
        assert manifiesto.conteos["findings"] == 5, "el paquete tiene que traer el WAL"

    def test_nunca_exporta_el_vault_de_pii(self, entorno: dict[str, Path]) -> None:
        """Es lo único con datos de personas físicas: no viaja."""
        destino = entorno["raiz"] / "p.tar.gz"
        manifiesto = exportar(
            database_url=f"sqlite:///{entorno['base']}",
            watchlist_path=entorno["watchlist"],
            regional_dir=entorno["regional"],
            destino=destino,
        )
        assert "pii_records" not in manifiesto.conteos
        assert "pii_records" in manifiesto.as_dict()["excluido"]

    def test_sin_watchlist_no_falla(self, entorno: dict[str, Path]) -> None:
        manifiesto = exportar(
            database_url=f"sqlite:///{entorno['base']}",
            watchlist_path=entorno["raiz"] / "no-existe.yaml",
            regional_dir=entorno["raiz"] / "tampoco",
            destino=entorno["raiz"] / "p.tar.gz",
        )
        assert not manifiesto.incluye_watchlist
        assert manifiesto.incluye_regionales == 0

    def test_rechaza_una_base_que_no_es_sqlite(self, entorno: dict[str, Path]) -> None:
        with pytest.raises(BundleError, match="SQLite"):
            exportar(
                database_url="postgresql://x/y",
                watchlist_path=entorno["watchlist"],
                regional_dir=entorno["regional"],
                destino=entorno["raiz"] / "p.tar.gz",
            )


class TestImportar:
    def _paquete(self, entorno: dict[str, Path]) -> Path:
        destino = entorno["raiz"] / "p.tar.gz"
        exportar(
            database_url=f"sqlite:///{entorno['base']}",
            watchlist_path=entorno["watchlist"],
            regional_dir=entorno["regional"],
            destino=destino,
        )
        return destino

    def test_viaje_completo(self, entorno: dict[str, Path]) -> None:
        paquete = self._paquete(entorno)
        destino = entorno["raiz"] / "nueva"
        importar(
            paquete,
            database_url=f"sqlite:///{destino / 'leaks.db'}",
            watchlist_path=destino / "watchlist.yaml",
            regional_dir=destino / "regional",
        )
        con = sqlite3.connect(destino / "leaks.db")
        assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
        con.close()
        assert (destino / "watchlist.yaml").exists()
        assert sorted(p.name for p in (destino / "regional").glob("*.yaml")) == [
            "br.yaml",
            "cl.yaml",
        ]

    def test_se_niega_a_pisar_una_base(self, entorno: dict[str, Path]) -> None:
        paquete = self._paquete(entorno)
        destino = entorno["raiz"] / "ocupada"
        destino.mkdir()
        base_con_datos(destino / "leaks.db", filas=99)

        with pytest.raises(BundleError, match="pisaría"):
            importar(
                paquete,
                database_url=f"sqlite:///{destino / 'leaks.db'}",
                watchlist_path=destino / "watchlist.yaml",
                regional_dir=destino / "regional",
            )
        con = sqlite3.connect(destino / "leaks.db")
        assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 99
        con.close()

    def test_con_force_pisa(self, entorno: dict[str, Path]) -> None:
        paquete = self._paquete(entorno)
        destino = entorno["raiz"] / "ocupada"
        destino.mkdir()
        base_con_datos(destino / "leaks.db", filas=99)

        importar(
            paquete,
            database_url=f"sqlite:///{destino / 'leaks.db'}",
            watchlist_path=destino / "watchlist.yaml",
            regional_dir=destino / "regional",
            force=True,
        )
        con = sqlite3.connect(destino / "leaks.db")
        assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
        con.close()

    def test_falla_antes_de_tocar_nada_si_no_puede_escribir(self, entorno: dict[str, Path]) -> None:
        """Pasó de verdad: importó la base y falló al copiar la watchlist.

        Quedaba una instalación a medio importar con un traceback por toda
        explicación. Ahora se verifican todos los destinos antes de empezar.
        """
        paquete = self._paquete(entorno)
        destino = entorno["raiz"] / "parcial"
        destino.mkdir()
        solo_lectura = destino / "bloqueado"
        solo_lectura.mkdir()
        solo_lectura.chmod(0o555)

        try:
            with pytest.raises(BundleError, match=r"escribible|permiso"):
                importar(
                    paquete,
                    database_url=f"sqlite:///{destino / 'leaks.db'}",
                    watchlist_path=solo_lectura / "watchlist.yaml",
                    regional_dir=destino / "regional",
                )
            assert not (destino / "leaks.db").exists(), (
                "no puede haber quedado una base a medio importar"
            )
        finally:
            solo_lectura.chmod(0o755)

    def test_limpia_los_sidecar_del_wal(self, entorno: dict[str, Path]) -> None:
        """Un `-wal` viejo se aplicaría sobre una base que ya no es la suya."""
        paquete = self._paquete(entorno)
        destino = entorno["raiz"] / "conwal"
        destino.mkdir()
        (destino / "leaks.db-wal").write_bytes(b"basura")

        importar(
            paquete,
            database_url=f"sqlite:///{destino / 'leaks.db'}",
            watchlist_path=destino / "watchlist.yaml",
            regional_dir=destino / "regional",
        )
        assert not (destino / "leaks.db-wal").exists()

    def test_rechaza_rutas_fuera_de_lugar(self, entorno: dict[str, Path]) -> None:
        """El paquete viaja por un canal que no controlamos."""
        malicioso = entorno["raiz"] / "malicioso.tar.gz"
        trampa = entorno["raiz"] / "trampa"
        trampa.write_text("x", encoding="utf-8")
        with tarfile.open(malicioso, "w:gz") as tar:
            tar.add(trampa, arcname="../fuera.txt")

        with pytest.raises(BundleError):
            importar(
                malicioso,
                database_url=f"sqlite:///{entorno['raiz'] / 'x' / 'leaks.db'}",
                watchlist_path=entorno["raiz"] / "x" / "w.yaml",
                regional_dir=entorno["raiz"] / "x" / "r",
            )

    def test_un_archivo_que_no_es_del_proyecto_se_rechaza(self, entorno: dict[str, Path]) -> None:
        cualquiera = entorno["raiz"] / "cualquiera.tar.gz"
        suelto = entorno["raiz"] / "suelto.txt"
        suelto.write_text("x", encoding="utf-8")
        with tarfile.open(cualquiera, "w:gz") as tar:
            tar.add(suelto, arcname="suelto.txt")

        with pytest.raises(BundleError, match="no parece un paquete"):
            leer_manifiesto(cualquiera)

    def test_avisa_si_el_paquete_no_existe(self, entorno: dict[str, Path]) -> None:
        with pytest.raises(BundleError, match="No existe"):
            importar(
                entorno["raiz"] / "fantasma.tar.gz",
                database_url=f"sqlite:///{entorno['raiz'] / 'x.db'}",
                watchlist_path=entorno["raiz"] / "w.yaml",
                regional_dir=entorno["raiz"] / "r",
            )

    def test_una_base_recien_sembrada_no_asusta(self, entorno: dict[str, Path]) -> None:
        """El caso común: levantar el compose antes de importar.

        Ahí la base tiene la semilla de ejemplo y cero hallazgos. Decir "vas a
        perder datos" sería falso y frena a quien no debería frenarse.
        """
        paquete = self._paquete(entorno)
        destino = entorno["raiz"] / "recien"
        destino.mkdir()
        base_con_datos(destino / "leaks.db", filas=0)

        with pytest.raises(BundleError, match="no hay nada que perder"):
            importar(
                paquete,
                database_url=f"sqlite:///{destino / 'leaks.db'}",
                watchlist_path=destino / "watchlist.yaml",
                regional_dir=destino / "regional",
            )

    def test_una_base_con_datos_avisa_cuantos(self, entorno: dict[str, Path]) -> None:
        paquete = self._paquete(entorno)
        destino = entorno["raiz"] / "conDatos"
        destino.mkdir()
        base_con_datos(destino / "leaks.db", filas=42)

        with pytest.raises(BundleError, match="42 hallazgos"):
            importar(
                paquete,
                database_url=f"sqlite:///{destino / 'leaks.db'}",
                watchlist_path=destino / "watchlist.yaml",
                regional_dir=destino / "regional",
            )
