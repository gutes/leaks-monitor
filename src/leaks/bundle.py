"""Empaquetado de los datos para repartir el prototipo a un equipo.

## Por qué existe y no alcanza con copiar el archivo

La base corre en modo **WAL**, así que lo recién escrito vive en `leaks.db-wal`
hasta que SQLite hace checkpoint. Medido en el despliegue real: la base tenía
1,8 MB y el WAL 4,3 MB, con el `.db` escrito el día anterior. Copiar `leaks.db`
a mano habría entregado una base **sin nada de la última jornada**, y sin ningún
error que lo delatara.

`VACUUM INTO` resuelve las dos cosas de una: toma una instantánea consistente
—incluye el WAL— y de paso compacta. No requiere parar el servicio.

## Qué lleva y qué no

Lleva la base entera y las watchlists. **No** lleva secretos: la configuración
sigue viniendo por entorno, y el vault de PII no se exporta aunque tenga
contenido — es lo único con datos de personas y no tiene por qué viajar.

El manifiesto anota la revisión de esquema, para que importar en una versión
distinta avise en vez de fallar raro tres pantallas después.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MANIFIESTO = "manifest.json"
BASE_EN_PAQUETE = "leaks.db"
WATCHLIST_EN_PAQUETE = "watchlist.yaml"
REGIONAL_EN_PAQUETE = "watchlist-regional"

#: Tablas cuyos conteos se anotan en el manifiesto, para que quien importe
#: pueda comprobar que llegó lo que se mandó.
TABLAS = (
    "findings",
    "watchlist_entries",
    "regional_victims",
    "adjacent_actors",
    "leak_sites",
    "telegram_channels",
)

#: NUNCA se exporta: es lo único con datos de personas físicas. Si algún día
#: hace falta compartirlo, que sea una decisión explícita y separada.
TABLAS_EXCLUIDAS = ("pii_records",)


class BundleError(RuntimeError):
    """El paquete no se pudo armar o no se puede importar."""


@dataclass(frozen=True)
class Manifiesto:
    """Qué hay en el paquete, para verificarlo del otro lado."""

    creado: str
    revision_esquema: str | None
    conteos: dict[str, int]
    incluye_watchlist: bool
    incluye_regionales: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "creado": self.creado,
            "revision_esquema": self.revision_esquema,
            "conteos": dict(self.conteos),
            "incluye_watchlist": self.incluye_watchlist,
            "incluye_regionales": self.incluye_regionales,
            "excluido": list(TABLAS_EXCLUIDAS),
        }


def _ruta_sqlite(database_url: str) -> Path:
    if not database_url.startswith("sqlite"):
        raise BundleError(
            f"Solo se empaquetan bases SQLite; esta es {database_url.split(':')[0]}. "
            "Para otro motor, usar las herramientas de respaldo del motor."
        )
    ruta = database_url.split("sqlite:///")[-1]
    if not ruta or ruta == database_url:
        raise BundleError(f"No se pudo sacar la ruta del archivo de {database_url!r}.")
    return Path(ruta)


def _instantanea(origen: Path, destino: Path) -> None:
    """Copia consistente con `VACUUM INTO`, incluyendo lo que está en el WAL."""
    if not origen.exists():
        raise BundleError(f"No hay base en {origen}.")
    with sqlite3.connect(f"file:{origen}?mode=ro", uri=True) as con:
        # `VACUUM INTO` falla si el destino existe, cosa que acá no puede pasar
        # porque se escribe en un temporal recién creado.
        con.execute("VACUUM INTO ?", (str(destino),))


def _conteos(base: Path) -> dict[str, int]:
    salida: dict[str, int] = {}
    with sqlite3.connect(f"file:{base}?mode=ro", uri=True) as con:
        for tabla in TABLAS:
            # El nombre no puede venir de afuera: sale de `TABLAS`, que es una
            # tupla del módulo. Se reafirma acá para que agregar una tabla por
            # una variable en el futuro rompa el test y no la seguridad.
            if tabla not in TABLAS:  # pragma: no cover — invariante
                continue
            # nosec B608 / noqa: S608 — `tabla` sale de `TABLAS`, una tupla
            # del módulo verificada arriba. No hay entrada de usuario acá.
            consulta = f"SELECT COUNT(*) FROM {tabla}"  # noqa: S608  # nosec B608
            try:
                salida[tabla] = int(con.execute(consulta).fetchone()[0])
            except sqlite3.Error:
                # Una base vieja puede no tener la tabla todavía.
                continue
    return salida


def _revision(base: Path) -> str | None:
    with sqlite3.connect(f"file:{base}?mode=ro", uri=True) as con:
        try:
            fila = con.execute("SELECT version_num FROM alembic_version").fetchone()
        except sqlite3.Error:
            return None
    return str(fila[0]) if fila else None


def exportar(
    *,
    database_url: str,
    watchlist_path: Path,
    regional_dir: Path,
    destino: Path,
) -> Manifiesto:
    """Arma el paquete. Devuelve el manifiesto de lo que quedó adentro."""
    origen = _ruta_sqlite(database_url)

    with tempfile.TemporaryDirectory() as tmp:
        area = Path(tmp)
        base = area / BASE_EN_PAQUETE
        _instantanea(origen, base)

        manifiesto = Manifiesto(
            creado=datetime.now(UTC).isoformat(timespec="seconds"),
            revision_esquema=_revision(base),
            conteos=_conteos(base),
            incluye_watchlist=watchlist_path.exists(),
            incluye_regionales=0,
        )

        if watchlist_path.exists():
            shutil.copy2(watchlist_path, area / WATCHLIST_EN_PAQUETE)

        regionales = 0
        if regional_dir.is_dir():
            copia = area / REGIONAL_EN_PAQUETE
            copia.mkdir()
            for archivo in sorted(regional_dir.glob("*.yaml")):
                shutil.copy2(archivo, copia / archivo.name)
                regionales += 1
        manifiesto = Manifiesto(
            creado=manifiesto.creado,
            revision_esquema=manifiesto.revision_esquema,
            conteos=manifiesto.conteos,
            incluye_watchlist=manifiesto.incluye_watchlist,
            incluye_regionales=regionales,
        )

        (area / MANIFIESTO).write_text(
            json.dumps(manifiesto.as_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )

        destino.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(destino, "w:gz") as tar:
            for elemento in sorted(area.iterdir()):
                tar.add(elemento, arcname=elemento.name)

    return manifiesto


def _seguro(miembro: tarfile.TarInfo, area: Path) -> bool:
    """Rechaza rutas que se escapen del directorio de extracción.

    Un tar puede traer `../../etc/algo`. El paquete lo genera este mismo
    código, pero se valida igual: el archivo viaja por un canal que no
    controlamos y basta con que alguien lo reemplace.
    """
    destino = (area / miembro.name).resolve()
    return destino.is_relative_to(area.resolve()) and not miembro.issym() and not miembro.islnk()


def _hallazgos(base: Path) -> int:
    """Cuántos hallazgos tiene una base, para saber si vale algo.

    Una base recién sembrada tiene watchlist pero cero hallazgos: pisarla no
    cuesta nada, y decirlo evita que alguien crea que está por perder datos.
    """
    try:
        with sqlite3.connect(f"file:{base}?mode=ro", uri=True) as con:
            return int(con.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
    except sqlite3.Error:
        # Sin tabla o base ilegible: no se puede afirmar que esté vacía.
        return -1


def _verificar_escribible(destino: Path, que: str) -> None:
    """Falla ANTES de tocar nada si no se va a poder escribir el destino."""
    directorio = destino.parent
    try:
        directorio.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BundleError(f"No se puede crear {directorio} para {que}: {exc.strerror}.") from exc

    if destino.exists() and not os.access(destino, os.W_OK):
        raise BundleError(f"No se puede escribir {destino} ({que}): sin permiso.")
    if not os.access(directorio, os.W_OK):
        raise BundleError(
            f"El directorio {directorio} no es escribible, y ahí va {que}.\n"
            "Si estás en Docker, revisá que el montaje no sea de solo lectura "
            "(`:ro` en docker-compose.yml)."
        )


def leer_manifiesto(paquete: Path) -> dict[str, Any]:
    """Manifiesto del paquete, sin extraer nada."""
    with tarfile.open(paquete, "r:gz") as tar:
        try:
            f = tar.extractfile(MANIFIESTO)
        except KeyError as exc:
            raise BundleError(f"{paquete} no parece un paquete de este proyecto.") from exc
        if f is None:
            raise BundleError(f"{paquete} tiene un manifiesto ilegible.")
        return dict(json.loads(f.read().decode("utf-8")))


def importar(
    paquete: Path,
    *,
    database_url: str,
    watchlist_path: Path,
    regional_dir: Path,
    force: bool = False,
) -> dict[str, Any]:
    """Restaura un paquete. Se niega a pisar datos salvo `force`."""
    if not paquete.exists():
        raise BundleError(f"No existe {paquete}.")

    manifiesto = leer_manifiesto(paquete)
    destino_base = _ruta_sqlite(database_url)

    if destino_base.exists() and destino_base.stat().st_size > 0 and not force:
        # El caso más común no es "tengo datos valiosos" sino "levanté el
        # compose antes de importar y se sembró el ejemplo". Distinguirlo
        # cambia el consejo por completo.
        propios = _hallazgos(destino_base)
        if propios == 0:
            raise BundleError(
                f"Ya hay una base en {destino_base}, pero está sin hallazgos: "
                "parece una instalación recién levantada con la semilla de "
                "ejemplo.\n"
                "En ese caso no hay nada que perder — repetí con --force."
            )
        raise BundleError(
            f"Ya hay una base en {destino_base} con {propios} hallazgos. "
            "Importar la pisaría entera.\n"
            "Respaldala con `leaks export-bundle` primero, o repetí con --force "
            "si es lo que querés."
        )

    # Chequeo previo: se verifica que TODOS los destinos se puedan escribir
    # antes de tocar ninguno. Sin esto la importación fallaba a mitad de camino
    # —base restaurada, watchlists no— y dejaba una instalación inconsistente
    # con un traceback por toda explicación. Pasó de verdad, con el directorio
    # de watchlists montado de solo lectura.
    _verificar_escribible(destino_base, "la base de datos")
    if manifiesto.get("incluye_watchlist"):
        _verificar_escribible(watchlist_path, "la watchlist")
    if manifiesto.get("incluye_regionales"):
        _verificar_escribible(regional_dir / "prueba.yaml", "las watchlists regionales")

    with tempfile.TemporaryDirectory() as tmp:
        area = Path(tmp)
        with tarfile.open(paquete, "r:gz") as tar:
            miembros = [m for m in tar.getmembers() if _seguro(m, area)]
            if len(miembros) != len(tar.getmembers()):
                raise BundleError("El paquete tiene rutas fuera de lugar; no se extrae.")
            # `filter="data"` es la extracción segura de la stdlib: rechaza
            # rutas absolutas, `..`, enlaces y archivos especiales. Se usa
            # ADEMÁS del filtro propio de arriba, no en su lugar — el paquete
            # llega por un canal que no controlamos.
            tar.extractall(area, members=miembros, filter="data")

        base = area / BASE_EN_PAQUETE
        if not base.exists():
            raise BundleError("El paquete no trae la base de datos.")

        destino_base.parent.mkdir(parents=True, exist_ok=True)
        # Se borran los sidecar del WAL: si quedaran, SQLite intentaría
        # aplicarlos sobre una base que ya no es la suya.
        for sufijo in ("-wal", "-shm"):
            sidecar = destino_base.with_name(destino_base.name + sufijo)
            sidecar.unlink(missing_ok=True)
        shutil.copy2(base, destino_base)

        origen_wl = area / WATCHLIST_EN_PAQUETE
        if origen_wl.exists():
            watchlist_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origen_wl, watchlist_path)

        origen_reg = area / REGIONAL_EN_PAQUETE
        if origen_reg.is_dir():
            regional_dir.mkdir(parents=True, exist_ok=True)
            for archivo in sorted(origen_reg.glob("*.yaml")):
                shutil.copy2(archivo, regional_dir / archivo.name)

    return manifiesto
