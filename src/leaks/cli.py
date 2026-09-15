"""Interfaz de línea de comandos.

Capa de entrada fina: parsea, delega en el composition root y traduce el
resultado a un código de salida. Nada de lógica de negocio acá.

Comandos:
    leaks init-db     crea el schema
    leaks run         una corrida (one-shot, para pruebas y para cron)
    leaks schedule    corrida diaria a la hora configurada
    leaks serve       API + frontend de solo lectura
    leaks feeds       lista el registro de feeds y su política
    leaks purge-pii   aplica la retención de la bóveda cifrada
    leaks sync-watchlist  importa las entradas nuevas del YAML semilla
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from leaks.adapters.fid_discovery import DEFAULT_FIRST_FID, DEFAULT_LAST_FID
from leaks.adapters.registry import FEED_REGISTRY, resolve_enabled
from leaks.bootstrap import build_application, configure_logging
from leaks.bundle import BundleError
from leaks.bundle import exportar as exportar_bundle
from leaks.bundle import importar as importar_bundle
from leaks.config import get_settings
from leaks.pipeline.discovery_coordinator import DiscoveryCoordinator
from leaks.pipeline.runner import RunReport
from leaks.pipeline.scheduler import run_forever
from leaks.telegram.importer import parsear as parsear_canales

logger = logging.getLogger("leaks.cli")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leaks",
        description="Monitoreo de leaks con capa de relevancia argentina.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Crea las tablas si no existen.")
    sub.add_parser("run", help="Corre el pipeline una vez y termina.")
    sub.add_parser("schedule", help="Corre el pipeline todos los días a la hora configurada.")
    sub.add_parser("feeds", help="Lista los feeds registrados y si corren.")
    sub.add_parser("purge-pii", help="Borra los registros con PII vencidos.")

    rebobinar = sub.add_parser(
        "rewind-cursor",
        help="Retrocede la marca incremental de una fuente para reprocesar su historia.",
    )
    rebobinar.add_argument("--feed", required=True, help="Nombre de la fuente.")
    rebobinar.add_argument(
        "--to", dest="hasta", required=True, help="Fecha ISO (2026-09-06 o 2026-09-06T00:00:00Z)."
    )

    descubrir = sub.add_parser(
        "discover-fids",
        help="Busca subforos de un foro MyBB para sumar ventana de cobertura.",
    )
    descubrir.add_argument("--feed", default="darkforums", help="Foro a barrer.")
    descubrir.add_argument("--from", dest="desde", type=int, default=DEFAULT_FIRST_FID)
    descubrir.add_argument("--to", dest="hasta", type=int, default=DEFAULT_LAST_FID)
    sub.add_parser(
        "sync-watchlist",
        help="Importa a la base las entradas nuevas del YAML semilla (no borra ni pisa).",
    )

    canales = sub.add_parser(
        "import-telegram",
        help="Da de alta canales de Telegram desde un archivo de texto.",
    )
    canales.add_argument("archivo", help="Un canal por línea. Acepta @x, t.me/x o la URL.")
    canales.add_argument(
        "--enabled",
        action="store_true",
        help="Habilitarlos al importar. Por defecto entran apagados.",
    )

    paquete = sub.add_parser(
        "export-bundle",
        help="Empaqueta la base y las watchlists para repartir el prototipo.",
    )
    paquete.add_argument("--out", required=True, help="Archivo .tar.gz de destino.")

    restaurar = sub.add_parser(
        "import-bundle", help="Restaura un paquete generado con export-bundle."
    )
    restaurar.add_argument("archivo", help="El .tar.gz a restaurar.")
    restaurar.add_argument(
        "--force", action="store_true", help="Pisa la base existente. Destructivo."
    )

    exportar = sub.add_parser(
        "export-watchlist",
        help="Vuelca la watchlist de la base a YAML, incluido lo editado desde la UI.",
    )
    exportar.add_argument("--out", default=None, help="Archivo destino. Sin esto sale por stdout.")

    serve = sub.add_parser("serve", help="Levanta la API y el frontend de solo lectura.")
    serve.add_argument("--host", default=None, help="Override de LEAKS_API_HOST.")
    serve.add_argument("--port", type=int, default=None, help="Override de LEAKS_API_PORT.")
    serve.add_argument("--reload", action="store_true", help="Autorecarga (desarrollo).")

    return parser


#: Fecha y hora en el log. Va la FECHA además de la hora: sin ella, mirando el
#: log no se puede distinguir la corrida de hoy de la de la semana pasada, que
#: es justamente lo que hay que poder ver.
_FORMATO_FECHA = "%Y-%m-%d %H:%M:%S %Z"


def _sello(momento: datetime) -> str:
    """Marca temporal en hora local: el investigador razona en su horario."""
    return momento.astimezone().strftime(_FORMATO_FECHA)


def _print_report(report: RunReport) -> None:
    """Resumen legible de la corrida, fuente por fuente."""
    duracion = (report.finished_at - report.started_at).total_seconds()

    if report.blocked:
        print("\n" + "=" * 72)
        print(f"  [{_sello(report.started_at)}] CORRIDA BLOQUEADA — no se consultó ninguna fuente")
        print(f"  {report.blocked_reason}")
        print("=" * 72, flush=True)
        return

    print(f"\n[{_sello(report.started_at)}] Corrida terminada en {duracion:.1f} s")
    print(f"{'FUENTE':<20} {'ESTADO':<9} {'TRAÍDOS':>8} {'AR':>6} {'NUEVOS':>7}")
    for r in report.results:
        print(
            f"{r.source:<20} {r.status:<9} {r.items_fetched:>8} "
            f"{r.items_matched:>6} {r.items_persisted:>7}"
        )
        if r.error:
            print(f"{'':<20} └─ {r.error}")
    print(
        f"\n[{_sello(report.finished_at)}] Total: {report.total_fetched} traídos, "
        f"{report.total_matched} relevantes AR, "
        f"{report.total_new} nuevos."
    )
    if report.pii_stored:
        print(f"PII cifrada: {report.pii_stored} registros.")
    if report.pii_purged:
        print(f"PII vencida borrada: {report.pii_purged} registros.")
    if report.failed_sources:
        print(f"Fuentes caídas (el run siguió igual): {', '.join(report.failed_sources)}")


def _cmd_feeds() -> int:
    """Muestra el registro: qué corre, qué no y por qué."""
    settings = get_settings()
    motivos = {spec.name: motivo for spec, motivo in resolve_enabled(settings)}
    print(f"{'FEED':<20} {'TIPO':<13} {'ESTADO'}")
    for spec in FEED_REGISTRY:
        motivo = motivos.get(spec.name, "no seleccionado en LEAKS_ENABLED_FEEDS")
        estado = "corre" if spec.name in motivos and motivo is None else f"no corre — {motivo}"
        print(f"{spec.name:<20} {spec.leak_type!s:<13} {estado}")
        if spec.license_note:
            print(f"{'':<20} licencia: {spec.license_note}")
    return 0


def _cmd_serve(host: str | None, port: int | None, reload: bool) -> int:
    """Levanta uvicorn con la app de solo lectura."""
    import uvicorn

    settings = get_settings()

    # El schema se crea acá y no en el primer request: sin tablas, TODOS los
    # endpoints devuelven 500 y el frontend se ve vacío sin decir por qué.
    build_application(settings).create_schema()

    destino_host = host or settings.api_host
    destino_port = port or settings.api_port
    if destino_host not in ("127.0.0.1", "localhost"):
        # No se bloquea: puede ser un despliegue detrás de un proxy que
        # autentique. Pero que quede dicho, porque el default es sin auth.
        logger.warning(
            "Sirviendo en %s: la API no tiene autenticación. "
            "Poné un proxy que autentique antes de exponerla.",
            destino_host,
        )
    uvicorn.run(
        "leaks.api.app:create_app",
        factory=True,
        host=destino_host,
        port=destino_port,
        reload=reload,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada. Devuelve el código de salida del proceso."""
    args = _build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)

    if args.command == "feeds":
        return _cmd_feeds()
    if args.command == "serve":
        return _cmd_serve(args.host, args.port, args.reload)

    app = build_application(settings)

    if args.command == "init-db":
        app.create_schema()
        print(f"Schema listo en {settings.database_url}")
        return 0

    if args.command == "import-telegram":
        lectura = parsear_canales(Path(args.archivo).read_text(encoding="utf-8"))
        importados = app.telegram_repo.import_many(lectura.canales, enabled=args.enabled)
        estado = "habilitados" if args.enabled else "deshabilitados"
        print(f"{importados} canales nuevos, {estado}.")
        if lectura.duplicadas:
            print(f"  {lectura.duplicadas} repetidos dentro del archivo")
        ya_estaban = len(lectura.canales) - importados
        if ya_estaban:
            print(f"  {ya_estaban} ya estaban dados de alta (no se tocaron)")
        # Lo rechazado se dice línea por línea: saltearlo en silencio haría
        # creer que entró todo.
        for x in lectura.rechazadas:
            print(f"  línea {x.numero} rechazada: {x.motivo}")
            print(f"    {x.contenido[:80]}")
        return 0

    if args.command == "export-bundle":
        # `VACUUM INTO` y no una copia: en modo WAL lo recién escrito vive en
        # `leaks.db-wal`, y copiar el `.db` entrega una base incompleta sin
        # que nada lo delate.
        manifiesto = exportar_bundle(
            database_url=settings.database_url,
            # Se empaqueta lo que efectivamente se está usando.
            watchlist_path=settings.watchlist_vigente,
            regional_dir=settings.regional_watchlist_vigente,
            destino=Path(args.out),
        )
        tam = Path(args.out).stat().st_size / 1e6
        print(f"Paquete escrito en {args.out} ({tam:.1f} MB)")
        for tabla, n in manifiesto.conteos.items():
            print(f"  {tabla:<20} {n:>6}")
        print(f"  watchlists regionales {manifiesto.incluye_regionales:>3}")
        print("\nNo incluye el vault de PII ni ninguna credencial: la")
        print("configuración viaja por entorno, no en el paquete.")
        return 0

    if args.command == "import-bundle":
        try:
            restaurado = importar_bundle(
                Path(args.archivo),
                database_url=settings.database_url,
                # Se restaura en el destino CONFIGURADO, nunca en el del
                # ejemplo: escribir ahí fue un bug real que hacía parecer que
                # el paquete se importaba bien.
                watchlist_path=settings.watchlist_path,
                regional_dir=settings.regional_watchlist_dir,
                force=args.force,
            )
        except BundleError as exc:
            print(f"No se pudo importar: {exc}")
            return 1
        print(f"Paquete restaurado (creado {restaurado.get('creado', '?')})")
        for tabla, n in (restaurado.get("conteos") or {}).items():
            print(f"  {tabla:<20} {n:>6}")
        return 0

    if args.command == "export-watchlist":
        # Respaldo de lo que vale: la base, no el YAML semilla. Apenas se edita
        # una entrada desde la UI el archivo original queda viejo.
        texto = app.watchlist_repo.export_yaml()
        if args.out:
            destino = Path(args.out)
            destino.write_text(texto, encoding="utf-8")
            conteos = app.watchlist_repo.counts()
            print(f"Watchlist exportada a {destino}: {conteos['total']} entradas")
        else:
            print(texto, end="")
        return 0

    if args.command == "sync-watchlist":
        # Solo agrega lo que falta: no toca lo que se editó desde la UI ni
        # revive lo que se borró... salvo que esté en el YAML, claro.
        agregadas = app.watchlist_repo.seed_from_yaml(
            settings.watchlist_vigente, allow_updates=True
        )
        conteos = app.watchlist_repo.counts()
        print(f"Entradas nuevas importadas: {agregadas}")
        print(
            f"Watchlist: {conteos['total']} entradas "
            f"({conteos['enabled']} activas, {conteos['domains']} dominios, "
            f"{conteos['keywords']} keywords)"
        )
        return 0

    if args.command == "purge-pii":
        borrados = app.pii_vault.purge_expired()
        eventos = app.event_sink.purge_expired()
        print(f"Registros con PII vencidos borrados: {borrados}")
        print(f"Eventos de actividad vencidos borrados: {eventos}")
        return 0

    if args.command == "run":
        # Crear el schema acá hace que `leaks run` funcione de cero sin un
        # paso previo: es el "corre con un comando" del enunciado.
        app.create_schema()
        reporte = app.runner.run()
        _print_report(reporte)
        # Fail-closed también en el exit code: si NINGUNA fuente respondió, el
        # run fue un fracaso aunque no haya excepción, y el cron tiene que
        # enterarse.
        return 0 if reporte.ok else 1

    if args.command == "rewind-cursor":
        try:
            hasta_dt = datetime.fromisoformat(args.hasta.replace("Z", "+00:00"))
        except ValueError:
            print(f"Fecha inválida: {args.hasta!r}. Usá ISO, por ejemplo 2026-09-06.")
            return 2
        if hasta_dt.tzinfo is None:
            hasta_dt = hasta_dt.replace(tzinfo=UTC)

        app.create_schema()
        anterior = app.repository.rewind_cursor(args.feed, hasta_dt)
        previo = _sello(anterior) if anterior else "(sin cursor)"
        print(f"Cursor de {args.feed}: {previo} -> {_sello(hasta_dt)}")
        print(
            "La próxima corrida reprocesa desde esa fecha. El dedup evita duplicados, "
            "y los hallazgos entran como novedades (no como importación inicial)."
        )
        return 0

    if args.command == "discover-fids":
        coordinador = DiscoveryCoordinator(settings)
        print(f"Barriendo subforos de {args.feed} (fids {args.desde}..{args.hasta})…")
        coordinador.trigger(args.feed, args.desde, args.hasta)
        while coordinador.state.running:
            time.sleep(0.5)
        resultado = coordinador.state
        if resultado.last_error:
            print(f"Falló: {resultado.last_error}")
            return 1
        if not resultado.probes:
            print("Ningún subforo con contenido en ese rango.")
            return 0

        print(f"\n{'FID':<6} {'THREADS':>7}  {'VENTANA':>12}  EJEMPLO")
        for p in resultado.probes:
            dias = f"{p.window_days:.1f} días" if p.window_days is not None else "sin fecha"
            print(f"{p.fid:<6} {p.threads:>7}  {dias:>12}  {p.sample_title or ''}")
        print(
            "\nPara sumarlos, pegá esta línea en el .env y recreá los contenedores.\n"
            "Revisá antes cuáles te sirven: cada uno es un request más por sondeo.\n"
        )
        print(resultado.env_line)
        return 0

    if args.command == "schedule":
        app.create_schema()
        if settings.run_on_start:
            # Sin esto el tablero queda vacío hasta la primera corrida
            # programada, y parece roto cuando en realidad no arrancó todavía.
            print(
                f"[{_sello(datetime.now(UTC))}] Corrida inicial (LEAKS_RUN_ON_START=true)…",
                flush=True,
            )
            _print_report(app.runner.run())
        print(
            f"[{_sello(datetime.now(UTC))}] Scheduler activo. "
            f"Corrida diaria a las {settings.daily_run_at} (hora local)."
        )
        # La cadencia sale del registro: sumar una fuente de ventana corta es
        # una línea de dato, no un cambio acá ni en el scheduler.
        sondeos = {
            spec.name: spec.poll_interval_minutes
            for spec in FEED_REGISTRY
            if spec.poll_interval_minutes
        }
        if sondeos:
            detalle = ", ".join(f"{f} cada {m} min" for f, m in sorted(sondeos.items()))
            print(f"Sondeos de fuentes efímeras: {detalle}", flush=True)
        if settings.scheduler_catchup:
            print(
                "Recuperación activa: si la máquina estuvo suspendida a la hora "
                "agendada, la corrida sale al despertar.",
                flush=True,
            )
        run_forever(
            app.runner.run,
            daily_at=settings.daily_run_at,
            polls=sondeos,
            catchup=settings.scheduler_catchup,
        )
        return 0

    return 2  # pragma: no cover — argparse ya cubre los comandos desconocidos


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
