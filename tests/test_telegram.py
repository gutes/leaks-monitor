"""Tests del conector de Telegram.

Cubre lo que ya falló o no puede fallar:

* que una invitación a grupo privado se rechace ANTES de generar un pedido;
* que un canal muerto se distinga de uno sin novedades (si no, el investigador
  vigila humo y no se entera);
* que el cursor haga la lectura incremental de verdad;
* que el cuerpo del mensaje NO llegue a `findings`.

Las fixtures son sintéticas: la página real trae contenido de un canal en vivo,
y no se versiona contenido de terceros en este repo.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from leaks.adapters.telegram import (
    NO_EXISTE,
    SIN_PREVIA,
    TelegramChannelAdapter,
    normalizar_handle,
)
from leaks.domain.models import RawItem
from leaks.storage.telegram_repository import (
    ORIGEN_CATALOGO,
    TelegramChannelRepository,
    TelegramValidationError,
)
from leaks.telegram.catalog import parse_catalog

FIXTURES = Path(__file__).parent / "fixtures"
CANAL_HTML = (FIXTURES / "telegram_channel.html").read_text(encoding="utf-8")
SIN_PREVIA_HTML = (FIXTURES / "telegram_no_preview.html").read_text(encoding="utf-8")
CATALOGO_MD = (FIXTURES / "telegram_catalog.md").read_text(encoding="utf-8")


class ClienteFalso:
    """Cliente HTTP de mentira, con respuesta por canal."""

    def __init__(self, por_canal: dict[str, str], fallar: set[str] | None = None) -> None:
        self.por_canal = por_canal
        self.fallar = fallar or set()
        self.pedidos: list[str] = []

    def get_text(self, url: str, params: Any = None) -> str:
        canal = url.rsplit("/", 1)[-1]
        self.pedidos.append(canal)
        if canal in self.fallar:
            raise TimeoutError("sin respuesta")
        return self.por_canal.get(canal, SIN_PREVIA_HTML)

    def close(self) -> None:  # pragma: no cover — no lo usa el adapter
        pass


class TestNormalizarHandle:
    @pytest.mark.parametrize(
        ("entrada", "esperado"),
        [
            ("@Durov", "Durov"),
            ("durov", "durov"),
            ("t.me/durov", "durov"),
            ("https://t.me/durov", "durov"),
            ("https://t.me/s/durov", "durov"),
            ("t.me/durov/123", "durov"),
            ("HTTPS://T.ME/Durov/", "Durov"),
        ],
    )
    def test_acepta_las_formas_habituales(self, entrada: str, esperado: str) -> None:
        assert normalizar_handle(entrada) == esperado

    @pytest.mark.parametrize(
        "entrada",
        [
            "https://t.me/+AbCdEfGhIj",  # invitación a grupo privado
            "t.me/joinchat/AAAA",
            "abc",  # demasiado corto
            "1canal",  # no puede empezar con dígito
            "con-guion",
            "",
        ],
    )
    def test_rechaza_lo_que_no_se_puede_leer(self, entrada: str) -> None:
        """Rechazar acá evita un 404 por corrida, para siempre."""
        assert normalizar_handle(entrada) is None


class TestAdapter:
    def _adapter(self, **kw: Any) -> tuple[TelegramChannelAdapter, ClienteFalso]:
        cliente = ClienteFalso({"ejemplo": CANAL_HTML})
        return TelegramChannelAdapter(cliente, ["ejemplo"], **kw), cliente  # type: ignore[arg-type]

    def test_parsea_los_mensajes(self) -> None:
        adapter, _ = self._adapter()
        items = list(adapter.fetch(None))
        assert len(items) == 2, "el mensaje sin texto no aporta nada que analizar"
        assert items[0].payload["post_id"] == "ejemplo/10"
        assert items[0].payload["url"] == "https://t.me/ejemplo/10"

    def test_conserva_los_saltos_de_linea(self) -> None:
        adapter, _ = self._adapter()
        (primero, _) = list(adapter.fetch(None))
        assert primero.payload["text"] == "Aviso de prueba uno\nsegunda linea"

    def test_desescapa_las_entidades(self) -> None:
        adapter, _ = self._adapter()
        (_, segundo) = list(adapter.fetch(None))
        assert "prevision-ejemplo.gob.ar & otros" in segundo.payload["text"]

    def test_usa_la_fecha_del_canal_y_no_la_de_hoy(self) -> None:
        """Fechar con `now()` es lo que hacía ver el histórico como novedad."""
        adapter, _ = self._adapter()
        item = next(iter(adapter.fetch(None)))
        normalizado = adapter.normalize(item)
        assert normalizado is not None
        assert normalizado.occurred_at == datetime(2026, 8, 10, 12, 0, tzinfo=UTC)

    def test_el_cuerpo_no_llega_al_modelo(self) -> None:
        """A `findings` va metadata; el cuerpo solo viaja al vault cifrado.

        El título es la PRIMERA LÍNEA, no el mensaje: un volcado con cien
        líneas de credenciales no puede terminar en el nombre de la víctima.
        """
        adapter, _ = self._adapter()
        items = list(adapter.fetch(None))
        normalizado = adapter.normalize(items[0])
        assert normalizado is not None
        assert normalizado.victim_name == "Aviso de prueba uno"
        assert "segunda linea" not in normalizado.victim_name
        assert "segunda linea" in items[0].payload["text"], "el crudo sí lo lleva"

    def test_el_titulo_tiene_tope(self) -> None:
        """Una sola línea larguísima tampoco puede entrar entera."""
        from leaks.adapters.telegram import MAX_TITULO

        adapter, _ = self._adapter()
        item = RawItem(source="telegram", payload={"channel": "x", "text": "a" * 5000})
        normalizado = adapter.normalize(item)
        assert normalizado is not None
        assert len(normalizado.victim_name) == MAX_TITULO

    def test_extrae_los_punteros_a_los_datos(self) -> None:
        adapter, _ = self._adapter()
        items = list(adapter.fetch(None))
        normalizado = adapter.normalize(items[1])
        assert normalizado is not None
        assert any("magnet:" in link.url for link in normalizado.download_links)

    def test_el_cursor_hace_la_lectura_incremental(self) -> None:
        adapter, _ = self._adapter(cursors={"ejemplo": "ejemplo/10"})
        items = list(adapter.fetch(None))
        assert [i.payload["post_id"] for i in items] == ["ejemplo/11"]

    def test_publica_el_cursor_nuevo(self) -> None:
        adapter, _ = self._adapter()
        list(adapter.fetch(None))
        assert adapter.nuevos_cursores == {"ejemplo": "ejemplo/12"}

    def test_un_canal_inexistente_se_distingue_de_uno_tranquilo(self) -> None:
        """Sin esto el investigador vigila humo y no se entera nunca."""
        cliente = ClienteFalso({})
        adapter = TelegramChannelAdapter(cliente, ["fantasma"])  # type: ignore[arg-type]
        assert list(adapter.fetch(None)) == []
        assert adapter.errores["fantasma"] == NO_EXISTE

    def test_un_canal_privado_lo_dice(self) -> None:
        cliente = ClienteFalso({"privado": "<html><title>Telegram: View @privado</title></html>"})
        adapter = TelegramChannelAdapter(cliente, ["privado"])  # type: ignore[arg-type]
        assert list(adapter.fetch(None)) == []
        assert adapter.errores["privado"] == SIN_PREVIA

    def test_un_canal_caido_no_cuesta_los_demas(self) -> None:
        cliente = ClienteFalso({"ejemplo": CANAL_HTML}, fallar={"roto"})
        adapter = TelegramChannelAdapter(cliente, ["roto", "ejemplo"])  # type: ignore[arg-type]
        assert len(list(adapter.fetch(None))) == 2
        assert "no respondió" in adapter.errores["roto"]

    def test_las_invitaciones_no_generan_pedido(self) -> None:
        cliente = ClienteFalso({})
        adapter = TelegramChannelAdapter(cliente, ["https://t.me/+AbCdEfGh"])  # type: ignore[arg-type]
        assert list(adapter.fetch(None)) == []
        assert cliente.pedidos == [], "no se le pide a Telegram algo que no se puede leer"

    def test_sin_canales_no_sale_un_solo_pedido(self) -> None:
        cliente = ClienteFalso({})
        adapter = TelegramChannelAdapter(cliente, [])  # type: ignore[arg-type]
        assert list(adapter.fetch(None)) == []
        assert cliente.pedidos == []

    def test_el_bloqueo_de_salida_corta_todo(self) -> None:
        from leaks.pipeline.egress_guard import EgressBlockedError

        class Bloqueado(ClienteFalso):
            def get_text(self, url: str, params: Any = None) -> str:
                raise EgressBlockedError("salida AR")

        adapter = TelegramChannelAdapter(Bloqueado({}), ["x_canal"])  # type: ignore[arg-type]
        with pytest.raises(EgressBlockedError):
            list(adapter.fetch(None))

    def test_un_payload_incompleto_no_rompe(self) -> None:
        adapter, _ = self._adapter()
        assert adapter.normalize(RawItem(source="telegram", payload={})) is None


class TestCatalogo:
    def test_parsea_la_tabla(self) -> None:
        entradas = parse_catalog(CATALOGO_MD)
        assert [e.handle for e in entradas] == ["canalvivo", "otrocanal", "sinactor"]

    def test_descarta_muertos_apagados_y_caidos(self) -> None:
        """Un conteo anterior dio de más por filtrar solo EXPIRED."""
        handles = {e.handle for e in parse_catalog(CATALOGO_MD)}
        assert not handles & {"muerto", "apagado", "caido"}

    def test_descarta_invitaciones_privadas(self) -> None:
        assert "AbCdEfGhIj" not in {e.handle for e in parse_catalog(CATALOGO_MD)}

    def test_deduplica(self) -> None:
        assert [e.handle for e in parse_catalog(CATALOGO_MD)].count("canalvivo") == 1

    def test_conserva_actor_y_tipo(self) -> None:
        (primero, *_) = parse_catalog(CATALOGO_MD)
        assert (primero.actor, primero.kind) == ("Grupo Vivo", "data leaks")

    def test_tolera_filas_sin_actor(self) -> None:
        sin_actor = next(e for e in parse_catalog(CATALOGO_MD) if e.handle == "sinactor")
        assert sin_actor.actor is None

    def test_un_texto_que_no_es_tabla_no_rompe(self) -> None:
        assert parse_catalog("solo texto suelto\nsin tabla") == []


@pytest.fixture
def tg_repo(session_factory: sessionmaker[Session]) -> TelegramChannelRepository:
    return TelegramChannelRepository(session_factory)


class TestRepositorio:
    def test_alta_normaliza_el_handle(self, tg_repo: TelegramChannelRepository) -> None:
        assert tg_repo.add("https://t.me/s/CanalUno").handle == "CanalUno"

    def test_rechaza_lo_ilegible_con_un_motivo(self, tg_repo: TelegramChannelRepository) -> None:
        with pytest.raises(TelegramValidationError, match="privados"):
            tg_repo.add("https://t.me/+AbCdEfGh")

    def test_solo_se_consultan_los_habilitados(self, tg_repo: TelegramChannelRepository) -> None:
        tg_repo.add("canal_activo", enabled=True)
        tg_repo.add("canal_apagado", enabled=False)
        assert tg_repo.enabled_handles() == ("canal_activo",)

    def test_deshabilitar_deja_la_entrada(self, tg_repo: TelegramChannelRepository) -> None:
        canal = tg_repo.add("canal_activo", enabled=True)
        tg_repo.set_enabled(canal.id, False)
        assert tg_repo.enabled_handles() == ()
        assert tg_repo.count_channels() == 1

    def test_el_catalogo_entra_apagado(self, tg_repo: TelegramChannelRepository) -> None:
        """Importar no puede convertirse en cientos de pedidos que nadie pidió."""
        tg_repo.import_many([{"handle": "delcatalogo", "actor": "X"}])
        assert tg_repo.enabled_handles() == ()
        assert tg_repo.list_channels()[0].origin == ORIGEN_CATALOGO

    def test_importar_no_pisa_lo_que_toco_el_investigador(
        self, tg_repo: TelegramChannelRepository
    ) -> None:
        tg_repo.add("compartido", enabled=True, notes="lo sigo yo")
        tg_repo.import_many([{"handle": "compartido", "actor": "Otro"}])
        (canal,) = tg_repo.list_channels()
        assert canal.enabled and canal.notes == "lo sigo yo"

    def test_guarda_y_devuelve_el_cursor(self, tg_repo: TelegramChannelRepository) -> None:
        tg_repo.add("canal_activo")
        tg_repo.save_cursors({"canal_activo": "canal_activo/42"})
        assert tg_repo.cursors() == {"canal_activo": "canal_activo/42"}

    def test_el_cursor_nuevo_limpia_el_error_anterior(
        self, tg_repo: TelegramChannelRepository
    ) -> None:
        tg_repo.add("canal_activo")
        tg_repo.save_errors({"canal_activo": "no existe"})
        tg_repo.save_cursors({"canal_activo": "canal_activo/1"})
        assert tg_repo.list_channels()[0].last_error is None

    def test_registra_por_que_falla_un_canal(self, tg_repo: TelegramChannelRepository) -> None:
        tg_repo.add("canal_muerto")
        tg_repo.save_errors({"canal_muerto": NO_EXISTE})
        assert tg_repo.list_channels()[0].last_error == NO_EXISTE

    def test_la_siembra_no_pisa_una_tabla_con_datos(
        self, tg_repo: TelegramChannelRepository
    ) -> None:
        tg_repo.add("canal_mio")
        assert tg_repo.seed([{"handle": "sembrado"}]) == 0

    def test_baja(self, tg_repo: TelegramChannelRepository) -> None:
        canal = tg_repo.add("canal_activo")
        assert tg_repo.remove(canal.id) is True
        assert tg_repo.count_channels() == 0

    def test_dar_de_alta_a_mano_lo_hace_propio(self, tg_repo: TelegramChannelRepository) -> None:
        """El filtro «cargados a mano» quiere decir «los que decidí yo»."""
        tg_repo.import_many([{"handle": "delcatalogo"}])
        assert tg_repo.add("delcatalogo", notes="lo sigo yo").origin == "user"


class TestRelevancia:
    """El camino completo: mensaje -> relevancia AR -> hallazgo.

    Es la pregunta operativa: ¿lo que aparece en un canal termina en Hallazgos?
    """

    CUERPO = (
        "MEGA LEAK 2026 — GOVERNMENT DATABASES\n"
        + "\n".join(f"relleno {i}" for i in range(40))
        + "\nTarget: prevision-ejemplo.gob.ar — 2.4M records"
    )

    def _item(self, texto: str) -> Any:
        adapter = TelegramChannelAdapter(ClienteFalso({}), [])  # type: ignore[arg-type]
        return adapter.normalize(
            RawItem(
                source="telegram",
                payload={
                    "channel": "canal",
                    "text": texto,
                    "published": "2026-08-10T00:00:00Z",
                    "url": "https://t.me/canal/1",
                },
            )
        )

    def test_ve_el_dominio_aunque_este_al_fondo_del_mensaje(self) -> None:
        """Estos canales ponen un titular genérico y el objetivo mucho más abajo.

        Recortar el cuerpo antes de evaluar hacía invisible al organismo
        afectado, y el hallazgo nunca se creaba.
        """
        from leaks.relevance.rules import extract_domains

        item = self._item(self.CUERPO)
        assert len(self.CUERPO) > 400, "el dominio tiene que quedar lejos del inicio"
        assert "prevision-ejemplo.gob.ar" in extract_domains(item)

    def test_el_cuerpo_entero_llega_a_la_evaluacion(self) -> None:
        item = self._item(self.CUERPO)
        assert item is not None
        assert item.description == self.CUERPO

    def test_pero_el_titulo_que_se_persiste_va_recortado(self) -> None:
        item = self._item(self.CUERPO)
        assert item is not None
        assert item.victim_name == "MEGA LEAK 2026 — GOVERNMENT DATABASES"

    def test_un_mensaje_sin_nada_argentino_no_genera_hallazgo(self) -> None:
        from leaks.relevance.rules import extract_domains

        item = self._item("Leak of some-random-company.co.za, 500k records")
        assert "prevision-ejemplo.gob.ar" not in extract_domains(item)


class TestOrdenEstable:
    """Habilitar un canal no puede mover las filas bajo el cursor.

    El orden era `enabled DESC, handle`, así que al habilitar uno saltaba al
    tope de la lista, otra fila ocupaba su lugar y parecía que el clic lo había
    DESACTIVADO. Reportado como bug; el canal se habilitaba bien.
    """

    def test_el_orden_no_cambia_al_habilitar(self, tg_repo: TelegramChannelRepository) -> None:
        for h in ("canal_alfa", "canal_beta", "canal_gama"):
            tg_repo.add(h, enabled=False)
        antes = [c.handle for c in tg_repo.list_channels()]

        medio = next(c for c in tg_repo.list_channels() if c.handle == "canal_beta")
        tg_repo.set_enabled(medio.id, True)

        assert [c.handle for c in tg_repo.list_channels()] == antes

    def test_se_ordena_alfabeticamente(self, tg_repo: TelegramChannelRepository) -> None:
        for h in ("canal_zeta", "canal_alfa", "canal_mika"):
            tg_repo.add(h)
        handles = [c.handle for c in tg_repo.list_channels()]
        assert handles == sorted(handles)

    def test_el_estado_se_acota_con_el_filtro(self, tg_repo: TelegramChannelRepository) -> None:
        """Es la vía para ver solo los activos, sin reordenar la tabla."""
        tg_repo.add("canal_activo", enabled=True)
        tg_repo.add("canal_apagado", enabled=False)
        assert [c.handle for c in tg_repo.list_channels(enabled=True)] == ["canal_activo"]
