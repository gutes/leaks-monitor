"""Tests del adapter de foros MyBB (DarkForums / BreachForums).

Lo que hay que garantizar acá es más fuerte que en los otros feeds: la fuente
publica volcados de datos, así que el test principal es que **nada de eso
llegue a la base**.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from leaks.adapters.http import FeedHttpClient
from leaks.adapters.mybb_forum import SYNDICATION_PATH, MyBBForumAdapter
from leaks.adapters.registry import get_spec
from leaks.config import Settings
from leaks.domain.models import LeakType, RawItem
from leaks.pipeline.runner import PipelineRunner
from leaks.privacy.scrub import redact_pii
from leaks.relevance.watchlist import Watchlist
from leaks.storage.models import FindingRow
from leaks.storage.repository import SqlAlchemyFindingRepository
from tests.conftest import read_fixture

BASE = "https://foro.test"
FEED_URL = f"{BASE}{SYNDICATION_PATH}"


@pytest.fixture
def client() -> FeedHttpClient:
    return FeedHttpClient(
        user_agent="leaks-monitor/test",
        max_retries=0,
        rate_limit_delay=0,
        sleep=lambda _s: None,
    )


@pytest.fixture
def adapter(client: FeedHttpClient) -> MyBBForumAdapter:
    return MyBBForumAdapter(client, "darkforums", (BASE,))


class TestParseo:
    @respx.mock
    def test_lee_el_indice_de_threads(self, adapter: MyBBForumAdapter) -> None:
        respx.get(FEED_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("darkforums_atom.xml"))
        )
        items = list(adapter.fetch(None))

        assert len(items) == 6
        assert all(i.source == "darkforums" for i in items)
        assert all(i.payload["title"] for i in items)

    @respx.mock
    def test_normaliza_titulo_autor_y_fecha(self, adapter: MyBBForumAdapter) -> None:
        respx.get(FEED_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("darkforums_atom.xml"))
        )
        item = adapter.normalize(next(iter(adapter.fetch(None))))

        assert item is not None
        assert item.leak_type is LeakType.FORUM_POST
        assert item.victim_name
        # El autor viene envuelto en HTML: tiene que salir en texto plano.
        assert item.actor and "<" not in item.actor
        assert item.discovered_at.tzinfo is not None

    def test_entrada_sin_titulo_se_descarta(self, adapter: MyBBForumAdapter) -> None:
        assert (
            adapter.normalize(
                RawItem(source="darkforums", payload={"published": "2026-08-14T20:00:00Z"})
            )
            is None
        )

    @respx.mock
    def test_xml_ilegible_falla_con_mensaje_claro(self, adapter: MyBBForumAdapter) -> None:
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text="<no-es-atom"))
        with pytest.raises(RuntimeError, match="Atom ilegible"):
            list(adapter.fetch(None))


class TestVentanaDeSindicacion:
    """Cuánta historia pide el adapter. Es lo que decide qué se pierde."""

    def test_pide_el_maximo_que_mybb_entrega(self) -> None:
        """Sin `limit` son 15 threads (3,3 h); con 50, 20,6 h — mismo request.

        Medido el 2026-09-01 contra darkforums. MyBB topea en 50: pedir más
        devuelve 50 igual. Bajar esto vuelve a abrir el agujero por el que se
        perdieron threads enteros mientras el pipeline estaba caído.
        """
        assert "limit=50" in SYNDICATION_PATH

    @respx.mock
    def test_parsea_una_ventana_grande(self, client: FeedHttpClient) -> None:
        respx.get(FEED_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("darkforums_atom.xml"))
        )
        adapter = MyBBForumAdapter(client, "darkforums", (BASE,))
        assert len(list(adapter.fetch(None))) == 6


class TestSubforos:
    """Cada subforo trae SUS últimos 50: suman ventana en vez de repetirla."""

    @respx.mock
    def test_consulta_el_global_y_cada_subforo(self, client: FeedHttpClient) -> None:
        atom = read_fixture("darkforums_atom.xml")
        global_ = respx.get(FEED_URL).mock(return_value=httpx.Response(200, text=atom))
        uno = respx.get(f"{FEED_URL}&fid=10").mock(return_value=httpx.Response(200, text=atom))
        otro = respx.get(f"{FEED_URL}&fid=23").mock(return_value=httpx.Response(200, text=atom))

        adapter = MyBBForumAdapter(client, "darkforums", (BASE,), fids=("10", "23"))
        list(adapter.fetch(None))

        assert global_.called and uno.called and otro.called

    @respx.mock
    def test_el_mismo_thread_no_se_cuenta_dos_veces(self, client: FeedHttpClient) -> None:
        """Un thread está en el índice global y otra vez en el de su subforo.

        Se deduplica en el adapter y no en el storage para que la telemetría
        diga cuántos threads distintos vimos, no cuántas veces los vimos.
        """
        atom = read_fixture("darkforums_atom.xml")
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text=atom))
        respx.get(f"{FEED_URL}&fid=10").mock(return_value=httpx.Response(200, text=atom))

        adapter = MyBBForumAdapter(client, "darkforums", (BASE,), fids=("10",))

        # La fixture tiene 6 threads; pedirla dos veces sigue dando 6.
        assert len(list(adapter.fetch(None))) == 6

    @respx.mock
    def test_un_subforo_caido_no_tumba_la_fuente(self, client: FeedHttpClient) -> None:
        """Los ids se cargan a mano: pueden quedar viejos si el foro reordena."""
        atom = read_fixture("darkforums_atom.xml")
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text=atom))
        respx.get(f"{FEED_URL}&fid=99").mock(return_value=httpx.Response(404))

        adapter = MyBBForumAdapter(client, "darkforums", (BASE,), fids=("99",))

        assert len(list(adapter.fetch(None))) == 6

    @respx.mock
    def test_sin_subforos_no_hace_pedidos_de_mas(self, client: FeedHttpClient) -> None:
        """El default es vacío: nadie paga requests que no pidió."""
        ruta = respx.get(FEED_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("darkforums_atom.xml"))
        )
        adapter = MyBBForumAdapter(client, "darkforums", (BASE,))
        list(adapter.fetch(None))

        assert ruta.call_count == 1
        assert len(respx.calls) == 1


class TestAtomConBasura:
    """Despliegues reales que sirven Atom bueno con algo colado adelante."""

    @respx.mock
    def test_un_espacio_antes_del_xml_no_pierde_la_fuente(self, client: FeedHttpClient) -> None:
        """El caso de bf.st: Atom válido detrás de un espacio y un salto.

        La declaración `<?xml…?>` tiene que ser el primer byte, así que el
        parser lo rechazaba entero. Perder una fuente por un byte de más no.
        """
        atom = " \n" + read_fixture("darkforums_atom.xml")
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text=atom))
        adapter = MyBBForumAdapter(client, "breachforums", (BASE,))

        assert len(list(adapter.fetch(None))) == 6

    @respx.mock
    def test_un_bom_tampoco(self, client: FeedHttpClient) -> None:
        atom = "\ufeff" + read_fixture("darkforums_atom.xml")
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text=atom))
        adapter = MyBBForumAdapter(client, "breachforums", (BASE,))

        assert len(list(adapter.fetch(None))) == 6

    @respx.mock
    def test_algo_ilegible_sigue_fallando(self, client: FeedHttpClient) -> None:
        """Tolerar el arranque no es tragar cualquier cosa."""
        # La página de desafío típica: HTML sin cerrar, no parsea.
        respx.get(FEED_URL).mock(
            return_value=httpx.Response(200, text="<html><meta charset='utf-8'>Checking...")
        )
        adapter = MyBBForumAdapter(client, "breachforums", (BASE,))

        with pytest.raises(RuntimeError, match="Atom ilegible"):
            list(adapter.fetch(None))

    @respx.mock
    def test_xml_bien_formado_sin_entradas_no_inventa_nada(self, client: FeedHttpClient) -> None:
        """Un XML válido que no es Atom no rompe: simplemente no trae threads."""
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text="<html>hola</html>"))
        adapter = MyBBForumAdapter(client, "breachforums", (BASE,))

        assert list(adapter.fetch(None)) == []


class TestDominiosRotativos:
    """Estos foros cambian de dominio: hay que sobrevivirlo."""

    @respx.mock
    def test_usa_el_primer_dominio_que_responde(self, client: FeedHttpClient) -> None:
        respx.get(f"https://caido.test{SYNDICATION_PATH}").mock(return_value=httpx.Response(503))
        respx.get(FEED_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("darkforums_atom.xml"))
        )
        adapter = MyBBForumAdapter(client, "darkforums", ("https://caido.test", BASE))

        assert len(list(adapter.fetch(None))) == 6

    @respx.mock
    def test_si_ninguno_responde_lo_dice(self, client: FeedHttpClient) -> None:
        respx.get(f"https://caido.test{SYNDICATION_PATH}").mock(return_value=httpx.Response(503))
        adapter = MyBBForumAdapter(client, "breachforums", ("https://caido.test",))

        with pytest.raises(RuntimeError, match=r"incautado|respondió"):
            list(adapter.fetch(None))

    @respx.mock
    def test_el_error_dice_que_falló_en_cada_dominio(self, client: FeedHttpClient) -> None:
        """Sin el detalle por dominio hay que reproducir el request a mano.

        No es lo mismo que el foro no responda (se mudó: hay que buscar dominio
        nuevo) que un 403 (nos bloquearon: el dominio sigue siendo el bueno).
        """
        respx.get(f"https://caido.test{SYNDICATION_PATH}").mock(return_value=httpx.Response(503))
        respx.get(f"https://bloqueado.test{SYNDICATION_PATH}").mock(
            return_value=httpx.Response(403)
        )
        adapter = MyBBForumAdapter(
            client, "darkforums", ("https://caido.test", "https://bloqueado.test")
        )

        with pytest.raises(RuntimeError) as fallo:
            list(adapter.fetch(None))

        mensaje = str(fallo.value)
        assert "https://caido.test" in mensaje and "503" in mensaje
        assert "https://bloqueado.test" in mensaje and "403" in mensaje
        # Entra entero en la columna `error` de `source_runs`, que trunca a 500.
        assert len(mensaje) <= 500

    def test_sin_dominios_configurados_no_sale_a_la_red(self, client: FeedHttpClient) -> None:
        """Es el estado de BreachForums hoy: registrado pero sin dominio."""
        adapter = MyBBForumAdapter(client, "breachforums", ())
        assert list(adapter.fetch(None)) == []


class TestPrivacidad:
    """La razón por la que estas fuentes están detrás del flag de PII."""

    def test_el_registro_las_marca_como_riesgosas(self) -> None:
        """Ambas exigen el toggle de PII y no persisten texto libre.

        No se chequea `enabled_by_default`: darkforums lo tiene en `True` a
        propósito, para que el único motivo por el que está apagado sea el
        toggle de PII y el interruptor pueda encenderlo. Que efectivamente no
        corra por defecto se verifica en `TestToggleDeFuentesConPii`.
        """
        for nombre in ("darkforums", "breachforums"):
            spec = get_spec(nombre)
            assert spec is not None
            assert spec.requires_pii is True, nombre
            assert spec.high_pii_surface is True, nombre

    def test_no_se_persiste_el_cuerpo_del_thread(
        self,
        repository: SqlAlchemyFindingRepository,
        watchlist: Watchlist,
        settings: Settings,
        session_factory: object,
    ) -> None:
        """El cuerpo trae las muestras de datos robados: no entra a la base."""
        from tests.test_pipeline import FakeAdapter, spec_for

        cuerpo = (
            "Location: Argentina | Site: prevision-ejemplo.gob.ar | "
            "Sample: juan.perez@prevision-ejemplo.gob.ar:Password123 DNI 30123456"
        )
        adapter = FakeAdapter(
            [
                {
                    "victim": "[DATABASE] Prevision Ejemplo Argentina 2026",
                    "domain": None,
                    "country": None,
                    "discovered": __import__("datetime").datetime(
                        2026, 8, 14, tzinfo=__import__("datetime").UTC
                    ),
                    "description": cuerpo,
                }
            ]
        )
        spec = spec_for(adapter)
        spec = type(spec)(**{**spec.__dict__, "high_pii_surface": True})

        runner = PipelineRunner(repository=repository, watchlist=watchlist, settings=settings)
        runner.run([(spec, None)])

        with session_factory() as session:  # type: ignore[operator]
            fila = session.query(FindingRow).one()

        # Matcheó gracias al cuerpo (ahí está el dominio)...
        assert "watchlist" in fila.ar_match_reason or "tld_ar" in fila.ar_match_reason
        # ...pero el cuerpo no se guardó.
        assert fila.description is None
        assert "Password123" not in str(fila.__dict__)
        assert "juan.perez@prevision-ejemplo.gob.ar" not in str(fila.__dict__)


class TestRedaccionDeTitulos:
    """El título es la identidad del hallazgo: se redacta, no se descarta."""

    def test_redacta_el_email_pero_conserva_el_resto(self) -> None:
        resultado = redact_pii("Prevision Ejemplo dump juan@x.gob.ar 2026")
        assert resultado is not None
        assert "juan@x.gob.ar" not in resultado
        assert "Prevision Ejemplo" in resultado
        assert "[redactado]" in resultado

    def test_un_titulo_limpio_no_se_toca(self) -> None:
        assert redact_pii("[DATABASE] Empresa Argentina 2026") == (
            "[DATABASE] Empresa Argentina 2026"
        )

    def test_texto_vacio(self) -> None:
        assert redact_pii(None) is None
        assert redact_pii("   ") is None


class TestToggleDeFuentesConPii:
    """El toggle tiene que poder encender los foros de verdad.

    Regresión: `darkforums` estaba además `enabled_by_default=False`, así que
    `resolve_enabled` lo descartaba por ese motivo *antes* de mirar el toggle
    y el interruptor de la UI no hacía nada.
    """

    def test_apagado_por_defecto(self) -> None:
        from leaks.adapters.registry import resolve_enabled

        motivos = {spec.name: motivo for spec, motivo in resolve_enabled(Settings(store_pii=False))}
        assert motivos["darkforums"] is not None
        assert "PII" in motivos["darkforums"]

    def test_el_toggle_lo_enciende(self) -> None:
        from leaks.adapters.registry import resolve_enabled

        motivos = {
            spec.name: motivo for spec, motivo in resolve_enabled(Settings(store_pii=False), True)
        }
        assert motivos["darkforums"] is None, "el toggle tiene que habilitarlo"

    def test_breachforums_apagado_mientras_no_tenga_dominio(self) -> None:
        """Tiene un motivo independiente del PII: no hay dominio operativo.

        Se pasa la lista vacía a mano: el default del repo trae el dominio
        verificado, y este test es sobre el estado "todavía no reapareció".
        """
        from leaks.adapters.registry import resolve_enabled

        config = Settings(store_pii=False, breachforums_base_urls=())
        motivos = {spec.name: motivo for spec, motivo in resolve_enabled(config, True)}

        assert motivos["breachforums"] is not None
        assert "dominio" in motivos["breachforums"]

    def test_configurarle_un_dominio_lo_enciende_solo(self) -> None:
        """El `disabled_reason` promete que configurar la URL alcanza.

        Antes no alcanzaba: había que además nombrarlo en `LEAKS_ENABLED_FEEDS`,
        y el mensaje que imprimía el sistema mandaba a hacer algo que no servía.
        """
        from leaks.adapters.registry import resolve_enabled

        config = Settings(store_pii=False, breachforums_base_urls="https://ejemplo.test")
        motivos = {spec.name: motivo for spec, motivo in resolve_enabled(config, True)}

        assert motivos["breachforums"] is None

    def test_el_dominio_no_saltea_el_gate_de_pii(self) -> None:
        """Encender por configuración no puede saltear la otra puerta."""
        from leaks.adapters.registry import resolve_enabled

        config = Settings(store_pii=False, breachforums_base_urls="https://ejemplo.test")
        motivos = {spec.name: motivo for spec, motivo in resolve_enabled(config, False)}

        assert "PII" in (motivos["breachforums"] or "")

    def test_un_feed_apagado_por_politica_no_se_enciende_asi(self) -> None:
        """La vía solo aplica a los apagados por falta de dato.

        `enables_with_setting` vacío = ningún ajuste lo enciende; para eso está
        `LEAKS_ENABLED_FEEDS`, que es una decisión explícita.
        """
        from leaks.adapters.registry import FEED_REGISTRY, _configurado

        config = Settings(store_pii=False, breachforums_base_urls="https://ejemplo.test")
        otros = [s for s in FEED_REGISTRY if not s.enables_with_setting]

        assert otros, "el test pierde sentido si todos declaran la vía"
        assert not any(_configurado(spec, config) for spec in otros)


class TestRelevanciaSobreElFeed:
    """La fixture sintética cubre casos que la captura real no tenía."""

    @respx.mock
    def test_matchea_el_thread_argentino_por_el_cuerpo(
        self, adapter: MyBBForumAdapter, watchlist: Watchlist
    ) -> None:
        """El dominio afectado está en el cuerpo, no en el título."""
        from leaks.relevance.rules import evaluate

        respx.get(FEED_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("darkforums_atom.xml"))
        )
        veredictos = {}
        for crudo in adapter.fetch(None):
            item = adapter.normalize(crudo)
            if item is None:
                continue
            veredictos[item.victim_name] = evaluate(item, watchlist)

        ar = next(v for k, v in veredictos.items() if "Organismo Nacional" in k)
        assert ar.is_match
        # prevision-ejemplo.gob.ar aparece solo en el cuerpo del post.
        assert "watchlist" in ar.detail

    @respx.mock
    def test_el_anuncio_del_foro_no_matchea(
        self, adapter: MyBBForumAdapter, watchlist: Watchlist
    ) -> None:
        """Ruido del foro: no puede entrar al pipeline de alertas."""
        from leaks.relevance.rules import evaluate

        respx.get(FEED_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("darkforums_atom.xml"))
        )
        for crudo in adapter.fetch(None):
            item = adapter.normalize(crudo)
            if item and "Anuncio del foro" in item.victim_name:
                assert not evaluate(item, watchlist).is_match
                return
        pytest.fail("no se encontró el thread de anuncio en la fixture")

    @respx.mock
    def test_el_titulo_con_credenciales_se_redacta(self, adapter: MyBBForumAdapter) -> None:
        """Un título de combolist no puede persistirse tal cual."""
        respx.get(FEED_URL).mock(
            return_value=httpx.Response(200, text=read_fixture("darkforums_atom.xml"))
        )
        titulos = [
            adapter.normalize(c).victim_name  # type: ignore[union-attr]
            for c in adapter.fetch(None)
            if adapter.normalize(c) is not None
        ]
        combo = next(t for t in titulos if "combo" in t)

        redactado = redact_pii(combo)
        assert redactado is not None
        assert "persona@ejemplo.test" not in redactado
        assert "clave123" not in redactado
        # Sigue siendo identificable como hallazgo.
        assert "combo" in redactado
