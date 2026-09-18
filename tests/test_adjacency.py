"""Tests de la sección de adyacencia.

Lo que se protege acá:

* que el score **no puntúe a los que ya golpearon Argentina**;
* que las víctimas regionales **no toquen `findings`**;
* que un dato aislado no produzca un score alto (fue un defecto real);
* que un país caído no cueste la pasada.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from leaks.adjacency.collector import AdjacencyCollector
from leaks.adjacency.countries import COUNTRY_CODES, get_country, proximidad
from leaks.adjacency.kinds import KIND_DLS, KIND_FORO, kind_for
from leaks.adjacency.registries import RegionalVictim, fetch_ransomware_live
from leaks.adjacency.scoring import (
    VictimaRegional,
    calcular,
    sectores_frecuentes,
)
from leaks.storage.adjacency_repository import AdjacencyRepository

HOY = date(2026, 8, 18)
BASE_DT = datetime(2026, 8, 18, tzinfo=UTC)


def vr(cc: str, dias_atras: int = 10, sector: str = "Government & Defense") -> VictimaRegional:
    return VictimaRegional(country=cc, occurred_at=HOY - timedelta(days=dias_atras), sector=sector)


class TestCatalogoDePaises:
    def test_argentina_no_esta(self) -> None:
        """Es el sujeto, no la región: incluirla haría que se puntúe sola."""
        assert "AR" not in COUNTRY_CODES

    def test_los_limitrofes_pesan_mas_que_el_caribe(self) -> None:
        assert proximidad("BR") > proximidad("CO") > proximidad("CU")

    def test_un_pais_desconocido_no_suma(self) -> None:
        """No se inventa cercanía para algo que no está en el catálogo."""
        assert proximidad("ZZ") == 0.0
        assert get_country("ZZ") is None


class TestScore:
    def test_sin_victimas_es_cero(self) -> None:
        assert calcular([], hoy=HOY).valor == 0.0

    def test_mas_paises_puntua_mas(self) -> None:
        pocos = calcular([vr("BR"), vr("BR")], hoy=HOY)
        muchos = calcular([vr("BR"), vr("CL"), vr("UY"), vr("PY")], hoy=HOY)
        assert muchos.breakdown["alcance"] > pocos.breakdown["alcance"]

    def test_lo_viejo_puntua_menos(self) -> None:
        reciente = calcular([vr("BR", 5), vr("CL", 5)], hoy=HOY)
        viejo = calcular([vr("BR", 900), vr("CL", 900)], hoy=HOY)
        assert reciente.breakdown["recencia"] > viejo.breakdown["recencia"]

    def test_un_limitrofe_pesa_mas_que_mexico(self) -> None:
        limitrofe = calcular([vr("BR"), vr("CL")], hoy=HOY)
        lejano = calcular([vr("MX"), vr("CR")], hoy=HOY)
        assert limitrofe.breakdown["proximidad"] > lejano.breakdown["proximidad"]

    def test_la_afinidad_mira_los_sectores_argentinos(self) -> None:
        sectores = frozenset({"Government & Defense"})
        afin = calcular([vr("BR", sector="Government & Defense")], sectores_ar=sectores, hoy=HOY)
        ajeno = calcular([vr("BR", sector="Hospitality")], sectores_ar=sectores, hoy=HOY)
        assert afin.breakdown["afinidad"] > ajeno.breakdown["afinidad"] == 0.0

    def test_un_dato_aislado_no_puede_valer_como_una_campana(self) -> None:
        """Fue un defecto real: 1 víctima empataba con 11 en 3 países.

        Recencia, tendencia, proximidad y afinidad son ratios que un solo dato
        satura; sin atenuarlos, 60 de los 100 puntos salían de una fila.
        """
        uno = calcular([vr("BR")], hoy=HOY)
        campana = calcular([vr("BR"), vr("CL"), vr("UY")] * 4, hoy=HOY)
        assert uno.valor < campana.valor

    def test_el_desglose_explica_el_numero(self) -> None:
        """Un score sin desglose no se puede discutir ni corregir."""
        score = calcular([vr("BR"), vr("CL")], hoy=HOY)
        componentes = {"alcance", "recencia", "volumen", "tendencia", "proximidad", "afinidad"}
        assert componentes <= set(score.breakdown)
        assert score.valor == pytest.approx(
            sum(v for k, v in score.breakdown.items() if k != "confianza"), abs=0.1
        )

    def test_la_confianza_se_publica(self) -> None:
        """Un score alto con poca evidencia tiene que poder verse como tal."""
        assert calcular([vr("BR")], hoy=HOY).breakdown["confianza"] < 0.6
        assert calcular([vr("BR")] * 20, hoy=HOY).breakdown["confianza"] > 0.9

    def test_no_pasa_de_cien(self) -> None:
        muchas = [vr(cc, d) for cc in COUNTRY_CODES for d in (1, 2, 3)]
        score = calcular(muchas, sectores_ar=frozenset({"Government & Defense"}), hoy=HOY)
        assert score.valor <= 100

    def test_ignora_lo_que_esta_en_el_futuro(self) -> None:
        futura = VictimaRegional("BR", HOY + timedelta(days=30))
        assert calcular([futura], hoy=HOY).valor == 0.0

    def test_los_sectores_frecuentes_salen_de_los_datos(self) -> None:
        assert sectores_frecuentes(["A", "A", "B", ""], tope=1) == frozenset({"A"})


class TestNormalizacion:
    def test_mapea_la_forma_del_feed(self) -> None:
        class Falso:
            def get_json(self, url: str) -> Any:
                return [
                    {
                        "group_name": "Qilin",
                        "post_title": "Empresa SA",
                        "website": "Empresa.CL",
                        "activity": "Manufacturing",
                        "discovered": "2026-07-24T10:37:25+00:00",
                    }
                ]

        (v,) = fetch_ransomware_live(Falso(), "cl")  # type: ignore[arg-type]
        assert v.actor == "qilin"
        assert v.country == "CL"
        assert v.victim_domain == "empresa.cl"
        assert v.sector == "Manufacturing"
        assert v.occurred_at is not None

    def test_una_fecha_imposible_es_ausencia_de_fecha(self) -> None:
        """Misma postura que el pipeline argentino: no se inventa ni se acepta."""

        class Falso:
            def get_json(self, url: str) -> Any:
                return [
                    {"group_name": "x", "post_title": "y", "discovered": "1970-01-01T00:00:00Z"}
                ]

        (v,) = fetch_ransomware_live(Falso(), "BR")  # type: ignore[arg-type]
        assert v.occurred_at is None

    def test_una_entrada_sin_actor_se_descarta(self) -> None:
        class Falso:
            def get_json(self, url: str) -> Any:
                return [{"post_title": "sin grupo"}, {"group_name": "g", "post_title": "ok"}]

        assert len(fetch_ransomware_live(Falso(), "BR")) == 1  # type: ignore[arg-type]

    def test_una_respuesta_con_otra_forma_no_rompe(self) -> None:
        class Falso:
            def get_json(self, url: str) -> Any:
                return {"error": "nope"}

        assert fetch_ransomware_live(Falso(), "BR") == []  # type: ignore[arg-type]


@pytest.fixture
def adj_repo(session_factory: sessionmaker[Session]) -> AdjacencyRepository:
    return AdjacencyRepository(session_factory)


def rv(
    actor: str = "babuk2",
    country: str = "BR",
    nombre: str = "Empresa SA",
    dias: int | None = 10,
) -> RegionalVictim:
    return RegionalVictim(
        actor=actor,
        country=country,
        victim_name=nombre,
        victim_domain="empresa.com.br",
        sector="Manufacturing",
        occurred_at=None if dias is None else BASE_DT - timedelta(days=dias),
        source="ransomware.live",
    )


class TestRepositorio:
    def test_guarda_y_cuenta(self, adj_repo: AdjacencyRepository) -> None:
        assert adj_repo.upsert_victims([rv(), rv(nombre="Otra")]).nuevas == 2
        assert adj_repo.count_victims() == 2

    def test_es_idempotente(self, adj_repo: AdjacencyRepository) -> None:
        """El feed republica su histórico entero en cada corrida."""
        adj_repo.upsert_victims([rv()])
        segunda = adj_repo.upsert_victims([rv()])
        assert (segunda.nuevas, segunda.existentes) == (0, 1)
        assert adj_repo.count_victims() == 1

    def test_dedup_dentro_del_mismo_lote(self, adj_repo: AdjacencyRepository) -> None:
        assert adj_repo.upsert_victims([rv(), rv()]).nuevas == 1

    def test_las_sin_fecha_no_alimentan_el_score(self, adj_repo: AdjacencyRepository) -> None:
        """No pueden sostener recencia ni tendencia, y para volumen inflarían."""
        adj_repo.upsert_victims([rv(), rv(nombre="Sin fecha", dias=None)])
        assert len(adj_repo.victims_by_actor()["babuk2"]) == 1

    def test_no_toca_la_tabla_de_hallazgos(
        self, adj_repo: AdjacencyRepository, session_factory: sessionmaker[Session]
    ) -> None:
        """El aislamiento es el punto: son poblaciones que no se mezclan."""
        from sqlalchemy import func, select

        from leaks.storage.models import FindingRow

        adj_repo.upsert_victims([rv(), rv(nombre="B"), rv(nombre="C")])
        with session_factory() as s:
            assert s.scalar(select(func.count()).select_from(FindingRow)) == 0

    def test_preserva_el_score_anterior_para_mostrar_la_variacion(
        self, adj_repo: AdjacencyRepository
    ) -> None:
        adj_repo.save_actor(
            "babuk2",
            victims_total=3,
            countries=["BR"],
            kind=KIND_DLS,
            first_seen=None,
            last_seen=None,
            hit_ar=False,
            ar_victims=0,
            score=calcular([vr("BR")], hoy=HOY),
        )
        (antes,) = adj_repo.list_actors()
        assert antes.score_prev is None, "la primera vez no hay anterior que fingir"

        adj_repo.save_actor(
            "babuk2",
            victims_total=9,
            countries=["BR", "CL"],
            kind=KIND_DLS,
            first_seen=None,
            last_seen=None,
            hit_ar=False,
            ar_victims=0,
            score=calcular([vr("BR"), vr("CL")] * 4, hoy=HOY),
        )
        (despues,) = adj_repo.list_actors()
        assert despues.score_prev == antes.score
        assert despues.variacion is not None and despues.variacion > 0

    def test_un_score_igual_no_borra_la_variacion(self, adj_repo: AdjacencyRepository) -> None:
        """Dos corridas sin novedad no pueden tapar el salto real anterior."""
        for total in (1, 4):
            adj_repo.save_actor(
                "x",
                victims_total=total,
                countries=["BR"],
                kind=KIND_DLS,
                first_seen=None,
                last_seen=None,
                hit_ar=False,
                ar_victims=0,
                score=calcular([vr("BR")] * total, hoy=HOY),
            )
        (tras_subir,) = adj_repo.list_actors()
        adj_repo.save_actor(
            "x",
            victims_total=4,
            countries=["BR"],
            kind=KIND_DLS,
            first_seen=None,
            last_seen=None,
            hit_ar=False,
            ar_victims=0,
            score=calcular([vr("BR")] * 4, hoy=HOY),
        )
        (sin_cambio,) = adj_repo.list_actors()
        assert sin_cambio.score_prev == tras_subir.score_prev


class ContextoAr:
    """Doble del lado argentino: solo el contrato mínimo."""

    def __init__(self, actores: dict[str, int], sectores: tuple[str, ...] = ()) -> None:
        self._actores = actores
        self._sectores = sectores

    def actor_counts(self) -> dict[str, int]:
        return dict(self._actores)

    def sector_values(self) -> tuple[str, ...]:
        return self._sectores


class ClienteFalso:
    """Cliente HTTP de mentira. `fallar` simula un país que no responde."""

    def __init__(self, por_pais: dict[str, list[dict[str, Any]]], fallar: set[str] | None = None):
        self.por_pais = por_pais
        self.fallar = fallar or set()
        self.consultados: list[str] = []
        self.cerrado = False

    def get_json(self, url: str) -> Any:
        cc = url.rsplit("/", 1)[-1]
        self.consultados.append(cc)
        if cc in self.fallar:
            raise TimeoutError("sin respuesta")
        return self.por_pais.get(cc, [])

    def close(self) -> None:
        self.cerrado = True


def entrada(actor: str, nombre: str, dias: int = 10) -> dict[str, Any]:
    cuando = datetime(2026, 8, 18, tzinfo=UTC) - timedelta(days=dias)
    return {
        "group_name": actor,
        "post_title": nombre,
        "activity": "Government & Defense",
        "discovered": cuando.isoformat(),
    }


class TestColector:
    @pytest.fixture
    def cliente(self) -> ClienteFalso:
        return ClienteFalso(
            {
                "BR": [entrada("babuk2", "Empresa BR"), entrada("qilin", "Otra BR")],
                "CL": [entrada("babuk2", "Empresa CL")],
            }
        )

    def _colector(
        self, repo: AdjacencyRepository, cliente: ClienteFalso, ar: dict[str, int]
    ) -> AdjacencyCollector:
        return AdjacencyCollector(
            repo,
            lambda: cliente,  # type: ignore[arg-type]
            ContextoAr(ar, ("Government & Defense",)),
            countries=("BR", "CL"),
        )

    def test_trae_y_puntua(self, adj_repo: AdjacencyRepository, cliente: ClienteFalso) -> None:
        r = self._colector(adj_repo, cliente, {}).collect()
        assert r.victimas_nuevas == 3
        assert r.actores == 2
        assert r.candidatos == 2

    def test_los_que_ya_golpearon_ar_no_llevan_score(
        self, adj_repo: AdjacencyRepository, cliente: ClienteFalso
    ) -> None:
        """Una probabilidad de cruzar no significa nada para quien ya cruzó."""
        r = self._colector(adj_repo, cliente, {"qilin": 29}).collect()
        assert (r.confirmados, r.candidatos) == (1, 1)
        perfiles = {p.actor: p for p in adj_repo.list_actors()}
        assert perfiles["qilin"].hit_ar and perfiles["qilin"].score == 0.0
        assert perfiles["qilin"].ar_victims == 29
        assert not perfiles["babuk2"].hit_ar and perfiles["babuk2"].score > 0

    def test_el_nombre_del_actor_se_normaliza_al_cruzar(
        self, adj_repo: AdjacencyRepository, cliente: ClienteFalso
    ) -> None:
        """El feed argentino escribe `Qilin` y el regional `qilin`."""
        r = self._colector(adj_repo, cliente, {"QILIN": 3}).collect()
        assert r.confirmados == 1

    def test_un_pais_caido_no_cuesta_la_pasada(self, adj_repo: AdjacencyRepository) -> None:
        cliente = ClienteFalso({"BR": [entrada("babuk2", "Empresa BR")]}, fallar={"CL"})
        r = self._colector(adj_repo, cliente, {}).collect()
        assert r.victimas_nuevas == 1
        assert r.paises_fallidos == ("ransomware.live/CL",)

    def test_cierra_el_cliente(self, adj_repo: AdjacencyRepository, cliente: ClienteFalso) -> None:
        self._colector(adj_repo, cliente, {}).collect()
        assert cliente.cerrado

    def test_el_bloqueo_de_salida_corta_todo(self, adj_repo: AdjacencyRepository) -> None:
        """OPSEC no se degrada a 'un país que falló'."""
        from leaks.pipeline.egress_guard import EgressBlockedError

        class Bloqueado(ClienteFalso):
            def get_json(self, url: str) -> Any:
                raise EgressBlockedError("salida AR")

        with pytest.raises(EgressBlockedError):
            self._colector(adj_repo, Bloqueado({}), {}).collect()

    def test_una_segunda_pasada_no_duplica(
        self, adj_repo: AdjacencyRepository, cliente: ClienteFalso
    ) -> None:
        colector = self._colector(adj_repo, cliente, {})
        colector.collect()
        segunda = colector.collect()
        assert segunda.victimas_nuevas == 0
        assert segunda.victimas_totales == 3


class TestAvisoPorSalto:
    """Se avisa por MOVIMIENTO, no por umbral.

    Un actor alto y quieto no es novedad, y avisar por umbral absoluto lo
    repetiría en cada corrida hasta que alguien apague las alertas.
    """

    def _guardar(
        self,
        repo: AdjacencyRepository,
        actor: str,
        victimas: int,
        *,
        hit_ar: bool = False,
    ) -> None:
        repo.save_actor(
            actor,
            victims_total=victimas,
            countries=["BR", "CL"],
            kind=KIND_DLS,
            first_seen=None,
            last_seen=None,
            hit_ar=hit_ar,
            ar_victims=3 if hit_ar else 0,
            score=None if hit_ar else calcular([vr("BR"), vr("CL")] * victimas, hoy=HOY),
        )

    def test_no_avisa_la_primera_vez(self, adj_repo: AdjacencyRepository) -> None:
        """Sin corrida anterior no hay salto que medir. Fingirlo sería inventar."""
        self._guardar(adj_repo, "babuk2", 10)
        assert adj_repo.pending_jumps(min_jump=1.0, min_score=0.0) == ()

    def test_avisa_cuando_salta(self, adj_repo: AdjacencyRepository) -> None:
        self._guardar(adj_repo, "babuk2", 1)
        self._guardar(adj_repo, "babuk2", 12)
        (salto,) = adj_repo.pending_jumps(min_jump=1.0, min_score=0.0)
        assert salto.actor == "babuk2"
        assert salto.variacion is not None and salto.variacion > 0

    def test_un_salto_chico_no_interrumpe(self, adj_repo: AdjacencyRepository) -> None:
        self._guardar(adj_repo, "babuk2", 5)
        self._guardar(adj_repo, "babuk2", 6)
        assert adj_repo.pending_jumps(min_jump=25.0, min_score=0.0) == ()

    def test_un_salto_por_debajo_del_piso_no_interrumpe(
        self, adj_repo: AdjacencyRepository
    ) -> None:
        """De 5 a 20 es un salto, pero no amerita despertar a nadie."""
        self._guardar(adj_repo, "chico", 1)
        self._guardar(adj_repo, "chico", 3)
        assert adj_repo.pending_jumps(min_jump=1.0, min_score=95.0) == ()

    def test_los_confirmados_nunca_saltan(self, adj_repo: AdjacencyRepository) -> None:
        """No se les calcula score: un 'salto' suyo no significaría nada."""
        self._guardar(adj_repo, "qilin", 1)
        self._guardar(adj_repo, "qilin", 12, hit_ar=True)
        assert adj_repo.pending_jumps(min_jump=1.0, min_score=0.0) == ()

    def test_no_se_repite_el_mismo_salto(self, adj_repo: AdjacencyRepository) -> None:
        self._guardar(adj_repo, "babuk2", 1)
        self._guardar(adj_repo, "babuk2", 12)
        adj_repo.mark_alerted(["babuk2"])
        assert adj_repo.pending_jumps(min_jump=1.0, min_score=0.0) == ()

    def test_pero_un_salto_nuevo_vuelve_a_avisar(self, adj_repo: AdjacencyRepository) -> None:
        """Avisar una vez no puede silenciar al actor para siempre."""
        self._guardar(adj_repo, "babuk2", 1)
        self._guardar(adj_repo, "babuk2", 8)
        adj_repo.mark_alerted(["babuk2"])
        self._guardar(adj_repo, "babuk2", 30)
        assert [p.actor for p in adj_repo.pending_jumps(min_jump=1.0, min_score=0.0)] == ["babuk2"]

    def test_una_baja_no_avisa(self, adj_repo: AdjacencyRepository) -> None:
        self._guardar(adj_repo, "babuk2", 12)
        self._guardar(adj_repo, "babuk2", 1)
        assert adj_repo.pending_jumps(min_jump=1.0, min_score=0.0) == ()


class TestCableado:
    """Que el runner REALMENTE llame al aviso.

    Los tests de arriba prueban el mecanismo. Este prueba que esté enchufado,
    que es donde ya se escondió un bug antes: una pieza correcta que nadie
    invocaba, con un test que la construía a mano y pasaba igual.
    """

    class AlertasFalsas:
        def __init__(self) -> None:
            self.avisos: list[str] = []

        @property
        def enabled(self) -> bool:
            return True

        def dispatch_notice(self, texto: str) -> None:
            self.avisos.append(texto)

    def test_el_runner_avisa_los_saltos(
        self,
        adj_repo: AdjacencyRepository,
        session_factory: sessionmaker[Session],
        tmp_path: Any,
    ) -> None:
        from leaks.config import Settings
        from leaks.pipeline.runner import PipelineRunner
        from leaks.relevance.watchlist import build_watchlist
        from leaks.storage.repository import SqlAlchemyFindingRepository

        # Un candidato que saltó de verdad.
        for cuantas in (1, 20):
            adj_repo.save_actor(
                "babuk2",
                victims_total=cuantas,
                countries=["BR", "CL"],
                kind=KIND_DLS,
                first_seen=None,
                last_seen=None,
                hit_ar=False,
                ar_victims=0,
                score=calcular([vr("BR"), vr("CL")] * cuantas, hoy=HOY),
            )

        alertas = self.AlertasFalsas()
        runner = PipelineRunner(
            repository=SqlAlchemyFindingRepository(session_factory),
            watchlist=build_watchlist(()),
            settings=Settings(
                database_url="sqlite://",
                adjacency_alert_jump=1.0,
                adjacency_alert_min_score=0.0,
            ),
            alert_dispatcher=alertas,  # type: ignore[arg-type]
            adjacency_repo=adj_repo,
        )
        runner._avisar_saltos()

        assert len(alertas.avisos) == 1, "el runner tiene que llamar al aviso"
        assert "babuk2" in alertas.avisos[0]
        assert "NO golpearon Argentina" in alertas.avisos[0], (
            "el aviso tiene que decir que todavía no cruzaron, o se lee como un ataque"
        )

    def test_sin_canales_no_avisa_ni_marca(
        self, adj_repo: AdjacencyRepository, session_factory: sessionmaker[Session]
    ) -> None:
        """Sin canales configurados no se puede marcar como avisado.

        Si se marcara, el salto quedaría silenciado para siempre sin que nadie
        se hubiera enterado.
        """
        from leaks.config import Settings
        from leaks.pipeline.runner import PipelineRunner
        from leaks.relevance.watchlist import build_watchlist
        from leaks.storage.repository import SqlAlchemyFindingRepository

        for cuantas in (1, 20):
            adj_repo.save_actor(
                "babuk2",
                victims_total=cuantas,
                countries=["BR"],
                kind=KIND_DLS,
                first_seen=None,
                last_seen=None,
                hit_ar=False,
                ar_victims=0,
                score=calcular([vr("BR")] * cuantas, hoy=HOY),
            )

        runner = PipelineRunner(
            repository=SqlAlchemyFindingRepository(session_factory),
            watchlist=build_watchlist(()),
            settings=Settings(database_url="sqlite://", adjacency_alert_min_score=0.0),
            adjacency_repo=adj_repo,
        )
        runner._avisar_saltos()

        assert adj_repo.pending_jumps(min_jump=1.0, min_score=0.0), (
            "el salto sigue pendiente: nadie se enteró"
        )


class TestWatchlistRegional:
    """La watchlist por país: para qué sirve de verdad."""

    @pytest.fixture
    def rwl(self) -> Any:
        from leaks.adjacency.regional_watchlist import load_regional_watchlists

        return load_regional_watchlists(Path("data/examples/watchlist-regional"))

    def test_carga_un_archivo_por_pais(self, rwl: Any) -> None:
        assert set(rwl.paises) >= {"BR", "CL", "UY", "PY", "BO"}, "los limítrofes primero"

    def test_reconoce_infraestructura_critica(self, rwl: Any) -> None:
        assert rwl.es_critica("BR", "petrobras.com.br")
        assert rwl.es_critica("CL", "bcentral.cl")
        assert rwl.es_critica("MX", "sat.gob.mx")

    def test_cubre_subdominios(self, rwl: Any) -> None:
        assert rwl.es_critica("BR", "intranet.gov.br")
        # `intranet.gov.br` no figura, pero `gov.br` sí y cubre sus subdominios.
        assert rwl.es_critica("BR", "saude.mt.gov.br")

    def test_una_empresa_cualquiera_no_es_critica(self, rwl: Any) -> None:
        assert not rwl.es_critica("BR", "panaderia-del-barrio.com.br")

    def test_un_pais_sin_watchlist_no_inventa_criticidad(self, rwl: Any) -> None:
        assert not rwl.es_critica("ZZ", "algo.zz")
        assert rwl.match("ZZ", "algo.zz") is None

    def test_un_directorio_inexistente_no_rompe(self, tmp_path: Path) -> None:
        from leaks.adjacency.regional_watchlist import load_regional_watchlists

        vacia = load_regional_watchlists(tmp_path / "no-existe")
        assert vacia.paises == ()
        assert not vacia.es_critica("BR", "petrobras.com.br")

    def test_es_independiente_de_la_argentina(self, rwl: Any) -> None:
        """Mezclarlas haría que una empresa brasileña genere un hallazgo argentino."""
        from leaks.relevance.watchlist import load_watchlist

        ar = load_watchlist(Path("data/examples/watchlist.yaml"))
        assert ar.match_domain("petrobras.com.br") is None
        assert not rwl.es_critica("BR", "prevision-ejemplo.gob.ar")


class TestCriticidadEnElScore:
    def test_una_victima_critica_pesa_mas_que_una_cualquiera(self) -> None:
        base = [VictimaRegional("BR", HOY - timedelta(days=5), sector="Otro") for _ in range(4)]
        criticas = [
            VictimaRegional("BR", HOY - timedelta(days=5), sector="Otro", critica=True)
            for _ in range(4)
        ]
        assert (
            calcular(criticas, hoy=HOY).breakdown["afinidad"]
            > (calcular(base, hoy=HOY).breakdown["afinidad"])
        )

    def test_se_toma_el_maximo_y_no_la_suma(self) -> None:
        """Son dos formas de medir lo mismo; sumarlas contaría doble."""
        sectores = frozenset({"Government & Defense"})
        ambas = [
            VictimaRegional("BR", HOY, sector="Government & Defense", critica=True)
            for _ in range(4)
        ]
        solo_una = [VictimaRegional("BR", HOY, sector="Government & Defense") for _ in range(4)]
        assert (
            calcular(ambas, sectores_ar=sectores, hoy=HOY).breakdown["afinidad"]
            == (calcular(solo_una, sectores_ar=sectores, hoy=HOY).breakdown["afinidad"])
        )


class TestVictimasCriticas:
    def test_lista_solo_las_criticas(self, adj_repo: AdjacencyRepository) -> None:
        """De ~1.350 regionales, la lista corta es la que se lee."""
        adj_repo.upsert_victims(
            [rv(nombre="Ministerio"), rv(nombre="PyME cualquiera", country="CL")]
        )
        adj_repo.reclasificar(lambda cc, dom: (cc == "BR", "gobierno" if cc == "BR" else None))
        assert adj_repo.count_critical() == 1
        (unica,) = adj_repo.critical_victims()
        assert unica["victim_name"] == "Ministerio"
        assert unica["sector"] == "gobierno"

    def test_reclasificar_reevalua_lo_ya_guardado(self, adj_repo: AdjacencyRepository) -> None:
        """Editar una watchlist regional tiene que reclasificar sin re-bajar nada."""
        adj_repo.upsert_victims([rv()])
        assert adj_repo.reclasificar(lambda cc, dom: (True, "energia")) == 1
        assert adj_repo.count_critical() == 1
        # Segunda pasada sin cambios: no toca nada.
        assert adj_repo.reclasificar(lambda cc, dom: (True, "energia")) == 0
        # Y se puede volver atrás.
        assert adj_repo.reclasificar(lambda cc, dom: (False, None)) == 1
        assert adj_repo.count_critical() == 0


class TestCarriles:
    """Los dos universos de la sección, separados.

    El score está calibrado sobre la cadencia de un DLS. Un broker de acceso
    publica de otra forma, así que va por su propio carril y no compite en el
    mismo ranking.
    """

    def test_el_carril_sale_de_la_fuente_de_las_victimas(
        self, adj_repo: AdjacencyRepository
    ) -> None:
        adj_repo.upsert_victims(
            [
                RegionalVictim(
                    actor="lockbit3",
                    country="BR",
                    victim_name="Empresa Ejemplo",
                    victim_domain="ejemplo.com.br",
                    sector=None,
                    occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
                    source="ransomware.live",
                ),
                RegionalVictim(
                    actor="rabbitt1337",
                    country="BR",
                    victim_name="prefeitura",
                    victim_domain="prefeitura.gov.br",
                    sector=None,
                    occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
                    source="telegram",
                ),
            ]
        )

        fuentes = adj_repo.sources_by_actor()
        assert fuentes == {"lockbit3": {"ransomware.live"}, "rabbitt1337": {"telegram"}}
        assert kind_for(fuentes["lockbit3"]) == KIND_DLS
        assert kind_for(fuentes["rabbitt1337"]) == KIND_FORO

    def test_el_carril_se_persiste_y_se_lee(self, adj_repo: AdjacencyRepository) -> None:
        adj_repo.save_actor(
            "rabbitt1337",
            victims_total=2,
            countries=["BR"],
            kind=KIND_FORO,
            first_seen=None,
            last_seen=None,
            hit_ar=False,
            ar_victims=0,
            score=None,
        )
        (perfil,) = adj_repo.list_actors()
        assert perfil.kind == KIND_FORO
        assert perfil.as_dict()["kind"] == KIND_FORO
