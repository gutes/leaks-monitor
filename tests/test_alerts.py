"""Tests del despacho de alertas.

Las tres propiedades que importan: no repite, no tumba la corrida y no filtra
PII.
"""

from __future__ import annotations

from collections.abc import Sequence

import httpx
import pytest
import respx

from leaks.adapters.http import FeedHttpClient
from leaks.alerts.channels import (
    CHANNEL_REGISTRY,
    TelegramChannel,
    WebhookChannel,
    format_text,
)
from leaks.alerts.dispatcher import AlertDispatcher, build_channels
from leaks.config import Settings
from leaks.domain.models import Finding, Severity
from leaks.storage.repository import SqlAlchemyFindingRepository
from tests.conftest import make_finding


@pytest.fixture
def client() -> FeedHttpClient:
    return FeedHttpClient(
        user_agent="leaks-monitor/test",
        max_retries=0,
        rate_limit_delay=0,
        sleep=lambda _s: None,
    )


class CanalDePrueba:
    """Registra lo que recibe; puede explotar a pedido."""

    def __init__(self, name: str = "prueba", explota: bool = False) -> None:
        self.name = name
        self._explota = explota
        self.recibidos: list[Sequence[Finding]] = []

    def send(self, findings: Sequence[Finding]) -> None:
        if self._explota:
            raise RuntimeError("canal caído")
        self.recibidos.append(findings)


class TestFormato:
    def test_resume_y_detalla(self) -> None:
        texto = format_text([make_finding(victim_name="Ministerio X")])
        assert "Ministerio X" in texto
        assert "1 hallazgos" in texto

    def test_destaca_los_criticos(self) -> None:
        texto = format_text([make_finding(severity=Severity.CRITICAL)])
        assert "críticos" in texto

    def test_no_detalla_mas_de_diez(self) -> None:
        """Un mensaje con 300 líneas no lo lee nadie y puede pasarse del límite."""
        muchos = [
            make_finding(victim_name=f"Org {i}", victim_domain=f"o{i}.gob.ar") for i in range(25)
        ]
        texto = format_text(muchos)
        assert "y 15 más" in texto

    def test_no_lleva_pii(self) -> None:
        """Sale la misma metadata que se persiste, ni un campo más."""
        f = make_finding(description="Contacto: persona@x.gob.ar password: hunter2")
        texto = format_text([f])
        assert "persona@x.gob.ar" not in texto
        assert "hunter2" not in texto


class TestCanales:
    @respx.mock
    def test_webhook_manda_texto_y_estructura(self, client: FeedHttpClient) -> None:
        ruta = respx.post("https://hook.test/aviso").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        WebhookChannel(client, "https://hook.test/aviso").send([make_finding()])

        cuerpo = ruta.calls[0].request.content.decode()
        assert "text" in cuerpo
        assert "findings" in cuerpo

    @respx.mock
    def test_telegram_usa_la_bot_api(self, client: FeedHttpClient) -> None:
        ruta = respx.post(url__regex=r"https://api\.telegram\.org/bot.+/sendMessage").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        TelegramChannel(client, "TOKEN123", "-100200").send([make_finding()])

        assert ruta.called
        assert "-100200" in ruta.calls[0].request.content.decode()

    @respx.mock
    def test_el_token_no_aparece_en_los_eventos(self, client: FeedHttpClient) -> None:
        """La URL de Telegram lleva el token: no puede terminar en la bitácora."""
        from leaks.domain.models import RunEvent

        eventos: list[RunEvent] = []
        cliente = FeedHttpClient(
            user_agent="test",
            max_retries=0,
            rate_limit_delay=0,
            sleep=lambda _s: None,
            emit=eventos.append,
        )
        respx.post(url__regex=r".*sendMessage").mock(return_value=httpx.Response(200, json={}))
        TelegramChannel(cliente, "SECRETO123", "-1").send([make_finding()])

        for e in eventos:
            assert "SECRETO123" not in e.message
            assert "SECRETO123" not in (e.url or "")


class TestConstruccionDeCanales:
    def test_sin_configuracion_no_hay_canales(self, client: FeedHttpClient) -> None:
        assert build_channels(Settings(), lambda: client) == []

    def test_el_webhook_se_activa_con_su_url(self, client: FeedHttpClient) -> None:
        canales = build_channels(Settings(alert_webhook_url="https://hook.test/x"), lambda: client)
        assert [c.name for c in canales] == ["webhook"]

    def test_telegram_necesita_token_y_chat(self, client: FeedHttpClient) -> None:
        solo_token = Settings(alert_telegram_token="abc")
        assert build_channels(solo_token, lambda: client) == []

        completo = Settings(alert_telegram_token="abc", alert_telegram_chat_id="-1")
        assert [c.name for c in build_channels(completo, lambda: client)] == ["telegram"]

    def test_el_registro_declara_lo_que_necesita(self) -> None:
        for spec in CHANNEL_REGISTRY:
            assert spec.requires


class TestDespachador:
    def test_sin_canales_no_hace_nada(self) -> None:
        d = AlertDispatcher([])
        assert d.enabled is False
        assert d.dispatch([make_finding()]).delivered is False

    def test_manda_a_todos_los_canales(self) -> None:
        a, b = CanalDePrueba("a"), CanalDePrueba("b")
        resultado = AlertDispatcher([a, b]).dispatch([make_finding()])

        assert resultado.channels_ok == ["a", "b"]
        assert len(a.recibidos) == 1 and len(b.recibidos) == 1

    def test_un_canal_caido_no_frena_a_los_otros(self) -> None:
        roto, sano = CanalDePrueba("roto", explota=True), CanalDePrueba("sano")
        resultado = AlertDispatcher([roto, sano]).dispatch([make_finding()])

        assert resultado.channels_failed == ["roto"]
        assert resultado.channels_ok == ["sano"]
        assert resultado.delivered is True

    def test_si_fallan_todos_no_se_da_por_entregado(self) -> None:
        """Clave: si no se entregó, el hallazgo tiene que quedar pendiente."""
        resultado = AlertDispatcher([CanalDePrueba("roto", explota=True)]).dispatch(
            [make_finding()]
        )
        assert resultado.delivered is False


class TestPendientes:
    def test_solo_lo_que_llega_al_umbral(self, repository: SqlAlchemyFindingRepository) -> None:
        # Dominios distintos: el dedup usa el dominio, no el nombre, así que
        # con el mismo dominio los cuatro colapsarían en una sola fila.
        repository.upsert_many(
            [
                make_finding(
                    victim_name="Critico", victim_domain="c.gob.ar", severity=Severity.CRITICAL
                ),
                make_finding(victim_name="Alto", victim_domain="a.gob.ar", severity=Severity.HIGH),
                make_finding(
                    victim_name="Medio", victim_domain="m.gob.ar", severity=Severity.MEDIUM
                ),
                make_finding(victim_name="Bajo", victim_domain="b.gob.ar", severity=Severity.LOW),
            ]
        )
        pendientes = repository.list_pending_alerts(min_severity="high", limit=50)
        assert {f.victim_name for f in pendientes} == {"Critico", "Alto"}

    def test_no_se_repite_lo_ya_avisado(self, repository: SqlAlchemyFindingRepository) -> None:
        f = make_finding(severity=Severity.CRITICAL)
        repository.upsert_many([f])

        assert len(repository.list_pending_alerts(min_severity="low", limit=50)) == 1
        assert repository.mark_alerted([f.dedup_hash]) == 1
        assert repository.list_pending_alerts(min_severity="low", limit=50) == []

    def test_lo_no_entregado_sigue_pendiente(self, repository: SqlAlchemyFindingRepository) -> None:
        """Si el envío falla no se marca, así se reintenta en la próxima corrida."""
        f = make_finding(severity=Severity.CRITICAL)
        repository.upsert_many([f])

        resultado = AlertDispatcher([CanalDePrueba(explota=True)]).dispatch([f])
        assert resultado.delivered is False
        # No se marcó nada: sigue pendiente.
        assert len(repository.list_pending_alerts(min_severity="low", limit=50)) == 1

    def test_respeta_el_tope_por_corrida(self, repository: SqlAlchemyFindingRepository) -> None:
        repository.upsert_many(
            [
                make_finding(
                    victim_name=f"Org {i}", victim_domain=f"o{i}.gob.ar", severity=Severity.CRITICAL
                )
                for i in range(10)
            ]
        )
        assert len(repository.list_pending_alerts(min_severity="high", limit=3)) == 3


class TestUmbralConfigurable:
    @pytest.mark.parametrize("valor", ["low", "medium", "high", "critical"])
    def test_valores_validos(self, valor: str) -> None:
        assert Settings(alert_min_severity=valor).alert_min_severity == valor

    def test_valor_invalido_no_arranca(self) -> None:
        """Falla al arrancar, no en la primera alerta."""
        with pytest.raises(ValueError, match="alert_min_severity"):
            Settings(alert_min_severity="urgentisimo")


class TestNoSeAlertaLoViejo:
    """El objetivo operativo del arreglo de frescura.

    Sin esto, la importación inicial de una fuente disparaba una alerta por
    cada hallazgo histórico: 230 avisos de cosas que pasaron entre 2020 y 2026.
    """

    def _finding(self, **extra: object) -> object:
        return make_finding(severity=Severity.CRITICAL, **extra)  # type: ignore[arg-type]

    def test_no_se_alerta_la_importacion_inicial(
        self, repository: SqlAlchemyFindingRepository
    ) -> None:
        from datetime import UTC, datetime

        repository.upsert_many(
            [
                make_finding(
                    victim_domain="a.gob.ar",
                    severity=Severity.CRITICAL,
                ).model_copy(update={"backfill": True, "occurred_at": datetime.now(UTC)})
            ]
        )
        assert repository.list_pending_alerts(min_severity="high", limit=50) == []

    def test_no_se_alerta_un_evento_viejo(self, repository: SqlAlchemyFindingRepository) -> None:
        from datetime import UTC, datetime, timedelta

        viejo = datetime.now(UTC) - timedelta(days=400)
        repository.upsert_many(
            [
                make_finding(victim_domain="b.gob.ar", severity=Severity.CRITICAL).model_copy(
                    update={"occurred_at": viejo}
                )
            ]
        )
        pendientes = repository.list_pending_alerts(min_severity="high", limit=50, max_age_days=30)
        assert pendientes == []

    def test_si_se_alerta_lo_reciente(self, repository: SqlAlchemyFindingRepository) -> None:
        from datetime import UTC, datetime, timedelta

        reciente = datetime.now(UTC) - timedelta(days=2)
        repository.upsert_many(
            [
                make_finding(victim_domain="c.gob.ar", severity=Severity.CRITICAL).model_copy(
                    update={"occurred_at": reciente}
                )
            ]
        )
        pendientes = repository.list_pending_alerts(min_severity="high", limit=50, max_age_days=30)
        assert len(pendientes) == 1

    def test_sin_fecha_no_se_alerta(self, repository: SqlAlchemyFindingRepository) -> None:
        """Si no se pudo fechar, no se puede afirmar que sea reciente."""
        repository.upsert_many(
            [
                make_finding(victim_domain="d.gob.ar", severity=Severity.CRITICAL).model_copy(
                    update={"occurred_at": None}
                )
            ]
        )
        assert repository.list_pending_alerts(min_severity="high", limit=50, max_age_days=30) == []
