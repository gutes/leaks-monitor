"""Cliente HTTP compartido por los adapters.

Concentra las obligaciones que el bootstrap pone sobre la recolección:
User-Agent declarado, timeouts, respeto de rate limits y backoff ante 429.

El `sleep` se inyecta para que los tests de reintento no tarden de verdad.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from leaks.domain.models import EventKind, EventLevel, RunEvent


def _host(url: str) -> str:
    """Solo el host de una URL.

    Los mensajes de alerta nunca muestran la URL completa: la de la Bot API de
    Telegram lleva el token adentro, y terminaría en la bitácora y en los logs.
    """
    try:
        return httpx.URL(url).host or "destino"
    except Exception:  # pragma: no cover — URL ilegible
        return "destino"


#: Códigos que ameritan reintentar: rate limit y fallas transitorias del server.
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


class FeedHttpError(RuntimeError):
    """Falla al hablar con un feed, ya agotados los reintentos."""


class FeedHttpClient:
    """Cliente HTTP con backoff, pensado para consumir feeds públicos."""

    def __init__(
        self,
        *,
        user_agent: str,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_base: float = 2.0,
        rate_limit_delay: float = 1.0,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        emit: Callable[[RunEvent], None] | None = None,
        source: str | None = None,
        before_request: Callable[[], None] | None = None,
    ) -> None:
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._rate_limit_delay = rate_limit_delay
        self._sleep = sleep
        # Reporta a qué sitio se le pega. Opcional: sin sink, el cliente
        # funciona igual (los tests lo usan así).
        self._emit = emit
        self._source = source
        # Gancho de control de OPSEC: se ejecuta ANTES de cada request y puede
        # abortarlo. La IP de salida puede cambiar a mitad de una corrida (una
        # VPN que se reconecta), así que chequear solo al principio no alcanza.
        self._before_request = before_request
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": user_agent, "Accept-Encoding": "gzip, deflate"},
        )

    # -- API pública ---------------------------------------------------------

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        """GET que devuelve JSON parseado."""
        response = self._get(url, params)
        try:
            return response.json()
        except ValueError as exc:
            raise FeedHttpError(f"{url} no devolvió JSON válido") from exc

    def get_text(self, url: str, params: dict[str, Any] | None = None) -> str:
        """GET que devuelve el cuerpo como texto (XML/Atom)."""
        return self._get(url, params).text

    def post_json(self, url: str, payload: dict[str, Any]) -> Any:
        """POST de un JSON. Lo usan los canales de alerta.

        Pasa por la misma barrera de IP de salida que los GET: mandar una
        alerta desde una IP bloqueada también sería tráfico atribuible.
        """
        if self._before_request is not None:
            self._before_request()

        comenzo = time.monotonic()
        try:
            response = self._client.post(url, json=payload)
        except httpx.HTTPError as exc:
            self._report(
                EventKind.HTTP_REQUEST,
                EventLevel.ERROR,
                f"POST falló: {type(exc).__name__}",
                duration_ms=self._elapsed_ms(comenzo),
            )
            raise FeedHttpError(f"POST a {_host(url)} falló: {type(exc).__name__}") from exc

        transcurrido = self._elapsed_ms(comenzo)
        if response.status_code >= 400:
            # No se incluye la URL: la de Telegram lleva el token adentro.
            self._report(
                EventKind.HTTP_REQUEST,
                EventLevel.ERROR,
                f"POST a {_host(url)} → {response.status_code}",
                status_code=response.status_code,
                duration_ms=transcurrido,
            )
            raise FeedHttpError(f"POST a {_host(url)} respondió {response.status_code}")

        self._report(
            EventKind.HTTP_REQUEST,
            EventLevel.INFO,
            f"POST a {_host(url)} → {response.status_code}",
            status_code=response.status_code,
            duration_ms=transcurrido,
        )
        try:
            return response.json()
        except ValueError:
            return None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> FeedHttpClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- Interno -------------------------------------------------------------

    def _get(self, url: str, params: dict[str, Any] | None) -> httpx.Response:
        # Última barrera antes de tocar la red. Si el gancho lanza, no sale
        # ni un byte.
        if self._before_request is not None:
            self._before_request()

        ultimo_error: Exception | None = None

        for intento in range(self._max_retries + 1):
            if intento > 0:
                self._sleep(self._backoff_for(intento, None))

            comenzo = time.monotonic()
            try:
                response = self._client.get(url, params=params)
            except httpx.HTTPError as exc:
                ultimo_error = exc
                self._report(
                    EventKind.HTTP_RETRY,
                    EventLevel.WARN,
                    f"GET {url} falló: {type(exc).__name__}",
                    url=url,
                    duration_ms=self._elapsed_ms(comenzo),
                )
                continue

            transcurrido = self._elapsed_ms(comenzo)

            if response.status_code in _RETRYABLE_STATUS:
                ultimo_error = FeedHttpError(f"{url} respondió {response.status_code}")
                self._report(
                    EventKind.HTTP_RETRY,
                    EventLevel.WARN,
                    f"GET {url} → {response.status_code}, reintentando",
                    url=url,
                    status_code=response.status_code,
                    duration_ms=transcurrido,
                )
                if intento < self._max_retries:
                    # Retry-After manda sobre nuestro backoff: es lo que el
                    # feed nos está pidiendo explícitamente.
                    self._sleep(self._backoff_for(intento + 1, response))
                continue

            if response.status_code >= 400:
                self._report(
                    EventKind.HTTP_REQUEST,
                    EventLevel.ERROR,
                    f"GET {url} → {response.status_code}",
                    url=url,
                    status_code=response.status_code,
                    duration_ms=transcurrido,
                )
                raise FeedHttpError(f"{url} respondió {response.status_code}")

            self._report(
                EventKind.HTTP_REQUEST,
                EventLevel.INFO,
                f"GET {url} → {response.status_code}",
                url=url,
                status_code=response.status_code,
                duration_ms=transcurrido,
                bytes_received=len(response.content),
            )

            # Autolimitación entre requests: varios de estos feeds no publican
            # sus límites, así que nos los imponemos nosotros.
            if self._rate_limit_delay:
                self._sleep(self._rate_limit_delay)
            return response

        self._report(
            EventKind.HTTP_REQUEST,
            EventLevel.ERROR,
            f"GET {url} agotó los {self._max_retries + 1} intentos",
            url=url,
        )
        raise FeedHttpError(f"{url} falló tras {self._max_retries + 1} intentos") from (
            ultimo_error
        )

    @staticmethod
    def _elapsed_ms(desde: float) -> int:
        return int((time.monotonic() - desde) * 1000)

    def _report(
        self,
        kind: EventKind,
        level: EventLevel,
        message: str,
        *,
        url: str | None = None,
        status_code: int | None = None,
        duration_ms: int | None = None,
        bytes_received: int | None = None,
    ) -> None:
        """Manda un evento al sink, si hay alguno enchufado."""
        if self._emit is None:
            return
        self._emit(
            RunEvent(
                occurred_at=datetime.now(UTC),
                level=level,
                kind=kind,
                source=self._source,
                message=message,
                url=url,
                status_code=status_code,
                duration_ms=duration_ms,
                bytes_received=bytes_received,
            )
        )

    def _backoff_for(self, intento: int, response: httpx.Response | None) -> float:
        """Espera exponencial, salvo que el server indique `Retry-After`."""
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    return min(float(retry_after), 300.0)
                except ValueError:
                    pass
        return float(self._backoff_base**intento)


def build_client(
    *,
    user_agent: str,
    timeout: float,
    max_retries: int,
    backoff_base: float,
    rate_limit_delay: float,
    emit: Callable[[RunEvent], None] | None = None,
    source: str | None = None,
    before_request: Callable[[], None] | None = None,
) -> FeedHttpClient:
    """Constructor usado por el registro de feeds."""
    return FeedHttpClient(
        user_agent=user_agent,
        timeout=timeout,
        max_retries=max_retries,
        backoff_base=backoff_base,
        rate_limit_delay=rate_limit_delay,
        emit=emit,
        source=source,
        before_request=before_request,
    )
