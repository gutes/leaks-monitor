"""Configuración del prototipo.

Todo entra por entorno / `.env` (12-factor). Nada de secretos hardcodeados.

La postura de privacidad es **fail-closed**: `store_pii` arranca en `False` y, si se
lo activa sin clave de cifrado, el proceso se niega a arrancar en lugar de degradar
silenciosamente a "guardo PII en claro".
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

#: Lista separada por comas leída del entorno.
#:
#: `NoDecode` es imprescindible: sin él, pydantic-settings intenta parsear el
#: valor como JSON *antes* de que corra el validador de abajo, y algo tan
#: común como `LEAKS_EGRESS_BLOCKED_COUNTRIES=AR` revienta el arranque con un
#: JSONDecodeError. Con `NoDecode` el string llega crudo y lo partimos nosotros.
CsvTuple = Annotated[tuple[str, ...], NoDecode]

# Raíz del repo: <root>/src/leaks/config.py -> parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Configuración efectiva del proceso, resuelta desde el entorno."""

    model_config = SettingsConfigDict(
        env_prefix="LEAKS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Persistencia ------------------------------------------------------
    database_url: str = "sqlite:///./data/leaks.db"

    # --- PII (fail-closed) -------------------------------------------------
    store_pii: bool = False
    pii_encryption_key: SecretStr | None = None
    pii_retention_days: int = Field(default=30, ge=1)

    # --- HTTP --------------------------------------------------------------
    # Default deliberadamente no atribuible: identifica a la herramienta, no al
    # operador ni al alcance del monitoreo.
    http_user_agent: str = "leaks-monitor/0.1"
    http_timeout_seconds: float = Field(default=30.0, gt=0)
    http_max_retries: int = Field(default=3, ge=0)
    http_backoff_base_seconds: float = Field(default=2.0, gt=0)
    http_rate_limit_delay_seconds: float = Field(default=1.0, ge=0)

    # --- Feeds -------------------------------------------------------------
    # Vacío => se usan los habilitados por defecto en el registro.
    enabled_feeds: CsvTuple = ()

    # Foros: rotan de dominio (bloqueos, incautaciones). Se prueba en orden y
    # gana el primero que responda.
    darkforums_base_urls: CsvTuple = ("https://darkforums.ru",)
    #: Vacío a propósito: al 2026-08-14 no hay dominio operativo de
    #: BreachForums (los conocidos están incautados). Ver docs/feeds.md.
    breachforums_base_urls: CsvTuple = ()

    # Hudson Rock consulta dominio por dominio contra un proveedor extranjero.
    # NO lee la watchlist a propósito: cada dominio que se consulta es una
    # decisión explícita, no un efecto secundario de la watchlist.
    hudsonrock_domains: CsvTuple = ()

    # --- IP de salida (verificación de VPN) ---------------------------------
    #: Consultar la IP pública de salida. Apagarlo deja el badge en desconocido
    #: y evita el único request que no va a un feed.
    egress_check_enabled: bool = True
    egress_providers: CsvTuple = (
        "https://ipinfo.io/json",
        "https://ifconfig.co/json",
        "https://ipapi.co/json",
    )
    egress_cache_seconds: int = Field(default=300, ge=0)

    #: Países desde los que NO se puede consultar feeds. Control de OPSEC: si
    #: el tráfico sale de Argentina, se bloquea la corrida entera antes de
    #: tocar una sola fuente. No hay override desde la UI, a propósito.
    egress_blocked_countries: CsvTuple = ("AR",)
    #: Fail-closed: si no se puede determinar el país, tampoco se consulta.
    #: El objetivo del control es *garantizar* que no se sale por AR, y una
    #: IP desconocida no da esa garantía.
    egress_block_on_unknown: bool = True

    # --- Relevancia AR -----------------------------------------------------
    watchlist_path: Path = PROJECT_ROOT / "data" / "watchlist.yaml"

    # --- Scheduler ----------------------------------------------------------
    #: Hora local (HH:MM, 24h) del run diario en modo `schedule`.
    daily_run_at: str = "03:00"
    #: Correr una vez al arrancar `leaks schedule`, sin esperar a la hora.
    #: En true por defecto: un tablero que arranca vacío hasta las 3 AM no
    #: sirve para ver el prototipo funcionando.
    run_on_start: bool = True

    # --- Bitácora de actividad ----------------------------------------------
    #: Días que se conserva la consola de actividad.
    event_retention_days: int = Field(default=14, ge=1)

    # --- API ---------------------------------------------------------------
    #: Dónde están los estáticos del frontend. Se configura porque instalado
    #: como wheel el paquete ya no vive al lado del repo (ver Dockerfile).
    frontend_dir: Path = PROJECT_ROOT / "frontend"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_max_page_size: int = Field(default=200, ge=1, le=1000)
    #: Permite editar watchlist y reglas desde la UI. Se puede cerrar en un
    #: despliegue compartido; el control de IP de salida NO se puede tocar por
    #: ninguna vía de la API, ni siquiera con esto en true.
    allow_rule_editing: bool = True

    log_level: str = "INFO"

    @field_validator(
        "enabled_feeds",
        "hudsonrock_domains",
        "darkforums_base_urls",
        "breachforums_base_urls",
        "egress_providers",
        "egress_blocked_countries",
        mode="before",
    )
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Acepta listas separadas por comas desde el entorno.

        También acepta una lista/tupla ya armada, que es como llegan los
        defaults y lo que pasan los tests.
        """
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        if isinstance(value, (list, tuple)):
            return tuple(str(v).strip() for v in value if str(v).strip())
        return value

    @field_validator("daily_run_at")
    @classmethod
    def _validate_time(cls, value: str) -> str:
        """Falla al arrancar, no a las 3 AM del primer run."""
        hora, _, minuto = value.partition(":")
        if not (hora.isdigit() and minuto.isdigit()):
            raise ValueError(f"daily_run_at debe ser HH:MM, se recibió {value!r}")
        if not (0 <= int(hora) <= 23 and 0 <= int(minuto) <= 59):
            raise ValueError(f"daily_run_at fuera de rango: {value!r}")
        return value

    @model_validator(mode="after")
    def _pii_requires_key(self) -> Settings:
        """Fail-closed: guardar PII sin clave de cifrado es un error de arranque."""
        if self.store_pii and not self.pii_encryption_key:
            raise ValueError(
                "STORE_PII=true requiere LEAKS_PII_ENCRYPTION_KEY. "
                "Sin clave no se persiste PII: el proceso no arranca."
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Configuración cacheada del proceso.

    El cache se limpia en tests con `get_settings.cache_clear()`.
    """
    return Settings()
