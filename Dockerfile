# Imagen del prototipo. Multi-stage para que la imagen final no arrastre el
# toolchain de build.
#
# Un solo artefacto para los tres modos de uso (run / schedule / serve): lo que
# cambia es el comando, no la imagen. Promover = mover la MISMA imagen.

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Las dependencias van antes que el código: cambiar una línea del proyecto no
# invalida la capa de dependencias.
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir .

# ---------------------------------------------------------------------------

FROM python:3.12-slim AS runtime

# Usuario sin privilegios: el proceso consume feeds hostiles, no corre como root.
RUN useradd --create-home --uid 10001 leaks

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LEAKS_DATABASE_URL=sqlite:////data/leaks.db \
    LEAKS_WATCHLIST_PATH=/app/data/watchlist.yaml \
    LEAKS_FRONTEND_DIR=/app/frontend \
    LEAKS_ALEMBIC_DIR=/app/alembic \
    LEAKS_ALEMBIC_INI=/app/alembic.ini \
    LEAKS_API_HOST=0.0.0.0

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=leaks:leaks data/watchlist.yaml ./data/watchlist.yaml
COPY --chown=leaks:leaks frontend ./frontend
COPY --chown=leaks:leaks alembic ./alembic
COPY --chown=leaks:leaks alembic.ini ./alembic.ini

# La base vive en un volumen: la imagen es inmutable, los datos no.
RUN mkdir -p /data && chown leaks:leaks /data
VOLUME ["/data"]

USER leaks
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/health').read()" \
    || exit 1

# Default: la UI de solo lectura. Para el pipeline: `docker run ... leaks run`.
CMD ["leaks", "serve"]
