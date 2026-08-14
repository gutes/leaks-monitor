#!/usr/bin/env bash
# Atajos de desarrollo. Uso: ./scripts/dev.sh <comando>
set -euo pipefail

cd "$(dirname "$0")/.."
VENV="${VENV:-.venv}"

case "${1:-help}" in
  setup)
    python3.12 -m venv "$VENV"
    "$VENV/bin/pip" install --upgrade pip
    "$VENV/bin/pip" install -e ".[dev]"
    [ -f .env ] || cp .env.example .env
    echo "Listo. Ahora: ./scripts/dev.sh run"
    ;;
  check)
    # Mismo orden que el CI: barato -> caro.
    "$VENV/bin/ruff" check src tests
    "$VENV/bin/ruff" format --check src tests
    "$VENV/bin/mypy"
    "$VENV/bin/pytest" -q
    "$VENV/bin/bandit" -c pyproject.toml -r src -q
    echo "Todo en verde."
    ;;
  run)     "$VENV/bin/leaks" run ;;
  serve)   "$VENV/bin/leaks" serve ;;
  feeds)   "$VENV/bin/leaks" feeds ;;
  *)
    cat <<'HELP'
Comandos:
  setup   crea el venv, instala y prepara el .env
  check   lint + formato + tipos + tests + SAST (lo mismo que el CI)
  run     una corrida del pipeline
  serve   levanta la API y el frontend
  feeds   lista los feeds registrados
HELP
    ;;
esac
