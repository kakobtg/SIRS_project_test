#!/usr/bin/env bash
# VM1 (DMZ) setup: install deps and start the FastAPI app server.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/chainofproduct}"
DB_HOST="${DB_HOST:-10.0.2.10}"  # Internal DB VM IP (example)
DB_URL="${COP_DB_URL:-postgresql+psycopg2://cop:cop@${DB_HOST}:5432/cop}"
PORT="${PORT:-8000}"

echo "[vm1] Using app dir: ${APP_DIR}"
cd "${APP_DIR}"

echo "[vm1] Installing dependencies..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt "psycopg2-binary"

echo "[vm1] Starting API (DMZ) with DB at ${DB_HOST}..."
export COP_DB_URL="${DB_URL}"
# For production, front with nginx + TLS termination or run uvicorn with --ssl-*-file.
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}"
