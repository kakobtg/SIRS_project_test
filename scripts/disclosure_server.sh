#!/usr/bin/env bash
# Launch the selective disclosure tracking server (separate from main DMZ API).
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/chainofproduct}"
DB_URL="${COP_DISCLOSURE_DB_URL:-sqlite:///./disclosures.db}"
PORT="${PORT:-8100}"

echo "[disclosure] Using app dir: ${APP_DIR}"
echo "[disclosure] DB: ${DB_URL}"
cd "${APP_DIR}"

export COP_DISCLOSURE_DB_URL="${DB_URL}"
exec uvicorn disclosure_service.main:app --host 0.0.0.0 --port "${PORT}"
