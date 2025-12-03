#!/usr/bin/env bash
# VM2 (internal DB) setup: launch a Postgres container bound to the internal interface only.
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-cop-db}"
DB_USER="${DB_USER:-cop}"
DB_PASS="${DB_PASS:-cop}"
DB_NAME="${DB_NAME:-cop}"
LISTEN_IP="${LISTEN_IP:-127.0.0.1}" # Bind locally on the DB VM; firewall allows only VM1 to reach it.

echo "[vm2] Starting Postgres container '${CONTAINER_NAME}'..."
docker run -d --restart unless-stopped \
  --name "${CONTAINER_NAME}" \
  -e POSTGRES_USER="${DB_USER}" \
  -e POSTGRES_PASSWORD="${DB_PASS}" \
  -e POSTGRES_DB="${DB_NAME}" \
  -p "${LISTEN_IP}:5432:5432" \
  postgres:15

echo "[vm2] Postgres listening on ${LISTEN_IP}:5432. Allow only VM1 (DMZ) through the firewall."
