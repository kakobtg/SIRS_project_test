#!/usr/bin/env bash
# VM3 seller terminal: generate seller/buyer keys if missing, protect and upload a transaction.
set -euo pipefail

API="${API:-http://dmz.example.com:8000}"   # Point to VM1 DMZ API
KEYS_DIR="${KEYS_DIR:-keys}"
TX_FILE="${TX_FILE:-tx.json}"
SELLER="${SELLER:-seller}"
BUYER="${BUYER:-buyer}"
OUT_PROTECTED="${OUT_PROTECTED:-protected.json}"

mkdir -p "${KEYS_DIR}"

if [[ ! -f "${KEYS_DIR}/${SELLER}.json" ]]; then
  python -m chainofproduct.cli --keys-dir "${KEYS_DIR}" generate-keys "${SELLER}"
fi
if [[ ! -f "${KEYS_DIR}/${BUYER}.json" ]]; then
  python -m chainofproduct.cli --keys-dir "${KEYS_DIR}" generate-keys "${BUYER}"
fi

if [[ ! -f "${TX_FILE}" ]]; then
  cat > "${TX_FILE}" <<'EOF'
{
  "id": "tx-001",
  "timestamp": 17663363400,
  "seller": "Ching Chong Extractions",
  "buyer": "Lays Chips",
  "product": "Indium",
  "units": 40000,
  "amount": 90000000
}
EOF
fi

echo "[seller] Protecting and uploading transaction..."
python clients/seller_client.py "${TX_FILE}" --seller "${SELLER}" --buyer "${BUYER}" --server "${API}" --output "${OUT_PROTECTED}"

echo "[seller] Protected transaction saved to ${OUT_PROTECTED}. Share tx_id with buyer (usually same as id field)."
