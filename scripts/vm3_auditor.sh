#!/usr/bin/env bash
# VM3 authorized third party (auditor) terminal: fetch share, verify, decrypt.
set -euo pipefail

API="${API:-http://10.0.0.10:8000}"   # Point to VM1 DMZ API (suggested IP plan)
KEYS_DIR="${KEYS_DIR:-keys}"
TX_ID="${TX_ID:-tx-001}"
SELLER="${SELLER:-seller}"
BUYER="${BUYER:-buyer}"
AUDITOR="${AUDITOR:-auditor}"
OUT_PLAIN="${OUT_PLAIN:-auditor_plain.json}"

mkdir -p "${KEYS_DIR}"

if [[ ! -f "${KEYS_DIR}/${AUDITOR}.json" ]]; then
  python -m chainofproduct.cli --keys-dir "${KEYS_DIR}" generate-keys "${AUDITOR}"
fi

echo "[auditor] Fetching share and decrypting tx ${TX_ID}..."
python clients/third_party_client.py "${TX_ID}" --company "${AUDITOR}" --seller "${SELLER}" --buyer "${BUYER}" --server "${API}" --output-plain "${OUT_PLAIN}"

echo "[auditor] Plaintext stored at ${OUT_PLAIN}."
