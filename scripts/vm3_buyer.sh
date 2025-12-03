#!/usr/bin/env bash
# VM3 buyer terminal: fetch transaction, verify, decrypt, sign, upload, and optionally share.
set -euo pipefail

API="${API:-http://10.0.0.10:8000}"   # Point to VM1 DMZ API (suggested IP plan)
KEYS_DIR="${KEYS_DIR:-keys}"
TX_ID="${TX_ID:-tx-001}"
SELLER="${SELLER:-seller}"
BUYER="${BUYER:-buyer}"
SHARE_WITH="${SHARE_WITH:-auditor}"  # set empty to skip sharing
OUT_PLAIN="${OUT_PLAIN:-buyer_plain.json}"
OUT_PROTECTED="${OUT_PROTECTED:-buyer_signed.json}"
OUT_SHARE="${OUT_SHARE:-share.json}"

mkdir -p "${KEYS_DIR}"

if [[ ! -f "${KEYS_DIR}/${BUYER}.json" ]]; then
  python -m chainofproduct.cli --keys-dir "${KEYS_DIR}" generate-keys "${BUYER}"
fi
if [[ ! -f "${KEYS_DIR}/${SELLER}.json" ]]; then
  python -m chainofproduct.cli --keys-dir "${KEYS_DIR}" generate-keys "${SELLER}"
fi
if [[ -n "${SHARE_WITH}" && ! -f "${KEYS_DIR}/${SHARE_WITH}.json" ]]; then
  python -m chainofproduct.cli --keys-dir "${KEYS_DIR}" generate-keys "${SHARE_WITH}"
fi

echo "[buyer] Fetching tx ${TX_ID} and processing..."
python clients/buyer_client.py "${TX_ID}" --seller "${SELLER}" --buyer "${BUYER}" --server "${API}" --output-plain "${OUT_PLAIN}" --output-protected "${OUT_PROTECTED}" --share-with "${SHARE_WITH}" --share-output "${OUT_SHARE}"

echo "[buyer] Plaintext stored at ${OUT_PLAIN}, updated protected at ${OUT_PROTECTED}, share (if any) at ${OUT_SHARE}."
