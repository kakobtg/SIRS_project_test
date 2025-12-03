#!/usr/bin/env bash
# VM3 (client) demo: run an end-to-end flow against the DMZ API.
set -euo pipefail

API="${API:-http://dmz.example.com:8000}" # Replace with VM1 address (443 if TLS terminated)
KEYS_DIR="${KEYS_DIR:-keys}"
TX_FILE="${TX_FILE:-tx.json}"
TX_ID="${TX_ID:-tx-001}"

mkdir -p "${KEYS_DIR}"

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

echo "[vm3] Generating keys..."
python -m chainofproduct.cli --keys-dir "${KEYS_DIR}" generate-keys seller
python -m chainofproduct.cli --keys-dir "${KEYS_DIR}" generate-keys buyer
python -m chainofproduct.cli --keys-dir "${KEYS_DIR}" generate-keys auditor

echo "[vm3] Seller protects and uploads transaction..."
python clients/seller_client.py "${TX_FILE}" --seller seller --buyer buyer --server "${API}" --output protected.json

echo "[vm3] Buyer retrieves, verifies, decrypts, signs, uploads, and shares with auditor..."
python clients/buyer_client.py "${TX_ID}" --seller seller --buyer buyer --server "${API}" --output-plain buyer_plain.json --output-protected buyer_signed.json --share-with auditor --share-output share.json

echo "[vm3] Auditor retrieves share and decrypts..."
python clients/third_party_client.py "${TX_ID}" --company auditor --seller seller --buyer buyer --server "${API}" --output-plain auditor_plain.json

echo "[vm3] Final audit of shares:"
curl -s "${API}/transactions/${TX_ID}/shares" | python -m json.tool
