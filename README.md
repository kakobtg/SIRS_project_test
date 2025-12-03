# ChainOfProduct Prototype

Minimal end-to-end prototype of a secure Chain of Product (CoP) “Delivery-vs-Payment” transaction system. It encrypts transactions, signs them, records protected payloads on an untrusted server, and supports verifiable sharing with third parties.

## System overview

- **SR1 (Confidentiality):** Transactions encrypted with per-tx AES-GCM; symmetric key wrapped per party with X25519.
- **SR2 (Authentication):** Ed25519 signatures by seller and buyer; only they can produce valid records.
- **SR3 (Integrity):** Signatures cover the hash of the canonical JSON; AES-GCM tag covers ciphertext.
- **SR4 (Auditability):** ShareRecords are signed to prove who disclosed to whom; server lists share history.
- **Separation of concerns:** crypto primitives in `chainofproduct/crypto.py`, key handling in `keymanager.py`, high-level flows in `library.py`, API in `app/`, demo clients in `clients/`.

## Dependencies

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Quick CLI usage (python -m chainofproduct.cli)

- Generate keys: `python -m chainofproduct.cli --keys-dir keys generate-keys seller`
- Protect: `python -m chainofproduct.cli --keys-dir keys protect tx.json seller buyer protected.json`
- Buyer signs: `python -m chainofproduct.cli --keys-dir keys buyer-sign protected.json seller buyer buyer_signed.json`
- Check: `python -m chainofproduct.cli --keys-dir keys check protected.json seller --buyer buyer`
- Share: `python -m chainofproduct.cli --keys-dir keys share protected.json buyer auditor share.json`
- Unprotect (seller/buyer): `python -m chainofproduct.cli --keys-dir keys unprotect protected.json buyer plain.json`
- Unprotect via share: `python -m chainofproduct.cli --keys-dir keys unprotect protected.json auditor plain.json --share share.json`

## FastAPI (DMZ component)

```bash
export COP_DB_URL=sqlite:///./cop.db  # or postgresql+psycopg2://cop:cop@10.0.2.10:5432/cop
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Endpoints:
- `POST /register_company`
- `POST /transactions`
- `GET /transactions/{tx_id}`
- `POST /transactions/{tx_id}/buyer_sign`
- `POST /transactions/{tx_id}/share`
- `GET /transactions/{tx_id}/shares`

## Demo clients

- Seller: `python clients/seller_client.py tx.json --seller seller --buyer buyer --server http://localhost:8000 --output protected.json`
- Buyer: `python clients/buyer_client.py <tx_id> --seller seller --buyer buyer --server http://localhost:8000 --output-plain buyer_plain.json --output-protected buyer_signed.json --share-with auditor --share-output share.json`
- Third party: `python clients/third_party_client.py <tx_id> --company auditor --seller seller --buyer buyer --server http://localhost:8000 --output-plain auditor_plain.json`

## End-to-end demo (SR1–SR4)

1. Seller generates keys, protects `tx.json`, and posts it to the server (only ciphertext + wrapped keys stored).
2. Buyer fetches the protected tx from the server, checks signatures, decrypts locally, signs, and posts `sig_buyer`.
3. Buyer shares with a third party (e.g., `auditor`) by wrapping the symmetric key for that party and posting a signed `ShareRecord`.
4. Third party fetches tx + share list, verifies share signature and original signatures, unwraps its key, and decrypts.
5. Seller (or buyer) fetches `/transactions/{tx_id}/shares` to audit who received the transaction.

## 3 Kali VM layout and runbook

**VM roles**
- VM1 (DMZ): FastAPI app server, exposed on TCP 443/8000.
- VM2 (Internal): Database server, reachable only from VM1 on DB port (e.g., 5432 Postgres).
- VM3 (Client): Runs CLI/clients; can only reach VM1 over HTTPS.

**Prereqs on all VMs**
```bash
sudo apt update
sudo apt install -y python3-venv python3-pip git
git clone <this-repo> chainofproduct && cd chainofproduct
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**VM2 (DB)**
- Install Docker: `sudo apt install -y docker.io`
- Run `scripts/vm2_db.sh` (binds Postgres to local interface; firewall should only allow VM1): `sudo bash scripts/vm2_db.sh`

**VM1 (DMZ app)**
- Ensure `COP_DB_URL` points to VM2 (example): `export COP_DB_URL=postgresql+psycopg2://cop:cop@10.0.2.10:5432/cop`
- Start API: `bash scripts/vm1_dmz_app.sh`
- For HTTPS, either front with nginx or run uvicorn with `--ssl-keyfile` and `--ssl-certfile`.

**VM3 (Client)**
- Set API endpoint to VM1: `export API=http://<vm1-ip>:8000` (or https://vm1:443 if TLS/terminating proxy)
- Run the automated demo: `bash scripts/vm3_client_demo.sh`
  - Generates keys for seller/buyer/auditor, protects and uploads tx, buyer signs and shares, auditor decrypts, prints shares.

**Firewall guidance**
- Client ↔ DMZ: allow TCP 443 (or 8000 for dev) from VM3 to VM1; deny other inbound.
- DMZ ↔ DB: allow TCP 5432 from VM1 to VM2; deny other inbound/outbound to DB.
- DB has no direct internet/Client exposure.

**TLS note**
- Terminate HTTPS on VM1 (`uvicorn ... --ssl-keyfile key.pem --ssl-certfile cert.pem`) or via nginx/HAProxy. Use an internal CA or self-signed cert for the prototype. Restrict DB connections to the internal subnet; enable TLS on Postgres if available.

## Testing

- Crypto unit tests: `python tests/test_crypto.py` (verbose) or `pytest -v`.

## Design notes

- Crypto: AES-256-GCM payload encryption with per-transaction symmetric keys; X25519 key wrapping; Ed25519 signatures over transaction hash and share records.
- Server stores only ciphertext, wrapped keys, and signatures; decryption occurs client-side.
- Components are modular: `crypto.py` (primitives), `keymanager.py` (dummy PKI), `library.py` (protect/check/unprotect), API in `app/`, demo clients in `clients/`, deployment scripts in `scripts/`.
