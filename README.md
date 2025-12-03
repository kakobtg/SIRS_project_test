# ChainOfProduct Prototype

Secure “Chain of Product” DvP transactions with client-side encryption/signing, server-side storage of ciphertext + wrapped keys, and verifiable sharing. This README is written so you can follow it from scratch on three Kali VMs (or any Linux).

## What’s inside
- **Crypto:** AES-256-GCM payloads; X25519+HKDF+AES-GCM key wrapping; Ed25519 signatures; SHA-256 hashing.
- **Library:** `protect()`, `buyer_sign()`, `check()`, `unprotect()`, `create_share_record()`.
- **API:** FastAPI server storing protected transactions/share records; public-key registry via `/register_company` and `/companies/{name}`.
- **Clients:** Seller/Buyer/Auditor scripts plus CLI.
- **Scripts:** Helpers for DB (VM2), app (VM1), and client flows (VM3).

## Install (per VM, Kali-friendly)
```bash
sudo apt update
sudo apt install -y python3-venv python3-pip git build-essential libssl-dev libffi-dev libpq-dev docker.io
git clone <repo-url> chainofproduct && cd chainofproduct
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt psycopg2-binary
```

## FastAPI (DMZ) server
```bash
export COP_DB_URL=sqlite:///./cop.db  # dev
# or PostgreSQL in 3-VM layout: postgresql+psycopg2://cop:cop@<vm2-ip>:5432/cop
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Endpoints: `POST /register_company`, `GET /companies/{name}`, `POST /transactions`, `GET /transactions/{tx_id}`, `POST /transactions/{tx_id}/buyer_sign`, `POST /transactions/{tx_id}/share`, `GET /transactions/{tx_id}/shares`.

## CLI basics (`python -m chainofproduct.cli`)
- Generate keys: `python -m chainofproduct.cli --keys-dir keys generate-keys seller`
- Protect: `python -m chainofproduct.cli --keys-dir keys protect tx.json seller buyer protected.json`
- Buyer signs: `python -m chainofproduct.cli --keys-dir keys buyer-sign protected.json seller buyer buyer_signed.json`
- Check: `python -m chainofproduct.cli --keys-dir keys check protected.json seller --buyer buyer`
- Share: `python -m chainofproduct.cli --keys-dir keys share protected.json buyer auditor share.json`
- Unprotect (seller/buyer): `python -m chainofproduct.cli --keys-dir keys unprotect protected.json buyer plain.json`
- Unprotect via share: `python -m chainofproduct.cli --keys-dir keys unprotect protected.json auditor plain.json --share share.json`

## 3-VM layout and step-by-step
**Roles**
- VM1 (DMZ): FastAPI app, exposed on 443/8000.
- VM2 (DB): Postgres, only reachable from VM1 on 5432.
- VM3 (Client): CLI/clients; only reaches VM1.

**VM2 (DB)**
```bash
sudo bash scripts/vm2_db.sh   # starts Postgres in Docker bound locally; firewall allow only VM1 on 5432
```

**VM1 (DMZ app)**
```bash
export COP_DB_URL=postgresql+psycopg2://cop:cop@<vm2-ip>:5432/cop
bash scripts/vm1_dmz_app.sh   # starts FastAPI/uvicorn
# For HTTPS: use uvicorn --ssl-keyfile/--ssl-certfile or front with nginx/HAProxy.
```

**VM3 (Clients)**
- Seller terminal: `bash scripts/vm3_seller.sh API=http://<vm1-ip>:8000`
- Buyer terminal: `bash scripts/vm3_buyer.sh API=http://<vm1-ip>:8000`
- Auditor terminal: `bash scripts/vm3_auditor.sh API=http://<vm1-ip>:8000`
- Or single-script demo: `bash scripts/vm3_client_demo.sh API=http://<vm1-ip>:8000`

## End-to-end flow (SR1–SR4)
1) Seller protects `tx.json` (encrypts, wraps keys, signs) and uploads.  
2) Buyer fetches, verifies seller sig, decrypts, signs, uploads `sig_buyer`.  
3) Buyer wraps the tx key for a third party, signs a ShareRecord, uploads it.  
4) Third party fetches tx + shares, verifies signatures, unwraps via share, decrypts.  
5) Seller/Buyer audit sharing via `/transactions/{tx_id}/shares`.

## Firewall/TLS
- Client → DMZ: allow 443 (or 8000 dev); deny other inbound to VM1.
- DMZ → DB: allow 5432 from VM1 to VM2; deny other inbound/outbound to DB.
- DB: no direct client/internet exposure.
- TLS: terminate HTTPS on VM1 (`uvicorn --ssl-keyfile ... --ssl-certfile ...` or nginx/HAProxy). Use internal CA/self-signed for prototype.

## Testing
```bash
pytest -vv -s --capture=no
```
Includes crypto, library, share, keymanager, and end-to-end flow tests with visible output.

## Design notes
- Server stores ciphertext, wrapped keys, signatures; private keys stay on VM3.
- `keymanager` is client-side; public keys can be fetched via `/companies/{name}`.
- Extensible: swap PKI/KMS, add auth/JWT, enforce TLS, or extend sharing policies.
