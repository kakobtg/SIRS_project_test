import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import crypto


def _canonical_bytes(obj: dict) -> bytes:
    """Produce deterministic JSON bytes for hashing/signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def protect(document: Dict, seller_keys: Dict[str, bytes], buyer_keys: Dict[str, bytes]) -> Dict:
    """
    Protect a DvP transaction by encrypting it, wrapping the symmetric key,
    and signing the transaction hash by the seller.
    """
    doc_bytes = _canonical_bytes(document)
    hash_t = crypto.hash_bytes(doc_bytes)
    sym_key = os.urandom(32)
    ciphertext, tag, nonce = crypto.encrypt_aes_gcm(sym_key, doc_bytes, associated_data=hash_t)

    ek_seller = crypto.wrap_key(seller_keys["encryption_public"], sym_key)
    ek_buyer = crypto.wrap_key(buyer_keys["encryption_public"], sym_key)
    sig_seller = crypto.sign(seller_keys["signing_private"], hash_t)

    tx_id = str(document.get("id", uuid.uuid4().hex))
    protected_doc = {
        "tx_id": tx_id,
        "ciphertext": crypto.b64e(ciphertext),
        "tag": crypto.b64e(tag),
        "nonce": crypto.b64e(nonce),
        "ek_map": {
            seller_keys.get("name", "seller"): crypto.b64e(ek_seller),
            buyer_keys.get("name", "buyer"): crypto.b64e(ek_buyer),
        },
        "hash_T": crypto.b64e(hash_t),
        "sig_seller": crypto.b64e(sig_seller),
        "sig_buyer": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "meta": {"hash_alg": "sha256", "cipher": "AES-256-GCM", "wrap": "X25519+AESGCM"},
    }
    return protected_doc


def buyer_sign(protected_doc: Dict, buyer_keys: Dict[str, bytes], seller_public_signing: bytes) -> Dict:
    """Buyer signs the transaction hash after verifying seller signature."""
    hash_t = crypto.b64d(protected_doc["hash_T"])
    seller_sig = crypto.b64d(protected_doc["sig_seller"])
    if not crypto.verify(seller_public_signing, hash_t, seller_sig):
        raise ValueError("Seller signature verification failed; refusing to sign.")
    sig_buyer = crypto.sign(buyer_keys["signing_private"], hash_t)
    protected_doc = dict(protected_doc)
    protected_doc["sig_buyer"] = crypto.b64e(sig_buyer)
    return protected_doc


def _select_wrapped_key(protected_doc: Dict, company_name: str, share_record: Optional[Dict] = None) -> bytes:
    """Pick the wrapped symmetric key for a company (transaction-level or share-level)."""
    if share_record:
        return crypto.b64d(share_record["ek_to"])
    ek_map = protected_doc.get("ek_map", {})
    if company_name in ek_map:
        return crypto.b64d(ek_map[company_name])
    raise KeyError(f"No wrapped key for company {company_name}")


def unprotect(protected_doc: Dict, company_keys: Dict[str, bytes], company_name: str, share_record: Optional[Dict] = None) -> Dict:
    """
    Decrypt the transaction for the provided company using its wrapped key.
    Optionally supply a ShareRecord (when not seller/buyer).
    """
    wrapped = _select_wrapped_key(protected_doc, company_name, share_record)
    sym_key = crypto.unwrap_key(company_keys["encryption_private"], wrapped)
    ciphertext = crypto.b64d(protected_doc["ciphertext"])
    tag = crypto.b64d(protected_doc["tag"])
    nonce = crypto.b64d(protected_doc["nonce"])
    hash_t = crypto.b64d(protected_doc["hash_T"])
    plaintext = crypto.decrypt_aes_gcm(sym_key, ciphertext, tag, nonce, associated_data=hash_t)
    return json.loads(plaintext.decode("utf-8"))


def create_share_record(
    protected_doc: Dict,
    from_company_keys: Dict[str, bytes],
    to_company_name: str,
    to_company_public_enc: bytes,
    from_company_name: Optional[str] = None,
) -> Dict:
    """
    Create a ShareRecord: wrap the transaction key for the recipient and sign the record.
    """
    from_name = from_company_name or from_company_keys.get("name") or "unknown"
    sym_key = crypto.unwrap_key(from_company_keys["encryption_private"], _select_wrapped_key(protected_doc, from_name))
    ek_to = crypto.wrap_key(to_company_public_enc, sym_key)
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "id": uuid.uuid4().hex,
        "tx_id": protected_doc["tx_id"],
        "from_company": from_name,
        "to_company": to_company_name,
        "ek_to": crypto.b64e(ek_to),
        "timestamp": timestamp,
    }
    record_bytes = _canonical_bytes(record)
    sig_share = crypto.sign(from_company_keys["signing_private"], crypto.hash_bytes(record_bytes))
    record["sig_share"] = crypto.b64e(sig_share)
    return record


def check(
    protected_doc: Dict,
    seller_public_signing: bytes,
    buyer_public_signing: Optional[bytes] = None,
    share_records: Optional[List[Dict]] = None,
    share_public_keys: Optional[Dict[str, bytes]] = None,
) -> Dict:
    """
    Verify signatures and structural integrity of the protected doc and any share records.
    Returns a dictionary of check results.
    """
    results = {"seller_sig_ok": False, "buyer_sig_ok": None, "shares": []}
    hash_t = crypto.b64d(protected_doc["hash_T"])
    seller_sig = crypto.b64d(protected_doc["sig_seller"])
    results["seller_sig_ok"] = crypto.verify(seller_public_signing, hash_t, seller_sig)

    sig_buyer_b64 = protected_doc.get("sig_buyer")
    if sig_buyer_b64 and buyer_public_signing:
        sig_buyer = crypto.b64d(sig_buyer_b64)
        results["buyer_sig_ok"] = crypto.verify(buyer_public_signing, hash_t, sig_buyer)
    elif sig_buyer_b64:
        results["buyer_sig_ok"] = False

    if share_records:
        for rec in share_records:
            entry = {"id": rec.get("id"), "from_company": rec.get("from_company"), "valid": False}
            if not share_public_keys:
                results["shares"].append(entry)
                continue
            from_company = rec.get("from_company")
            pub = share_public_keys.get(from_company)
            if not pub:
                results["shares"].append(entry)
                continue
            rec_copy = dict(rec)
            sig_share = crypto.b64d(rec_copy.pop("sig_share"))
            rec_bytes = _canonical_bytes(rec_copy)
            entry["valid"] = crypto.verify(pub, crypto.hash_bytes(rec_bytes), sig_share)
            results["shares"].append(entry)
    return results
