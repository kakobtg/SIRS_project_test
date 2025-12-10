import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

from . import crypto


def _canonical_bytes(obj: dict) -> bytes:
    """Produce deterministic JSON bytes for hashing/signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _protect_envelope(
    payload_bytes: bytes,
    seller_keys: Dict[str, bytes],
    buyer_keys: Dict[str, bytes],
    tx_id: str,
    meta_extra: Optional[Dict] = None,
) -> Dict:
    """Encrypt and sign a payload, returning the protected envelope fields."""
    hash_t = crypto.hash_bytes(payload_bytes)
    sym_key = os.urandom(32)
    ciphertext, tag, nonce = crypto.encrypt_aes_gcm(sym_key, payload_bytes, associated_data=hash_t)

    ek_seller = crypto.wrap_key(seller_keys["encryption_public"], sym_key)
    ek_buyer = crypto.wrap_key(buyer_keys["encryption_public"], sym_key)
    sig_seller = crypto.sign(seller_keys["signing_private"], hash_t)

    meta = {"hash_alg": "sha256", "cipher": "AES-256-GCM", "wrap": "X25519+AESGCM"}
    if meta_extra:
        meta.update(meta_extra)

    return {
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
        "meta": meta,
    }


def protect(document: Dict, seller_keys: Dict[str, bytes], buyer_keys: Dict[str, bytes]) -> Dict:
    """
    Protect a DvP transaction by encrypting it, wrapping the symmetric key,
    and signing the transaction hash by the seller.
    """
    tx_id = str(document.get("id", uuid.uuid4().hex))
    return _protect_envelope(_canonical_bytes(document), seller_keys, buyer_keys, tx_id)


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


def _select_wrapped_key(
    protected_doc: Dict,
    company_name: str,
    share_record: Optional[Dict] = None,
    expected_section: Optional[str] = None,
    expected_tx: Optional[str] = None,
) -> bytes:
    """Pick the wrapped symmetric key for a company (transaction-level or share-level)."""
    if share_record:
        if expected_section and share_record.get("section") != expected_section:
            raise KeyError(f"Share record is not for section {expected_section}")
        if expected_tx and share_record.get("tx_id") != expected_tx:
            raise KeyError(f"Share record tx_id {share_record.get('tx_id')} does not match {expected_tx}")
        return crypto.b64d(share_record["ek_to"])
    ek_map = protected_doc.get("ek_map", {})
    if company_name in ek_map:
        return crypto.b64d(ek_map[company_name])
    raise KeyError(f"No wrapped key for company {company_name}")


def _decrypt_envelope(
    protected_doc: Dict,
    company_keys: Dict[str, bytes],
    company_name: str,
    share_record: Optional[Dict] = None,
    expected_section: Optional[str] = None,
    expected_tx: Optional[str] = None,
) -> Dict:
    """Common decryptor for full transaction and layered envelopes."""
    wrapped = _select_wrapped_key(
        protected_doc,
        company_name,
        share_record=share_record,
        expected_section=expected_section,
        expected_tx=expected_tx,
    )
    sym_key = crypto.unwrap_key(company_keys["encryption_private"], wrapped)
    ciphertext = crypto.b64d(protected_doc["ciphertext"])
    tag = crypto.b64d(protected_doc["tag"])
    nonce = crypto.b64d(protected_doc["nonce"])
    hash_t = crypto.b64d(protected_doc["hash_T"])
    plaintext = crypto.decrypt_aes_gcm(sym_key, ciphertext, tag, nonce, associated_data=hash_t)
    return json.loads(plaintext.decode("utf-8"))


def unprotect(protected_doc: Dict, company_keys: Dict[str, bytes], company_name: str, share_record: Optional[Dict] = None) -> Dict:
    """
    Decrypt the transaction for the provided company using its wrapped key.
    Optionally supply a ShareRecord (when not seller/buyer).
    """
    return _decrypt_envelope(
        protected_doc,
        company_keys=company_keys,
        company_name=company_name,
        share_record=share_record,
        expected_tx=protected_doc.get("tx_id"),
    )


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


def _slice_document(document: Dict, fields: Sequence[str]) -> Dict:
    """Extract a subset of fields for a layer."""
    missing = [f for f in fields if f not in document]
    if missing:
        raise KeyError(f"Missing fields for selective disclosure: {missing}")
    return {f: document[f] for f in fields}


def protect_with_layers(
    document: Dict,
    seller_keys: Dict[str, bytes],
    buyer_keys: Dict[str, bytes],
    layers: Optional[Dict[str, Sequence[str]]] = None,
) -> Dict:
    """
    Protect a transaction and also produce independently encrypted layers (sections)
    for selective disclosure. Layers is a mapping of section name -> list of fields
    to include from the document.
    """
    protected_doc = protect(document, seller_keys, buyer_keys)
    if not layers:
        return protected_doc

    tx_id = protected_doc["tx_id"]
    layered_payloads = {}
    for section, fields in layers.items():
        slice_doc = _slice_document(document, fields)
        envelope = _protect_envelope(
            _canonical_bytes(slice_doc),
            seller_keys,
            buyer_keys,
            tx_id=tx_id,
            meta_extra={"section": section, "fields": list(fields)},
        )
        layered_payloads[section] = envelope
    protected_doc["layers"] = layered_payloads
    return protected_doc


def unprotect_layer(
    protected_doc: Dict,
    company_keys: Dict[str, bytes],
    company_name: str,
    section: str,
    share_record: Optional[Dict] = None,
) -> Dict:
    """Decrypt a specific protected layer/section."""
    layers = protected_doc.get("layers") or {}
    if section not in layers:
        raise KeyError(f"No protected layer named {section}")
    envelope = layers[section]
    return _decrypt_envelope(
        envelope,
        company_keys=company_keys,
        company_name=company_name,
        share_record=share_record,
        expected_section=section,
        expected_tx=protected_doc.get("tx_id"),
    )


def create_layer_share_records(
    protected_doc: Dict,
    sections: Sequence[str],
    from_company_keys: Dict[str, bytes],
    to_company_name: str,
    to_company_public_enc: bytes,
    from_company_name: Optional[str] = None,
) -> List[Dict]:
    """
    Create share records for specific sections/layers so recipients can decrypt only those.
    """
    layers = protected_doc.get("layers") or {}
    missing = [s for s in sections if s not in layers]
    if missing:
        raise KeyError(f"Missing layers: {missing}")

    from_name = from_company_name or from_company_keys.get("name") or "unknown"
    share_records: List[Dict] = []
    for section in sections:
        layer = layers[section]
        sym_key = crypto.unwrap_key(
            from_company_keys["encryption_private"],
            _select_wrapped_key(layer, from_name),
        )
        ek_to = crypto.wrap_key(to_company_public_enc, sym_key)
        timestamp = datetime.now(timezone.utc).isoformat()
        record = {
            "id": uuid.uuid4().hex,
            "tx_id": protected_doc["tx_id"],
            "section": section,
            "from_company": from_name,
            "to_company": to_company_name,
            "ek_to": crypto.b64e(ek_to),
            "timestamp": timestamp,
            "layer_hash": layer["hash_T"],
        }
        rec_bytes = _canonical_bytes(record)
        sig_share = crypto.sign(from_company_keys["signing_private"], crypto.hash_bytes(rec_bytes))
        record["sig_share"] = crypto.b64e(sig_share)
        share_records.append(record)
    return share_records


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
            section = rec.get("section")
            if section:
                entry["section"] = section
                expected_layer_hash = (protected_doc.get("layers") or {}).get(section, {}).get("hash_T")
                entry["layer_hash_ok"] = rec.get("layer_hash") == expected_layer_hash if expected_layer_hash else False
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
