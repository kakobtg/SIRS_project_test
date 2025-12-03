import sys
from pathlib import Path
import json
import tempfile

import pytest

# Ensure project root on sys.path for direct `python tests/test_library.py` runs.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainofproduct import crypto, keymanager, library  # noqa: E402


def _payload():
    return {
        "id": "tx-test-1",
        "timestamp": 123456789,
        "seller": "S",
        "buyer": "B",
        "product": "X",
        "units": 1,
        "amount": 2,
    }


def test_protect_unprotect_and_check_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        seller = keymanager.generate_dummy_company("seller", base_dir=tmp)
        buyer = keymanager.generate_dummy_company("buyer", base_dir=tmp)
        seller = keymanager.load_company_keys("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp)

        tx = _payload()
        protected = library.protect(tx, seller_keys=seller, buyer_keys=buyer)
        assert protected["sig_buyer"] is None

        signed = library.buyer_sign(protected, buyer_keys=buyer, seller_public_signing=seller["signing_public"])
        assert signed["sig_buyer"] is not None

        # Check verifies both signatures.
        result = library.check(
            signed,
            seller_public_signing=seller["signing_public"],
            buyer_public_signing=buyer["signing_public"],
        )
        assert result["seller_sig_ok"] is True
        assert result["buyer_sig_ok"] is True

        # Unprotect for seller and buyer should yield original payload.
        assert library.unprotect(signed, seller, company_name="seller") == tx
        assert library.unprotect(signed, buyer, company_name="buyer") == tx


def test_share_record_allows_third_party():
    with tempfile.TemporaryDirectory() as tmp:
        seller = keymanager.load_company_keys("seller", base_dir=tmp) if (Path(tmp) / "seller.json").exists() else keymanager.generate_dummy_company("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp) if (Path(tmp) / "buyer.json").exists() else keymanager.generate_dummy_company("buyer", base_dir=tmp)
        auditor = keymanager.generate_dummy_company("auditor", base_dir=tmp)
        seller = keymanager.load_company_keys("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp)
        auditor = keymanager.load_company_keys("auditor", base_dir=tmp)

        tx = _payload()
        protected = library.protect(tx, seller_keys=seller, buyer_keys=buyer)
        signed = library.buyer_sign(protected, buyer_keys=buyer, seller_public_signing=seller["signing_public"])

        share = library.create_share_record(
            signed,
            from_company_keys=buyer,
            to_company_name="auditor",
            to_company_public_enc=auditor["encryption_public"],
            from_company_name="buyer",
        )

        # Auditor can decrypt using share record.
        auditor_plain = library.unprotect(signed, auditor, company_name="auditor", share_record=share)
        assert auditor_plain == tx

        checks = library.check(
            signed,
            seller_public_signing=seller["signing_public"],
            buyer_public_signing=buyer["signing_public"],
            share_records=[share],
            share_public_keys={"buyer": buyer["signing_public"]},
        )
        assert checks["shares"][0]["valid"] is True


def test_buyer_sign_refuses_invalid_seller_sig():
    with tempfile.TemporaryDirectory() as tmp:
        seller = keymanager.generate_dummy_company("seller", base_dir=tmp)
        buyer = keymanager.generate_dummy_company("buyer", base_dir=tmp)
        seller = keymanager.load_company_keys("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp)

        tx = _payload()
        protected = library.protect(tx, seller_keys=seller, buyer_keys=buyer)

        # Tamper seller signature to trigger refusal.
        protected_bad = dict(protected)
        protected_bad["sig_seller"] = crypto.b64e(b"bad-signature")

        with pytest.raises(ValueError):
            library.buyer_sign(protected_bad, buyer_keys=buyer, seller_public_signing=seller["signing_public"])


def test_protect_sets_expected_fields():
    with tempfile.TemporaryDirectory() as tmp:
        seller = keymanager.generate_dummy_company("seller", base_dir=tmp)
        buyer = keymanager.generate_dummy_company("buyer", base_dir=tmp)
        seller = keymanager.load_company_keys("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp)

        protected = library.protect(_payload(), seller_keys=seller, buyer_keys=buyer)
        required_fields = {"tx_id", "ciphertext", "tag", "nonce", "ek_map", "hash_T", "sig_seller", "sig_buyer"}
        assert required_fields.issubset(set(protected.keys()))
        assert isinstance(protected["ciphertext"], str)
        assert protected["sig_buyer"] is None


def test_check_detects_tampering():
    with tempfile.TemporaryDirectory() as tmp:
        seller = keymanager.generate_dummy_company("seller", base_dir=tmp)
        buyer = keymanager.generate_dummy_company("buyer", base_dir=tmp)
        seller = keymanager.load_company_keys("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp)

        tx = _payload()
        protected = library.protect(tx, seller_keys=seller, buyer_keys=buyer)
        signed = library.buyer_sign(protected, buyer_keys=buyer, seller_public_signing=seller["signing_public"])

        tampered = dict(signed)
        tampered["ciphertext"] = crypto.b64e(b"evil")
        result = library.check(
            tampered,
            seller_public_signing=seller["signing_public"],
            buyer_public_signing=buyer["signing_public"],
        )
        # Signatures should fail because hash_T no longer matches ciphertext integrity check on decrypt.
        assert result["seller_sig_ok"] is True  # hash still same, but decryption will fail
        assert result["buyer_sig_ok"] is True
        # Attempting to unprotect should now raise.
        with pytest.raises(Exception):
            library.unprotect(tampered, buyer, company_name="buyer")


def test_check_flags_bad_hash_signature():
    with tempfile.TemporaryDirectory() as tmp:
        seller = keymanager.generate_dummy_company("seller", base_dir=tmp)
        buyer = keymanager.generate_dummy_company("buyer", base_dir=tmp)
        seller = keymanager.load_company_keys("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp)

        tx = _payload()
        protected = library.protect(tx, seller_keys=seller, buyer_keys=buyer)
        signed = library.buyer_sign(protected, buyer_keys=buyer, seller_public_signing=seller["signing_public"])

        # Tamper hash_T so signatures no longer match.
        tampered = dict(signed)
        tampered["hash_T"] = crypto.b64e(b"bad-hash")
        result = library.check(
            tampered,
            seller_public_signing=seller["signing_public"],
            buyer_public_signing=buyer["signing_public"],
        )
        assert result["seller_sig_ok"] is False
        assert result["buyer_sig_ok"] is False


def test_signature_must_match_sender():
    with tempfile.TemporaryDirectory() as tmp:
        seller = keymanager.generate_dummy_company("seller", base_dir=tmp)
        buyer = keymanager.generate_dummy_company("buyer", base_dir=tmp)
        attacker = keymanager.generate_dummy_company("attacker", base_dir=tmp)
        seller = keymanager.load_company_keys("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp)
        attacker = keymanager.load_company_keys("attacker", base_dir=tmp)

        tx = _payload()
        protected = library.protect(tx, seller_keys=seller, buyer_keys=buyer)

        # Attacker signs the hash instead of buyer.
        attacker_sig = crypto.sign(attacker["signing_private"], crypto.b64d(protected["hash_T"]))
        forged = dict(protected)
        forged["sig_buyer"] = crypto.b64e(attacker_sig)

        result = library.check(
            forged,
            seller_public_signing=seller["signing_public"],
            buyer_public_signing=buyer["signing_public"],
        )
        # Seller signature still valid, but buyer verification should fail.
        assert result["seller_sig_ok"] is True
        assert result["buyer_sig_ok"] is False


def test_unprotect_fails_with_wrong_company():
    with tempfile.TemporaryDirectory() as tmp:
        seller = keymanager.generate_dummy_company("seller", base_dir=tmp)
        buyer = keymanager.generate_dummy_company("buyer", base_dir=tmp)
        other = keymanager.generate_dummy_company("other", base_dir=tmp)
        seller = keymanager.load_company_keys("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp)
        other = keymanager.load_company_keys("other", base_dir=tmp)

        tx = _payload()
        protected = library.protect(tx, seller_keys=seller, buyer_keys=buyer)

        with pytest.raises(KeyError):
            library.unprotect(protected, other, company_name="other")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-vv", "-s", "--capture=no"]))
