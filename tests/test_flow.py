import sys
from pathlib import Path
import json
import tempfile
from pprint import pprint

import pytest

# Ensure project root on path for direct execution.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainofproduct import crypto, keymanager, library  # noqa: E402

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RESET = "\033[0m"


def banner(text: str, color: str = CYAN):
    print(f"{color}{'-'*30}\n{text}\n{'-'*30}{RESET}")


def _sample_payload():
    return {
        "id": "tx-comm-1",
        "timestamp": 17663363400,
        "seller": "Acme Metals",
        "buyer": "Chips Corp",
        "product": "Indium",
        "units": 40000,
        "amount": 90000000,
    }


def test_buyer_seller_end_to_end():
    banner("Starting end-to-end flow with sample payload")
    # Create isolated key storage for test.
    with tempfile.TemporaryDirectory() as tmpdir:
        seller_meta = keymanager.generate_dummy_company("seller", base_dir=tmpdir)
        buyer_meta = keymanager.generate_dummy_company("buyer", base_dir=tmpdir)
        auditor_meta = keymanager.generate_dummy_company("auditor", base_dir=tmpdir)

        seller = keymanager.load_company_keys("seller", base_dir=tmpdir)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmpdir)
        auditor = keymanager.load_company_keys("auditor", base_dir=tmpdir)

        payload = _sample_payload()
        banner("Plaintext payload", color=YELLOW)
        pprint(payload)

        # Seller protects the payload.
        protected = library.protect(payload, seller_keys=seller, buyer_keys=buyer)
        assert protected["sig_buyer"] is None
        banner("Protected transaction (ciphertext, wrapped keys, seller signature)", color=YELLOW)
        pprint({k: protected[k] for k in ("tx_id", "ciphertext", "tag", "nonce", "ek_map", "sig_seller")})

        # Explicitly verify seller signature using crypto.verify
        seller_sig_valid = crypto.verify(
            seller["signing_public"],
            crypto.b64d(protected["hash_T"]),
            crypto.b64d(protected["sig_seller"]),
        )
        assert seller_sig_valid is True
        banner("Seller signature verified with crypto.verify.", color=GREEN)

        # Buyer checks seller signature and signs.
        protected_signed = library.buyer_sign(protected, buyer_keys=buyer, seller_public_signing=seller["signing_public"])
        assert protected_signed["sig_buyer"] is not None
        banner("Buyer signature added", color=GREEN)
        print(f"{MAGENTA}Buyer signature (base64):{RESET} {protected_signed['sig_buyer']}")

        # Explicitly verify buyer signature using crypto.verify
        buyer_sig_valid = crypto.verify(
            buyer["signing_public"],
            crypto.b64d(protected_signed["hash_T"]),
            crypto.b64d(protected_signed["sig_buyer"]),
        )
        assert buyer_sig_valid is True
        banner("Buyer signature verified with crypto.verify.", color=GREEN)

        # Buyer decrypts using own wrapped key.
        decrypted = library.unprotect(protected_signed, company_keys=buyer, company_name="buyer")
        assert decrypted == payload
        banner("Buyer decrypted payload successfully.", color=GREEN)

        # Create a share for auditor and verify auditor can decrypt.
        share_record = library.create_share_record(
            protected_signed,
            from_company_keys=buyer,
            to_company_name="auditor",
            to_company_public_enc=auditor["encryption_public"],
            from_company_name="buyer",
        )
        banner("ShareRecord created for auditor", color=YELLOW)
        pprint(share_record)

        auditor_plain = library.unprotect(protected_signed, company_keys=auditor, company_name="auditor", share_record=share_record)
        assert auditor_plain == payload
        banner("Auditor decrypted payload successfully.", color=GREEN)

        # Check signatures and share validity.
        checks = library.check(
            protected_signed,
            seller_public_signing=seller["signing_public"],
            buyer_public_signing=buyer["signing_public"],
            share_records=[share_record],
            share_public_keys={"buyer": buyer["signing_public"]},
        )
        assert checks["seller_sig_ok"] is True
        assert checks["buyer_sig_ok"] is True
        assert checks["shares"][0]["valid"] is True
        banner("Verification summary", color=CYAN)
        pprint(checks)
        banner("End of flow", color=CYAN)


if __name__ == "__main__":
    # -s/--capture=no ensures print output is visible when run directly.
    raise SystemExit(pytest.main([__file__, "-vv", "-s", "--capture=no"]))
