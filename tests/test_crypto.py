import sys
from pathlib import Path
import base64
import json

import pytest

# Ensure project root is on sys.path for direct `python tests/test_crypto.py` runs.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainofproduct import crypto

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def heading(name: str, color: str = CYAN):
    print(f"\n{color}--- {name} ---{RESET}")

def test_b64_roundtrip():
    heading("test_b64_roundtrip", color=YELLOW)
    raw = b"hello world"
    encoded = crypto.b64e(raw)
    assert isinstance(encoded, str)
    assert crypto.b64d(encoded) == raw
    # Ensure URL-safe encoding (no padding issues)
    base64.urlsafe_b64decode(encoded.encode("ascii"))


def test_key_generation_and_loading():
    heading("test_key_generation_and_loading", color=YELLOW)
    priv_sign, pub_sign = crypto.generate_signing_keypair()
    assert b"BEGIN PRIVATE KEY" in priv_sign
    assert b"BEGIN PUBLIC KEY" in pub_sign
    priv_enc, pub_enc = crypto.generate_encryption_keypair()
    assert b"BEGIN PRIVATE KEY" in priv_enc
    assert b"BEGIN PUBLIC KEY" in pub_enc

    # Loading should yield usable keys
    loaded_priv_sign = crypto.load_signing_private_key(priv_sign)
    loaded_pub_sign = crypto.load_signing_public_key(pub_sign)
    message = b"loadable"
    sig = loaded_priv_sign.sign(message)
    loaded_pub_sign.verify(sig, message)

    loaded_priv_enc = crypto.load_encryption_private_key(priv_enc)
    loaded_pub_enc = crypto.load_encryption_public_key(pub_enc)
    shared = loaded_priv_enc.exchange(loaded_pub_enc)  # self-exchange for check
    assert isinstance(shared, bytes)


def test_sign_and_verify_roundtrip():
    heading("test_sign_and_verify_roundtrip", color=GREEN)
    priv_pem, pub_pem = crypto.generate_signing_keypair()
    message = b"important message"
    sig = crypto.sign(priv_pem, message)
    assert crypto.verify(pub_pem, message, sig) is True
    # Tampered message should not verify
    assert crypto.verify(pub_pem, message + b"!", sig) is False


def test_encrypt_decrypt_aes_gcm():
    heading("test_encrypt_decrypt_aes_gcm", color=GREEN)
    key = crypto.hash_bytes(b"key-material")  # derive deterministic key for test
    plaintext = b"confidential payload"
    associated = b"aad"
    ciphertext, tag, nonce = crypto.encrypt_aes_gcm(key, plaintext, associated_data=associated)
    recovered = crypto.decrypt_aes_gcm(key, ciphertext, tag, nonce, associated_data=associated)
    assert recovered == plaintext
    # Wrong AAD should fail authentication
    with pytest.raises(Exception):
        crypto.decrypt_aes_gcm(key, ciphertext, tag, nonce, associated_data=b"wrong")


def test_wrap_and_unwrap_key():
    heading("test_wrap_and_unwrap_key", color=GREEN)
    priv_a, pub_a = crypto.generate_encryption_keypair()
    priv_b, pub_b = crypto.generate_encryption_keypair()
    symmetric_key = b"symmetric-key-32bytes-len-1234"

    wrapped_for_b = crypto.wrap_key(pub_b, symmetric_key)
    recovered = crypto.unwrap_key(priv_b, wrapped_for_b)
    assert recovered == symmetric_key

    # Using the wrong private key should fail
    with pytest.raises(Exception):
        crypto.unwrap_key(priv_a, wrapped_for_b)


def test_hash_bytes_deterministic():
    heading("test_hash_bytes_deterministic", color=YELLOW)
    data = b"same data"
    h1 = crypto.hash_bytes(data)
    h2 = crypto.hash_bytes(data)
    assert h1 == h2


def test_wrap_payload_structure():
    heading("test_wrap_payload_structure", color=CYAN)
    _, pub_b = crypto.generate_encryption_keypair()
    symmetric_key = b"32-bytes-key-for-wrap----"
    wrapped = crypto.wrap_key(pub_b, symmetric_key)
    payload = json.loads(wrapped.decode("utf-8"))
    assert set(payload.keys()) == {"ephemeral_public", "nonce", "ciphertext"}
    # Ensure fields are valid base64
    crypto.b64d(payload["ephemeral_public"])
    crypto.b64d(payload["nonce"])
    crypto.b64d(payload["ciphertext"])


if __name__ == "__main__":
    # Running as a script shows verbose pytest output in the terminal.
    raise SystemExit(pytest.main([__file__, "-vv", "-s", "--capture=no"]))
