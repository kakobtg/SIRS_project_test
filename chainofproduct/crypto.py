import base64
import json
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64e(data: bytes) -> str:
    """URL-safe base64 encoding without newlines."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """URL-safe base64 decoding from string."""
    return base64.urlsafe_b64decode(data.encode("ascii"))


def generate_signing_keypair() -> Tuple[bytes, bytes]:
    """Generate an Ed25519 signing keypair (private PEM, public PEM)."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def generate_encryption_keypair() -> Tuple[bytes, bytes]:
    """Generate an X25519 keypair for key agreement (private PEM, public PEM)."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def load_signing_private_key(pem: bytes) -> ed25519.Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def load_signing_public_key(pem: bytes) -> ed25519.Ed25519PublicKey:
    return serialization.load_pem_public_key(pem)


def load_encryption_private_key(pem: bytes) -> x25519.X25519PrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def load_encryption_public_key(pem: bytes) -> x25519.X25519PublicKey:
    return serialization.load_pem_public_key(pem)


def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> Tuple[bytes, bytes, bytes]:
    """Encrypt using AES-GCM. Returns (ciphertext, tag, nonce)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return ciphertext, tag, nonce


def decrypt_aes_gcm(key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes, associated_data: bytes | None = None) -> bytes:
    """Decrypt using AES-GCM and verify tag."""
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_with_tag, associated_data)


def _derive_wrap_key(shared_secret: bytes) -> bytes:
    """Derive a symmetric key for wrapping using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cop-key-wrap",
    )
    return hkdf.derive(shared_secret)


def wrap_key(recipient_public_pem: bytes, symmetric_key: bytes) -> bytes:
    """
    Wrap a symmetric key for the recipient using X25519 + AES-GCM.
    Returns a JSON blob (bytes) containing ephemeral public key, nonce, ciphertext.
    """
    recipient_pub = load_encryption_public_key(recipient_public_pem)
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    shared = ephemeral_priv.exchange(recipient_pub)
    wrap_key_bytes = _derive_wrap_key(shared)
    nonce = os.urandom(12)
    aesgcm = AESGCM(wrap_key_bytes)
    ct = aesgcm.encrypt(nonce, symmetric_key, None)
    payload = {
        "ephemeral_public": b64e(
            ephemeral_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
    }
    return json.dumps(payload).encode("utf-8")


def unwrap_key(recipient_private_pem: bytes, wrapped: bytes) -> bytes:
    """Recover the symmetric key from a wrapped blob."""
    recipient_priv = load_encryption_private_key(recipient_private_pem)
    payload = json.loads(wrapped.decode("utf-8"))
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(b64d(payload["ephemeral_public"]))
    shared = recipient_priv.exchange(ephemeral_public)
    wrap_key_bytes = _derive_wrap_key(shared)
    nonce = b64d(payload["nonce"])
    ct = b64d(payload["ciphertext"])
    aesgcm = AESGCM(wrap_key_bytes)
    return aesgcm.decrypt(nonce, ct, None)


def sign(private_signing_pem: bytes, message: bytes) -> bytes:
    """Sign a message with Ed25519."""
    priv = load_signing_private_key(private_signing_pem)
    return priv.sign(message)


def verify(public_signing_pem: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature. Returns True when valid, False otherwise."""
    pub = load_signing_public_key(public_signing_pem)
    try:
        pub.verify(signature, message)
        return True
    except Exception:
        return False


def hash_bytes(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
