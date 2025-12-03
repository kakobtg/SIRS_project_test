import json
import os
from pathlib import Path
from typing import Dict

from . import crypto


DEFAULT_KEYS_DIR = Path("keys")


def _ensure_dir(base_dir: Path) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)


def _serialize_keypair(priv: bytes, pub: bytes) -> Dict[str, str]:
    return {"private": crypto.b64e(priv), "public": crypto.b64e(pub)}


def generate_dummy_company(name: str, base_dir: Path | str = DEFAULT_KEYS_DIR) -> Dict[str, str]:
    """
    Generate signing and encryption keys for a dummy company.
    Keys are stored as PEM blobs base64-encoded in JSON.
    """
    base_dir = Path(base_dir)
    _ensure_dir(base_dir)
    signing_priv, signing_pub = crypto.generate_signing_keypair()
    enc_priv, enc_pub = crypto.generate_encryption_keypair()
    data = {
        "name": name,
        "signing": _serialize_keypair(signing_priv, signing_pub),
        "encryption": _serialize_keypair(enc_priv, enc_pub),
    }
    out_path = base_dir / f"{name}.json"
    out_path.write_text(json.dumps(data, indent=2))
    return data


def load_company_keys(name: str, base_dir: Path | str = DEFAULT_KEYS_DIR) -> Dict[str, bytes]:
    """
    Load keys for a company.
    Returns dictionary with PEM bytes for signing/encryption keys.
    """
    base_dir = Path(base_dir)
    path = base_dir / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"No keys for {name} in {path}")
    raw = json.loads(path.read_text())
    return {
        "name": raw["name"],
        "signing_private": crypto.b64d(raw["signing"]["private"]),
        "signing_public": crypto.b64d(raw["signing"]["public"]),
        "encryption_private": crypto.b64d(raw["encryption"]["private"]),
        "encryption_public": crypto.b64d(raw["encryption"]["public"]),
    }


def list_companies(base_dir: Path | str = DEFAULT_KEYS_DIR) -> list[str]:
    base_dir = Path(base_dir)
    if not base_dir.exists():
        return []
    return [p.stem for p in base_dir.glob("*.json")]


def save_company_keys(name: str, data: Dict[str, bytes], base_dir: Path | str = DEFAULT_KEYS_DIR) -> None:
    """
    Save provided PEM key material for a company to disk.
    """
    base_dir = Path(base_dir)
    _ensure_dir(base_dir)
    payload = {
        "name": name,
        "signing": _serialize_keypair(data["signing_private"], data["signing_public"]),
        "encryption": _serialize_keypair(data["encryption_private"], data["encryption_public"]),
    }
    (base_dir / f"{name}.json").write_text(json.dumps(payload, indent=2))
