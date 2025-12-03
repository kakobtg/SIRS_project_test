import sys
from pathlib import Path
import tempfile

import pytest

# Ensure project root on sys.path for direct execution.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainofproduct import keymanager  # noqa: E402


def test_generate_load_and_list():
    with tempfile.TemporaryDirectory() as tmp:
        data = keymanager.generate_dummy_company("acme", base_dir=tmp)
        assert data["name"] == "acme"
        keys = keymanager.load_company_keys("acme", base_dir=tmp)
        assert "signing_private" in keys and "encryption_public" in keys
        companies = keymanager.list_companies(base_dir=tmp)
        assert "acme" in companies


def test_save_company_keys_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        # Generate keys for source, then save under new name.
        orig = keymanager.generate_dummy_company("source", base_dir=tmp)
        keys = keymanager.load_company_keys("source", base_dir=tmp)
        keymanager.save_company_keys("copy", keys, base_dir=tmp)
        loaded_copy = keymanager.load_company_keys("copy", base_dir=tmp)
        assert loaded_copy["signing_private"] == keys["signing_private"]
        assert loaded_copy["encryption_public"] == keys["encryption_public"]


def test_missing_company_raises():
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(FileNotFoundError):
            keymanager.load_company_keys("missing", base_dir=tmp)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-vv", "-s", "--capture=no"]))
