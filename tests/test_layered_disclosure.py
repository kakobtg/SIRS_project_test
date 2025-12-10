import importlib
import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure project root on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainofproduct import keymanager, library  # noqa: E402


def _doc():
    return {
        "id": "tx-layer-1",
        "product": "Palladium",
        "amount": 1200000,
        "units": 5000,
        "route": "SEA->SFO",
        "warehouse": "WH-22",
        "timestamp": 999999,
    }


def test_selective_layers_allow_partial_disclosure():
    with tempfile.TemporaryDirectory() as tmp:
        seller = keymanager.generate_dummy_company("seller", base_dir=tmp)
        buyer = keymanager.generate_dummy_company("buyer", base_dir=tmp)
        auditor = keymanager.generate_dummy_company("auditor", base_dir=tmp)
        seller = keymanager.load_company_keys("seller", base_dir=tmp)
        buyer = keymanager.load_company_keys("buyer", base_dir=tmp)
        auditor = keymanager.load_company_keys("auditor", base_dir=tmp)

        doc = _doc()
        layers = {"pricing": ["product", "amount", "units"], "logistics": ["route", "warehouse"]}
        protected = library.protect_with_layers(doc, seller_keys=seller, buyer_keys=buyer, layers=layers)

        assert set(protected["layers"].keys()) == set(layers.keys())

        # Seller can open a layer directly.
        pricing_plain = library.unprotect_layer(protected, seller, company_name="seller", section="pricing")
        assert pricing_plain["amount"] == doc["amount"]

        # Share only pricing with auditor.
        share_records = library.create_layer_share_records(
            protected,
            sections=["pricing"],
            from_company_keys=buyer,
            to_company_name="auditor",
            to_company_public_enc=auditor["encryption_public"],
            from_company_name="buyer",
        )
        share = share_records[0]
        auditor_plain = library.unprotect_layer(
            protected,
            auditor,
            company_name="auditor",
            section="pricing",
            share_record=share,
        )
        assert auditor_plain == pricing_plain

        # Auditor cannot open undisclosed sections.
        with pytest.raises(KeyError):
            library.unprotect_layer(
                protected,
                auditor,
                company_name="auditor",
                section="logistics",
                share_record=share,
            )

        checks = library.check(
            protected,
            seller_public_signing=seller["signing_public"],
            buyer_public_signing=buyer["signing_public"],
            share_records=share_records,
            share_public_keys={"buyer": buyer["signing_public"]},
        )
        assert checks["shares"][0]["valid"] is True
        assert checks["shares"][0]["layer_hash_ok"] is True


def test_disclosure_server_tracks_section_shares(tmp_path, monkeypatch):
    # Point disclosure service to an isolated test DB before import.
    db_path = tmp_path / "disclosures.db"
    monkeypatch.setenv("COP_DISCLOSURE_DB_URL", f"sqlite:///{db_path}")
    from disclosure_service import db as disclosure_db  # noqa: WPS433

    importlib.reload(disclosure_db)
    from disclosure_service import main as disclosure_main  # noqa: WPS433

    importlib.reload(disclosure_main)

    payload = {
        "id": "share-1",
        "tx_id": "tx-layer-1",
        "section": "pricing",
        "from_company": "buyer",
        "to_company": "auditor",
        "ek_to": "wrapped-key",
        "timestamp": "2024-01-01T00:00:00Z",
        "layer_hash": "abc",
        "sig_share": "sig",
    }

    with TestClient(disclosure_main.app) as client:
        res = client.post("/disclosures", json=payload)
        assert res.status_code == 200
        res = client.get(f"/disclosures/{payload['tx_id']}")
        body = res.json()
        assert len(body) == 1
        assert body[0]["section"] == "pricing"
        res = client.get(f"/disclosures/{payload['tx_id']}?section=pricing")
        assert len(res.json()) == 1
        res = client.get(f"/disclosures/{payload['tx_id']}?section=logistics")
        assert res.json() == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-vv", "-s", "--capture=no"]))
