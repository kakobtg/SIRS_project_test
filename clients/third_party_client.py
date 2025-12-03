import argparse
import json
from pathlib import Path

import requests

from chainofproduct import keymanager, library


def ensure_company(name: str, keys_dir: str):
    path = Path(keys_dir) / f"{name}.json"
    if not path.exists():
        keymanager.generate_dummy_company(name, base_dir=keys_dir)
    return keymanager.load_company_keys(name, base_dir=keys_dir)


def register_company(base_url: str, name: str, keys_dir: str):
    keys = keymanager.load_company_keys(name, base_dir=keys_dir)
    payload = {
        "name": name,
        "signing_public": keymanager.crypto.b64e(keys["signing_public"]),
        "encryption_public": keymanager.crypto.b64e(keys["encryption_public"]),
    }
    try:
        res = requests.post(f"{base_url}/register_company", json=payload, timeout=5)
        if res.status_code not in (200, 400):
            print(f"Register company failed: {res.text}")
    except Exception as exc:  # pragma: no cover
        print(f"Warning: could not register company {name}: {exc}")


def run(args):
    company_keys = ensure_company(args.company, args.keys_dir)
    seller_keys = ensure_company(args.seller, args.keys_dir)
    buyer_keys = ensure_company(args.buyer, args.keys_dir)
    register_company(args.server, args.company, args.keys_dir)

    tx_res = requests.get(f"{args.server}/transactions/{args.tx_id}", timeout=5)
    if tx_res.status_code != 200:
        raise SystemExit(f"Could not fetch transaction: {tx_res.text}")
    tx = tx_res.json()

    shares_res = requests.get(f"{args.server}/transactions/{args.tx_id}/shares", timeout=5)
    if shares_res.status_code != 200:
        raise SystemExit(f"Could not fetch shares: {shares_res.text}")
    shares = shares_res.json()
    share_for_me = next((s for s in shares if s["to_company"] == args.company), None)
    if not share_for_me:
        raise SystemExit("No share record for this company.")

    check_result = library.check(
        tx,
        seller_public_signing=seller_keys["signing_public"],
        buyer_public_signing=buyer_keys["signing_public"],
        share_records=[share_for_me],
        share_public_keys={
            seller_keys["name"]: seller_keys["signing_public"],
            buyer_keys["name"]: buyer_keys["signing_public"],
        },
    )
    print("Check result:", json.dumps(check_result, indent=2))

    plaintext = library.unprotect(tx, company_keys, company_name=args.company, share_record=share_for_me)
    Path(args.output_plain).write_text(json.dumps(plaintext, indent=2))
    print(f"Plaintext written to {args.output_plain}")


def main():
    parser = argparse.ArgumentParser(description="Third-party client workflow")
    parser.add_argument("tx_id", help="Transaction id to fetch")
    parser.add_argument("--company", default="auditor", help="This third-party company name")
    parser.add_argument("--seller", default="seller", help="Seller company name")
    parser.add_argument("--buyer", default="buyer", help="Buyer company name")
    parser.add_argument("--server", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--output-plain", default="auditor_plain.json", help="Where to store plaintext")
    parser.add_argument("--keys-dir", default="keys", help="Directory for keys")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
