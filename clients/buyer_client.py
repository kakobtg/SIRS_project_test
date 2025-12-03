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
    buyer_keys = ensure_company(args.buyer, args.keys_dir)
    seller_keys = ensure_company(args.seller, args.keys_dir)
    register_company(args.server, args.buyer, args.keys_dir)

    res = requests.get(f"{args.server}/transactions/{args.tx_id}", timeout=5)
    if res.status_code != 200:
        raise SystemExit(f"Could not fetch transaction: {res.text}")
    tx = res.json()

    check_result = library.check(
        tx,
        seller_public_signing=seller_keys["signing_public"],
        buyer_public_signing=buyer_keys["signing_public"],
    )
    print("Check result:", json.dumps(check_result, indent=2))

    plaintext = library.unprotect(tx, buyer_keys, company_name=args.buyer)
    Path(args.output_plain).write_text(json.dumps(plaintext, indent=2))
    print(f"Plaintext written to {args.output_plain}")

    signed = library.buyer_sign(tx, buyer_keys, seller_keys["signing_public"])
    Path(args.output_protected).write_text(json.dumps(signed, indent=2))

    res = requests.post(f"{args.server}/transactions/{args.tx_id}/buyer_sign", json={"sig_buyer": signed["sig_buyer"]}, timeout=5)
    if res.status_code != 200:
        print(f"Failed to push buyer signature: {res.text}")
    else:
        print(f"Buyer signature stored for tx {args.tx_id}")

    if args.share_with:
        to_keys = ensure_company(args.share_with, args.keys_dir)
        register_company(args.server, args.share_with, args.keys_dir)
        share_record = library.create_share_record(
            signed,
            from_company_keys=buyer_keys,
            to_company_name=args.share_with,
            to_company_public_enc=to_keys["encryption_public"],
            from_company_name=args.buyer,
        )
        Path(args.share_output).write_text(json.dumps(share_record, indent=2))
        res = requests.post(f"{args.server}/transactions/{args.tx_id}/share", json=share_record, timeout=5)
        if res.status_code != 200:
            print(f"Failed to push share: {res.text}")
        else:
            print(f"Share stored for tx {args.tx_id}")


def main():
    parser = argparse.ArgumentParser(description="Buyer workflow client")
    parser.add_argument("tx_id", help="Transaction id to fetch")
    parser.add_argument("--seller", default="seller", help="Seller company name")
    parser.add_argument("--buyer", default="buyer", help="Buyer company name")
    parser.add_argument("--server", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--output-plain", default="buyer_plain.json", help="Where to store plaintext")
    parser.add_argument("--output-protected", default="buyer_signed.json", help="Where to store updated protected transaction")
    parser.add_argument("--share-with", help="Third party to share with")
    parser.add_argument("--share-output", default="share_record.json", help="Where to store share record JSON")
    parser.add_argument("--keys-dir", default="keys", help="Directory for keys")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
