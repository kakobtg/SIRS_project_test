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
        if res.status_code not in (200, 400):  # already registered -> 400
            print(f"Register company failed: {res.text}")
    except Exception as exc:  # pragma: no cover - network errors
        print(f"Warning: could not register company {name}: {exc}")


def run(args):
    tx = json.loads(Path(args.input).read_text())
    seller_keys = ensure_company(args.seller, args.keys_dir)
    buyer_keys = ensure_company(args.buyer, args.keys_dir)

    register_company(args.server, args.seller, args.keys_dir)
    register_company(args.server, args.buyer, args.keys_dir)

    protected = library.protect(tx, seller_keys, buyer_keys)
    Path(args.output).write_text(json.dumps(protected, indent=2))

    try:
        res = requests.post(f"{args.server}/transactions", json=protected, timeout=5)
        if res.status_code != 200:
            print(f"Server returned {res.status_code}: {res.text}")
        else:
            print(f"Transaction stored on server: {res.json()}")
    except Exception as exc:  # pragma: no cover
        print(f"Warning: could not send to server: {exc}")

    print(f"Protected transaction saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(description="Seller client workflow")
    parser.add_argument("input", help="Path to plaintext DvP JSON")
    parser.add_argument("--seller", default="seller", help="Seller company name")
    parser.add_argument("--buyer", default="buyer", help="Buyer company name")
    parser.add_argument("--server", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--output", default="protected_tx.json", help="Where to store protected transaction")
    parser.add_argument("--keys-dir", default="keys", help="Directory for keys")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
