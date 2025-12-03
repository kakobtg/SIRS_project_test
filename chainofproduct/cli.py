import argparse
import json
import sys
from pathlib import Path

from . import keymanager, library


def _load_json(path: Path):
    return json.loads(path.read_text())


def _write_json(path: Path, data):
    path.write_text(json.dumps(data, indent=2))


def cmd_generate_keys(args):
    data = keymanager.generate_dummy_company(args.name, base_dir=args.keys_dir)
    print(f"Generated keys for {data['name']} in {args.keys_dir}")


def cmd_protect(args):
    doc = _load_json(Path(args.input))
    seller_keys = keymanager.load_company_keys(args.seller, base_dir=args.keys_dir)
    buyer_keys = keymanager.load_company_keys(args.buyer, base_dir=args.keys_dir)
    protected = library.protect(doc, seller_keys, buyer_keys)
    _write_json(Path(args.output), protected)
    print(f"Protected transaction stored at {args.output}")


def cmd_buyer_sign(args):
    tx = _load_json(Path(args.input))
    buyer_keys = keymanager.load_company_keys(args.buyer, base_dir=args.keys_dir)
    seller_keys = keymanager.load_company_keys(args.seller, base_dir=args.keys_dir)
    signed = library.buyer_sign(tx, buyer_keys, seller_keys["signing_public"])
    _write_json(Path(args.output), signed)
    print(f"Buyer signature added and written to {args.output}")


def cmd_check(args):
    tx = _load_json(Path(args.input))
    seller_keys = keymanager.load_company_keys(args.seller, base_dir=args.keys_dir)
    buyer_keys = None
    if args.buyer:
        buyer_keys = keymanager.load_company_keys(args.buyer, base_dir=args.keys_dir)
    share_records = None
    share_pub_keys = None
    if args.shares:
        share_records = _load_json(Path(args.shares))
        if isinstance(share_records, dict):
            share_records = [share_records]
    if args.share_companies:
        share_pub_keys = {}
        for name in args.share_companies:
            k = keymanager.load_company_keys(name, base_dir=args.keys_dir)
            share_pub_keys[name] = k["signing_public"]
    result = library.check(
        tx,
        seller_public_signing=seller_keys["signing_public"],
        buyer_public_signing=buyer_keys["signing_public"] if buyer_keys else None,
        share_records=share_records,
        share_public_keys=share_pub_keys,
    )
    print(json.dumps(result, indent=2))


def cmd_unprotect(args):
    tx = _load_json(Path(args.input))
    company_keys = keymanager.load_company_keys(args.company, base_dir=args.keys_dir)
    share_record = _load_json(Path(args.share)) if args.share else None
    plaintext = library.unprotect(tx, company_keys, company_name=args.company, share_record=share_record)
    _write_json(Path(args.output), plaintext)
    print(f"Decrypted transaction written to {args.output}")


def cmd_share(args):
    tx = _load_json(Path(args.input))
    from_keys = keymanager.load_company_keys(args.from_company, base_dir=args.keys_dir)
    to_keys = keymanager.load_company_keys(args.to_company, base_dir=args.keys_dir)
    share_record = library.create_share_record(
        tx,
        from_company_keys=from_keys,
        to_company_name=args.to_company,
        to_company_public_enc=to_keys["encryption_public"],
        from_company_name=args.from_company,
    )
    _write_json(Path(args.output), share_record)
    print(f"Share record saved to {args.output}")


def build_parser():
    parser = argparse.ArgumentParser(prog="cop", description="ChainOfProduct CLI prototype")
    parser.add_argument("--keys-dir", default="keys", help="Directory for dummy key files")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate-keys", help="Generate dummy keys for a company")
    p_gen.add_argument("name")
    p_gen.set_defaults(func=cmd_generate_keys)

    p_protect = sub.add_parser("protect", help="Protect a plaintext transaction")
    p_protect.add_argument("input", help="Path to plaintext JSON transaction")
    p_protect.add_argument("seller", help="Seller company name (keys must exist)")
    p_protect.add_argument("buyer", help="Buyer company name (keys must exist)")
    p_protect.add_argument("output", help="Path to write protected document")
    p_protect.set_defaults(func=cmd_protect)

    p_sign = sub.add_parser("buyer-sign", help="Buyer adds signature to protected transaction")
    p_sign.add_argument("input", help="Path to protected JSON transaction")
    p_sign.add_argument("seller", help="Seller company name (for signature verification)")
    p_sign.add_argument("buyer", help="Buyer company name (keys must exist)")
    p_sign.add_argument("output", help="Path to write updated protected transaction")
    p_sign.set_defaults(func=cmd_buyer_sign)

    p_check = sub.add_parser("check", help="Verify protected transaction and optional shares")
    p_check.add_argument("input", help="Path to protected transaction JSON")
    p_check.add_argument("seller", help="Seller company name")
    p_check.add_argument("--buyer", help="Buyer company name (to verify buyer signature)")
    p_check.add_argument("--shares", help="Path to JSON share record or list of records")
    p_check.add_argument("--share-companies", nargs="*", help="Company names to load public signing keys for share verification")
    p_check.set_defaults(func=cmd_check)

    p_unp = sub.add_parser("unprotect", help="Decrypt a protected transaction")
    p_unp.add_argument("input", help="Path to protected transaction JSON")
    p_unp.add_argument("company", help="Company name whose keys will be used")
    p_unp.add_argument("output", help="Path to write plaintext JSON")
    p_unp.add_argument("--share", help="Path to share record JSON when decrypting as third party")
    p_unp.set_defaults(func=cmd_unprotect)

    p_share = sub.add_parser("share", help="Create a ShareRecord to disclose to another party")
    p_share.add_argument("input", help="Path to protected transaction JSON")
    p_share.add_argument("from_company", help="Company creating the share")
    p_share.add_argument("to_company", help="Recipient company")
    p_share.add_argument("output", help="Path to write share record JSON")
    p_share.set_defaults(func=cmd_share)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
