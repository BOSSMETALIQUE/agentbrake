"""AgentBrake command line: keygen, export, and standalone receipt verification.

The ``verify`` subcommand is the point of the whole receipt system: it runs on
an auditor's machine, takes an export bundle produced by AgentBrake, and
confirms — using only the public key — that every receipt is authentic and the
chain is intact. It never talks to a server and holds no private material, so
its verdict does not depend on trusting the operator.

Output is deliberately ASCII-only (Windows consoles included) and ends with an
explicit statement of what the verification does and does not prove. Exit code
0 means verified, 1 means verification failed, 2 means usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from agentbrake import export as export_mod
from agentbrake import signing

PROG = "agentbrake"


# ----- keygen ---------------------------------------------------------------

def _cmd_keygen(args: argparse.Namespace) -> int:
    target = Path(args.out).expanduser()
    if target.exists():
        print(f"error: {target} already exists — refusing to overwrite a key", file=sys.stderr)
        return 2
    signer = signing.Ed25519Signer.generate()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(signer.private_pem())
    try:  # best effort; not available on Windows filesystems
        target.chmod(0o600)
    except OSError:
        pass
    print(f"Ed25519 keypair generated. Private key: {target}")
    print("KEEP THE PRIVATE KEY SECRET. Configure signing with:")
    print(f"    {signing.SIGNING_KEY_FILE_ENV}={target}")
    print()
    print("Share ONLY the public half with verifiers (out-of-band):")
    print(f"    public key: {signer.public_key_hex()}")
    print(f"    key_id:     {signer.key_id}")
    return 0


# ----- export ----------------------------------------------------------------

def _cmd_export(args: argparse.Namespace) -> int:
    if args.receipts:
        rows = export_mod.rows_from_jsonl(args.receipts)
        source = args.receipts
    else:
        rows = export_mod.rows_from_db(args.db)
        source = args.db

    signer, key_source = signing.resolve_signer_from_env()
    if key_source == "generated":
        # A freshly generated key did not sign these receipts and its head
        # signature would be meaningless to any verifier. Export honest:
        # unsigned head, and say so.
        signer = None
        print(
            "warning: no signing key configured "
            f"(set {signing.SIGNING_SEED_ENV} or {signing.SIGNING_KEY_FILE_ENV}); "
            "the chain head will be exported UNSIGNED.",
            file=sys.stderr,
        )

    extra_keys: Dict[str, str] = {}
    for public_key_hex in args.public_key or []:
        verifier = signing.Ed25519Verifier(public_key_hex)
        extra_keys[verifier.key_id] = verifier.public_key_hex()

    bundle = export_mod.build_export(rows, signer=signer, extra_public_keys=extra_keys)
    target = export_mod.write_export(bundle, args.out)
    print(f"Exported {len(bundle['entries'])} receipt(s) from {source} to {target}")
    statement = bundle["head"]["statement"]
    print(f"Chain head: length={statement['length']} hash={statement['head_hash']}")
    if bundle["head"]["signature"] is None:
        print("Head: UNSIGNED (no key material available at export time)")
    else:
        print(f"Head: signed ({statement['alg']}, key_id {statement['key_id']})")
    return 0


# ----- verify ----------------------------------------------------------------

def _parse_expected_head(value: str) -> Tuple[int, str]:
    try:
        length_part, hash_part = value.split(":", 1)
        return int(length_part), hash_part.strip().lower()
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            "--expect-head takes LENGTH:HEAD_HASH, e.g. 12:9c41ab..."
        ) from e


def _trust_model_lines(report: dict) -> list:
    """Say exactly what a passing verification proves — and what it doesn't."""
    key_ids = ", ".join(report["public_keys"]) or "(none)"
    committed = report.get("head", {}).get("length", report["entry_count"])
    single_receipt = report["entry_count"] == 1 and committed != 1
    lines = ["What this verification PROVES:"]
    if report["third_party_verifiable"]:
        lines += [
            f"  + Every receipt was signed by the holder of private key(s) [{key_ids}]",
            "    and is byte-for-byte unmodified. No one without that private key",
            "    (including the verifier) could have produced these records.",
        ]
        if single_receipt:
            lines += [
                "  + The receipt provably sits at its signed position in the log,",
                "    without any other entry being disclosed (Merkle inclusion).",
            ]
        else:
            lines += [
                "  + The sequence is complete and ordered as signed: nothing was",
                "    inserted, deleted, or reordered inside this export.",
            ]
        lines += [
            f"  + The signed head commits the exporter to exactly "
            f"{committed} receipt(s); a future export of this chain",
            "    with fewer entries contradicts a commitment they already signed.",
        ]
    else:
        lines += [
            "  + The records are internally consistent (hash chain intact).",
            "  ! NOT third-party proof: HMAC receipts (or an unsigned head) can be",
            "    (re)produced by anyone holding the shared secret, including the",
            "    verifier. Treat this as an integrity self-check only.",
        ]
    lines += [
        "What it does NOT prove:",
        "  - That the key holder never regenerated the whole history before this",
        "    export was anchored. Pin each export's head (--expect-head) or store",
        "    heads with a party the operator cannot rewrite.",
        "  - That timestamps are accurate: they come from the signer's own clock.",
    ]
    if report["keys_pinned"]:
        lines.append("  * Public key(s) were PINNED by you -- key substitution is excluded.")
    else:
        lines += [
            "  - That the embedded public key belongs to who you think it does.",
            "    Compare the key_id above with one obtained out-of-band, or pass",
            "    --public-key to pin the key you trust.",
        ]
    return lines


def _ascii(text: str) -> str:
    """Console-safe output: Windows terminals often choke on cp1252 gaps."""
    return text.replace("—", "--").replace("…", "...")


class _UsageError(Exception):
    """Bad input on the command line or an unreadable file; exit code 2."""


def _load_json(path_str: str, what: str) -> dict:
    try:
        return json.loads(Path(path_str).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise _UsageError(f"cannot read {what} {path_str}: {e}") from e


def _pinned_keys(args: argparse.Namespace) -> Optional[Dict[str, str]]:
    """The pinned-keys map from --public-key flags, or None when unpinned."""
    if not args.public_key:
        return None
    pinned: Dict[str, str] = {}
    for public_key_hex in args.public_key:
        try:
            verifier = signing.Ed25519Verifier(public_key_hex)
        except ValueError as e:
            raise _UsageError(f"bad --public-key: {e}") from e
        pinned[verifier.key_id] = verifier.public_key_hex()
    return pinned


def _cmd_verify(args: argparse.Namespace) -> int:
    bundle = _load_json(args.bundle, "bundle")
    pinned = _pinned_keys(args)

    consistent_with = None
    if getattr(args, "consistent_with", None):
        consistent_with = _load_json(args.consistent_with, "older bundle")

    hmac_key = args.hmac_key.encode("utf-8") if args.hmac_key else None

    report = export_mod.verify_export(
        bundle,
        pinned_public_keys=pinned,
        hmac_key=hmac_key,
        expected_head=args.expect_head,
        consistent_with=consistent_with,
    )
    return _print_report(report, args.bundle, as_json=args.json)


def _print_report(report: dict, path: str, *, as_json: bool) -> int:
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["ok"] else 1

    print(f"AgentBrake receipt verification: {path}")
    print(
        f"  entries: {report['entry_count']}   chain_id: {report['chain_id']}   "
        f"algorithms: {', '.join(report['algorithms']) or '(empty chain)'}"
    )
    key_note = "PINNED by verifier" if report["keys_pinned"] else "embedded in bundle -- compare out-of-band"
    print(f"  trusted key_id(s): {', '.join(report['public_keys']) or '(none)'}  [{key_note}]")
    print()
    for chk in report["checks"]:
        verdict = "PASS" if chk["ok"] else "FAIL"
        print(f"  [{verdict}] {chk['name']}: {_ascii(chk['detail'])}")
    print()
    for line in _trust_model_lines(report):
        print(line)
    print()
    verdict = "VERIFIED" if report["ok"] else "VERIFICATION FAILED"
    print(f"Verdict: {verdict}")
    return 0 if report["ok"] else 1


# ----- prove / verify-receipt (selective disclosure) ---------------------------

def _cmd_prove(args: argparse.Namespace) -> int:
    if args.receipts:
        rows = export_mod.rows_from_jsonl(args.receipts)
    else:
        rows = export_mod.rows_from_db(args.db)

    signer, key_source = signing.resolve_signer_from_env()
    if key_source == "generated":
        signer = None
        print(
            "warning: no signing key configured; the head in this proof will be "
            "UNSIGNED and carries no commitment.",
            file=sys.stderr,
        )

    try:
        proof = export_mod.build_receipt_proof(rows, args.seq, signer=signer)
    except ValueError as e:
        raise _UsageError(str(e)) from e

    target = export_mod.write_export(proof, args.out)
    statement = proof["head"]["statement"]
    print(f"Inclusion proof for receipt seq={args.seq} written to {target}")
    print(
        f"Proves membership at position {proof['leaf_index']} of a log of "
        f"{statement['tree_size']} (root {statement['tree_root'][:16]}..) "
        "without disclosing any other receipt."
    )
    return 0


def _cmd_verify_receipt(args: argparse.Namespace) -> int:
    proof = _load_json(args.proof, "receipt proof")
    pinned = _pinned_keys(args)
    hmac_key = args.hmac_key.encode("utf-8") if args.hmac_key else None
    report = export_mod.verify_receipt_proof(
        proof, pinned_public_keys=pinned, hmac_key=hmac_key
    )
    return _print_report(report, args.proof, as_json=args.json)


# ----- report -------------------------------------------------------------------

def _parse_date(value: str) -> "datetime":
    from datetime import datetime, timezone

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"{value!r} is not an ISO date (e.g. 2026-07-01 or 2026-07-01T00:00:00+00:00)"
        ) from e
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _cmd_report(args: argparse.Namespace) -> int:
    from agentbrake import report as report_mod

    bundle = _load_json(args.bundle, "bundle")
    pinned = _pinned_keys(args)
    hmac_key = args.hmac_key.encode("utf-8") if args.hmac_key else None

    verification = export_mod.verify_export(
        bundle, pinned_public_keys=pinned, hmac_key=hmac_key
    )
    report = report_mod.build_report(
        bundle,
        verification,
        period_start=getattr(args, "from"),
        period_end=args.to,
        source_name=str(args.bundle),
    )
    document = report_mod.render_markdown(report)

    Path(args.out).expanduser().write_text(document, encoding="utf-8")
    verdict = "VERIFIED" if verification["ok"] else "VERIFICATION FAILED"
    print(f"Compliance report written to {args.out} (evidence: {verdict})")
    print(
        f"  {report['events_in_period']} event(s) in period: "
        f"{report['summary']['autonomous_blocks']} autonomous block(s), "
        f"{report['summary']['human_kills']} human kill(s), "
        f"{report['summary']['human_approvals']} human approval(s)"
    )
    return 0 if verification["ok"] else 1


# ----- entry point ------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="AgentBrake receipts: generate keys, export chains, verify bundles.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    keygen.add_argument(
        "-o", "--out", default="agentbrake_key.pem", help="private key PEM path"
    )
    keygen.set_defaults(func=_cmd_keygen)

    export_cmd = sub.add_parser("export", help="export a receipt chain to a bundle")
    src = export_cmd.add_mutually_exclusive_group(required=True)
    src.add_argument("--receipts", help="path to a receipts.jsonl ledger")
    src.add_argument("--db", help="path to a server agentbrake.db")
    export_cmd.add_argument("-o", "--out", default="receipts_export.json")
    export_cmd.add_argument(
        "--public-key",
        action="append",
        help="extra public key (hex) to embed, e.g. a rotated-out key",
    )
    export_cmd.set_defaults(func=_cmd_export)

    verify = sub.add_parser(
        "verify", help="verify an export bundle offline (no server, no private key)"
    )
    verify.add_argument("bundle", help="path to the export bundle JSON")
    verify.add_argument(
        "--public-key",
        action="append",
        help="pin the trusted public key(s) (hex); embedded keys are then ignored",
    )
    verify.add_argument(
        "--hmac-key", help="shared secret for legacy HMAC receipts (integrity-only)"
    )
    verify.add_argument(
        "--expect-head",
        type=_parse_expected_head,
        help="LENGTH:HEAD_HASH from a previously pinned export; detects rollback",
    )
    verify.add_argument(
        "--consistent-with",
        help="path to an OLDER bundle of the same chain; verifies it is an "
        "exact prefix of this one (Merkle-root recomputation)",
    )
    verify.add_argument("--json", action="store_true", help="machine-readable report")
    verify.set_defaults(func=_cmd_verify)

    prove = sub.add_parser(
        "prove",
        help="extract ONE receipt with an inclusion proof (selective disclosure)",
    )
    src = prove.add_mutually_exclusive_group(required=True)
    src.add_argument("--receipts", help="path to a receipts.jsonl ledger")
    src.add_argument("--db", help="path to a server agentbrake.db")
    prove.add_argument("--seq", type=int, required=True, help="receipt sequence number")
    prove.add_argument("-o", "--out", default="receipt_proof.json")
    prove.set_defaults(func=_cmd_prove)

    verify_receipt = sub.add_parser(
        "verify-receipt",
        help="verify a single-receipt proof offline (no log, no server)",
    )
    verify_receipt.add_argument("proof", help="path to the receipt proof JSON")
    verify_receipt.add_argument(
        "--public-key",
        action="append",
        help="pin the trusted public key(s) (hex); embedded keys are then ignored",
    )
    verify_receipt.add_argument(
        "--hmac-key", help="shared secret for legacy HMAC receipts (integrity-only)"
    )
    verify_receipt.add_argument("--json", action="store_true", help="machine-readable report")
    verify_receipt.set_defaults(func=_cmd_verify_receipt)

    report = sub.add_parser(
        "report",
        help="generate an auditor-readable compliance report from a bundle",
    )
    report.add_argument("bundle", help="path to the export bundle JSON")
    report.add_argument("-o", "--out", default="compliance_report.md")
    report.add_argument(
        "--public-key",
        action="append",
        help="pin the trusted public key(s) (hex) for the embedded verification",
    )
    report.add_argument(
        "--hmac-key", help="shared secret for legacy HMAC receipts (integrity-only)"
    )
    report.add_argument(
        "--from", type=_parse_date, default=None, dest="from",
        help="period start (ISO date)",
    )
    report.add_argument(
        "--to", type=_parse_date, default=None, help="period end (ISO date)"
    )
    report.set_defaults(func=_cmd_report)

    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except _UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
