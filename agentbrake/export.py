"""Self-contained receipt export bundles a third party can verify offline.

The chain endpoints on the server (``/attestations``) let anyone *read* the
receipts, but reading is not verifying: the ``signature_valid`` flag there is
the server grading its own homework. An export bundle removes the server from
the trust equation entirely — it packages, in one JSON document:

* the receipt entries (the exact signed bytes, signatures, and chain hashes),
* the public key(s) needed to check every signature, and
* a **signed chain head**: a statement "this chain has exactly N entries and
  ends at hash H", signed by the same key.

Anyone holding the bundle — an auditor, a customer's CISO — runs
``agentbrake verify bundle.json`` on their own machine and independently
confirms that every receipt is authentic, nothing was altered, inserted,
deleted or reordered, and the export really ends where it claims to.

Why the signed head matters: a hash chain alone cannot reveal that its *tail*
was cut off — any prefix of a valid chain is itself a valid chain. The head
statement is the exporter's signed commitment to the chain's length. Two
exports of the same chain can only grow; an export that shrinks contradicts a
commitment the key holder already signed, and ``--expect-head`` lets a verifier
who pinned an earlier head detect exactly that.

Honest limitations:

* The key holder can still fabricate a *parallel* history and export that
  instead. A bundle proves consistency under a key, not that no other history
  exists. Anchoring heads with the auditor (send them each export's head, or
  publish it) is what closes this; that workflow is the point of
  ``--expect-head``.
* Timestamps inside receipts are self-reported by the signer's clock.
* An HMAC-signed bundle (legacy key) is NOT third-party verifiable — the
  verifier needs the secret, and with the secret they could forge. The
  verifier labels this loudly instead of pretending.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agentbrake import merkle, signing
from agentbrake.server import attest

EXPORT_FORMAT = "agentbrake-receipts-export"
EXPORT_FORMAT_VERSION = "1"
HEAD_STATEMENT_TYPE = "agentbrake.chain-head"
RECEIPT_PROOF_FORMAT = "agentbrake-receipt-proof"
RECEIPT_PROOF_FORMAT_VERSION = "1"

# The head of an empty chain: nothing to point at yet.
EMPTY_HEAD_HASH = attest.GENESIS_HASH

_ENTRY_FIELDS = ("seq", "attestation_json", "signature", "prev_hash", "entry_hash")


def _normalize_entry(row: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce a stored row to the verifiable fields only.

    The parsed ``attestation`` dict is deliberately dropped: the signed bytes
    are ``attestation_json``, and shipping a second, parsed copy invites a
    consumer to trust fields that were never covered by the signature.
    """
    return {field: row[field] for field in _ENTRY_FIELDS}


def _chain_id_of(entries: List[Dict[str, Any]]) -> Optional[str]:
    """The chain_id carried by the entries (None for empty or pure-v1 chains)."""
    for entry in entries:
        chain_id = json.loads(entry["attestation_json"]).get("chain_id")
        if chain_id:
            return chain_id
    return None


# ----- chain head statement ------------------------------------------------

def build_head_statement(
    *,
    chain_id: Optional[str],
    length: int,
    head_hash: str,
    tree_root: str,
    key_id: str,
    alg: str,
    exported_at: Optional[str] = None,
) -> Dict[str, Any]:
    """The exporter's commitment: this chain has ``length`` entries ending at
    ``head_hash``, with RFC 6962 Merkle root ``tree_root``. Signed separately
    from the entries (own domain), so it can be stored, forwarded, or pinned on
    its own. ``tree_size`` always equals ``length``; both are kept because the
    head_hash binds the *chain* form and the tree_root binds the *tree* form
    (which is what single-receipt inclusion proofs verify against)."""
    return {
        "type": HEAD_STATEMENT_TYPE,
        "chain_id": chain_id,
        "length": length,
        "head_hash": head_hash,
        "tree_size": length,
        "tree_root": tree_root,
        "key_id": key_id,
        "alg": alg,
        "exported_at": exported_at or datetime.now(timezone.utc).isoformat(),
    }


def sign_head_statement(statement: Dict[str, Any], signer: signing.Signer) -> str:
    body = attest.canonical_json(statement, strict=True)
    return signer.sign(signing.DOMAIN_CHAIN_HEAD_V1 + body.encode("utf-8"))


def verify_head_statement(
    statement: Dict[str, Any],
    signature: str,
    *,
    public_key_hex: Optional[str] = None,
    hmac_key: Optional[bytes] = None,
) -> bool:
    body = attest.canonical_json(statement, strict=True)
    message = signing.DOMAIN_CHAIN_HEAD_V1 + body.encode("utf-8")
    alg = statement.get("alg")
    if alg == signing.ALG_ED25519:
        if public_key_hex is None:
            return False
        return signing.verify_ed25519(public_key_hex, message, signature)
    if alg == signing.ALG_HMAC_SHA256:
        if hmac_key is None:
            return False
        return signing.HmacSigner(hmac_key).verify(message, signature)
    return False


# ----- building a bundle ----------------------------------------------------

def build_export(
    rows: List[Dict[str, Any]],
    *,
    signer: Optional[signing.Signer] = None,
    extra_public_keys: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Assemble the export bundle for a chain.

    ``signer`` defaults to the process signer (the key that minted the
    receipts, in the normal in-process/server flow) and is used to sign the
    head statement. Pass ``signer=None`` explicitly *and* provide
    ``extra_public_keys`` when exporting on a box that holds receipts but no
    private key — the head is then left unsigned and the verifier will say so.

    ``extra_public_keys`` ({key_id: public_key_hex}) covers key rotation:
    entries signed by retired keys stay verifiable if their public halves are
    embedded alongside the current one.
    """
    entries = [_normalize_entry(r) for r in rows]
    chain_id = _chain_id_of(entries)
    head_hash = entries[-1]["entry_hash"] if entries else EMPTY_HEAD_HASH
    tree_root = merkle.root_for_entries(entries)

    public_keys: Dict[str, str] = dict(extra_public_keys or {})
    signing_block: Optional[Dict[str, Any]] = None
    head: Dict[str, Any]

    if signer is not None:
        public_key = signer.public_key_hex()
        if public_key:
            public_keys.setdefault(signer.key_id, public_key)
        signing_block = {
            "alg": signer.alg,
            "key_id": signer.key_id,
            "public_key": public_key,
        }
        statement = build_head_statement(
            chain_id=chain_id,
            length=len(entries),
            head_hash=head_hash,
            tree_root=tree_root,
            key_id=signer.key_id,
            alg=signer.alg,
        )
        head = {"statement": statement, "signature": sign_head_statement(statement, signer)}
    else:
        statement = build_head_statement(
            chain_id=chain_id,
            length=len(entries),
            head_hash=head_hash,
            tree_root=tree_root,
            key_id="",
            alg="none",
        )
        head = {"statement": statement, "signature": None}

    return {
        "format": EXPORT_FORMAT,
        "format_version": EXPORT_FORMAT_VERSION,
        "exported_at": head["statement"]["exported_at"],
        "chain_id": chain_id,
        "signing": signing_block,
        "public_keys": public_keys,
        "head": head,
        "entries": entries,
    }


def default_signer() -> signing.Signer:
    """The process signer used when no explicit signer is passed."""
    return attest.SIGNER


def write_export(bundle: Dict[str, Any], path: str) -> Path:
    """Write a bundle as pretty-printed JSON (human-diffable, auditor-friendly)."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    return target


# ----- verifying a bundle ---------------------------------------------------

class Check:
    """One named verification step with a verdict and human detail."""

    def __init__(self, name: str, ok: bool, detail: str):
        self.name = name
        self.ok = ok
        self.detail = detail

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


def verify_export(
    bundle: Dict[str, Any],
    *,
    pinned_public_keys: Optional[Dict[str, str]] = None,
    hmac_key: Optional[bytes] = None,
    expected_head: Optional[Tuple[int, str]] = None,
    consistent_with: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify a bundle offline. Returns a structured report; trusts nothing
    from the bundle beyond what the checks themselves establish.

    * ``pinned_public_keys`` — when given, ONLY these keys are trusted and the
      bundle's embedded keys are ignored. This is how a verifier who obtained
      the public key out-of-band defeats a substituted-key bundle.
    * ``hmac_key`` — required to check legacy HMAC receipts; the report then
      flags the result as NOT third-party verifiable.
    * ``expected_head`` — ``(length, head_hash)`` from a previously pinned
      export; detects rollback/truncation between two exports.
    * ``consistent_with`` — an OLDER bundle of the same chain. The Merkle root
      over this bundle's first ``old.tree_size`` entries must reproduce the
      old bundle's signed root: the old export must be an exact prefix of this
      one, or history was rewritten between the two audits.
    """
    checks: List[Check] = []

    def check(name: str, ok: bool, detail: str) -> bool:
        checks.append(Check(name, ok, detail))
        return ok

    entries = bundle.get("entries") or []
    embedded_keys: Dict[str, str] = dict(bundle.get("public_keys") or {})
    public_keys = pinned_public_keys if pinned_public_keys is not None else embedded_keys
    keys_pinned = pinned_public_keys is not None

    check(
        "format",
        bundle.get("format") == EXPORT_FORMAT
        and bundle.get("format_version") == EXPORT_FORMAT_VERSION,
        f"expected {EXPORT_FORMAT} v{EXPORT_FORMAT_VERSION}, "
        f"got {bundle.get('format')!r} v{bundle.get('format_version')!r}",
    )

    ok, error = attest.verify_chain(entries, public_keys=public_keys, hmac_key=hmac_key)
    check(
        "signatures_and_chain",
        ok,
        error or f"all {len(entries)} signatures valid; hash chain intact "
        "(nothing altered, inserted, deleted or reordered)",
    )

    head = bundle.get("head") or {}
    statement = head.get("statement") or {}
    head_signature = head.get("signature")

    actual_head_hash = entries[-1]["entry_hash"] if entries else EMPTY_HEAD_HASH
    check(
        "head_matches_entries",
        statement.get("length") == len(entries)
        and statement.get("head_hash") == actual_head_hash,
        f"head commits to length={statement.get('length')} hash={str(statement.get('head_hash'))[:16]}..; "
        f"entries show length={len(entries)} hash={actual_head_hash[:16]}..",
    )

    actual_root = merkle.root_for_entries(entries)
    check(
        "merkle_root",
        statement.get("tree_size") == len(entries)
        and statement.get("tree_root") == actual_root,
        f"RFC 6962 root over {len(entries)} entries is {actual_root[:16]}..; "
        f"head commits to {str(statement.get('tree_root'))[:16]}..",
    )

    if head_signature is None:
        check(
            "head_signature",
            False,
            "head statement is UNSIGNED — the exporter held no key; the length "
            "commitment is not cryptographically bound",
        )
    else:
        head_key = public_keys.get(statement.get("key_id"))
        head_ok = verify_head_statement(
            statement, head_signature, public_key_hex=head_key, hmac_key=hmac_key
        )
        check(
            "head_signature",
            head_ok,
            "signed length commitment verifies under key "
            f"{statement.get('key_id')}" if head_ok
            else f"head signature invalid or key {statement.get('key_id')} not trusted",
        )

    chain_id = _chain_id_of(entries)
    check(
        "chain_id_consistent",
        statement.get("chain_id") == chain_id and bundle.get("chain_id") == chain_id,
        f"chain_id={chain_id}",
    )

    # Deep check: delegation receipts embed the full signed token links, so
    # the tokens themselves are re-verified here — signatures, identity chain,
    # parent binding, scope monotonicity, intent invariance. Expiry is NOT
    # re-checked: it is enforced (and receipted) at use time, and any token in
    # an old export is expected to have expired since.
    delegation_entries = []
    for entry in entries:
        try:
            att = json.loads(entry["attestation_json"])
        except (KeyError, json.JSONDecodeError):
            continue
        if str(att.get("kind") or "").startswith("delegation") and (
            (att.get("delegation") or {}).get("links")
        ):
            delegation_entries.append((entry["seq"], att))
    if delegation_entries:
        from agentbrake import delegation as delegation_mod

        deep_ok = True
        deep_detail = (
            f"{len(delegation_entries)} embedded token chain(s) re-verified "
            "(expiry is judged at use time, not audit time)"
        )
        for seq, att in delegation_entries:
            try:
                token = delegation_mod.DelegationToken(att["delegation"]["links"])
            except delegation_mod.DelegationError as e:
                deep_ok, deep_detail = False, f"receipt #{seq}: embedded token unreadable ({e})"
                break
            token_report = delegation_mod.verify(token, public_keys=public_keys)
            failed = [
                c for c in token_report["checks"]
                if not c["ok"] and c["name"] != "not_expired"
            ]
            if failed:
                deep_ok = False
                deep_detail = (
                    f"receipt #{seq}: embedded token failed {failed[0]['name']} "
                    f"({failed[0]['detail']})"
                )
                break
        check("delegation_tokens", deep_ok, deep_detail)

    if consistent_with is not None:
        old_statement = (consistent_with.get("head") or {}).get("statement") or {}
        old_signature = (consistent_with.get("head") or {}).get("signature")
        old_size = old_statement.get("tree_size")
        old_root = old_statement.get("tree_root")
        old_head_ok = old_signature is not None and verify_head_statement(
            old_statement,
            old_signature,
            public_key_hex=public_keys.get(old_statement.get("key_id")),
            hmac_key=hmac_key,
        )
        check(
            "old_head_signature",
            old_head_ok,
            "older bundle's signed head verifies"
            if old_head_ok
            else "older bundle's head is unsigned or does not verify — its root "
            "cannot anchor a consistency claim",
        )
        if not isinstance(old_size, int) or old_size > len(entries):
            check(
                "consistency",
                False,
                f"older export commits to {old_size} entries but this one has "
                f"{len(entries)} — receipts were truncated or rolled back",
            )
        else:
            prefix_root = merkle.root_for_entries(entries[:old_size])
            check(
                "consistency",
                prefix_root == old_root,
                f"first {old_size} entries reproduce the older signed root — the "
                "old export is an exact prefix of this one"
                if prefix_root == old_root
                else f"root over the first {old_size} entries does not match the "
                "older signed root — history was rewritten between exports",
            )

    if expected_head is not None:
        exp_len, exp_hash = expected_head
        if exp_len == len(entries):
            head_consistent = actual_head_hash == exp_hash
            detail = (
                "matches the pinned head exactly"
                if head_consistent
                else "SAME length but DIFFERENT head hash — history was rewritten"
            )
        elif exp_len < len(entries):
            # The chain grew; the pinned head must be the entry_hash at that
            # earlier position, i.e. the old export must be a prefix of this one.
            head_consistent = entries[exp_len - 1]["entry_hash"] == exp_hash
            detail = (
                f"pinned head (length {exp_len}) is a prefix of this export"
                if head_consistent
                else f"entry #{exp_len} does not match the pinned head — history was rewritten"
            )
        else:
            head_consistent = False
            detail = (
                f"pinned head commits to {exp_len} entries but this export has "
                f"only {len(entries)} — receipts were truncated or rolled back"
            )
        check("expected_head", head_consistent, detail)

    algs = {json.loads(e["attestation_json"]).get("alg") or "hmac-sha256(v1)" for e in entries}
    third_party = bool(entries) and algs == {signing.ALG_ED25519} and head_signature is not None

    return {
        "ok": all(c.ok for c in checks),
        "entry_count": len(entries),
        "chain_id": chain_id,
        "algorithms": sorted(algs),
        "public_keys": public_keys,
        "keys_pinned": keys_pinned,
        "third_party_verifiable": third_party,
        "head": {"length": statement.get("length"), "head_hash": statement.get("head_hash")},
        "checks": [c.as_dict() for c in checks],
    }


# ----- single-receipt proofs (selective disclosure) --------------------------

def build_receipt_proof(
    rows: List[Dict[str, Any]],
    seq: int,
    *,
    signer: Optional[signing.Signer] = None,
    extra_public_keys: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Package ONE receipt with an inclusion proof against the signed head.

    The holder of this artifact can verify that the receipt is authentic and
    sits at position ``seq`` in a log of the committed size — without ever
    seeing any other receipt. This is what you hand to a party who is entitled
    to one enforcement proof but not to the whole log.
    """
    entries = [_normalize_entry(r) for r in rows]
    index = seq - 1
    if not 0 <= index < len(entries):
        raise ValueError(f"seq {seq} not in chain of length {len(entries)}")
    if entries[index]["seq"] != seq:
        raise ValueError(f"chain is not seq-ordered at position {index}")

    bundle = build_export(rows, signer=signer, extra_public_keys=extra_public_keys)
    return {
        "format": RECEIPT_PROOF_FORMAT,
        "format_version": RECEIPT_PROOF_FORMAT_VERSION,
        "entry": entries[index],
        "leaf_index": index,
        "inclusion_proof": merkle.proof_for_entry(index, entries),
        "public_keys": bundle["public_keys"],
        "head": bundle["head"],
    }


def verify_receipt_proof(
    proof: Dict[str, Any],
    *,
    pinned_public_keys: Optional[Dict[str, str]] = None,
    hmac_key: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Verify a single-receipt proof offline. Same report shape as
    :func:`verify_export`, scoped to one entry."""
    checks: List[Check] = []

    def check(name: str, ok: bool, detail: str) -> bool:
        checks.append(Check(name, ok, detail))
        return ok

    entry = proof.get("entry") or {}
    embedded_keys: Dict[str, str] = dict(proof.get("public_keys") or {})
    public_keys = pinned_public_keys if pinned_public_keys is not None else embedded_keys
    keys_pinned = pinned_public_keys is not None

    check(
        "format",
        proof.get("format") == RECEIPT_PROOF_FORMAT
        and proof.get("format_version") == RECEIPT_PROOF_FORMAT_VERSION,
        f"expected {RECEIPT_PROOF_FORMAT} v{RECEIPT_PROOF_FORMAT_VERSION}",
    )

    try:
        attestation = json.loads(entry.get("attestation_json") or "")
    except json.JSONDecodeError:
        attestation = None
    if attestation is None:
        check("entry_signature", False, "entry attestation is not parseable JSON")
    else:
        sig_ok, sig_err = attest.verify_record_signature(
            attestation,
            entry["attestation_json"],
            entry["signature"],
            public_keys=public_keys,
            hmac_key=hmac_key,
        )
        check(
            "entry_signature",
            sig_ok,
            sig_err or "receipt signature valid under trusted key",
        )
        recomputed = attest.entry_hash(entry["attestation_json"], entry["signature"])
        check(
            "entry_hash",
            recomputed == entry.get("entry_hash"),
            "entry_hash matches the signed bytes",
        )

    statement = (proof.get("head") or {}).get("statement") or {}
    head_signature = (proof.get("head") or {}).get("signature")
    index = proof.get("leaf_index")
    tree_size = statement.get("tree_size")

    included = isinstance(index, int) and isinstance(tree_size, int) and (
        merkle.verify_entry_inclusion(
            entry,
            index,
            tree_size,
            proof.get("inclusion_proof") or [],
            str(statement.get("tree_root")),
        )
    )
    check(
        "inclusion",
        bool(included),
        f"receipt proven at position {index} of a log of {tree_size} "
        "under the signed root"
        if included
        else "inclusion proof does not reach the signed root",
    )

    check(
        "position_matches_seq",
        attestation is not None
        and isinstance(index, int)
        and attestation.get("seq") == index + 1
        and entry.get("seq") == index + 1,
        "the signed seq equals the proven tree position",
    )

    if head_signature is None:
        check("head_signature", False, "head statement is UNSIGNED")
    else:
        head_key = public_keys.get(statement.get("key_id"))
        head_ok = verify_head_statement(
            statement, head_signature, public_key_hex=head_key, hmac_key=hmac_key
        )
        check(
            "head_signature",
            head_ok,
            "signed head verifies under key "
            f"{statement.get('key_id')}" if head_ok
            else f"head signature invalid or key {statement.get('key_id')} not trusted",
        )

    if attestation is not None:
        check(
            "chain_id_consistent",
            attestation.get("chain_id") == statement.get("chain_id"),
            f"chain_id={statement.get('chain_id')}",
        )

    alg = (attestation or {}).get("alg")
    third_party = alg == signing.ALG_ED25519 and head_signature is not None

    return {
        "ok": all(c.ok for c in checks),
        "entry_count": 1,
        "chain_id": statement.get("chain_id"),
        "algorithms": [alg or "hmac-sha256(v1)"],
        "public_keys": public_keys,
        "keys_pinned": keys_pinned,
        "third_party_verifiable": third_party,
        "head": {"length": statement.get("length"), "head_hash": statement.get("head_hash")},
        "checks": [c.as_dict() for c in checks],
    }


# ----- loading rows from the two storage backends ---------------------------

def rows_from_jsonl(path: str) -> List[Dict[str, Any]]:
    """Load receipt rows from a JsonlLedger file."""
    rows: List[Dict[str, Any]] = []
    with Path(path).expanduser().open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def rows_from_db(path: str) -> List[Dict[str, Any]]:
    """Load the attestation chain from a server SQLite database."""
    from agentbrake.server import store

    return store.get_attestation_chain(db_path=Path(path).expanduser())
