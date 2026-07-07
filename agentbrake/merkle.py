"""RFC 6962 Merkle tree over receipt entries: inclusion proofs for the chain.

Why a Merkle tree, honestly
---------------------------

The signed chain head (see :mod:`agentbrake.export`) already detects
truncation and rollback when the verifier holds the *full* export. What a hash
chain cannot do is prove that ONE receipt belongs to the log without shipping
the whole log: each ``entry_hash`` depends on the complete body of the entry
before it, so a single-entry proof would drag every other entry along.

A Merkle tree fixes exactly that: the signed head commits to a ``tree_root``,
and any single entry can be proven to sit at a given index under that root
with O(log n) hashes — no other entry disclosed. That is *selective
disclosure*: hand a customer the one receipt that concerns them, plus a proof,
without revealing the rest of the log.

What it does NOT change: the trust model. The private-key holder can still
regenerate a parallel tree and sign it. Anchoring heads externally remains the
answer there; the tree adds efficiency and disclosure control, not a new
defense against the signer.

Construction (RFC 6962 §2.1, verification per RFC 9162 §2.1.3.2)
----------------------------------------------------------------

Leaf input for entry *i* is the UTF-8 bytes of its ``entry_hash`` hex string —
which itself binds the entry's signed body and signature. Then:

    MTH([])       = SHA-256("")
    MTH([d])      = SHA-256(0x00 || d)
    MTH(D[0:n])   = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))

with k the largest power of two strictly smaller than n. The 0x00/0x01
prefixes domain-separate leaves from interior nodes (no second-preimage
splice). This is byte-compatible with Certificate Transparency, so a verifier
can be re-implemented from the RFCs alone.
"""

from __future__ import annotations

import hashlib
from typing import List, Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    """SHA-256(0x00 || data) — the hash of one leaf input."""
    return _hash(LEAF_PREFIX + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right) — an interior node."""
    return _hash(NODE_PREFIX + left + right)


def _split_point(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def tree_root(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash over the leaf inputs (RFC 6962 MTH)."""
    n = len(leaves)
    if n == 0:
        return _hash(b"")
    if n == 1:
        return leaf_hash(leaves[0])
    k = _split_point(n)
    return node_hash(tree_root(leaves[:k]), tree_root(leaves[k:]))


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> List[bytes]:
    """Audit path for the leaf at ``index`` (RFC 6962 PATH), leaf-to-root order."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(f"leaf index {index} out of range for {n} leaves")
    if n == 1:
        return []
    k = _split_point(n)
    if index < k:
        return inclusion_proof(index, leaves[:k]) + [tree_root(leaves[k:])]
    return inclusion_proof(index - k, leaves[k:]) + [tree_root(leaves[:k])]


def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Check that ``leaf`` sits at ``index`` in the tree of ``tree_size``
    committed to by ``root`` (RFC 9162 §2.1.3.2, iterative form).

    ``leaf`` is the raw leaf *input* (it is leaf-hashed here), matching what
    :func:`inclusion_proof` was generated over.
    """
    if index >= tree_size or index < 0:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(leaf)
    for p in proof:
        if sn == 0:
            return False  # proof longer than the path to the root
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:  # right-border node: skip levels with no sibling
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ----- receipt-entry helpers -------------------------------------------------

def entry_leaf(entry: dict) -> bytes:
    """The leaf input for one receipt entry: its entry_hash hex, UTF-8."""
    return entry["entry_hash"].encode("utf-8")


def root_for_entries(entries: Sequence[dict]) -> str:
    """Hex Merkle root over a seq-ordered list of receipt entries."""
    return tree_root([entry_leaf(e) for e in entries]).hex()


def proof_for_entry(index: int, entries: Sequence[dict]) -> List[str]:
    """Hex inclusion proof for the entry at ``index`` (0-based, == seq-1)."""
    return [h.hex() for h in inclusion_proof(index, [entry_leaf(e) for e in entries])]


def verify_entry_inclusion(
    entry: dict,
    index: int,
    tree_size: int,
    proof_hex: Sequence[str],
    root_hex: str,
) -> bool:
    """Check one receipt entry against a hex root under a hex proof."""
    try:
        proof = [bytes.fromhex(p) for p in proof_hex]
        root = bytes.fromhex(root_hex)
    except (ValueError, TypeError):
        return False
    return verify_inclusion(entry_leaf(entry), index, tree_size, proof, root)
