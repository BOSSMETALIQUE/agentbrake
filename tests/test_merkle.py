"""RFC 6962 Merkle tree: definitional vectors + exhaustive proof checks."""

from __future__ import annotations

import hashlib

import pytest

from agentbrake import merkle


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --- roots match the RFC definition, derived by hand -------------------------

def test_empty_tree_root_is_hash_of_empty_string():
    assert merkle.tree_root([]) == _h(b"")
    # The well-known SHA-256 of the empty string, for cross-implementation checks.
    assert merkle.tree_root([]).hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_single_leaf_root():
    assert merkle.tree_root([b"d0"]) == _h(b"\x00" + b"d0")


def test_two_leaf_root():
    l0, l1 = _h(b"\x00d0"), _h(b"\x00d1")
    assert merkle.tree_root([b"d0", b"d1"]) == _h(b"\x01" + l0 + l1)


def test_three_leaf_root_splits_at_largest_power_of_two():
    # k=2: root = node(MTH([d0,d1]), MTH([d2]))
    left = merkle.tree_root([b"d0", b"d1"])
    right = merkle.tree_root([b"d2"])
    assert merkle.tree_root([b"d0", b"d1", b"d2"]) == _h(b"\x01" + left + right)


def test_leaf_and_node_domains_are_separated():
    """A leaf can never be confused with an interior node (0x00 vs 0x01)."""
    assert merkle.leaf_hash(b"x") != merkle.node_hash(b"", b"x")


# --- inclusion proofs: exhaustive over sizes 1..64 ----------------------------

def test_every_index_verifies_for_every_tree_size():
    for n in range(1, 65):
        leaves = [f"leaf-{i}".encode() for i in range(n)]
        root = merkle.tree_root(leaves)
        for i in range(n):
            proof = merkle.inclusion_proof(i, leaves)
            assert merkle.verify_inclusion(leaves[i], i, n, proof, root), (n, i)


def test_wrong_leaf_fails():
    leaves = [f"leaf-{i}".encode() for i in range(10)]
    root = merkle.tree_root(leaves)
    proof = merkle.inclusion_proof(3, leaves)
    assert merkle.verify_inclusion(b"forged", 3, 10, proof, root) is False


def test_wrong_index_fails():
    leaves = [f"leaf-{i}".encode() for i in range(10)]
    root = merkle.tree_root(leaves)
    proof = merkle.inclusion_proof(3, leaves)
    assert merkle.verify_inclusion(leaves[3], 4, 10, proof, root) is False
    assert merkle.verify_inclusion(leaves[3], 12, 10, proof, root) is False


def test_proof_does_not_verify_against_another_trees_root():
    """(root, tree_size) travel together in the signed head; a proof made for
    one tree must not verify against the signed head of a different tree."""
    leaves_10 = [f"leaf-{i}".encode() for i in range(10)]
    leaves_11 = leaves_10 + [b"leaf-10"]
    proof = merkle.inclusion_proof(3, leaves_10)
    root_11 = merkle.tree_root(leaves_11)
    assert merkle.verify_inclusion(leaves_10[3], 3, 11, proof, root_11) is False


def test_truncated_and_padded_proofs_fail():
    leaves = [f"leaf-{i}".encode() for i in range(16)]
    root = merkle.tree_root(leaves)
    proof = merkle.inclusion_proof(5, leaves)
    assert merkle.verify_inclusion(leaves[5], 5, 16, proof[:-1], root) is False
    assert merkle.verify_inclusion(leaves[5], 5, 16, proof + [b"\x00" * 32], root) is False


def test_proof_out_of_range_raises():
    with pytest.raises(IndexError):
        merkle.inclusion_proof(2, [b"a", b"b"])


# --- entry-level helpers -------------------------------------------------------

def _entries(n: int) -> list:
    return [{"entry_hash": hashlib.sha256(str(i).encode()).hexdigest()} for i in range(n)]


def test_entry_helpers_roundtrip():
    entries = _entries(7)
    root = merkle.root_for_entries(entries)
    for i, entry in enumerate(entries):
        proof = merkle.proof_for_entry(i, entries)
        assert merkle.verify_entry_inclusion(entry, i, len(entries), proof, root)
    # An entry from another log does not verify.
    alien = {"entry_hash": "ff" * 32}
    assert merkle.verify_entry_inclusion(
        alien, 0, len(entries), merkle.proof_for_entry(0, entries), root
    ) is False


def test_entry_helpers_tolerate_malformed_hex():
    entries = _entries(3)
    root = merkle.root_for_entries(entries)
    assert merkle.verify_entry_inclusion(entries[0], 0, 3, ["zz-not-hex"], root) is False
    assert merkle.verify_entry_inclusion(entries[0], 0, 3, [], "not-hex") is False
