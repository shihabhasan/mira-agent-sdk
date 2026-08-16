"""Merkle Mountain Range — verification only.

A client never builds an accumulator; it checks proofs the log hands it. This
is the verification half of the MMRIVER reference algorithms
(draft-bryce-cose-merkle-mountain-range-proofs), kept deliberately separate
from any storage so it can run offline against an exported bundle.

Domain separation matters here: leaves hash under 0x00 and interior nodes
under 0x01, so a leaf can never be presented as an interior node
(CVE-2012-2459 class). Interior hashes also commit their own position, which
stops a subtree being re-parented somewhere else in the tree.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_leaf(payload: bytes) -> bytes:
    return _hash(LEAF_PREFIX + payload)


def _hash_pos_pair(pos: int, left: bytes, right: bytes) -> bytes:
    return _hash(NODE_PREFIX + pos.to_bytes(8, "big") + left + right)


def _all_ones(pos: int) -> bool:
    return (1 << pos.bit_length()) - 1 == pos


def _most_sig_bit(pos: int) -> int:
    return 1 << (pos.bit_length() - 1)


def index_height(i: int) -> int:
    """Height of the node at 0-based MMR position i."""
    pos = i + 1
    while not _all_ones(pos):
        pos = pos - (_most_sig_bit(pos) - 1)
    return pos.bit_length() - 1


def leaf_index_to_pos(leaf_index: int) -> int:
    """MMR position of the leaf with the given 0-based leaf index."""
    total = 0
    while leaf_index > 0:
        h = leaf_index.bit_length()
        total += (1 << h) - 1
        leaf_index -= 1 << (h - 1)
    return total


@dataclass(frozen=True)
class InclusionProof:
    leaf_pos: int
    mmr_size: int
    path: list[str]   # sibling hashes, hex, leaf -> peak
    peaks: list[str]  # peak hashes at mmr_size, hex

    @classmethod
    def from_dict(cls, d: dict) -> "InclusionProof":
        return cls(
            leaf_pos=int(d["leaf_pos"]),
            mmr_size=int(d["mmr_size"]),
            path=list(d.get("path") or []),
            peaks=list(d.get("peaks") or []),
        )


def verify_inclusion(payload: bytes, leaf_index: int, proof: InclusionProof) -> bool:
    """Recompute leaf -> peak and check the result is one of the proof's peaks.

    On its own this proves nothing about the log: the peaks still have to fold
    to a root someone signed. Always pair it with verify_root().
    """
    pos = leaf_index_to_pos(leaf_index)
    if pos != proof.leaf_pos:
        return False
    node = hash_leaf(payload)
    height = 0
    for sibling_hex in proof.path:
        sibling = bytes.fromhex(sibling_hex)
        if index_height(pos + 1) > height:  # right child, sibling on the left
            pos = pos + 1
            node = _hash_pos_pair(pos, sibling, node)
        else:
            pos = pos + (2 << height)
            node = _hash_pos_pair(pos, node, sibling)
        height += 1
    return node.hex() in proof.peaks


def verify_root(proof: InclusionProof, expected_root_hex: str) -> bool:
    """Check the proof's peaks fold to the root a checkpoint signed."""
    ph = [bytes.fromhex(h) for h in proof.peaks]
    if not ph:
        return False
    acc = ph[-1]
    for peak in reversed(ph[:-1]):
        acc = _hash(NODE_PREFIX + proof.mmr_size.to_bytes(8, "big") + peak + acc)
    return acc.hex() == expected_root_hex
