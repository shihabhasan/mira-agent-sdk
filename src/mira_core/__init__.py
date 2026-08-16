"""Mira core primitives: canonical records, keys, accumulator proofs, offline
verification. Shared by the SDK and the control plane so canonicalisation
cannot drift between them."""

from .checkpoint import Checkpoint, parse_checkpoint, verify_checkpoint
from .keys import SigningKey, key_id
from .keys import verify as verify_signature
from .mmr import InclusionProof, hash_leaf, verify_inclusion, verify_root
from .records import (
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    Envelope,
    RecordType,
    build_statement,
    canonical,
    content_hash,
    now_ms,
    pae,
    sha256_hex,
)
from .verify import BundleResult, RecordResult, verify_bundle

__version__ = "0.1.0"
__all__ = [
    "Checkpoint", "parse_checkpoint", "verify_checkpoint",
    "SigningKey", "key_id", "verify_signature",
    "InclusionProof", "hash_leaf", "verify_inclusion", "verify_root",
    "Envelope", "RecordType", "build_statement", "canonical", "content_hash",
    "now_ms", "pae", "sha256_hex",
    "PAYLOAD_TYPE", "PREDICATE_TYPE", "STATEMENT_TYPE",
    "BundleResult", "RecordResult", "verify_bundle",
]
