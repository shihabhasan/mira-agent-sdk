"""Core primitives: canonical records, keys, accumulator proofs, offline
verification.

Nested under `mira_agent` rather than shipped as a top-level `mira_core` so it
cannot collide with anyone else's package. Same implementation the control
plane runs — see tests/test_conformance.py."""

from .checkpoint import (
    Checkpoint,
    Signature,
    parse_checkpoint,
    verify_checkpoint,
    verify_witnesses,
)
from .identity import AgentIdentity, SpiffeError, SpiffeId, load_identity, spiffe_id_from_certificate
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

__version__ = "0.2.0"
__all__ = [
    "Checkpoint", "Signature", "parse_checkpoint", "verify_checkpoint",
    "verify_witnesses",
    "AgentIdentity", "SpiffeId", "SpiffeError", "load_identity",
    "spiffe_id_from_certificate",
    "SigningKey", "key_id", "verify_signature",
    "InclusionProof", "hash_leaf", "verify_inclusion", "verify_root",
    "Envelope", "RecordType", "build_statement", "canonical", "content_hash",
    "now_ms", "pae", "sha256_hex",
    "PAYLOAD_TYPE", "PREDICATE_TYPE", "STATEMENT_TYPE",
    "BundleResult", "RecordResult", "verify_bundle",
]
