"""Offline verification of an exported Mira lineage bundle.

This runs with no network, no Mira account and no cooperation from the control
plane. That is the whole point: an auditor who must call the vendor's API to
check the vendor's claims is being asked to trust them twice.

Five independent checks per record, and a record is valid only if all five
pass:

  1. signature    — Ed25519 over the DSSE PAE of the STORED bytes
  2. chain link   — prevRecordHash equals the previous record's hash
  3. sequence     — seq increases by exactly one
  4. inclusion    — the leaf recomputes to the checkpoint's signed root
  5. checkpoint   — the note's own signature verifies

Check 4 is the one people skip, and it is the one that catches a record that
was never actually in the published log.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from .checkpoint import verify_checkpoint
from .keys import verify as verify_sig
from .mmr import InclusionProof, verify_inclusion, verify_root
from .records import Envelope, sha256_hex


@dataclass
class RecordResult:
    seq: int
    record_hash: str
    record_type: str
    node: str | None
    signature_valid: bool
    hash_valid: bool
    chain_link_valid: bool
    seq_valid: bool
    inclusion_valid: bool

    @property
    def valid(self) -> bool:
        return (
            self.signature_valid
            and self.hash_valid
            and self.chain_link_valid
            and self.seq_valid
            and self.inclusion_valid
        )

    def failures(self) -> list[str]:
        return [
            name
            for name, ok in (
                ("signature", self.signature_valid),
                ("record hash", self.hash_valid),
                ("chain link", self.chain_link_valid),
                ("sequence", self.seq_valid),
                ("inclusion proof", self.inclusion_valid),
            )
            if not ok
        ]


@dataclass
class BundleResult:
    txn_id: str
    valid: bool
    checkpoint_signature_valid: bool
    records: list[RecordResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def invalid_records(self) -> list[RecordResult]:
        return [r for r in self.records if not r.valid]


def verify_bundle(bundle: dict) -> BundleResult:
    """Verify an exported bundle offline.

    Expected shape (what `GET /api/v1/txn/{id}/bundle` produces):

        {
          "txn_id": "txn-…",
          "keys": {"<key_id>": {"name": "...", "public_b64": "..."}},
          "checkpoint": {"note": "...", "key_name": "mira/ledger",
                          "root_hex": "...", "mmr_size": 19},
          "records": [
            {"seq": 0, "leaf_index": 0, "record_type": "INTENT", "node": "...",
             "envelope": {...}, "proof": {...}}
          ]
        }
    """
    result = BundleResult(
        txn_id=bundle.get("txn_id", "?"), valid=False, checkpoint_signature_valid=False
    )

    keys: dict[str, dict] = bundle.get("keys") or {}
    cp = bundle.get("checkpoint") or {}
    note = cp.get("note")
    root_hex = cp.get("root_hex")

    # ---- 5. the checkpoint's own signature -----------------------------
    if not note:
        result.errors.append("bundle carries no checkpoint — inclusion cannot be proven")
    else:
        cp_key_name = cp.get("key_name", "mira/ledger")
        cp_key = next(
            (k for k in keys.values() if k.get("name") == cp_key_name), None
        )
        if not cp_key:
            result.errors.append(f"no public key for checkpoint signer {cp_key_name!r}")
        else:
            parsed = verify_checkpoint(
                note, cp_key_name, base64.b64decode(cp_key["public_b64"])
            )
            if parsed is None:
                result.errors.append("checkpoint note signature did not verify")
            elif root_hex and parsed.root_hex != root_hex:
                result.errors.append("checkpoint root disagrees with the note")
            else:
                result.checkpoint_signature_valid = True
                root_hex = parsed.root_hex

    # ---- per record ----------------------------------------------------
    prev_hash: str | None = None
    last_seq = -1
    for raw in bundle.get("records") or []:
        env = Envelope.from_dict(raw["envelope"])
        payload = env.payload_bytes

        hash_ok = sha256_hex(payload) == env.record_hash
        key = keys.get(env.key_id)
        sig_ok = False
        if key:
            from .records import PAYLOAD_TYPE, pae

            sig_ok = verify_sig(
                base64.b64decode(key["public_b64"]),
                base64.b64decode(env.signature_b64),
                pae(env.payload_type or PAYLOAD_TYPE, payload),
            )
        else:
            result.errors.append(f"no public key for signer {env.key_id!r}")

        seq = int(raw.get("seq", -1))
        # A tampered payload may not even be JSON any more. That is a finding,
        # not a crash — a verifier handed a hostile bundle must still return a
        # verdict.
        try:
            stmt = env.statement
        except Exception:
            stmt = {}
            result.errors.append(f"record {seq}: payload is not valid JSON")
        chain = (stmt.get("predicate") or {}).get("chain") or {}
        link_ok = bool(stmt) and (chain.get("prevRecordHash") or None) == prev_hash
        seq_ok = seq == last_seq + 1

        incl_ok = False
        proof_raw = raw.get("proof")
        if proof_raw and root_hex:
            proof = InclusionProof.from_dict(proof_raw)
            incl_ok = verify_inclusion(
                payload, int(raw["leaf_index"]), proof
            ) and verify_root(proof, root_hex)

        result.records.append(
            RecordResult(
                seq=seq,
                record_hash=env.record_hash,
                record_type=raw.get("record_type", "?"),
                node=raw.get("node"),
                signature_valid=sig_ok,
                hash_valid=hash_ok,
                chain_link_valid=link_ok,
                seq_valid=seq_ok,
                inclusion_valid=incl_ok,
            )
        )
        prev_hash, last_seq = env.record_hash, seq

    result.valid = (
        bool(result.records)
        and result.checkpoint_signature_valid
        and all(r.valid for r in result.records)
    )
    return result
