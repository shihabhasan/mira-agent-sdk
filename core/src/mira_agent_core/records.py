"""Canonical bytes, record hashes and DSSE envelopes.

This module is the load-bearing one. If its canonicalisation differs from the
control plane's by a single byte, every signature verifies against bytes nobody
stored and the whole chain becomes decorative — so this code and the server's
are the SAME implementation, and `tests/test_conformance.py` pins that with
vectors generated from the server.

The bytes discipline, in one rule: **canonicalise exactly once, then never
re-serialise**. The record hash, the signature and the accumulator leaf all
read the same byte string, and verification always reads the stored bytes
rather than re-canonicalising parsed JSON.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import rfc8785

from .backend import rust as _rust

PAYLOAD_TYPE = "application/vnd.mira.provenance+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://liora-ai.co/mira/agent-step/v1"


class RecordType(StrEnum):
    SPAN = "SPAN"
    CHECKPOINT = "CHECKPOINT"
    INTERVENTION = "INTERVENTION"
    RECOVERY = "RECOVERY"
    BREAK = "BREAK"
    INTENT = "INTENT"
    SNAPSHOT = "SNAPSHOT"
    DECISION = "DECISION"


def now_ms() -> int:
    """Integer Unix milliseconds.

    JCS cannot safely round-trip floats or integers past 2^53, which rules out
    both time.time() and time.time_ns().
    """
    return time.time_ns() // 1_000_000


def sha256_hex(data: bytes) -> str:
    rs = _rust()
    if rs is not None:
        return rs.sha256_hex(data)
    return hashlib.sha256(data).hexdigest()


def jcs_safe(obj: Any) -> Any:
    """Coerce a structure into something RFC 8785 can canonicalise: string
    keys, finite floats, integers inside 2^53, no exotic types."""
    if isinstance(obj, dict):
        return {str(k): jcs_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jcs_safe(v) for v in obj]
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return obj
    if isinstance(obj, int):
        return obj if abs(obj) < 2**53 else str(obj)
    if isinstance(obj, float):
        return obj if obj == obj and abs(obj) != float("inf") else str(obj)
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode()
    return str(obj)


def canonical(obj: Any) -> bytes:
    """The one canonicalisation. Everything downstream reads these bytes.

    Routes to the Rust core when MIRA_CORE_BACKEND=rust. The two are proven
    byte-identical by the conformance vectors, so this can never change what a
    record hashes to — only how fast it gets there.
    """
    rs = _rust()
    if rs is not None:
        import json as _json

        return rs.canonicalize(_json.dumps(jcs_safe(obj)))
    return rfc8785.dumps(jcs_safe(obj))


def content_hash(obj: Any) -> str:
    """Digest arbitrary JSON-able content, e.g. a step's input or output."""
    return "sha256:" + sha256_hex(canonical(obj))


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding — what actually gets signed."""
    pt = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def build_statement(
    *,
    record_type: RecordType | str,
    identity: dict,
    seq: int,
    prev_record_hash: str | None,
    mmr_size_before: int,
    otel: dict | None = None,
    langgraph: dict | None = None,
    subject: list[dict] | None = None,
    predicate: dict | None = None,
    ts_ms: int | None = None,
) -> dict:
    """Assemble an in-toto Statement v1 carrying Mira's predicate."""
    return {
        "_type": STATEMENT_TYPE,
        "subject": jcs_safe(subject or []),
        "predicateType": PREDICATE_TYPE,
        "predicate": jcs_safe(
            {
                "recordType": str(record_type),
                "identity": identity,
                "otel": otel or {},
                "langgraph": langgraph or {},
                "chain": {
                    "seq": seq,
                    "prevRecordHash": prev_record_hash or "",
                    "mmrSizeBefore": mmr_size_before,
                },
                "tsMs": ts_ms if ts_ms is not None else now_ms(),
                **(predicate or {}),
            }
        ),
    }


@dataclass(frozen=True)
class Envelope:
    """A DSSE envelope wrapping the canonical record bytes."""

    payload_type: str
    payload_b64: str
    key_id: str
    signature_b64: str
    record_hash: str

    @property
    def payload_bytes(self) -> bytes:
        return base64.b64decode(self.payload_b64)

    @property
    def statement(self) -> dict:
        import json

        return json.loads(self.payload_bytes)

    def to_dict(self) -> dict:
        return {
            "payloadType": self.payload_type,
            "payload": self.payload_b64,
            "signatures": [{"keyid": self.key_id, "sig": self.signature_b64}],
            "recordHash": self.record_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Envelope":
        sig = (d.get("signatures") or [{}])[0]
        return cls(
            payload_type=d.get("payloadType", PAYLOAD_TYPE),
            payload_b64=d["payload"],
            key_id=sig.get("keyid", ""),
            signature_b64=sig.get("sig", ""),
            record_hash=d.get("recordHash", ""),
        )
