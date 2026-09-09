"""Evidence, compiled after the decision and sent when convenient.

The decision path and the evidence path have different requirements and should
not share a deadline. A boundary that waits for the ledger before releasing an
action has made the ledger's availability part of the estate's availability,
which is the dependency MSEP exists to remove.

So the receipt is compiled after the disposition, queued durably, and drained
in the background. If the ledger is unreachable the queue grows; nothing
stops. Receipts carry their parent commitment, so the ledger can rebuild the
causal graph from batches that arrive late or out of order, and a parent that
never arrives stays visible as a gap rather than being quietly stitched over.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from mira_agent.msep.disposition import Disposition


@dataclass(frozen=True)
class Receipt:
    """Enough to prove the transition, without carrying the payload.

    `action_released` and `response_digest` together are what the boundary
    can honestly attest: what it let through, and what came back. Side
    effects beyond the boundary are not observable from it, and a receipt
    that claimed to record "what happened" would be claiming more than it
    saw.
    """

    inbound_commitment: str | None
    successor_commitment: str | None
    identity: str
    boundary: str
    disposition: Disposition
    action_released: str | None
    policy_digest: str
    epoch: int
    state_digest: str
    at_ms: int
    reasons: list[str] = field(default_factory=list)
    adverse_commitment: str | None = None
    storage_ref: str | None = None
    # Every commitment the transition was caused by, so a join is recorded as
    # the fan-in it actually was rather than as a single arbitrary parent.
    parent_commitments: list[str] = field(default_factory=list)
    # Fields removed or replaced before release, where the disposition was
    # REDACT. What was released is not what was requested, and the evidence has
    # to say which parts differed.
    redactions: list[str] = field(default_factory=list)
    # Whether the onward hop fell back from native MSEP to a governed
    # enforcement point. A downgrade nobody can see in the evidence is
    # indistinguishable from a gap in coverage.
    downgraded: bool = False
    fallback_via: str | None = None
    # Unauthenticated correlation identifiers from the transport, kept so
    # evidence lines up with the customer's traces. Never load-bearing: a
    # forged header can make a trace view wrong, it cannot make an action
    # authorised.
    trace: dict | None = None
    # Digest of the response the boundary observed, where there was one.
    response_digest: str | None = None
    # Which boundary key produced this transition, so a compromised key's
    # blast radius can be enumerated from the evidence.
    signer_key_id: str | None = None

    def to_jcs(self) -> dict:
        return {
            "inboundCommitment": self.inbound_commitment,
            "successorCommitment": self.successor_commitment,
            "identity": self.identity,
            "boundary": self.boundary,
            "disposition": str(self.disposition),
            "actionReleased": self.action_released,
            "policyDigest": self.policy_digest,
            "epoch": self.epoch,
            "stateDigest": self.state_digest,
            "atMs": self.at_ms,
            "reasons": self.reasons,
            "adverseCommitment": self.adverse_commitment,
            "storageRef": self.storage_ref,
            "parentCommitments": self.parent_commitments,
            "redactions": self.redactions,
            "downgraded": self.downgraded,
            "fallbackVia": self.fallback_via,
            "trace": self.trace,
            "responseDigest": self.response_digest,
            "signerKeyId": self.signer_key_id,
        }


class ReceiptQueue:
    """Bounded, thread-safe, and honest about loss.

    An unbounded queue in someone else's agent process is a memory leak with
    our name on it. When it overflows the OLDEST receipt is dropped and
    counted, because the newest evidence is the evidence most likely still
    needed, and a dropped count that nobody can see is worse than the drop.
    """

    def __init__(self, capacity: int = 10_000):
        self.capacity = capacity
        self._q: deque[Receipt] = deque()
        self._lock = threading.Lock()
        self.dropped = 0
        self.sealed = 0

    def put(self, r: Receipt) -> None:
        with self._lock:
            if len(self._q) >= self.capacity:
                self._q.popleft()
                self.dropped += 1
            self._q.append(r)

    def drain(self, limit: int = 256) -> list[Receipt]:
        with self._lock:
            out = [self._q.popleft() for _ in range(min(limit, len(self._q)))]
        self.sealed += len(out)
        return out

    def relay_batch(self, limit: int = 8) -> list[Receipt]:
        """Receipts to piggyback onto an outbound interaction.

        A boundary that can reach its peer but not the ledger can hand its
        backlog to the next hop, which may have connectivity it lacks. Bounded
        deliberately: unbounded piggybacking would let the envelope grow with
        the size of the outage.
        """
        return self.drain(limit)

    def depth(self) -> int:
        with self._lock:
            return len(self._q)

    def peek(self) -> list[Receipt]:
        """What is queued, without draining it."""
        with self._lock:
            return list(self._q)


def compile_receipt(
    *, inbound, successor, identity: str, boundary: str,
    disposition: Disposition, action_released: str | None,
    policy_digest: str, epoch: int, state_digest: str,
    reasons: list[str] | None = None, adverse_commitment: str | None = None,
    storage_ref: str | None = None, redactions: tuple[str, ...] = (),
    downgraded: bool = False, fallback_via: str | None = None,
    trace=None, response_digest: str | None = None,
    signer_key_id: str | None = None, now_ms: int | None = None,
) -> Receipt:
    return Receipt(
        inbound_commitment=inbound.commitment() if inbound else None,
        successor_commitment=successor.commitment() if successor else None,
        identity=identity, boundary=boundary, disposition=disposition,
        action_released=action_released, policy_digest=policy_digest,
        epoch=epoch, state_digest=state_digest,
        reasons=list(reasons or []), adverse_commitment=adverse_commitment,
        storage_ref=storage_ref,
        parent_commitments=list(inbound.parents()) if inbound else [],
        redactions=list(redactions), downgraded=downgraded,
        fallback_via=fallback_via,
        trace=trace.to_jcs() if trace is not None else None,
        response_digest=response_digest, signer_key_id=signer_key_id,
        at_ms=now_ms if now_ms is not None else int(time.time() * 1000),
    )
