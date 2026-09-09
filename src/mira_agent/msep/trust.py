"""Persistent adverse trust state, and the freshness that bounds local authority.

Most governance systems assess the interaction in front of them and then
forget. For a single request that is fine. For an agent running a long workflow
across several boundaries it is not: if trust resets to neutral after every
hop, an actor that has already done something serious arrives at the next
boundary looking exactly like one that has not.

An adverse trust assertion — a Red Card — makes a trust failure a property of
the actor rather than of the request that exposed it. It is issued by the
trusted boundary, never by the actor being assessed, bound to the causal event
that triggered it, and carried into every successor envelope until an
authorised resolution changes the posture. Reinstatement is a new event; it
does not erase the original.

The other half of this file is freshness. Local authority is only safe because
it expires. Epochs let the control plane invalidate everything issued before a
policy or trust change without having to reach each node synchronously: a node
holding an old epoch fails closed on its next verification rather than
continuing on state nobody can revoke.
"""

from __future__ import annotations

from mira_agent.msep._compat import _kid

import time
from dataclasses import dataclass
from enum import StrEnum

from mira_agent_core.keys import SigningKey
from mira_agent_core.keys import verify as verify_signature
from mira_agent_core.records import sha256_hex
from mira_agent.msep.envelope import _ENVELOPE_CONTEXT, _canon, _pae

_ADVERSE_CONTEXT = b"MSEP-v1-adverse"


class Severity(StrEnum):
    """How much of the actor's future the event should constrain."""

    # Recorded, carried, but does not itself change what the actor may do.
    NOTED = "noted"
    # Authority narrows: high-consequence capabilities are withheld.
    RESTRICTED = "restricted"
    # The actor is stopped. Continuing requires an authenticated, recorded
    # decision by someone willing to own it.
    TERMINAL = "terminal"


# The events serious enough to change an actor's standing rather than just
# fail a request. Named rather than inferred, because "what counts as
# serious" is a policy question and should be visible in the source.
CRITICAL_TRUST_EVENTS = frozenset({
    "envelope_tampering",
    "credential_bypass_attempt",
    "prohibited_exfiltration",
    "honey_tool_trip",
    "repeat_after_terminal_stop",
    "authority_widening_attempt",
})


@dataclass(frozen=True)
class AdverseTrustAssertion:
    """A Red Card. Issued by a boundary, about an execution identity."""

    subject: str
    severity: Severity
    reason: str
    trigger_commitment: str
    issued_by: str
    epoch: int
    issued_ms: int
    policy_digest: str = ""
    resolution: str | None = None
    key_id: str = ""
    signature: str = ""

    def signing_body(self) -> dict:
        return {
            "subject": self.subject,
            "severity": str(self.severity),
            "reason": self.reason,
            "triggerCommitment": self.trigger_commitment,
            "issuedBy": self.issued_by,
            "epoch": self.epoch,
            "issuedMs": self.issued_ms,
            "policyDigest": self.policy_digest,
            "resolution": self.resolution,
            "keyId": self.key_id,
        }

    def signing_bytes(self) -> bytes:
        return _pae(_ADVERSE_CONTEXT, _canon(self.signing_body()))

    def sign(self, key: SigningKey) -> "AdverseTrustAssertion":
        from dataclasses import replace
        a = replace(self, key_id=_kid(key))
        return replace(a, signature=key.sign(a.signing_bytes()).hex())

    def signature_valid(self, public_bytes: bytes) -> bool:
        if not self.signature:
            return False
        try:
            raw = bytes.fromhex(self.signature)
        except ValueError:
            return False
        return verify_signature(public_bytes, raw, self.signing_bytes())

    def commitment(self) -> str:
        return "sha256:" + sha256_hex(self.signing_bytes())

    def to_wire(self) -> dict:
        d = self.signing_body()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "AdverseTrustAssertion":
        return cls(
            subject=d["subject"], severity=Severity(d["severity"]),
            reason=d["reason"], trigger_commitment=d["triggerCommitment"],
            issued_by=d["issuedBy"], epoch=int(d["epoch"]),
            issued_ms=int(d["issuedMs"]), policy_digest=d.get("policyDigest", ""),
            resolution=d.get("resolution"), key_id=d.get("keyId", ""),
            signature=d.get("signature", ""),
        )


def issue_red_card(
    *, subject: str, reason: str, trigger_commitment: str, issued_by: str,
    epoch: int, key: SigningKey, severity: Severity = Severity.TERMINAL,
    policy_digest: str = "", now_ms: int | None = None,
) -> AdverseTrustAssertion:
    """Mint an adverse assertion. Only a boundary holding a signing key can.

    That the actor cannot issue one about itself is the point: an agent must
    not be able to clear, downgrade or forge its own standing.
    """
    if reason not in CRITICAL_TRUST_EVENTS:
        raise ValueError(
            f"{reason!r} is not a declared critical trust event. Adding one is a "
            "policy decision and belongs in CRITICAL_TRUST_EVENTS, not at a call site."
        )
    t = now_ms if now_ms is not None else int(time.time() * 1000)
    return AdverseTrustAssertion(
        subject=subject, severity=severity, reason=reason,
        trigger_commitment=trigger_commitment, issued_by=issued_by,
        epoch=epoch, issued_ms=t, policy_digest=policy_digest,
    ).sign(key)


def reinstate(
    card: AdverseTrustAssertion, *, authorised_by: str, key: SigningKey,
    now_ms: int | None = None,
) -> AdverseTrustAssertion:
    """Resolve a Red Card. A new signed event, not an erasure.

    The historical assertion stays in the lineage. What changes is the posture
    from here on, and who is on record as having decided that.
    """
    t = now_ms if now_ms is not None else int(time.time() * 1000)
    from dataclasses import replace
    return replace(
        card, severity=Severity.NOTED,
        resolution=f"reinstated_by:{authorised_by}", issued_ms=t,
        key_id="", signature="",
    ).sign(key)


@dataclass
class TrustEpoch:
    """The freshness horizon a boundary will accept.

    A node cannot learn about a revocation it has not received. Epochs make
    that bounded and explicit rather than hoping: authority minted before the
    current epoch is refused locally, so the blast radius of an unreachable
    control plane is one epoch rather than indefinite.
    """

    current: int
    max_skew_ms: int = 5_000

    def bump(self) -> int:
        """A revocation broadcast. Everything minted at the old epoch stops
        verifying at every boundary that has received the new one."""
        self.current += 1
        return self.current

    def accepts(self, epoch: int) -> bool:
        return epoch >= self.current
