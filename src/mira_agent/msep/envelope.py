"""The MSEP execution envelope: bounded authority that travels with the action.

A central policy engine is a network destination. When every governed hop has
to ask it for a decision, the control plane's latency and availability become
part of the execution path, and in a deep agentic workflow that cost repeats at
every step. MSEP inverts that: the authority needed for the next governed
action travels with the interaction, and the receiving boundary verifies it
locally against cached trust material.

The construction follows the protocol paper. A node forms the execution state

    X_n = payload digest || action || context || permissions

and the envelope commits to a hash of it rather than carrying it:

    E_n = Sign_k( H(E_{n-1}) || H(X_n) || T_n || scope || epoch || ... )

Hashing rather than carrying is what keeps the object bounded: the envelope
stays roughly a kilobyte no matter how deep the workflow runs, because it
references its immediate predecessor instead of accumulating history. The
causal graph is reassembled on the evidence plane, where size does not sit in
the hot path.

Two things this deliberately is not. It is not a bearer token being forwarded:
a successor is a fresh state minted by a trusted boundary after it has seen
what actually happened, which is why authority can narrow across a hop but
never widen. And it is not a transport: the interaction still travels over
whatever HTTP, gRPC, MCP or A2A the application already uses, with the envelope
riding alongside it.
"""

from __future__ import annotations

from mira_agent.msep._compat import _kid

import os
import time
from dataclasses import asdict, dataclass, field, replace
from typing import Any

import rfc8785

from mira_agent.msep import fast

from mira_agent_core.keys import SigningKey
from mira_agent_core.keys import verify as verify_signature
from mira_agent_core.records import sha256_hex

PROTOCOL = "msep/1"

# Domain separation. MIL provenance records and MSEP envelopes are both
# Ed25519 signatures made by the same keyring, so without distinct prefixes a
# signature over one could be presented as a signature over the other. The
# separator is inside the signed bytes, not beside them.
_ENVELOPE_CONTEXT = b"MSEP-v1-envelope"
_STATE_CONTEXT = b"MSEP-v1-state"

WILDCARD = "*"


def _canon(obj: Any) -> bytes:
    """RFC 8785 canonical bytes — the same canonicalisation the ledger uses, so
    a digest computed here means the same thing computed anywhere else."""
    return rfc8785.dumps(obj)


def _pae(context: bytes, body: bytes) -> bytes:
    """Length-prefixed authenticated encoding.

    Concatenating fields directly would let two different field splits produce
    identical bytes; length prefixes make the encoding unambiguous.
    """
    return b"%s %d %s" % (context, len(body), body)


@dataclass(frozen=True)
class Capability:
    """One permitted action shape. `*` widens a field to anything."""

    action: str
    target: str = WILDCARD
    artifact: str = WILDCARD

    def subsumes(self, other: "Capability") -> bool:
        """True when everything `other` permits, this already permitted."""
        return all(
            mine == WILDCARD or mine == theirs
            for mine, theirs in (
                (self.action, other.action),
                (self.target, other.target),
                (self.artifact, other.artifact),
            )
        )

    def permits(self, action: str, target: str, artifact: str) -> bool:
        return self.subsumes(Capability(action, target, artifact))

    def to_jcs(self) -> dict:
        return {"action": self.action, "target": self.target, "artifact": self.artifact}


@dataclass(frozen=True)
class Permissions:
    """The destination-applicable permission state.

    Compiled centrally from enterprise policy and carried in the envelope so
    the receiving boundary can decide without asking anyone. Deliberately a
    flat allowlist rather than a rule language: the hot path should be a
    comparison, not an evaluation.
    """

    caps: tuple[Capability, ...] = ()

    def permits(self, action: str, target: str, artifact: str) -> bool:
        return any(c.permits(action, target, artifact) for c in self.caps)

    def subsumes(self, other: "Permissions") -> bool:
        """Every capability the successor claims must already be covered here.

        This is the invariant that makes a hop safe to verify locally. A
        successor may drop or narrow capabilities; it can never introduce one
        its predecessor did not hold, so authority is monotonically
        non-increasing along a chain no matter how many hops it crosses.
        """
        return all(any(mine.subsumes(theirs) for mine in self.caps) for theirs in other.caps)

    def narrowed_to(self, *caps: Capability) -> "Permissions":
        """A subset of this permission state, refusing anything not covered."""
        for c in caps:
            if not self.permits(c.action, c.target, c.artifact):
                raise ValueError(
                    f"cannot narrow to {c.action}/{c.target}/{c.artifact}: it is not "
                    "permitted by the state being narrowed, and narrowing may only "
                    "remove authority"
                )
        return Permissions(tuple(caps))

    def to_jcs(self) -> list[dict]:
        return [c.to_jcs() for c in self.caps]

    @classmethod
    def from_jcs(cls, rows: list[dict]) -> "Permissions":
        return cls(tuple(Capability(r["action"], r.get("target", WILDCARD),
                                    r.get("artifact", WILDCARD)) for r in rows))


@dataclass(frozen=True)
class ExecutionState:
    """X_n — what the authority is actually about.

    Hashed into the envelope rather than carried, so altering the payload, the
    action or the ruleset at an intermediate hop changes H(X_n) and breaks
    every signature downstream of it.
    """

    payload_digest: str
    action: str
    target: str
    artifact: str
    context_digest: str = ""
    permissions: Permissions = field(default_factory=Permissions)
    # What executing this does to the world beyond the boundary. "none" and
    # "idempotent" can be recovered by re-running; "external" cannot, because
    # the side effect already happened somewhere the boundary cannot see, and
    # Recover & resend for such a step is a second copy of it rather than a
    # retry. The boundary downgrades Recover to Elevate on that basis.
    side_effects: str = "none"

    def to_jcs(self) -> dict:
        return {
            "payloadDigest": self.payload_digest,
            "action": self.action,
            "target": self.target,
            "artifact": self.artifact,
            "contextDigest": self.context_digest,
            "permissions": self.permissions.to_jcs(),
            "sideEffects": self.side_effects,
        }

    def digest(self) -> str:
        """H(X_n)."""
        jcs = self.to_jcs()
        return fast.state_digest(
            jcs, lambda: "sha256:" + sha256_hex(_pae(_STATE_CONTEXT, _canon(jcs))))


@dataclass(frozen=True)
class Envelope:
    """E_n — the signed, bounded hot-path object."""

    v: str
    identity: str
    state_digest: str
    predecessor: str | None
    scope: str
    permissions: Permissions
    epoch: int
    policy_digest: str
    issued_ms: int
    expires_ms: int
    depth: int
    max_depth: int
    nonce: str
    adverse: dict | None = None
    # A reference to the attested execution context that minted this state — a
    # TPM quote, an SVID serial, an enclave measurement. The identity says who
    # the actor claims to be; this says which trusted context vouched for it.
    # Carried and signed rather than interpreted here: what counts as an
    # acceptable attestation is a deployment decision, and baking one scheme
    # into the protocol would tie MSEP to whichever hardware root is fashionable.
    attestation: str | None = None
    # Additional parent commitments for a join. A fan-in step is caused by more
    # than one predecessor, and recording only the last one to arrive would
    # make the causal graph claim something untrue about why the step ran.
    co_predecessors: tuple[str, ...] = ()
    # Named, because a verifier that has to guess the algorithm from the key
    # length is a verifier with a downgrade path. Ed25519 for hops that cross
    # a trust boundary; a keyed BLAKE3 tag for hops inside one, where the
    # control plane can distribute a shared key and the ~5x cheaper check is
    # worth the key-distribution problem it brings.
    alg: str = "Ed25519"
    key_id: str = ""
    signature: str = ""

    # ------------------------------------------------------------- signing
    def signing_body(self) -> dict:
        """Everything the signature covers. Excludes the signature itself."""
        return {
            "v": self.v,
            "identity": self.identity,
            "stateDigest": self.state_digest,
            "predecessor": self.predecessor,
            "scope": self.scope,
            "permissions": self.permissions.to_jcs(),
            "epoch": self.epoch,
            "policyDigest": self.policy_digest,
            "issuedMs": self.issued_ms,
            "expiresMs": self.expires_ms,
            "depth": self.depth,
            "maxDepth": self.max_depth,
            "nonce": self.nonce,
            "adverse": self.adverse,
            "attestation": self.attestation,
            "coPredecessors": list(self.co_predecessors),
            "alg": self.alg,
            "keyId": self.key_id,
        }

    def signing_bytes(self) -> bytes:
        return _pae(_ENVELOPE_CONTEXT, _canon(self.signing_body()))

    def parents(self) -> tuple[str, ...]:
        """Every commitment this state names as a cause of itself."""
        first = (self.predecessor,) if self.predecessor else ()
        return first + tuple(self.co_predecessors)

    def commitment(self) -> str:
        """H(E_n) — what a successor names as its predecessor.

        Computed over the signing input rather than the whole envelope, so the
        commitment is stable regardless of how the envelope is serialised on
        the wire.
        """
        return "sha256:" + sha256_hex(self.signing_bytes())

    def sign(self, key: SigningKey) -> "Envelope":
        e = replace(self, key_id=_kid(key), alg=fast.ALGORITHM)
        return replace(e, signature=key.sign(e.signing_bytes()).hex())

    def sign_mac(self, shared_key: bytes, key_id: str) -> "Envelope":
        """Tag with a shared key instead of signing. Intra-domain only: any
        holder of the key can mint a valid tag, so this must never cross a
        boundary that has to be unable to forge."""
        e = replace(self, key_id=key_id, alg=fast.MAC_ALGORITHM)
        return replace(e, signature=fast.mac_tag(shared_key, e.signing_body()))

    def signature_valid(self, key_bytes: bytes) -> bool:
        """`key_bytes` is the public key for Ed25519, the shared key for MAC."""
        if not self.signature:
            return False
        if self.alg == fast.MAC_ALGORITHM:
            return fast.mac_verify(key_bytes, self.signing_body(), self.signature)
        if self.alg != fast.ALGORITHM:
            return False
        return fast.verify_envelope(self.signing_body(), self.signature, key_bytes,
                                    signing_bytes=self.signing_bytes())

    # ------------------------------------------------------------ transport
    def to_wire(self) -> dict:
        d = self.signing_body()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "Envelope":
        return cls(
            v=d["v"], identity=d["identity"], state_digest=d["stateDigest"],
            predecessor=d.get("predecessor"), scope=d["scope"],
            permissions=Permissions.from_jcs(d.get("permissions") or []),
            epoch=int(d["epoch"]), policy_digest=d["policyDigest"],
            issued_ms=int(d["issuedMs"]), expires_ms=int(d["expiresMs"]),
            depth=int(d["depth"]), max_depth=int(d["maxDepth"]),
            nonce=d["nonce"], adverse=d.get("adverse"),
            attestation=d.get("attestation"),
            co_predecessors=tuple(d.get("coPredecessors") or ()),
            alg=_known_alg(d.get("alg", "Ed25519")),
            key_id=d.get("keyId", ""), signature=d.get("signature", ""),
        )

    def wire_size(self) -> int:
        return len(_canon(self.to_wire()))


def _known_alg(alg: str) -> str:
    if alg not in (fast.ALGORITHM, fast.MAC_ALGORITHM):
        raise ValueError(f"unsupported envelope algorithm {alg!r}")
    return alg


def new_envelope(
    *,
    identity: str,
    state: ExecutionState,
    scope: str,
    permissions: Permissions,
    epoch: int,
    policy_digest: str,
    key: SigningKey,
    ttl_ms: int = 30_000,
    predecessor: str | None = None,
    depth: int = 0,
    max_depth: int = 16,
    adverse: dict | None = None,
    attestation: str | None = None,
    co_predecessors: tuple[str, ...] = (),
    now_ms: int | None = None,
) -> Envelope:
    """Mint a root envelope. Successors come from `rematerialise`, not here."""
    t = now_ms if now_ms is not None else int(time.time() * 1000)
    return Envelope(
        v=PROTOCOL, identity=identity, state_digest=state.digest(),
        predecessor=predecessor, scope=scope, permissions=permissions,
        epoch=epoch, policy_digest=policy_digest,
        issued_ms=t, expires_ms=t + ttl_ms,
        depth=depth, max_depth=max_depth,
        nonce=os.urandom(12).hex(), adverse=adverse, attestation=attestation,
        co_predecessors=tuple(co_predecessors),
    ).sign(key)
