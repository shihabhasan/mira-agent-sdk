"""The sealing path: evidence without custody of the payload.

MSEP separates two things that are usually conflated. The *commitment* to what
happened is small, needs to reach Liora's ledger, and proves the transition.
The *execution state itself* can be large, is the customer's data, and needs
never leave storage the customer controls.

So the retained state is encrypted under a data key minted fresh for that one
record, the ciphertext is written to the customer's own sink, and the evidence
plane receives only a commitment, a storage reference and the wrapped key
material. The ledger can prove a record belongs to the history without being
able to read it, and without a residency conversation about payload data.

The invariant that matters commercially is in the wrapping. A data key wrapped
only to Liora would mean a customer who ends the relationship keeps ciphertext
it can no longer read — retention theatre. Dual wrapping fixes that: the same
key is wrapped independently to a customer-held recovery key, so either side
can reconstruct alone. `dual_wrapped` is what a procurement reviewer should be
pointed at.

What this module deliberately does not do is decide the customer's key custody
model. Escrow, split custody, KMS or HSM participation are all reachable by
supplying a different `KeyWrapper`; baking one in would make the residency
answer ours rather than theirs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mira_agent_core.records import sha256_hex

# Domain separator, so a state commitment can never be mistaken for an
# envelope commitment or a MIL record digest.
_SEAL_CONTEXT = b"MSEP-v1-sealed-state"


class Custody(StrEnum):
    """Who can ever turn ciphertext back into a record.

    CUSTOMER_ONLY is the default and the strongest claim: the data key is
    wrapped only to keys the customer holds, Liora keeps the commitment and
    the storage reference, and there is no key-release path through Liora
    to be subpoenaed. DUAL adds a Liora-held wrap for operational recovery,
    and makes Liora a decryption oracle for that record; it is a choice the
    customer opts into with its eyes open, not something that ships on.
    """

    CUSTOMER_ONLY = "customer-only"
    DUAL = "dual"
    ESCROW = "escrow"


class KeyWrapper(Protocol):
    """How a data key is protected for one holder.

    Deliberately narrow. Anything that can wrap and unwrap 32 bytes fits —
    a local key for tests, a customer KMS, an HSM, a threshold scheme.
    """

    name: str
    holder: str        # "customer", "liora", or an escrow agent

    def wrap(self, dek: bytes) -> str: ...
    def unwrap(self, wrapped: str) -> bytes: ...


class LocalWrapper:
    """A wrapper backed by one symmetric key held in this process.

    Real deployments use a KMS. This exists so the sealing path can be tested
    and demonstrated without one, and so the shape of the interface is fixed by
    something that actually runs.
    """

    def __init__(self, name: str, key: bytes | None = None, holder: str = "customer"):
        if key is not None and len(key) != 32:
            raise ValueError("wrapping key must be 32 bytes")
        self.name = name
        self.holder = holder
        self._key = key or os.urandom(32)

    def wrap(self, dek: bytes) -> str:
        nonce = os.urandom(12)
        return (nonce + AESGCM(self._key).encrypt(nonce, dek, self.name.encode())).hex()

    def unwrap(self, wrapped: str) -> bytes:
        raw = bytes.fromhex(wrapped)
        return AESGCM(self._key).decrypt(raw[:12], raw[12:], self.name.encode())


@dataclass(frozen=True)
class SealedState:
    """The ciphertext. Goes to the customer's storage sink, not to us."""

    ciphertext: bytes
    nonce: bytes
    commitment: str

    def size(self) -> int:
        return len(self.ciphertext)

    def recompute_commitment(self) -> str:
        """The commitment implied by the bytes actually held.

        Recomputed rather than read off the object, because the object may have
        come back from storage we do not control. Trusting the field would make
        the integrity check compare a claim against itself.
        """
        return "sha256:" + sha256_hex(_SEAL_CONTEXT + self.ciphertext)


@dataclass(frozen=True)
class Lodgement:
    """What the evidence plane receives.

    A commitment, where the ciphertext lives, and the data key wrapped to each
    holder. No plaintext, no ciphertext, and no unwrapped key — the ledger can
    prove membership and lineage while being unable to read the record.
    """

    commitment: str
    storage_ref: str
    nonce: str
    wrapped_keys: dict[str, str] = field(default_factory=dict)
    size_bytes: int = 0
    custody: str = Custody.CUSTOMER_ONLY
    # Whether any wrap is held by Liora. If true, Liora can read this record
    # and can be compelled to. A procurement reviewer should expect false.
    liora_can_decrypt: bool = False

    @property
    def dual_wrapped(self) -> bool:
        """True when at least two independent holders can recover the key.

        The property a customer should check before believing its retained
        history survives the end of the service relationship.
        """
        return len(self.wrapped_keys) >= 2

    def to_jcs(self) -> dict:
        return {
            "commitment": self.commitment,
            "storageRef": self.storage_ref,
            "nonce": self.nonce,
            "wrappedKeys": dict(sorted(self.wrapped_keys.items())),
            "sizeBytes": self.size_bytes,
            "custody": str(self.custody),
            "lioraCanDecrypt": self.liora_can_decrypt,
        }


def seal(
    plaintext: bytes, *, storage_ref: str, wrappers: list[KeyWrapper],
    aad: bytes = b"", custody: Custody = Custody.CUSTOMER_ONLY,
) -> tuple[SealedState, Lodgement]:
    """Encrypt retained state under a fresh key and lodge only the metadata.

    The data key is generated here and never returned, so nothing upstream can
    retain it by accident: recovery has to go through a wrapper, which is what
    makes the custody model auditable.
    """
    if not wrappers:
        raise ValueError(
            "sealing needs at least one key wrapper; a data key nobody can "
            "unwrap is indistinguishable from discarding the record"
        )
    liora_held = [w.name for w in wrappers if getattr(w, "holder", "customer") == "liora"]
    if custody is Custody.CUSTOMER_ONLY and liora_held:
        raise ValueError(
            f"custody is customer-only but {liora_held} would be held by Liora; "
            "a Liora-held wrap makes Liora a decryption oracle for this record, "
            "which is a choice the customer makes with custody=Custody.DUAL, not "
            "a default"
        )
    if custody is not Custody.CUSTOMER_ONLY and not any(
            getattr(w, "holder", "customer") == "customer" for w in wrappers):
        raise ValueError("every custody model requires at least one customer-held wrap")
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad or None)
    commitment = "sha256:" + sha256_hex(_SEAL_CONTEXT + ct)
    sealed = SealedState(ciphertext=ct, nonce=nonce, commitment=commitment)
    lodgement = Lodgement(
        commitment=commitment, storage_ref=storage_ref, nonce=nonce.hex(),
        wrapped_keys={w.name: w.wrap(dek) for w in wrappers},
        size_bytes=len(ct), custody=custody, liora_can_decrypt=bool(liora_held),
    )
    return sealed, lodgement


def reconstruct(
    sealed: SealedState, lodgement: Lodgement, *, wrapper: KeyWrapper,
    aad: bytes = b"",
) -> bytes:
    """Recreate the readable state locally, in the holder's own environment.

    Takes ciphertext from customer storage and key material from the evidence
    plane and puts them together where the caller is, which is the point: the
    ledger never has both halves.
    """
    # Against the bytes in hand, not against what the object claims about
    # itself. This is the check that catches storage returning something other
    # than what was sealed.
    if lodgement.commitment != sealed.recompute_commitment():
        raise ValueError(
            "lodgement does not describe this ciphertext; refusing to decrypt "
            "state whose commitment does not match the evidence"
        )
    wrapped = lodgement.wrapped_keys.get(wrapper.name)
    if wrapped is None:
        raise KeyError(
            f"no data key wrapped to {wrapper.name!r}; this holder cannot "
            f"recover this record (available: {sorted(lodgement.wrapped_keys)})"
        )
    dek = wrapper.unwrap(wrapped)
    try:
        return AESGCM(dek).decrypt(sealed.nonce, sealed.ciphertext, aad or None)
    except InvalidTag as e:
        raise ValueError("ciphertext failed authentication; it has been altered") from e
