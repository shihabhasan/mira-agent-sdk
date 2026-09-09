"""Who is allowed to mint authority, and how that is proven.

Moving the decision from one gateway to N boundaries multiplies the number of
places holding a signing key. That is the honest cost of the topology, and it
is not paid for by a table row. This module is the answer in code.

A boundary key is not trusted because it is in a cache. It is trusted because a
control-plane root has issued a short-lived certificate for it that names the
boundary, binds it to an attestation of the context it runs in, and expires.
A receiving boundary resolves keys through the certificate store, so a key
that is unknown, expired, revoked, issued by a root it does not trust, or
presented from a context other than the one it was certified for, does not
verify anything.

The blast radius of one compromised boundary is bounded three ways: its
certificate expires on its own, the root can revoke it and push the revocation
as a trust-epoch bump, and everything it signed is enumerable from the receipts
so the recovery is a list rather than a guess.

Cross-organisation trust is a different problem. It needs each side to trust
the other's root, which is a PKI and a governance agreement, not code. The
model here supports a foreign anchor so the shape is right, and marks
everything under it as foreign so policy can refuse it. It is deliberately not
counted as delivered.
"""

from __future__ import annotations

from mira_agent.msep._compat import _kid

import time
from dataclasses import dataclass, field, replace

import rfc8785

from mira_agent_core.keys import SigningKey
from mira_agent_core.keys import verify as verify_signature
from mira_agent_core.records import sha256_hex

_CERT_CONTEXT = b"MSEP-v1-boundary-cert"
DEFAULT_VALIDITY_MS = 24 * 3_600_000       # a day; rotation is routine, not an event


def _pae(ctx: bytes, body: bytes) -> bytes:
    return b"%s %d %s" % (ctx, len(body), body)


@dataclass(frozen=True)
class TrustAnchor:
    """A root that may issue boundary certificates.

    `foreign` marks an anchor belonging to another organisation. Authority
    chained to it is real but is another party's; whether to act on it is a
    policy decision, and by default the boundary refuses.
    """

    name: str
    public_bytes: bytes
    foreign: bool = False

    @property
    def key_id(self) -> str:
        return sha256_hex(b"anchor:" + self.name.encode() + b"\n" + self.public_bytes)[:16]


@dataclass(frozen=True)
class BoundaryCertificate:
    """A root's statement that this key belongs to this boundary, for now."""

    boundary: str
    key_id: str
    public_key_hex: str
    issuer: str
    not_before_ms: int
    not_after_ms: int
    epoch: int
    # What context the key was certified for. A key presented from a different
    # context is a key that has moved, and a key that has moved is the first
    # thing a compromise looks like.
    attestation: str | None = None
    signature: str = ""

    def signing_body(self) -> dict:
        return {
            "boundary": self.boundary, "keyId": self.key_id,
            "publicKey": self.public_key_hex, "issuer": self.issuer,
            "notBeforeMs": self.not_before_ms, "notAfterMs": self.not_after_ms,
            "epoch": self.epoch, "attestation": self.attestation,
        }

    def signing_bytes(self) -> bytes:
        return _pae(_CERT_CONTEXT, rfc8785.dumps(self.signing_body()))

    def signature_valid(self, anchor_public: bytes) -> bool:
        try:
            return verify_signature(anchor_public, bytes.fromhex(self.signature),
                                    self.signing_bytes())
        except ValueError:
            return False

    def to_wire(self) -> dict:
        d = self.signing_body(); d["signature"] = self.signature
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "BoundaryCertificate":
        return cls(boundary=d["boundary"], key_id=d["keyId"], public_key_hex=d["publicKey"],
                   issuer=d["issuer"], not_before_ms=int(d["notBeforeMs"]),
                   not_after_ms=int(d["notAfterMs"]), epoch=int(d["epoch"]),
                   attestation=d.get("attestation"), signature=d.get("signature", ""))


def issue_certificate(
    *, anchor_key: SigningKey, anchor_name: str, boundary: str, key: SigningKey,
    epoch: int, validity_ms: int = DEFAULT_VALIDITY_MS, attestation: str | None = None,
    now_ms: int | None = None,
) -> BoundaryCertificate:
    """The control plane certifies a boundary key. Short validity by default:
    a key that expires on its own needs no revocation to stop mattering."""
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    cert = BoundaryCertificate(
        boundary=boundary, key_id=_kid(key), public_key_hex=key.public_bytes.hex(),
        issuer=anchor_name, not_before_ms=now, not_after_ms=now + validity_ms,
        epoch=epoch, attestation=attestation,
    )
    return replace(cert, signature=anchor_key.sign(cert.signing_bytes()).hex())


@dataclass
class Resolution:
    public_bytes: bytes | None
    reason: str = ""
    foreign: bool = False
    code: str = "ok"

    def __bool__(self) -> bool:
        return self.public_bytes is not None


class CertificateStore:
    """Resolves a key id to a public key, or to a reason it does not.

    Drop-in for `KeyCache.get()` on the verify path, with the difference that
    the answer depends on time, on the issuing root, on revocation and on the
    attestation the caller presents.
    """

    def __init__(self, anchors: list[TrustAnchor] | None = None, *, now_ms=None):
        self._anchors: dict[str, TrustAnchor] = {a.name: a for a in (anchors or [])}
        self._certs: dict[str, BoundaryCertificate] = {}
        self._revoked: set[str] = set()
        self._now = now_ms or (lambda: int(time.time() * 1000))
        self.accept_foreign = False

    # ----------------------------------------------------------- roots
    def add_anchor(self, anchor: TrustAnchor) -> None:
        self._anchors[anchor.name] = anchor

    def federate(self, anchor: TrustAnchor) -> None:
        """Trust another organisation's root. Marked foreign, refused by
        default; this is the shape of cross-enterprise trust, not a claim to
        have solved its governance."""
        self._anchors[anchor.name] = replace(anchor, foreign=True)

    # ---------------------------------------------------------- certs
    def install(self, cert: BoundaryCertificate) -> None:
        anchor = self._anchors.get(cert.issuer)
        if anchor is None:
            raise ValueError(f"certificate issued by unknown root {cert.issuer!r}")
        if not cert.signature_valid(anchor.public_bytes):
            raise ValueError("certificate signature does not verify against its root")
        self._certs[cert.key_id] = cert

    def revoke(self, key_id: str) -> None:
        self._revoked.add(key_id)

    def rotate(self, old_key_id: str, new_cert: BoundaryCertificate) -> None:
        """Install the successor and retire the predecessor in one step, so
        there is no window in which both are valid by accident."""
        self.install(new_cert)
        self.revoke(old_key_id)

    # -------------------------------------------------------- resolve
    def resolve(self, key_id: str, *, attestation: str | None = None,
                check_attestation: bool = True) -> Resolution:
        cert = self._certs.get(key_id)
        if cert is None:
            return Resolution(None, "no certificate for this key", code="unknown")
        if key_id in self._revoked:
            return Resolution(None, "key revoked", code="revoked")
        now = self._now()
        if now < cert.not_before_ms:
            return Resolution(None, "certificate not yet valid", code="not_yet_valid")
        if now > cert.not_after_ms:
            return Resolution(None, "certificate expired", code="expired")
        anchor = self._anchors[cert.issuer]
        if anchor.foreign and not self.accept_foreign:
            return Resolution(None, f"issued under foreign root {cert.issuer!r}; refused by policy",
                              foreign=True, code="foreign")
        if check_attestation and cert.attestation is not None and attestation != cert.attestation:
            # The key is real but is being used from somewhere it was not
            # certified for. Treat as compromise, not as misconfiguration.
            return Resolution(None, "attestation does not match the certified context",
                              code="attestation")
        return Resolution(bytes.fromhex(cert.public_key_hex), foreign=anchor.foreign)

    def get(self, key_id: str) -> bytes | None:
        """KeyCache-compatible: the key if it is certified, valid and not
        revoked, without judging the context it is presented from.

        Used to verify things a boundary *signed* — Red Cards, Security Event
        Tokens — rather than envelopes it is *presenting*. Enforcing the
        attestation here would refuse every attested boundary's own
        signatures, since a card does not travel with a context.
        """
        return self.resolve(key_id, check_attestation=False).public_bytes

    def exclude(self, key_id: str) -> None:
        self.revoke(key_id)

    def __len__(self) -> int:
        return len(self._certs)

    def certificate(self, key_id: str) -> BoundaryCertificate | None:
        return self._certs.get(key_id)


# ------------------------------------------------------------ blast radius
@dataclass
class BlastRadius:
    key_id: str
    boundary: str | None
    receipts_signed: int
    successors_minted: list[str] = field(default_factory=list)
    identities_touched: list[str] = field(default_factory=list)
    first_ms: int | None = None
    last_ms: int | None = None

    def summary(self) -> str:
        return (f"key {self.key_id} ({self.boundary or 'unknown boundary'}): "
                f"{self.receipts_signed} transitions, {len(self.successors_minted)} "
                f"successors, {len(self.identities_touched)} identities")


def blast_radius(receipts, key_id: str, cert: BoundaryCertificate | None = None) -> BlastRadius:
    """What one compromised key could have affected.

    Enumerated from the evidence, so incident response starts from a list of
    exactly which successors to distrust and which actors to re-verify, rather
    than from an estimate. Every successor a compromised boundary minted is a
    successor the next hop accepted in good faith.
    """
    hits = [r for r in receipts if getattr(r, "signer_key_id", None) == key_id
            or (cert is not None and getattr(r, "boundary", None) == cert.boundary)]
    times = [r.at_ms for r in hits if getattr(r, "at_ms", None) is not None]
    return BlastRadius(
        key_id=key_id, boundary=cert.boundary if cert else None,
        receipts_signed=len(hits),
        successors_minted=[r.successor_commitment for r in hits if r.successor_commitment],
        identities_touched=sorted({r.identity for r in hits}),
        first_ms=min(times) if times else None, last_ms=max(times) if times else None,
    )
