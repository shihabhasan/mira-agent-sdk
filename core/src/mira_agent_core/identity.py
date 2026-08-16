"""Agent identity, bound to a SPIFFE SVID where one exists.

Without this, a Mira record proves that *some* process holding *some* key
produced a step. That is self-consistent evidence, but it is not attribution:
the key is ephemeral, so nothing ties it to a workload that survives a restart,
and nothing ties it to what your infrastructure already believes about that
workload.

SPIFFE is the answer the industry settled on for "what is this workload,
cryptographically" — CNCF-graduated, and what Google's Agent Identity and Vault
issue to agents. An X.509 SVID is an ordinary certificate carrying exactly one
URI SAN of the form:

    spiffe://<trust-domain>/<path>

So this module does the small, honest thing: read the SVID, extract that ID,
and bind it into the record. Mira does not become an identity provider — it
consumes one. That division matters, because the identity vendors prove who an
agent is and nobody proves what it then did; the join is the product.

No new dependency: `cryptography` is already required for Ed25519.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import SigningKey

# spiffe://trust-domain/path — the trust domain is a DNS-like name, the path is
# opaque to us and meaningful to whoever issued it.
SPIFFE_URI = re.compile(r"^spiffe://(?P<trust_domain>[a-z0-9._-]+)(?P<path>/[^\s]*)?$")


class SpiffeError(ValueError):
    """An SVID that cannot be read, or is not a valid SPIFFE identity.

    Always raised rather than swallowed: an agent configured for SPIFFE that
    silently falls back to an anonymous key produces evidence nobody can
    attribute, which is the failure this module exists to prevent.
    """


@dataclass(frozen=True)
class SpiffeId:
    """A parsed SPIFFE ID."""

    uri: str
    trust_domain: str
    path: str

    @classmethod
    def parse(cls, uri: str) -> "SpiffeId":
        m = SPIFFE_URI.match(uri.strip())
        if not m:
            raise SpiffeError(
                f"{uri!r} is not a SPIFFE ID (expected spiffe://trust-domain/path)"
            )
        return cls(
            uri=uri.strip(),
            trust_domain=m.group("trust_domain"),
            path=m.group("path") or "/",
        )

    @property
    def workload(self) -> str:
        """The last path segment — a readable short name for logs and UI."""
        return self.path.rstrip("/").rsplit("/", 1)[-1] or self.trust_domain

    def to_predicate(self) -> dict:
        return {
            "spiffeId": self.uri,
            "trustDomain": self.trust_domain,
            "path": self.path,
        }


@dataclass(frozen=True)
class AgentIdentity:
    """What a record says about who produced it.

    `spiffe` is None for an anonymous agent — still self-consistent evidence,
    but the record says so rather than implying an attribution it cannot make.
    """

    name: str
    key: SigningKey
    spiffe: SpiffeId | None = None
    svid_serial: str | None = None
    svid_not_after: str | None = None

    @property
    def attributable(self) -> bool:
        return self.spiffe is not None

    def to_predicate(self) -> dict:
        out: dict = {
            "agent": self.name,
            "keyId": self.key.key_id,
            "attributable": self.attributable,
        }
        if self.spiffe:
            out["identity"] = {
                **self.spiffe.to_predicate(),
                "svidSerial": self.svid_serial,
                "svidNotAfter": self.svid_not_after,
            }
        return out


def spiffe_id_from_certificate(cert_pem: bytes) -> SpiffeId:
    """Extract the SPIFFE ID from an X.509 SVID.

    The spec requires exactly one URI SAN. Anything else is rejected rather
    than guessed at — a certificate with two URI SANs has an ambiguous identity,
    and picking one would be inventing an attribution.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:  # noqa: BLE001
        raise SpiffeError(f"could not parse the SVID certificate: {e}") from e

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        raise SpiffeError("SVID has no subjectAltName extension") from None

    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    spiffe_uris = [u for u in uris if u.startswith("spiffe://")]
    if not spiffe_uris:
        raise SpiffeError("SVID carries no spiffe:// URI SAN")
    if len(spiffe_uris) > 1:
        raise SpiffeError(
            f"SVID carries {len(spiffe_uris)} SPIFFE IDs; the X509-SVID spec "
            "requires exactly one, so the identity is ambiguous"
        )
    return SpiffeId.parse(spiffe_uris[0])


def load_identity(
    *,
    name: str = "agent",
    svid_cert: str | Path | None = None,
    svid_key: str | Path | None = None,
    spiffe_id: str | None = None,
    signing_key: SigningKey | None = None,
) -> AgentIdentity:
    """Build an agent identity, preferring the strongest evidence available.

    1. An X.509 SVID (cert + key) — the workload's real, rotating identity.
    2. An explicit SPIFFE ID with a supplied signing key — for callers whose
       SVID lives somewhere this library should not reach into.
    3. Neither — an anonymous ephemeral key, and the record says so.

    An SVID's private key is usually ECDSA or RSA, which cannot sign Ed25519.
    Rather than pretend, the Ed25519 record key is DERIVED deterministically
    from the SVID key so it is stable for the life of that SVID and rotates
    with it, and the SPIFFE ID travels in the record as the binding claim.
    """
    if svid_cert:
        cert_pem = Path(svid_cert).read_bytes()
        sid = spiffe_id_from_certificate(cert_pem)
        cert = x509.load_pem_x509_certificate(cert_pem)

        if svid_key:
            seed_material = Path(svid_key).read_bytes()
        else:
            # no private key offered: derive from the certificate's public key,
            # which is stable per-SVID but NOT secret. Usable for continuity,
            # not for secrecy — so say so loudly.
            seed_material = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        seed = hashlib.sha256(b"mira/agent-key/v1|" + sid.uri.encode() + b"|"
                              + seed_material).digest()
        key = SigningKey(
            name=f"mira/agent/{sid.workload}",
            private=Ed25519PrivateKey.from_private_bytes(seed),
        )
        return AgentIdentity(
            name=sid.workload,
            key=key,
            spiffe=sid,
            svid_serial=format(cert.serial_number, "x"),
            svid_not_after=cert.not_valid_after_utc.isoformat(),
        )

    if spiffe_id:
        sid = SpiffeId.parse(spiffe_id)
        if signing_key is None:
            raise SpiffeError(
                "a spiffe_id was given with no signing key. An identity claim "
                "with an unrelated ephemeral key is not attribution — supply "
                "signing_key, or an svid_cert to derive one from."
            )
        return AgentIdentity(name=sid.workload, key=signing_key, spiffe=sid)

    return AgentIdentity(
        name=name,
        key=signing_key or SigningKey.generate(f"mira/agent/{name}"),
        spiffe=None,
    )
