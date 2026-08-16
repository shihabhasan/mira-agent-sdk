"""Ed25519 signing and verification, with C2SP-style key ids.

A key id is the first four bytes of SHA-256(name || 0x0A || 0x01 || pubkey),
the convention C2SP signed notes use — the same one the control plane's ledger
key follows, so a client key and a log key are named the same way.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ED25519_NOTE_TYPE = b"\x01"


def key_id(name: str, public_bytes: bytes) -> str:
    h = hashlib.sha256(name.encode() + b"\n" + ED25519_NOTE_TYPE + public_bytes)
    return h.digest()[:4].hex()


@dataclass(frozen=True)
class SigningKey:
    """A private Ed25519 key with a name. The name is part of the key id, so
    renaming a key changes its identity — deliberately."""

    name: str
    private: Ed25519PrivateKey

    @classmethod
    def generate(cls, name: str) -> "SigningKey":
        return cls(name=name, private=Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, name: str, seed: bytes) -> "SigningKey":
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        return cls(name=name, private=Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def load(cls, name: str, path: str | Path) -> "SigningKey":
        data = Path(path).read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 private key")
        return cls(name=name, private=key)

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.write_bytes(
            self.private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        p.chmod(0o600)  # a signing key is a credential

    @property
    def public_bytes(self) -> bytes:
        return self.private.public_key().public_bytes_raw()

    @property
    def key_id(self) -> str:
        return key_id(self.name, self.public_bytes)

    @property
    def public_b64(self) -> str:
        import base64

        return base64.b64encode(self.public_bytes).decode()

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)


def verify(public_bytes: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a raw Ed25519 signature. Never raises — a bad signature is an
    answer, not an exception."""
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
