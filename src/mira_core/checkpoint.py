"""C2SP tlog-checkpoint signed notes — parsing and verification.

This is the same note format Sigstore's Rekor v2 uses, which is the point: a
Mira checkpoint can be verified by ordinary transparency-log tooling, and the
log can eventually be co-signed by independent witnesses without changing the
format.

    <origin>\\n
    <tree size, ASCII decimal>\\n
    <base64 std root hash>\\n
    \\n
    — <keyname> <base64(4-byte keyID || signature)>\\n

The signature covers the body up to and including the trailing newline of the
last body line — not the blank line, not the signature lines. Base64 is
standard RFC 4648, and the signature-line dash is U+2014 EM DASH plus a space.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from .keys import verify

EM_DASH = "—"


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    mmr_size: int
    root_hex: str
    key_name: str
    key_id: str

    @property
    def body(self) -> str:
        root_b64 = base64.b64encode(bytes.fromhex(self.root_hex)).decode()
        return f"{self.origin}\n{self.mmr_size}\n{root_b64}\n"


def parse_checkpoint(note: str) -> Checkpoint | None:
    """Parse a note WITHOUT verifying it. Use verify_checkpoint to trust it."""
    try:
        body, sig_section = note.split("\n\n", 1)
        origin, size_str, root_b64 = body.split("\n")[:3]
        sig_line = sig_section.strip().split("\n")[0]
        if not sig_line.startswith(f"{EM_DASH} "):
            return None
        rest = sig_line[len(EM_DASH) + 1:]
        key_name, blob_b64 = rest.split(" ", 1)
        blob = base64.b64decode(blob_b64, validate=True)
        return Checkpoint(
            origin=origin,
            mmr_size=int(size_str),
            root_hex=base64.b64decode(root_b64, validate=True).hex(),
            key_name=key_name,
            key_id=blob[:4].hex(),
        )
    except Exception:
        return None


def verify_checkpoint(note: str, key_name: str, public_bytes: bytes) -> Checkpoint | None:
    """Verify a signed note against a public key.

    Returns the parsed checkpoint on success and None on any failure — a bad
    checkpoint is an answer, not an exception.
    """
    try:
        body, sig_section = note.split("\n\n", 1)
        sig_line = sig_section.strip().split("\n")[0]
        prefix = f"{EM_DASH} {key_name} "
        if not sig_line.startswith(prefix):
            return None
        blob = base64.b64decode(sig_line[len(prefix):], validate=True)
        signature = blob[4:]
        if not verify(public_bytes, signature, (body + "\n").encode()):
            return None
        return parse_checkpoint(note)
    except Exception:
        return None
