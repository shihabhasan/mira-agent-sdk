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
class Signature:
    key_name: str
    key_id: str
    signature: bytes


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    mmr_size: int
    root_hex: str
    key_name: str
    key_id: str
    signatures: tuple[Signature, ...] = ()

    @property
    def body(self) -> str:
        root_b64 = base64.b64encode(bytes.fromhex(self.root_hex)).decode()
        return f"{self.origin}\n{self.mmr_size}\n{root_b64}\n"

    def witnesses(self) -> list[Signature]:
        """Every signature that is not the log's own."""
        return [s for s in self.signatures if s.key_name != self.key_name]


def _parse_signature_lines(sig_section: str) -> list[Signature]:
    """A C2SP note may carry MANY signature lines — that is how witnessing
    works. Unparseable lines are skipped rather than failing the whole note:
    an unknown witness must not stop the log's own signature verifying."""
    out: list[Signature] = []
    for line in sig_section.strip().split("\n"):
        line = line.strip()
        if not line.startswith(f"{EM_DASH} "):
            continue
        try:
            key_name, blob_b64 = line[len(EM_DASH) + 1:].split(" ", 1)
            blob = base64.b64decode(blob_b64, validate=True)
            out.append(Signature(key_name=key_name, key_id=blob[:4].hex(),
                                 signature=blob[4:]))
        except Exception:
            continue
    return out


def parse_checkpoint(note: str) -> Checkpoint | None:
    """Parse a note WITHOUT verifying it. Use verify_checkpoint to trust it."""
    try:
        body, sig_section = note.split("\n\n", 1)
        origin, size_str, root_b64 = body.split("\n")[:3]
        sigs = _parse_signature_lines(sig_section)
        if not sigs:
            return None
        return Checkpoint(
            origin=origin,
            mmr_size=int(size_str),
            root_hex=base64.b64decode(root_b64, validate=True).hex(),
            key_name=sigs[0].key_name,
            key_id=sigs[0].key_id,
            signatures=tuple(sigs),
        )
    except Exception:
        return None


def verify_checkpoint(note: str, key_name: str, public_bytes: bytes) -> Checkpoint | None:
    """Verify a note against the log's own key.

    Returns the parsed checkpoint on success and None on any failure — a bad
    checkpoint is an answer, not an exception.
    """
    try:
        body, _ = note.split("\n\n", 1)
        cp = parse_checkpoint(note)
        if cp is None:
            return None
        signed = (body + "\n").encode()
        for sig in cp.signatures:
            if sig.key_name == key_name and verify(public_bytes, sig.signature, signed):
                return cp
        return None
    except Exception:
        return None


def verify_witnesses(
    note: str, witness_keys: dict[str, bytes], *, threshold: int = 1
) -> tuple[bool, list[str]]:
    """Check independent witness co-signatures over the same checkpoint body.

    The log's own signature proves it published a root. It does NOT prove the
    log never rewrote history — an operator holding the log key can sign a
    different root for a different past. Witnesses are the answer: independent
    parties that only ever counter-sign a checkpoint consistent with what they
    have already seen, so a fork requires colluding with all of them.

    Returns (met_threshold, names_that_verified). Unknown signature lines are
    ignored; only keys the caller supplied can count toward the threshold.
    """
    try:
        body, _ = note.split("\n\n", 1)
    except ValueError:
        return False, []
    cp = parse_checkpoint(note)
    if cp is None:
        return False, []

    signed = (body + "\n").encode()
    verified = [
        s.key_name
        for s in cp.signatures
        if s.key_name in witness_keys
        and verify(witness_keys[s.key_name], s.signature, signed)
    ]
    return len(set(verified)) >= threshold, sorted(set(verified))
