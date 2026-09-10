"""The hot-path primitives, from Rust when it is built and Python when not.

The protocol logic stays in Python; only the parts measured to cost something
go through `mira_core`. Both implementations produce identical bytes, and the
test suite proves it on every run, so which one is loaded is a deployment
detail rather than a correctness question.
"""

from __future__ import annotations

import json
from typing import Any

try:
    import mira_agent_core_rs as _rs
    if not hasattr(_rs, "verify_envelope"):
        raise ImportError("mira_agent_core_rs built without the MSEP hot path")
    AVAILABLE = True
    ALGORITHM = _rs.ALGORITHM
    MAC_ALGORITHM = _rs.MAC_ALGORITHM
except ImportError:            # pragma: no cover - exercised on boxes without the build
    _rs = None
    AVAILABLE = False
    ALGORITHM = "Ed25519"
    MAC_ALGORITHM = "BLAKE3-keyed"


def _j(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))


def verify_envelope(body: dict | str, signature_hex: str, public_bytes: bytes,
                    signing_bytes: bytes | None = None) -> bool:
    if _rs is not None:
        return _rs.verify_envelope(body if isinstance(body, str) else _j(body),
                                   signature_hex, public_bytes)
    from mira_agent_core.keys import verify as verify_signature
    try:
        return verify_signature(public_bytes, bytes.fromhex(signature_hex), signing_bytes)
    except ValueError:
        return False


def canon(obj: Any, fallback) -> bytes:
    """RFC 8785 canonical bytes. The Python canonicaliser is the single most
    expensive thing in a hop once verification is in Rust — it ran five times
    per hop and cost more than the signature it fed — so it goes through the
    core too. Identical bytes either way; the conformance vectors prove it."""
    if _rs is not None:
        return _rs.canon(_j(obj))
    return fallback()


def state_digest(state_jcs: dict, fallback) -> str:
    if _rs is not None:
        return _rs.state_digest(_j(state_jcs))
    return fallback()


def permits(caps: list[tuple[str, str, str]], action: str, target: str, artifact: str,
            fallback=None) -> bool:
    if _rs is not None:
        return _rs.permits(caps, action, target, artifact)
    return fallback()


class MacUnavailable(RuntimeError):
    """MAC mode needs the Rust core.

    Keyed BLAKE3 is not in the Python standard library, and a fallback that
    used a different keyed hash would produce tags the Rust side rejects and
    accept tags it never made. An incompatible fallback is a silent
    interoperability bug; refusing is a loud configuration one.
    """


def mac_tag(key: bytes, body: dict) -> str:
    if _rs is None:
        raise MacUnavailable("MAC mode requires the mira_agent_core_rs build")
    return _rs.mac_tag(key, _j(body))


def mac_verify(key: bytes, body: dict, tag_hex: str) -> bool:
    if _rs is None:
        raise MacUnavailable("MAC mode requires the mira_agent_core_rs build")
    return _rs.mac_verify(key, _j(body), tag_hex)
