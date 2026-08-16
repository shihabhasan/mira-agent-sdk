"""Which implementation of the record core is in use.

There are two, and they are proven byte-identical by `vectors/conformance.json`
— the same fixtures the control plane generated. That proof is the whole point
of having a second implementation at all.

**Pure Python is the default, deliberately.** The Rust core is roughly 1.6x
faster end to end for sealing a record, which is not enough to justify making
every install need a compiler or a platform wheel. Python's Ed25519 already
delegates to OpenSSL, so signing is a wash; the gain is concentrated in
canonicalisation and hashing, and most of that is eaten crossing the FFI
boundary for small records.

The Rust core exists for a different reason: **a Go or Rust gateway can link
it** and get identical bytes without a third implementation of RFC 8785 to keep
in step. Accelerating Python is a side effect, offered here for anyone sealing
at high volume who has the wheel available.

    MIRA_CORE_BACKEND=rust     opt in (raises if unavailable)
    MIRA_CORE_BACKEND=python   force pure Python
    unset                      pure Python

Whichever is active, `backend()` reports it, so nobody has to guess which code
produced a record.
"""

from __future__ import annotations

import os

_RUST = None
try:  # pragma: no cover - depends on whether the compiled wheel is installed
    import mira_agent_core_rs as _rs

    _RUST = _rs
except ImportError:
    _RUST = None


def rust_available() -> bool:
    return _RUST is not None


def _selected() -> str:
    want = os.environ.get("MIRA_CORE_BACKEND", "python").strip().lower()
    if want == "rust":
        if _RUST is None:
            raise RuntimeError(
                "MIRA_CORE_BACKEND=rust but mira_agent_core_rs is not installed. "
                "Build it with: cd core-rs && maturin build --release"
            )
        return "rust"
    if want not in ("python", "rust"):
        raise RuntimeError(
            f"MIRA_CORE_BACKEND={want!r} is not a backend. Use 'python' or 'rust'."
        )
    return "python"


def backend() -> str:
    """The active backend: 'python' or 'rust'."""
    return _selected()


def rust() -> object | None:
    """The Rust module when it is both installed and selected, else None."""
    return _RUST if _selected() == "rust" else None
