# mira-agent-core-rs

The Mira record core in Rust: RFC 8785 canonicalisation, SHA-256, DSSE
pre-authentication encoding, Ed25519, and Merkle Mountain Range proof
verification.

## Why this exists

Not for speed. It is ~1.6x faster than the Python core end to end, which is not
enough on its own to justify a compiled dependency.

It exists so there is **one implementation**. A Go or Rust gateway that needed
to canonicalise a record would otherwise be a third implementation of RFC 8785
to keep byte-identical with the other two — and if any of them drifts, records
signed by one fail verification by another, which looks like a crypto bug and
is actually a serialisation bug.

This crate links into a native gateway directly, and into Python through PyO3.

## Verification

Proven against `../vectors/conformance.json` — the same fixtures the control
plane generated, that the pure-Python core is already pinned to. One vector
file, every implementation, byte for byte.

That proof earned its keep immediately: the first build passed every case
except an integer past 2^53. JCS serialises numbers per ECMAScript, so Python
carries those as strings; Rust was canonicalising the raw number. Every
signature over such a record would have verified on one side and failed on the
other. The vectors caught it before a line of it shipped.

## Build

```bash
cargo test --no-default-features     # pure-Rust logic, no libpython needed
PYO3_PYTHON=/path/to/python3.12 cargo build --release
```

Needs a C toolchain (`build-essential` on Debian/Ubuntu). PyO3 0.22 supports
Python up to 3.13, so point `PYO3_PYTHON` at a suitable interpreter if the
system default is newer.

## Use from Python

Pure Python remains the default so nothing needs a compiler to install:

```bash
MIRA_CORE_BACKEND=rust python -m your_agent
```

```python
import mira_agent_core
mira_agent_core.backend()         # 'python' | 'rust'
mira_agent_core.rust_available()  # is the compiled module importable
```

Apache-2.0.
