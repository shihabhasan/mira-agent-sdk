"""Redaction that a hot path can afford: by schema, not by reading.

The Redact disposition lets an interaction proceed with a defined portion
removed. "Defined" is doing real work in that sentence. If deciding what to
remove meant classifying the content of a payload, redaction would be an
inference call sitting inside the microsecond decision path, which is the
one thing the design says never happens there.

So a redaction rule is a path and a fixed treatment. The path is a JSON pointer
into the payload; the treatment is remove, mask, or hash. The rule is
deterministic: the same payload and the same rule always produce the same
output, which is what lets the receipt name the paths that changed and lets an
auditor reproduce the released payload from the retained one.

What this cannot do is find a tax file number in a free-text field nobody
declared. That is a classifier's job, and a classifier's answer arrives as a
derived signal that policy turns into Gate or Elevate. Naming the limit is
part of the design; a redaction feature that quietly promised content
detection would be worse than none.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Treatment(StrEnum):
    REMOVE = "remove"     # the key disappears
    MASK = "mask"         # replaced with a fixed marker
    HASH = "hash"         # replaced with sha256 of the canonical value


@dataclass(frozen=True)
class RedactionRule:
    """One path, one treatment. Paths are RFC 6901 JSON pointers."""

    path: str
    treatment: Treatment = Treatment.MASK
    mask: str = "[REDACTED]"

    def __post_init__(self):
        if not self.path.startswith("/"):
            raise ValueError(f"redaction path must be a JSON pointer starting with '/': {self.path!r}")


def _walk(doc: Any, tokens: list[str]):
    """Yield (parent, key) for the pointer, or nothing if it does not resolve."""
    cur = doc
    for i, tok in enumerate(tokens):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict):
            if tok not in cur:
                return
            if i == len(tokens) - 1:
                yield cur, tok
                return
            cur = cur[tok]
        elif isinstance(cur, list):
            try:
                idx = int(tok)
            except ValueError:
                return
            if idx >= len(cur):
                return
            if i == len(tokens) - 1:
                yield cur, idx
                return
            cur = cur[idx]
        else:
            return


def _hash_value(v: Any) -> str:
    import rfc8785
    return "sha256:" + hashlib.sha256(rfc8785.dumps(v)).hexdigest()[:32]


@dataclass(frozen=True)
class RedactionResult:
    payload: Any
    applied: tuple[str, ...]        # paths that existed and were treated
    absent: tuple[str, ...]         # paths in the rule set that did not resolve

    @property
    def changed(self) -> bool:
        return bool(self.applied)


def apply_redactions(payload: Any, rules: list[RedactionRule]) -> RedactionResult:
    """Apply every rule that resolves. A path that does not exist is recorded
    as absent rather than raising, because "the field was not there" is a fact
    the receipt should carry, not an error that stops the release."""
    out = copy.deepcopy(payload)
    applied, absent = [], []
    for rule in rules:
        tokens = rule.path.split("/")[1:]
        hit = False
        for parent, key in _walk(out, tokens):
            hit = True
            if rule.treatment is Treatment.REMOVE:
                del parent[key]
            elif rule.treatment is Treatment.MASK:
                parent[key] = rule.mask
            else:
                # Unsalted on purpose: deterministic, so two payloads carrying
                # the same value redact to the same token and can be matched
                # by an auditor. The cost is that a low-entropy value is
                # guessable from its hash; use MASK for those.
                parent[key] = _hash_value(parent[key])
        (applied if hit else absent).append(rule.path)
    return RedactionResult(out, tuple(applied), tuple(absent))
