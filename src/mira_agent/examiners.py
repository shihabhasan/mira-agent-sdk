"""Examiner readings an agent can hand to the gate — signed, bound, and checked.

The control plane has been able to take a signed examiner reading for a while:
a registered examiner signs `{name, value, examinerId, examinerVersion,
payloadHash, issuedMs}`, and the gate verifies it against the registry before a
`signal.*` condition is allowed to see it. The SDK could not take part. Its only
way to pass a reading was `Mira.decide(signals={...})` — an unsigned dict that
the gate took on the caller's word — and `Run.authorize`, the one path that
seals a record, took no readings at all. Worse, it accepted `**proposal`, so a
`signals=` keyword was silently swallowed into the proposal: the rule that
should have held did not fire, the release beneath it did, and the sealed
record showed the reading sitting beside a release.

This module is the missing half, and it is a port rather than a re-design. The
canonical bytes must match the server's exactly, or an assertion signed on one
side of the seam will not verify on the other; `tests/test_examiners_parity.py`
in the server repository compares the two implementations directly.

What it keeps from the server, deliberately:

- A reading is about **one payload**. With no payload hash to bind it to, it is
  refused — otherwise any reading an examiner ever signed, over any content,
  would count for this action.
- An examiner is held to **what it registered**. Declaring a toxicity checker
  does not grant it authority over prompt injection.
- The **more alarming reading wins**, and a registered examiner only breaks a
  tie against the built-in one. The other order let a registered examiner
  lower a signal and release what the rulebook would have refused.
- A **future date** is refused, because freshness is `now - issued` and a
  future-dated reading never goes stale.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable

from mira_agent_core.keys import SigningKey
from mira_agent_core.keys import verify as verify_signature
from mira_agent_core.records import canonical, sha256_hex

SIGNAL_PREFIX = "signal."
BUILTIN_ID = "mira-basic"
ASSERTION_MAX_AGE_MS = 10 * 60 * 1000     # a reading is about a payload, not a period
FUTURE_SKEW_MS = 60_000                   # clock skew between examiner and boundary


def payload_hash(payload: str | bytes) -> str:
    """The binding an assertion is made against: SHA-256 of exactly what was
    examined. A caller whose payload must not leave its perimeter sends this
    instead of the payload."""
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    return sha256_hex(data)


@dataclass(frozen=True)
class Assertion:
    """A signed statement by an examiner about one payload."""

    name: str
    value: Any
    examiner_id: str
    examiner_version: str
    payload_hash: str
    issued_ms: int
    key_id: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        # "pii_medical" and "signal.pii_medical" are the same signal, and the
        # signature must cover the same bytes whichever way it was written.
        if not self.name.startswith(SIGNAL_PREFIX):
            object.__setattr__(self, "name", SIGNAL_PREFIX + self.name)

    @property
    def signal(self) -> str:
        return self.name

    def payload(self) -> dict:
        return {"name": self.signal, "value": self.value, "examinerId": self.examiner_id,
                "examinerVersion": self.examiner_version, "payloadHash": self.payload_hash,
                "issuedMs": self.issued_ms}

    def canonical(self) -> bytes:
        return canonical(self.payload())

    def to_dict(self) -> dict:
        return {**self.payload(), "keyId": self.key_id, "signature": self.signature}

    @classmethod
    def from_dict(cls, d: dict) -> "Assertion":
        return cls(name=str(d["name"]), value=d.get("value"),
                   examiner_id=str(d["examinerId"]),
                   examiner_version=str(d.get("examinerVersion", "")),
                   payload_hash=str(d.get("payloadHash", "")),
                   issued_ms=int(d.get("issuedMs", 0)),
                   key_id=str(d.get("keyId", "")), signature=str(d.get("signature", "")))


def sign_assertion(a: Assertion, key: SigningKey) -> Assertion:
    return replace(a, key_id=key.key_id,
                   signature=base64.b64encode(key.sign(a.canonical())).decode())


def verify_assertion(a: Assertion, public_bytes: bytes) -> bool:
    try:
        return verify_signature(public_bytes, base64.b64decode(a.signature, validate=True),
                                a.canonical())
    except Exception:
        return False


def _severity(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return float("-inf")
    return float(value)


@dataclass(frozen=True)
class Verified:
    """What the gate takes, and everything it did not."""

    signals: dict[str, Any]
    sources: dict[str, str]
    readings: dict[str, dict[str, Any]]
    rejected: list[dict]


def verified_signals(assertions: Iterable[Assertion], *,
                     public_key_for: Callable[[str], bytes | None],
                     now_ms: int, payload_hash: str | None,
                     declared_for: Callable[[str], set[str] | None] | None = None,
                     max_age_ms: int = ASSERTION_MAX_AGE_MS,
                     builtin_id: str = BUILTIN_ID) -> Verified:
    """Reduce assertions to the `{signal: value}` map the gate takes, keeping
    only those a registered examiner signed about this payload, recently, for a
    signal it registered to emit. The server's `verified_signals`, verbatim in
    behaviour."""
    signals: dict[str, Any] = {}
    sources: dict[str, str] = {}
    readings: dict[str, dict[str, Any]] = {}
    best: dict[str, tuple] = {}
    latest_per: dict[tuple[str, str], int] = {}
    rejected: list[dict] = []
    for a in assertions:
        pub = public_key_for(a.examiner_id)
        why = None
        if pub is None:
            why = f"examiner {a.examiner_id!r} is not registered in this workspace"
        elif not verify_assertion(a, pub):
            why = "signature does not verify against the registered key"
        elif payload_hash is None:
            why = ("no payload to bind the reading to; send the payload, or the "
                   "SHA-256 of it, with the assertion")
        elif a.payload_hash != payload_hash:
            why = "assertion is about a different payload"
        elif a.issued_ms - now_ms > FUTURE_SKEW_MS:
            why = "assertion is dated in the future"
        elif now_ms - a.issued_ms > max_age_ms:
            why = f"assertion is older than {max_age_ms // 60000} minutes"
        elif (declared := (declared_for(a.examiner_id) if declared_for else None)) is not None \
                and a.signal not in declared:
            why = (f"examiner {a.examiner_id!r} did not register {a.signal!r}; it emits "
                   f"{', '.join(sorted(declared)) or 'nothing'}")
        if why:
            rejected.append({"name": a.signal, "examiner": a.examiner_id, "reason": why})
            continue
        pk = (a.signal, a.examiner_id)
        if pk not in latest_per or a.issued_ms >= latest_per[pk]:
            readings.setdefault(a.signal, {})[a.examiner_id] = a.value
            latest_per[pk] = a.issued_ms
        # Severity first, registered as the tiebreak — the fail-closed order.
        rank = (_severity(a.value), 0 if a.examiner_id == builtin_id else 1)
        if a.signal not in best or rank > best[a.signal]:
            signals[a.signal] = a.value
            sources[a.signal] = a.examiner_id
            best[a.signal] = rank
    return Verified(signals, sources, readings, rejected)


@dataclass(frozen=True)
class Roster:
    """The examiners registered in a workspace, pinned at construction.

    Fail-closed exactly as the policy bundle is: with no roster, no assertion
    verifies, no `signal.*` enters the request, and a condition on an absent
    field never holds.
    """

    keys: dict[str, bytes]
    declared: dict[str, frozenset[str]]

    @classmethod
    def empty(cls) -> "Roster":
        return cls({}, {})

    @classmethod
    def from_api(cls, body: dict) -> "Roster":
        keys: dict[str, bytes] = {}
        declared: dict[str, frozenset[str]] = {}
        for e in body.get("examiners", []):
            eid = e.get("examiner_id")
            raw = e.get("public_key_b64")
            if not eid or not raw:
                continue
            try:
                keys[eid] = base64.b64decode(raw, validate=True)
            except Exception:
                continue
            declared[eid] = frozenset(
                s if s.startswith(SIGNAL_PREFIX) else SIGNAL_PREFIX + s
                for s in (e.get("signals") or {}))
        return cls(keys, declared)

    def public_key_for(self, examiner_id: str) -> bytes | None:
        return self.keys.get(examiner_id)

    def declared_for(self, examiner_id: str) -> set[str] | None:
        d = self.declared.get(examiner_id)
        return set(d) if d is not None else None
