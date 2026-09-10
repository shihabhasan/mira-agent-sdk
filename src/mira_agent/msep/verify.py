"""Local verification: everything a receiving boundary checks, with no network.

This is the file the architecture stands on. If verification needed a call to
the control plane, MSEP would just be a gateway with extra steps, so every
check here works from the envelope plus locally cached trust material.

Three vectors, in cost order, cheapest first so a bad envelope is rejected
before anything expensive runs:

  1. Cryptographic provenance — signature by a known boundary key, freshness
     inside the accepted window, and the predecessor commitment intact.
  2. Deterministic permission bounds — is the requested action inside the
     permission state the envelope actually carries?
  3. Drift thresholds — a comparison against an already-derived signal, never
     a model call. Semantic analysis is welcome to be expensive; it just has
     to happen somewhere other than the hot path.

Successors get a fourth set: the monotonicity invariants. These are what make
a chain safe to verify one hop at a time. Because authority can only ever
narrow, a boundary that trusts the envelope in front of it does not need to
re-examine the whole history to know nothing was widened along the way.
"""

from __future__ import annotations

from mira_agent.msep._compat import _kid

import time
from dataclasses import dataclass, field
from enum import StrEnum

from mira_agent.msep import fast
from mira_agent.msep.envelope import Envelope, ExecutionState
from mira_agent.msep.trust import AdverseTrustAssertion, Severity, TrustEpoch


class Reject(StrEnum):
    """Why an envelope was refused. Named so a receipt can record the reason
    rather than a boolean nobody can investigate later."""

    UNKNOWN_KEY = "unknown_signing_key"
    BAD_SIGNATURE = "signature_invalid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    STALE_EPOCH = "stale_trust_epoch"
    POLICY_MISMATCH = "policy_version_mismatch"
    WRONG_DESTINATION = "scope_mismatch"
    STATE_MISMATCH = "execution_state_digest_mismatch"
    NOT_PERMITTED = "action_not_permitted"
    DRIFT = "drift_threshold_exceeded"
    REPLAY = "nonce_replayed"
    DEPTH_EXCEEDED = "delegation_depth_exceeded"
    # successor invariants
    BROKEN_LINK = "predecessor_commitment_mismatch"
    AUTHORITY_WIDENED = "authority_widened"
    TTL_EXTENDED = "ttl_extended_beyond_predecessor"
    DEPTH_NOT_MONOTONIC = "depth_not_monotonic"
    ADVERSE_TERMINAL = "actor_under_terminal_adverse_trust"
    ATTESTATION_MISMATCH = "key_presented_outside_certified_context"
    FOREIGN_ROOT = "issued_under_foreign_trust_root"
    KEY_REVOKED = "signing_key_revoked"
    KEY_EXPIRED = "signing_key_certificate_expired"
    STALE_STATE = "boundary_trust_state_too_stale"


@dataclass
class Verdict:
    ok: bool
    reasons: list[Reject] = field(default_factory=list)
    detail: str = ""
    checked_us: float = 0.0

    def __bool__(self) -> bool:
        return self.ok


class KeyCache:
    """The public key ring, resolved in memory.

    Verification must not do I/O, so trust material is distributed by the
    control plane out of band and held here. A key the cache does not know is
    a rejection, not a lookup: fetching on demand would put the control plane
    back on the hot path and hand an attacker a way to stall every hop.
    """

    def __init__(self, keys: dict[str, bytes] | None = None):
        self._keys: dict[str, bytes] = dict(keys or {})

    def add(self, key_id_hex: str, public_bytes: bytes) -> None:
        self._keys[key_id_hex] = public_bytes

    def add_keyring(self, keyring, names: list[str]) -> None:
        for n in names:
            k = keyring.get(n)
            self._keys[_kid(k)] = k.public_bytes

    def get(self, key_id_hex: str) -> bytes | None:
        return self._keys.get(key_id_hex)

    def add_mac_key(self, key_id_hex: str, shared_key: bytes) -> None:
        """A shared key for the intra-domain MAC mode. Stored alongside public
        keys under its id; the envelope's `alg` says which kind is expected."""
        if len(shared_key) != 32:
            raise ValueError("MAC key must be 32 bytes")
        self._keys[key_id_hex] = shared_key

    def exclude(self, key_id_hex: str) -> None:
        """Drop a compromised boundary key. Everything it signed stops
        verifying at the next hop that has received this exclusion."""
        self._keys.pop(key_id_hex, None)

    def __len__(self) -> int:
        return len(self._keys)


class ReplayWindow:
    """Bounded nonce memory.

    Unbounded would be a memory leak in someone else's process; a window keeps
    the cost fixed and the freshness TTL is what stops an old envelope being
    useful once its nonce has aged out.
    """

    def __init__(self, capacity: int = 65_536):
        self.capacity = capacity
        self._seen: dict[str, int] = {}

    def check_and_add(self, nonce: str, now_ms: int) -> bool:
        """False if this nonce has been seen before."""
        if nonce in self._seen:
            return False
        if len(self._seen) >= self.capacity:
            cutoff = sorted(self._seen.values())[len(self._seen) // 4]
            self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
        self._seen[nonce] = now_ms
        return True


# The Rust core, when the build has it. Switchable so the two paths can be
# compared on the same inputs.
_USE_RS = bool(getattr(fast, "_rs", None) and hasattr(fast._rs, "verify_inbound"))

_RESOLUTION_REJECTS = {
    "unknown": Reject.UNKNOWN_KEY, "revoked": Reject.KEY_REVOKED,
    "expired": Reject.KEY_EXPIRED, "not_yet_valid": Reject.KEY_EXPIRED,
    "foreign": Reject.FOREIGN_ROOT, "attestation": Reject.ATTESTATION_MISMATCH,
}


def verify_inbound(
    env: Envelope,
    *,
    keys: KeyCache,
    epoch: TrustEpoch,
    destination: str,
    state: ExecutionState | None = None,
    policy_digest: str | None = None,
    replay: ReplayWindow | None = None,
    drift_score: float = 0.0,
    drift_threshold: float = 1.0,
    adverse_lookup=None,
    now_ms: int | None = None,
) -> Verdict:
    """The tri-vector check. No I/O, no model call, no control-plane round trip."""
    t0 = time.perf_counter_ns()
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    bad: list[Reject] = []
    detail = ""

    # -- vector 1: cryptographic provenance -------------------------------
    # A certificate store answers with a reason and checks the attestation the
    # envelope presents against the one the key was certified for; a plain
    # key cache answers yes or no. Both are accepted so a deployment can start
    # with distributed keys and move to issued certificates without touching
    # the verifier.
    if hasattr(keys, "resolve"):
        res = keys.resolve(env.key_id, attestation=env.attestation)
        pub = res.public_bytes
        if pub is None:
            bad.append(_RESOLUTION_REJECTS.get(res.code, Reject.UNKNOWN_KEY))
            detail = res.reason
    else:
        pub = keys.get(env.key_id)
        if pub is None:
            bad.append(Reject.UNKNOWN_KEY)

    if _USE_RS and env.alg == fast.ALGORITHM:
        # The pure checks, in one Rust call: signature, clock, epoch, policy,
        # destination, depth, state digest, permission bound. Python keeps
        # what needs host state - replay memory, adverse cards, drift.
        import json as _json
        names = fast._rs.verify_inbound(
            env.signing_json, env.signature, pub, now, epoch.current,
            epoch.max_skew_ms, destination,
            _json.dumps(state.to_jcs()) if state is not None else None, policy_digest)
        bad.extend(Reject[n] for n in names)
        if Reject.STALE_EPOCH in bad:
            detail = detail or f"envelope epoch {env.epoch} < accepted {epoch.current}"
        if Reject.WRONG_DESTINATION in bad:
            detail = detail or f"envelope is scoped to {env.scope!r}, not {destination!r}"
        if replay is not None and not replay.check_and_add(env.nonce, now):
            bad.append(Reject.REPLAY)
        permitted_checked = True
    else:
        if pub is not None and not env.signature_valid(pub):
            bad.append(Reject.BAD_SIGNATURE)

        if now > env.expires_ms:
            bad.append(Reject.EXPIRED)
        if now + epoch.max_skew_ms < env.issued_ms:
            bad.append(Reject.NOT_YET_VALID)
        if not epoch.accepts(env.epoch):
            bad.append(Reject.STALE_EPOCH)
            detail = f"envelope epoch {env.epoch} < accepted {epoch.current}"
        if policy_digest is not None and env.policy_digest != policy_digest:
            bad.append(Reject.POLICY_MISMATCH)
        if env.scope != destination:
            bad.append(Reject.WRONG_DESTINATION)
            detail = detail or f"envelope is scoped to {env.scope!r}, not {destination!r}"
        if env.depth > env.max_depth:
            bad.append(Reject.DEPTH_EXCEEDED)
        if replay is not None and not replay.check_and_add(env.nonce, now):
            bad.append(Reject.REPLAY)

        # The envelope commits to a hash of the execution state. Recomputing it
        # here is what makes tampering with the payload, the action or the ruleset
        # at an intermediate hop detectable rather than merely discouraged.
        if state is not None and state.digest() != env.state_digest:
            bad.append(Reject.STATE_MISMATCH)
        permitted_checked = False

    # -- adverse trust state ----------------------------------------------
    # The envelope's own claim about the actor's standing is the *weakest*
    # thing consulted here. It is checked because a card travelling with the
    # action is what makes standing enforceable off-premises, but the
    # boundary's own record is always consulted too, and the more severe of
    # the two wins. Otherwise an actor escapes a terminal card by presenting a
    # stale mild one, which is the same evasion as omitting it with extra
    # steps.
    if env.adverse:
        card = AdverseTrustAssertion.from_wire(env.adverse)
        apub = keys.get(card.key_id)
        if apub is None or not card.signature_valid(apub):
            bad.append(Reject.BAD_SIGNATURE)
            detail = detail or "adverse trust assertion does not verify"
        elif card.severity is Severity.TERMINAL:
            bad.append(Reject.ADVERSE_TERMINAL)
            detail = detail or f"actor carries a terminal Red Card: {card.reason}"
    if adverse_lookup is not None and Reject.ADVERSE_TERMINAL not in bad:
        local = adverse_lookup(env.identity)
        if local is not None and local.severity is Severity.TERMINAL:
            bad.append(Reject.ADVERSE_TERMINAL)
            detail = detail or f"boundary holds a terminal Red Card: {local.reason}"

    # -- vector 2: deterministic permission bounds ------------------------
    if state is not None and not permitted_checked and not env.permissions.permits(
        state.action, state.target, state.artifact
    ):
        bad.append(Reject.NOT_PERMITTED)
    if Reject.NOT_PERMITTED in bad and state is not None:
        detail = detail or (
            f"{state.action} -> {state.target} ({state.artifact}) is outside the "
            "permission state this envelope carries"
        )

    # -- vector 3: drift threshold ----------------------------------------
    # A number produced elsewhere, compared here. Deriving it in this function
    # is what would make the decision path expensive.
    if drift_score > drift_threshold:
        bad.append(Reject.DRIFT)
        detail = detail or f"drift {drift_score:.3f} over threshold {drift_threshold:.3f}"

    return Verdict(
        ok=not bad, reasons=bad, detail=detail,
        checked_us=(time.perf_counter_ns() - t0) / 1000.0,
    )


def verify_succession(predecessor: Envelope, successor: Envelope) -> Verdict:
    """The monotonicity invariants across one hop.

    Authority may narrow, expire sooner and descend one level. It may never
    widen, outlive its parent, or claim a predecessor it does not actually
    commit to. Checking these locally is what lets a boundary trust a chain it
    has not seen the whole of.
    """
    t0 = time.perf_counter_ns()
    bad: list[Reject] = []
    detail = ""

    # A successor names its immediate parent, and a join names the others it
    # converged from. Either position is a genuine causal link, so accept the
    # predecessor in whichever one it occupies.
    if predecessor.commitment() not in successor.parents():
        bad.append(Reject.BROKEN_LINK)
    if not predecessor.permissions.subsumes(successor.permissions):
        bad.append(Reject.AUTHORITY_WIDENED)
        detail = "successor claims authority its predecessor did not hold"
    if successor.expires_ms > predecessor.expires_ms:
        bad.append(Reject.TTL_EXTENDED)
    if successor.depth != predecessor.depth + 1:
        bad.append(Reject.DEPTH_NOT_MONOTONIC)
    if successor.depth > successor.max_depth:
        bad.append(Reject.DEPTH_EXCEEDED)

    return Verdict(ok=not bad, reasons=bad, detail=detail,
                   checked_us=(time.perf_counter_ns() - t0) / 1000.0)
