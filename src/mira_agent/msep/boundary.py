"""The MSEP execution boundary: one hop, start to finish.

This is the component that actually repeats. It receives an interaction with
an envelope, verifies that envelope locally, decides what to do, releases what
is permitted, mints a successor for the next destination, and queues the
evidence. The central plane distributes policy, keys and trust epochs; it is
not consulted during any of that.

The ordering matters and is not arbitrary:

    verify -> decide -> execute -> re-materialise -> seal

Verification precedes the decision so an unverifiable envelope never reaches
policy. The successor is minted after execution rather than before, because it
has to describe what actually happened rather than what was requested — that is
the difference between re-materialisation and forwarding a token. And sealing
comes last, off the critical path, so evidence can never be the reason an
action is slow.

The agent is outside all of this. It cannot mint authority, widen its own
permissions, clear its own adverse trust state or decline to be observed,
because none of those things live in the agent's process.
"""

from __future__ import annotations

from mira_agent.msep._compat import _kid

import time
from dataclasses import dataclass, replace
from typing import Callable

from mira_agent_core.keys import SigningKey
from mira_agent_core.records import sha256_hex
from mira_agent.msep.disposition import Disposition
from mira_agent.msep.envelope import (Capability, Envelope, ExecutionState, Permissions,
                                new_envelope)
from mira_agent.msep.receipt import Receipt, ReceiptQueue, compile_receipt
from mira_agent.msep.trace import TraceContext
from mira_agent.msep.freshness import Consequence, SyncState, consequence_of
from mira_agent.msep.signals import ingest as ingest_signal
from mira_agent.msep.trust import (AdverseTrustAssertion, Severity, TrustEpoch,
                             issue_red_card)
from mira_agent.msep.verify import (KeyCache, Reject, ReplayWindow, Verdict,
                              verify_inbound, verify_succession)

# A rejection that means the actor misbehaved, not merely that the request was
# outside policy. Being outside policy is ordinary and gets an interdiction;
# these are attempts to defeat the mechanism itself and change the actor's
# standing.
_TRUST_FAILURES: dict[Reject, str] = {
    Reject.BAD_SIGNATURE: "envelope_tampering",
    Reject.STATE_MISMATCH: "envelope_tampering",
    Reject.AUTHORITY_WIDENED: "authority_widening_attempt",
    Reject.REPLAY: "envelope_tampering",
}


@dataclass(frozen=True)
class PolicyOutcome:
    """What local policy decided, once the envelope has already verified.

    Separate from the verdict on purpose. Verification answers "is this
    authority real and does it cover this action"; policy answers "given that
    it does, what should happen". Keeping them apart is what stops a policy
    hook being able to wave through something that failed verification — the
    hook is only ever consulted on a verdict that already passed.
    """

    disposition: Disposition = Disposition.RELEASE
    reason: str = ""
    # Field paths removed or replaced before release, for REDACT.
    redactions: tuple[str, ...] = ()
    # What REDACT actually let through, where that differs from the request.
    released_action: str | None = None


@dataclass
class HopResult:
    disposition: Disposition
    verdict: Verdict
    successor: Envelope | None
    receipt: Receipt
    # The state the successor was sealed over, so the next hop can present
    # exactly what was handed to it rather than reconstructing it and getting
    # a field wrong.
    successor_state: ExecutionState | None = None
    red_card: AdverseTrustAssertion | None = None
    released_action: str | None = None
    decide_us: float = 0.0
    redactions: tuple[str, ...] = ()
    # True when the onward hop could not consume MSEP natively and was routed
    # through a governed fallback enforcement point instead.
    downgraded: bool = False

    @property
    def executed(self) -> bool:
        return self.disposition.executes

    @property
    def pending(self) -> bool:
        return self.disposition.pending


class ExecutionBoundary:
    """A trusted component sitting beside an agent or tool execution point."""

    def __init__(
        self,
        *,
        name: str,
        key: SigningKey,
        keys: KeyCache,
        epoch: TrustEpoch,
        policy_digest: str,
        queue: ReceiptQueue | None = None,
        drift_threshold: float = 1.0,
        successor_ttl_ms: int = 30_000,
        decide: Callable[[Envelope, ExecutionState], PolicyOutcome] | None = None,
        fallback: str | None = None,
        attestation: str | None = None,
        sync: SyncState | None = None,
        consequence: Callable[[str, str], Consequence] = consequence_of,
    ):
        self.name = name
        self.key = key
        self.keys = keys
        self.epoch = epoch
        self.policy_digest = policy_digest
        self.queue = queue or ReceiptQueue()
        self.drift_threshold = drift_threshold
        self.successor_ttl_ms = successor_ttl_ms
        # Local policy beyond the permission bound the envelope already carries.
        # Consulted only after verification passes, and it can only narrow the
        # outcome: there is no return value that turns a refusal into a release.
        self.decide = decide
        # A governed enforcement point that can stand in for a destination not
        # yet able to consume MSEP. Without one, an uninstrumented onward hop is
        # refused rather than released ungoverned.
        self.fallback = fallback
        self.attestation = attestation
        # How recently this boundary heard from the control plane. Absent, the
        # boundary is assumed fresh, which is the right default for a test and
        # the wrong one for a deployment; a deployment passes a SyncState and
        # records each sync into it.
        self.sync = sync
        self.consequence = consequence
        self.replay = ReplayWindow()
        # Adverse trust the boundary knows about locally, whether or not the
        # inbound envelope admits to it. An actor cannot escape a Red Card by
        # arriving with an envelope that omits it.
        self._adverse: dict[str, AdverseTrustAssertion] = {}

    # ------------------------------------------------------------- trust
    def record_adverse(self, card: AdverseTrustAssertion) -> None:
        self._adverse[card.subject] = card

    def adverse_for(self, identity: str) -> AdverseTrustAssertion | None:
        return self._adverse.get(identity)

    def heard_from_control_plane(self, now_ms: int | None = None, channel: str | None = None) -> None:
        """Record a sync. Called by whatever fetches policy, epochs and
        revocations on the boundary's behalf."""
        if self.sync is None:
            return
        if channel:
            self.sync.record(channel, now_ms)
        else:
            self.sync.record_all(now_ms)

    def apply_signal(self, compact_set: str, *, audience: str | None = None,
                     now_ms: int | None = None) -> AdverseTrustAssertion:
        """Ingest a Security Event Token carrying a Red Card.

        This is how a Red Card issued in one workflow reaches a boundary that
        never saw that workflow: the control plane pushes it. The token and the
        assertion inside it are both verified before the local record changes.
        """
        card = ingest_signal(compact_set, resolve_key=self.keys.get,
                             expected_audience=audience or self.name, now_ms=now_ms)
        self.record_adverse(card)
        self.heard_from_control_plane(now_ms, "revocation")
        return card

    # -------------------------------------------------------------- hop
    def handle(
        self,
        *,
        inbound: Envelope,
        state: ExecutionState,
        next_destination: str | None = None,
        next_permissions: Permissions | None = None,
        next_action: str | None = None,
        next_side_effects: str | None = None,
        drift_score: float = 0.0,
        execute: Callable[[], str] | None = None,
        destination_instrumented: bool = True,
        trace: TraceContext | None = None,
        now_ms: int | None = None,
    ) -> HopResult:
        """Run one governed hop."""
        t0 = time.perf_counter_ns()
        now = now_ms if now_ms is not None else int(time.time() * 1000)

        verdict = verify_inbound(
            inbound, keys=self.keys, epoch=self.epoch, destination=self.name,
            state=state, policy_digest=self.policy_digest, replay=self.replay,
            drift_score=drift_score, drift_threshold=self.drift_threshold,
            adverse_lookup=self.adverse_for, now_ms=now,
        )

        disposition = Disposition.RELEASE if verdict.ok else Disposition.INTERDICT
        red_card: AdverseTrustAssertion | None = None
        redactions: tuple[str, ...] = ()
        redacted_action: str | None = None

        # Staleness is a property of this boundary, not of the envelope. An
        # envelope can be perfectly valid and the boundary still not be in a
        # position to act on it, because the last thing it heard from the
        # control plane is old enough that a revocation could be in flight.
        if verdict.ok and self.sync is not None:
            fresh = self.sync.assess(self.consequence(state.action, state.target), now)
            if not fresh.ok:
                disposition = fresh.degrade_to
                verdict = replace(verdict, ok=False, reasons=[Reject.STALE_STATE],
                                  detail=fresh.reason)

        if verdict.ok and self.decide is not None:
            outcome = self.decide(inbound, state)
            disposition = outcome.disposition
            redactions = outcome.redactions
            redacted_action = outcome.released_action
            if outcome.reason:
                verdict = replace(verdict, detail=outcome.reason)

        # Recover & resend restores a prior state and re-runs. For a step whose
        # side effect already left the boundary, a re-run is a second copy of
        # the effect, not a retry. Refer it to someone instead.
        if disposition is Disposition.RECOVER and state.side_effects == "external":
            disposition = Disposition.ELEVATE
            verdict = replace(verdict, detail=(
                "recover requested for a step with external side effects; a "
                "replay would repeat the effect rather than undo it, so this is "
                "referred for a human decision instead"))

        if not verdict.ok:
            # Distinguish "policy said no" from "the actor attacked the
            # mechanism". Only the second changes what the actor is allowed to
            # do next; the first is the boundary working normally.
            for reason in verdict.reasons:
                event = _TRUST_FAILURES.get(reason)
                if event:
                    red_card = issue_red_card(
                        subject=inbound.identity, reason=event,
                        trigger_commitment=inbound.commitment(),
                        issued_by=self.name, epoch=self.epoch.current,
                        key=self.key, policy_digest=self.policy_digest, now_ms=now,
                    )
                    self.record_adverse(red_card)
                    disposition = Disposition.RECOVER
                    break

        released: str | None = None
        response_digest: str | None = None
        if disposition.executes:
            if execute:
                result = execute()
                # An executor may hand back what it observed as well as what it
                # released, so the receipt can attest to both.
                if isinstance(result, tuple):
                    released, observed = result
                    response_digest = "sha256:" + sha256_hex(
                        observed if isinstance(observed, bytes) else str(observed).encode())
                else:
                    released = result
            else:
                released = redacted_action or state.action

        # An onward destination that cannot consume MSEP is not a reason to
        # release ungoverned. Route it through the configured fallback
        # enforcement point, and record the downgrade — a fallback nobody can
        # see in the evidence is indistinguishable from a gap in coverage.
        downgraded = False
        onward_to = next_destination
        if disposition.executes and next_destination and not destination_instrumented:
            if self.fallback is None:
                disposition = Disposition.INTERDICT
                released = None
                verdict = replace(verdict, detail=(
                    f"{next_destination!r} cannot consume MSEP and no governed "
                    "fallback is configured; releasing to it would leave the hop "
                    "ungoverned"))
            else:
                onward_to, downgraded = self.fallback, True

        successor = None
        successor_state = None
        if disposition.executes and onward_to:
            successor, successor_state = self._rematerialise(
                inbound=inbound, state=state, destination=onward_to,
                permissions=next_permissions, action=next_action,
                side_effects=next_side_effects, now=now,
            )

        decide_us = (time.perf_counter_ns() - t0) / 1000.0
        receipt = compile_receipt(
            inbound=inbound, successor=successor, identity=inbound.identity,
            boundary=self.name, disposition=disposition, action_released=released,
            policy_digest=self.policy_digest, epoch=self.epoch.current,
            state_digest=state.digest(),
            reasons=[str(r) for r in verdict.reasons],
            adverse_commitment=red_card.commitment() if red_card else None,
            redactions=redactions, downgraded=downgraded,
            fallback_via=self.fallback if downgraded else None,
            trace=trace, response_digest=response_digest,
            signer_key_id=_kid(self.key), now_ms=now,
        )
        # Queued, not sent. Sealing sits outside the decision so the ledger is
        # never in the path of an action.
        self.queue.put(receipt)

        return HopResult(
            disposition=disposition, verdict=verdict, successor=successor,
            receipt=receipt, successor_state=successor_state, red_card=red_card,
            released_action=released, decide_us=decide_us, redactions=redactions,
            downgraded=downgraded,
        )

    # --------------------------------------------------- re-materialisation
    def _rematerialise(
        self, *, inbound: Envelope, state: ExecutionState, destination: str,
        permissions: Permissions | None, action: str | None, now: int,
        side_effects: str | None = None,
    ) -> tuple[Envelope, ExecutionState]:
        """Mint the next destination's authority.

        Not a forwarded token. The successor is a fresh signed state describing
        the verified inbound authority, this boundary's disposition and what was
        actually released, scoped to where it is going next. Because this
        boundary holds the signing key and the agent does not, the agent cannot
        produce one of these for itself.
        """
        onward = permissions if permissions is not None else inbound.permissions
        if not inbound.permissions.subsumes(onward):
            # Refused here rather than caught at the far end, so a
            # misconfigured boundary fails at the point of the mistake.
            raise ValueError(
                "successor permissions are not a subset of the inbound envelope's; "
                "authority may narrow across a hop but never widen"
            )

        # A successor may not outlive its parent, so a chain cannot extend its
        # own life by re-issuing.
        expires = min(now + self.successor_ttl_ms, inbound.expires_ms)

        adverse = inbound.adverse
        local = self.adverse_for(inbound.identity)
        if local is not None:
            adverse = local.to_wire()

        # An envelope seals the action its hop will attempt, so the successor
        # has to name the *next* step rather than repeat the one just executed.
        # Inheriting the executed action is right only while it stays inside the
        # narrowed authority; where it does not, the successor would be sealed
        # self-inconsistent and die at the far end with a confusing refusal.
        # Catch that here, at the point of the mistake.
        onward_action = action or state.action
        if not onward.permits(onward_action, state.target, state.artifact):
            raise ValueError(
                f"successor would carry '{onward_action}' but its own permission "
                "state does not allow it; name the next action explicitly, or widen "
                "the successor's permissions to include it"
            )

        # The resource target carries forward unchanged. `destination` is where
        # the envelope is going, which is the envelope's scope; conflating the
        # two would silently re-point every permission check at a node name and
        # quietly stop matching the policy that was written about resources.
        succ_state = ExecutionState(
            payload_digest=state.payload_digest, action=onward_action,
            target=state.target, artifact=state.artifact,
            context_digest=state.context_digest, permissions=onward,
            # What executing the next step does to the world is part of what
            # is sealed; a successor that dropped it would make a declared
            # external side effect look like tampering at the next hop.
            side_effects=side_effects or state.side_effects,
        )
        env = new_envelope(
            identity=inbound.identity, state=succ_state, scope=destination,
            permissions=onward, epoch=self.epoch.current,
            policy_digest=self.policy_digest, key=self.key,
            ttl_ms=max(0, expires - now), predecessor=inbound.commitment(),
            depth=inbound.depth + 1, max_depth=inbound.max_depth,
            adverse=adverse, attestation=self.attestation, now_ms=now,
        )
        # Prove the invariants on the object actually produced, rather than
        # trusting that the construction above was right.
        check = verify_succession(inbound, env)
        if not check.ok:
            raise ValueError(f"re-materialisation broke an invariant: {check.reasons}")
        return env, succ_state

    # ------------------------------------------------------------ join
    def converge(
        self, *, inbounds: list[Envelope], state: ExecutionState,
        destination: str, permissions: Permissions, action: str | None = None,
        now_ms: int | None = None,
    ) -> Envelope:
        """Mint a successor for a step caused by more than one predecessor.

        A fan-in is genuinely caused by every branch that fed it, so the
        successor names them all. Recording only the branch that happened to
        arrive last would make the causal graph assert something untrue about
        why the step ran, and that graph is what an investigator reads.

        Authority at a join is bounded by the *narrowest* parent, not the
        widest and not the union. Converging two narrow authorities into a
        broad one would be widening with extra steps: an agent that could
        arrange to be the join point would otherwise accumulate permissions by
        collecting envelopes.
        """
        if not inbounds:
            raise ValueError("a join needs at least one predecessor")
        now = now_ms if now_ms is not None else int(time.time() * 1000)

        for env in inbounds:
            if not env.permissions.subsumes(permissions):
                raise ValueError(
                    "join authority must be within EVERY predecessor's permission "
                    f"state; {env.scope!r} at depth {env.depth} does not cover it"
                )
        onward_action = action or state.action
        if not permissions.permits(onward_action, state.target, state.artifact):
            raise ValueError(
                f"join would carry '{onward_action}' but its own permission state "
                "does not allow it"
            )

        # The join cannot outlive the shortest-lived branch, or a fan-in would
        # be a way to launder an expiring authority into a fresh one.
        expires = min([now + self.successor_ttl_ms] + [e.expires_ms for e in inbounds])
        parents = [e.commitment() for e in inbounds]
        adverse = None
        for env in inbounds:
            local = self.adverse_for(env.identity)
            if local is not None:
                adverse = local.to_wire()
                break
            if env.adverse:
                adverse = env.adverse

        return new_envelope(
            identity=inbounds[0].identity,
            state=ExecutionState(
                payload_digest=state.payload_digest, action=onward_action,
                target=state.target, artifact=state.artifact,
                context_digest=state.context_digest, permissions=permissions),
            scope=destination, permissions=permissions,
            epoch=self.epoch.current, policy_digest=self.policy_digest,
            key=self.key, ttl_ms=max(0, expires - now),
            predecessor=parents[0], co_predecessors=tuple(parents[1:]),
            depth=max(e.depth for e in inbounds) + 1,
            max_depth=min(e.max_depth for e in inbounds),
            adverse=adverse, attestation=self.attestation, now_ms=now,
        )
