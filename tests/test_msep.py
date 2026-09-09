"""MSEP: authority that travels with the action.

The protocol's value rests on a small number of properties that are easy to
state and easy to lose in a refactor. Authority narrows and never widens. A
successor is minted by a boundary, not forwarded by the actor. Tampering
anywhere in the chain is detectable at the next hop without asking anyone. And
none of the verification touches the network, because the moment it does, MSEP
is a gateway with extra steps.

These tests exist to make each of those expensive to break by accident.
"""

import time

import pytest

from _msep_keys import KeyRing
from mira_agent.msep import (Capability, Disposition, ExecutionBoundary, ExecutionState,
                       KeyCache, Permissions, PolicyOutcome, Reject, ReceiptQueue,
                       ReplayWindow, Severity, TrustEpoch, issue_red_card,
                       new_envelope, reinstate, verify_inbound, verify_succession)

POLICY = "sha256:policy-v1"


@pytest.fixture
def ring():
    return KeyRing()


@pytest.fixture
def keys(ring):
    kc = KeyCache()
    kc.add_keyring(ring, ["msep/a", "msep/b", "msep/c", "msep/rogue"])
    return kc


@pytest.fixture
def perms():
    return Permissions((Capability("deploy", "dev"), Capability("inspect")))


@pytest.fixture
def state(perms):
    return ExecutionState("sha256:payload", "deploy", "dev", "update_set",
                          permissions=perms)


def envelope(ring, state, perms, **kw):
    args = dict(identity="spiffe://acme/agent/1", state=state, scope="node-b",
                permissions=perms, epoch=1, policy_digest=POLICY,
                key=ring.get("msep/a"))
    args.update(kw)
    return new_envelope(**args)


def boundary(ring, keys, name="node-b", **kw):
    args = dict(name=name, key=ring.get("msep/b"), keys=keys,
                epoch=TrustEpoch(1), policy_digest=POLICY)
    args.update(kw)
    return ExecutionBoundary(**args)


# ===================================================== the central invariant

def test_authority_can_narrow_across_a_hop(ring, keys, state, perms):
    b = boundary(ring, keys)
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c", next_action="inspect",
                 next_permissions=Permissions((Capability("inspect"),)))
    assert r.disposition is Disposition.RELEASE
    assert [c.action for c in r.successor.permissions.caps] == ["inspect"]


def test_authority_cannot_widen_across_a_hop(ring, keys, state, perms):
    """The property the whole protocol rests on.

    If a successor could claim more than its predecessor held, verifying one
    hop locally would tell you nothing about the chain behind it, and the
    architecture would have to fall back on asking a central service.
    """
    b = boundary(ring, keys)
    with pytest.raises(ValueError, match="never widen"):
        b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c",
                 next_permissions=Permissions((Capability("deploy", "prod"),)))


def test_a_forged_wider_successor_is_caught_at_the_next_hop(ring, keys, state, perms):
    """Even if a boundary is compromised and mints a widened successor, the
    receiving boundary rejects it without consulting anyone."""
    parent = envelope(ring, state, perms)
    wide = Permissions((Capability("deploy", "prod"), Capability("drop_table")))
    forged = new_envelope(
        identity="spiffe://acme/agent/1",
        state=ExecutionState("sha256:payload", "deploy", "prod", "update_set",
                             permissions=wide),
        scope="node-c", permissions=wide, epoch=1, policy_digest=POLICY,
        key=ring.get("msep/rogue"), predecessor=parent.commitment(),
        depth=parent.depth + 1,
    )
    v = verify_succession(parent, forged)
    assert v.ok is False
    assert Reject.AUTHORITY_WIDENED in v.reasons


def test_wildcards_do_not_let_a_successor_escape(perms):
    """A `*` in a successor is a widening even though it looks like one field."""
    narrow = Permissions((Capability("deploy", "dev"),))
    wider = Permissions((Capability("deploy", "*"),))
    assert narrow.subsumes(wider) is False
    assert wider.subsumes(narrow) is True


# ================================================== chain integrity

def test_a_successor_may_not_outlive_its_parent(ring, keys, state, perms):
    b = boundary(ring, keys, successor_ttl_ms=10_000_000)
    parent = envelope(ring, state, perms, ttl_ms=5_000)
    r = b.handle(inbound=parent, state=state, next_destination="node-c")
    assert r.successor.expires_ms <= parent.expires_ms


def test_depth_advances_by_exactly_one(ring, keys, state, perms):
    b = boundary(ring, keys)
    parent = envelope(ring, state, perms)
    r = b.handle(inbound=parent, state=state, next_destination="node-c")
    assert r.successor.depth == parent.depth + 1
    assert verify_succession(parent, r.successor).ok


def test_a_broken_predecessor_link_is_detected(ring, keys, state, perms):
    parent = envelope(ring, state, perms)
    other = envelope(ring, state, perms, identity="spiffe://acme/agent/2")
    b = boundary(ring, keys)
    r = b.handle(inbound=parent, state=state, next_destination="node-c")
    v = verify_succession(other, r.successor)      # wrong parent
    assert Reject.BROKEN_LINK in v.reasons


def test_depth_is_bounded(ring, keys, state, perms):
    e = envelope(ring, state, perms, depth=9, max_depth=8)
    v = verify_inbound(e, keys=keys, epoch=TrustEpoch(1), destination="node-b",
                       state=state, policy_digest=POLICY)
    assert Reject.DEPTH_EXCEEDED in v.reasons


# ================================================== tamper detection

@pytest.mark.parametrize("field,value", [
    ("payload_digest", "sha256:tampered"),
    ("action", "drop_table"),
    ("target", "prod"),
    ("artifact", "database"),
])
def test_altering_the_execution_state_breaks_the_envelope(ring, keys, state, perms,
                                                          field, value):
    """The envelope commits to H(X_n). Changing the payload, the action or the
    ruleset at an intermediate hop has to be detectable, or 'governed' means
    only 'governed at the point it was signed'."""
    from dataclasses import replace
    e = envelope(ring, state, perms)
    v = verify_inbound(e, keys=keys, epoch=TrustEpoch(1), destination="node-b",
                       state=replace(state, **{field: value}), policy_digest=POLICY)
    assert Reject.STATE_MISMATCH in v.reasons


def test_altering_the_ruleset_breaks_the_envelope(ring, keys, state, perms):
    from dataclasses import replace
    e = envelope(ring, state, perms)
    swapped = replace(state, permissions=Permissions((Capability("deploy", "prod"),)))
    v = verify_inbound(e, keys=keys, epoch=TrustEpoch(1), destination="node-b",
                       state=swapped, policy_digest=POLICY)
    assert Reject.STATE_MISMATCH in v.reasons


def test_a_modified_signature_field_fails(ring, keys, state, perms):
    from dataclasses import replace
    e = envelope(ring, state, perms)
    bad = replace(e, scope="node-z")               # signed body changed, sig stale
    v = verify_inbound(bad, keys=keys, epoch=TrustEpoch(1), destination="node-z",
                       state=state, policy_digest=POLICY)
    assert Reject.BAD_SIGNATURE in v.reasons


def test_an_envelope_is_bound_to_one_destination(ring, keys, state, perms):
    """Otherwise a captured envelope is a bearer token for the whole estate."""
    e = envelope(ring, state, perms, scope="node-b")
    v = verify_inbound(e, keys=keys, epoch=TrustEpoch(1), destination="node-c",
                       state=state, policy_digest=POLICY)
    assert Reject.WRONG_DESTINATION in v.reasons


def test_an_unknown_signing_key_is_refused_not_fetched(ring, state, perms):
    """Fetching on demand would put the control plane back in the hot path and
    hand an attacker a way to stall every hop."""
    v = verify_inbound(envelope(ring, state, perms), keys=KeyCache(),
                       epoch=TrustEpoch(1), destination="node-b", state=state,
                       policy_digest=POLICY)
    assert Reject.UNKNOWN_KEY in v.reasons


def test_an_excluded_key_stops_verifying(ring, keys, state, perms):
    """Key exclusion is how a compromised boundary is contained."""
    e = envelope(ring, state, perms)
    keys.exclude(e.key_id)
    v = verify_inbound(e, keys=keys, epoch=TrustEpoch(1), destination="node-b",
                       state=state, policy_digest=POLICY)
    assert Reject.UNKNOWN_KEY in v.reasons


# ================================================== freshness

def test_replay_is_refused(ring, keys, state, perms):
    e = envelope(ring, state, perms)
    w = ReplayWindow()
    args = dict(keys=keys, epoch=TrustEpoch(1), destination="node-b",
                state=state, policy_digest=POLICY, replay=w)
    assert verify_inbound(e, **args).ok
    assert Reject.REPLAY in verify_inbound(e, **args).reasons


def test_an_expired_envelope_is_refused(ring, keys, state, perms):
    e = envelope(ring, state, perms, ttl_ms=1)
    v = verify_inbound(e, keys=keys, epoch=TrustEpoch(1), destination="node-b",
                       state=state, policy_digest=POLICY,
                       now_ms=e.expires_ms + 1000)
    assert Reject.EXPIRED in v.reasons


def test_a_stale_trust_epoch_is_refused(ring, keys, state, perms):
    """A node cannot learn of a revocation it has not received. Epochs bound
    how long authority minted before a change stays usable."""
    e = envelope(ring, state, perms, epoch=1)
    v = verify_inbound(e, keys=keys, epoch=TrustEpoch(2), destination="node-b",
                       state=state, policy_digest=POLICY)
    assert Reject.STALE_EPOCH in v.reasons


def test_a_policy_version_mismatch_is_refused(ring, keys, state, perms):
    e = envelope(ring, state, perms)
    v = verify_inbound(e, keys=keys, epoch=TrustEpoch(1), destination="node-b",
                       state=state, policy_digest="sha256:policy-v2")
    assert Reject.POLICY_MISMATCH in v.reasons


# ================================================== adverse trust state

def test_a_terminal_red_card_stops_the_actor_downstream(ring, keys, state, perms):
    card = issue_red_card(
        subject="spiffe://acme/agent/1", reason="prohibited_exfiltration",
        trigger_commitment="sha256:evt", issued_by="node-a", epoch=1,
        key=ring.get("msep/a"))
    e = envelope(ring, state, perms, adverse=card.to_wire())
    v = verify_inbound(e, keys=keys, epoch=TrustEpoch(1), destination="node-b",
                       state=state, policy_digest=POLICY)
    assert Reject.ADVERSE_TERMINAL in v.reasons


def test_an_actor_cannot_escape_a_red_card_by_omitting_it(ring, keys, state, perms):
    """The boundary's own record wins over what the envelope admits to."""
    b = boundary(ring, keys)
    b.record_adverse(issue_red_card(
        subject="spiffe://acme/agent/1", reason="honey_tool_trip",
        trigger_commitment="sha256:evt", issued_by="node-b", epoch=1,
        key=ring.get("msep/b")))
    r = b.handle(inbound=envelope(ring, state, perms), state=state)
    assert Reject.ADVERSE_TERMINAL in r.verdict.reasons
    assert r.disposition is Disposition.INTERDICT


def test_tampering_issues_a_red_card_but_policy_refusal_does_not(ring, keys, state, perms):
    """Being outside policy is ordinary and must not change an actor's
    standing. Attacking the mechanism is different."""
    from dataclasses import replace
    b = boundary(ring, keys)
    tampered = b.handle(inbound=envelope(ring, state, perms), state=state,
                        now_ms=None)
    assert tampered.red_card is None          # clean hop

    b2 = boundary(ring, keys)
    e = envelope(ring, state, perms)
    r = b2.handle(inbound=e, state=replace(state, action="drop_table"))
    assert r.red_card is not None
    assert r.red_card.reason == "envelope_tampering"
    assert r.disposition is Disposition.RECOVER


def test_an_actor_cannot_downgrade_a_red_card_by_presenting_a_milder_one(
        ring, keys, state, perms):
    """The subtler version of the same evasion.

    Carrying *a* card looks like cooperation, so it must not be a way to stop
    the boundary consulting its own record. The more severe assessment wins.
    """
    mild = issue_red_card(
        subject="spiffe://acme/agent/1", reason="honey_tool_trip",
        trigger_commitment="sha256:old", issued_by="node-a", epoch=1,
        key=ring.get("msep/a"), severity=Severity.NOTED)
    b = boundary(ring, keys)
    b.record_adverse(issue_red_card(
        subject="spiffe://acme/agent/1", reason="prohibited_exfiltration",
        trigger_commitment="sha256:evt", issued_by="node-b", epoch=1,
        key=ring.get("msep/b")))
    r = b.handle(inbound=envelope(ring, state, perms, adverse=mild.to_wire()),
                 state=state)
    assert Reject.ADVERSE_TERMINAL in r.verdict.reasons
    assert r.disposition is Disposition.INTERDICT


def test_a_red_card_propagates_into_successors(ring, keys, state, perms):
    b = boundary(ring, keys)
    card = issue_red_card(
        subject="spiffe://acme/agent/1", reason="honey_tool_trip",
        trigger_commitment="sha256:evt", issued_by="node-b", epoch=1,
        key=ring.get("msep/b"), severity=Severity.NOTED)
    b.record_adverse(card)
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c")
    assert r.successor.adverse is not None
    assert r.successor.adverse["reason"] == "honey_tool_trip"


def test_reinstatement_is_a_new_event_not_an_erasure(ring):
    k = ring.get("msep/b")
    card = issue_red_card(subject="a", reason="honey_tool_trip",
                          trigger_commitment="sha256:evt", issued_by="node-b",
                          epoch=1, key=k)
    back = reinstate(card, authorised_by="ciso@acme", key=k)
    assert back.severity is Severity.NOTED
    assert back.reason == "honey_tool_trip"      # the history survives
    assert "ciso@acme" in back.resolution
    assert back.commitment() != card.commitment()
    assert back.signature_valid(k.public_bytes)


def test_an_agent_cannot_forge_a_red_card_resolution(ring, keys):
    """Only a key the cache trusts can change standing."""
    from _msep_keys import SigningKey
    rogue = SigningKey.generate("attacker")
    card = issue_red_card(subject="a", reason="honey_tool_trip",
                          trigger_commitment="sha256:evt", issued_by="node-b",
                          epoch=1, key=ring.get("msep/b"))
    cleared = reinstate(card, authorised_by="self", key=rogue)
    assert keys.get(cleared.key_id) is None


# ================================================== evidence path

def test_a_decision_does_not_wait_for_the_ledger(ring, keys, state, perms):
    """Sealing sits outside the decision. If it did not, the ledger's
    availability would become the estate's availability."""
    q = ReceiptQueue()
    b = boundary(ring, keys, queue=q)
    for _ in range(5):
        r = b.handle(inbound=envelope(ring, state, perms), state=state)
        assert r.disposition is Disposition.RELEASE
    assert q.depth() == 5, "receipts should be queued, not sent inline"


def test_receipts_record_refusals_as_well_as_releases(ring, keys, state, perms):
    b = boundary(ring, keys)
    b.handle(inbound=envelope(ring, state, perms, scope="elsewhere"), state=state)
    r = b.queue.drain()[0]
    assert r.disposition is Disposition.INTERDICT
    assert "scope_mismatch" in r.reasons


def test_the_queue_drops_oldest_and_counts_it(ring, keys, state, perms):
    """An unbounded queue in someone else's agent is a memory leak with our
    name on it; a silent drop is worse than a counted one."""
    q = ReceiptQueue(capacity=3)
    b = boundary(ring, keys, queue=q)
    for _ in range(6):
        b.handle(inbound=envelope(ring, state, perms), state=state)
    assert q.depth() == 3
    assert q.dropped == 3


def test_receipts_carry_the_parent_commitment_for_out_of_order_ingest(ring, keys,
                                                                     state, perms):
    b = boundary(ring, keys)
    e = envelope(ring, state, perms)
    r = b.handle(inbound=e, state=state, next_destination="node-c")
    assert r.receipt.inbound_commitment == e.commitment()
    assert r.receipt.successor_commitment == r.successor.commitment()


def test_a_relay_batch_is_bounded(ring, keys, state, perms):
    """A boundary that cannot reach the ledger can hand its backlog to the next
    hop, but not without limit, or an outage grows the envelope."""
    b = boundary(ring, keys)
    for _ in range(50):
        b.handle(inbound=envelope(ring, state, perms), state=state)
    assert len(b.queue.relay_batch(limit=8)) == 8
    assert b.queue.depth() == 42


# ================================================== cross-protocol safety

def test_a_provenance_record_signature_is_not_an_envelope_signature(ring, keys,
                                                                    state, perms):
    """MIL records and MSEP envelopes are signed by the same keyring. Without
    domain separation inside the signed bytes, one could be presented as the
    other."""
    from mira_agent.msep.envelope import _ENVELOPE_CONTEXT, _STATE_CONTEXT
    from mira_agent.msep.trust import _ADVERSE_CONTEXT
    e = envelope(ring, state, perms)
    assert e.signing_bytes().startswith(_ENVELOPE_CONTEXT)
    assert len({_ENVELOPE_CONTEXT, _STATE_CONTEXT, _ADVERSE_CONTEXT}) == 3
    from mira_agent_core.records import pae
    assert not e.signing_bytes().startswith(pae("x", b"y")[:8])


# ================================================== a multi-hop chain

def test_a_three_hop_chain_verifies_end_to_end(ring, keys):
    """The shape the protocol actually runs in.

    Authority narrows along the way, every hop is checked locally, and nothing
    is asked of the centre. Each boundary re-materialises the next hop's
    authority from what it just verified and executed, so the state travelling
    onward is the state the previous hop committed to.
    """
    wide = Permissions((Capability("deploy", "dev"), Capability("inspect"),
                        Capability("validate")))
    st = ExecutionState("sha256:pay", "deploy", "dev", "update_set", permissions=wide)
    env = new_envelope(identity="spiffe://acme/agent/1", state=st, scope="node-b",
                       permissions=wide, epoch=1, policy_digest=POLICY,
                       key=ring.get("msep/a"), ttl_ms=60_000)

    hops = [("node-b", "node-c", "validate",
             Permissions((Capability("inspect"), Capability("validate")))),
            ("node-c", "node-d", "inspect",
             Permissions((Capability("inspect"),)))]

    chain, states = [env], [st]
    for here, onward_to, onward_action, onward_perms in hops:
        b = ExecutionBoundary(name=here, key=ring.get("msep/b"), keys=keys,
                              epoch=TrustEpoch(1), policy_digest=POLICY)
        r = b.handle(inbound=chain[-1], state=states[-1],
                     next_destination=onward_to, next_action=onward_action,
                     next_permissions=onward_perms)
        assert r.disposition is Disposition.RELEASE, r.verdict.reasons
        assert verify_succession(chain[-1], r.successor).ok
        chain.append(r.successor)
        # what the successor committed to is what the next hop must present
        states.append(ExecutionState(
            states[-1].payload_digest, onward_action, states[-1].target,
            states[-1].artifact, permissions=onward_perms))

    assert [e.depth for e in chain] == [0, 1, 2]
    assert [len(e.permissions.caps) for e in chain] == [3, 2, 1]
    for parent, child in zip(chain, chain[1:]):
        assert parent.permissions.subsumes(child.permissions)
        assert child.expires_ms <= parent.expires_ms
    # the final hop can be verified with nothing but the chain and the keys
    last = ExecutionBoundary(name="node-d", key=ring.get("msep/c"), keys=keys,
                             epoch=TrustEpoch(1), policy_digest=POLICY)
    assert last.handle(inbound=chain[-1], state=states[-1]).disposition \
        is Disposition.RELEASE


def test_the_resource_target_is_not_the_next_destination(ring, keys, state, perms):
    """A successor is scoped to a node but still speaks about a resource.

    Collapsing the two would re-point every downstream permission check at a
    node name, and policy written about resources would quietly stop matching.
    """
    b = boundary(ring, keys)
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c")
    assert r.successor.scope == "node-c"
    assert r.successor.state_digest == ExecutionState(
        state.payload_digest, state.action, state.target, state.artifact,
        permissions=perms).digest()


def test_verification_touches_no_network(ring, keys, state, perms, monkeypatch):
    """MSEP's whole claim is that a hop is decided locally. A socket opened
    anywhere under verification would make that false."""
    import socket
    def forbidden(*a, **k):
        raise AssertionError("verification attempted a network call")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    v = verify_inbound(envelope(ring, state, perms), keys=keys,
                       epoch=TrustEpoch(1), destination="node-b", state=state,
                       policy_digest=POLICY)
    assert v.ok


def test_the_wire_form_survives_a_round_trip(ring, state, perms):
    """Envelopes cross process boundaries as JSON; the signature has to hold
    over the canonical form, not over Python object identity."""
    from mira_agent.msep import Envelope
    e = envelope(ring, state, perms)
    back = Envelope.from_wire(e.to_wire())
    assert back.commitment() == e.commitment()
    assert back.signature_valid(ring.get("msep/a").public_bytes)


def test_a_successor_cannot_be_sealed_carrying_an_action_it_may_not_take(
        ring, keys, state, perms):
    """Narrowing authority while inheriting the executed action would mint an
    envelope that contradicts itself, and the failure would surface a hop later
    as an unexplained refusal. It is refused where the mistake is made."""
    b = boundary(ring, keys)
    with pytest.raises(ValueError, match="does not allow it"):
        b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c",
                 next_permissions=Permissions((Capability("inspect"),)))


# ============================================ V9: the full disposition set

def test_elevate_does_not_release_the_action(ring, keys, state, perms):
    """The one that matters most in the set.

    Elevate refers a material judgement to a human or another trusted system.
    If it released as a side effect of being asked about, the action would
    already have happened by the time anyone read the referral, and the
    disposition would be a notification rather than a control.
    """
    b = boundary(ring, keys, decide=lambda e, s: PolicyOutcome(
        Disposition.ELEVATE, reason="material change needs a second signature"))
    fired = []
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c", execute=lambda: fired.append(1))
    assert r.disposition is Disposition.ELEVATE
    assert fired == [], "elevate must not execute"
    assert r.released_action is None
    assert r.successor is None, "a held action has no onward authority yet"
    assert r.pending and not r.executed


def test_gate_holds_without_refusing(ring, keys, state, perms):
    """Gate is not a denial, and a caller that collapses it into one loses the
    distinction policy asked for."""
    b = boundary(ring, keys, decide=lambda e, s: PolicyOutcome(Disposition.GATE))
    r = b.handle(inbound=envelope(ring, state, perms), state=state)
    assert r.disposition.pending and not r.disposition.refused
    assert not r.disposition.executes


def test_redact_releases_a_modified_action_and_says_which_parts(ring, keys,
                                                                state, perms):
    b = boundary(ring, keys, decide=lambda e, s: PolicyOutcome(
        Disposition.REDACT, redactions=("applicant.tfn", "applicant.dob"),
        released_action="deploy"))
    r = b.handle(inbound=envelope(ring, state, perms), state=state)
    assert r.executed and r.disposition is Disposition.REDACT
    assert r.receipt.redactions == ["applicant.tfn", "applicant.dob"]


def test_policy_cannot_release_something_verification_refused(ring, keys,
                                                              state, perms):
    """The hook is consulted only on a verdict that already passed. A policy
    that could overturn a failed signature check would make verification
    advisory."""
    called = []
    def permissive(env, st):
        called.append(1)
        return PolicyOutcome(Disposition.RELEASE)
    b = boundary(ring, keys, decide=permissive)
    r = b.handle(inbound=envelope(ring, state, perms, scope="elsewhere"), state=state)
    assert called == [], "policy must not run on an unverified envelope"
    assert r.disposition is Disposition.INTERDICT


# ================================================ V9: hybrid fallback

def test_an_uninstrumented_destination_routes_through_the_fallback(ring, keys,
                                                                   state, perms):
    b = boundary(ring, keys, fallback="fallback-gw")
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="legacy-cmdb", destination_instrumented=False)
    assert r.executed and r.downgraded
    assert r.successor.scope == "fallback-gw"
    assert r.receipt.downgraded and r.receipt.fallback_via == "fallback-gw"


def test_the_downgrade_is_visible_in_the_evidence(ring, keys, state, perms):
    """'Explicit, observable and evidentially consistent' is the production
    requirement. A fallback nobody can see in the receipts is indistinguishable
    from a hole in coverage."""
    b = boundary(ring, keys, fallback="fallback-gw")
    b.handle(inbound=envelope(ring, state, perms), state=state,
             next_destination="node-c")
    b.handle(inbound=envelope(ring, state, perms), state=state,
             next_destination="legacy", destination_instrumented=False)
    native, fell_back = b.queue.drain()
    assert native.downgraded is False and native.fallback_via is None
    assert fell_back.downgraded is True and fell_back.fallback_via == "fallback-gw"


def test_without_a_fallback_an_uninstrumented_hop_is_refused(ring, keys,
                                                             state, perms):
    """Releasing to a destination that cannot be governed, because governance
    is inconvenient there, is the failure mode the whole product exists to
    prevent."""
    b = boundary(ring, keys, fallback=None)
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="legacy-cmdb", destination_instrumented=False)
    assert r.disposition is Disposition.INTERDICT
    assert r.released_action is None
    assert "ungoverned" in r.verdict.detail


# ================================================ V9: many-to-one convergence

def test_a_join_records_every_parent_that_caused_it(ring, keys, state, perms):
    """Fan-in is normal in agent workflows. Recording only the branch that
    arrived last would make the causal graph assert something untrue."""
    b = boundary(ring, keys)
    a1 = envelope(ring, state, perms)
    a2 = envelope(ring, state, perms, identity="spiffe://acme/agent/1")
    j = b.converge(inbounds=[a1, a2], state=state, destination="node-d",
                   permissions=Permissions((Capability("inspect"),)),
                   action="inspect")
    assert set(j.parents()) == {a1.commitment(), a2.commitment()}
    assert verify_succession(a1, j).ok and verify_succession(a2, j).ok


def test_a_join_cannot_accumulate_authority_from_its_branches(ring, keys, state):
    """Otherwise an agent that arranges to be the join point collects
    permissions by collecting envelopes — widening with extra steps."""
    b = boundary(ring, keys)
    deploy = Permissions((Capability("deploy", "dev"),))
    inspect = Permissions((Capability("inspect"),))
    s1 = ExecutionState("sha256:p", "deploy", "dev", "update_set", permissions=deploy)
    s2 = ExecutionState("sha256:p", "inspect", "dev", "update_set", permissions=inspect)
    a1 = envelope(ring, s1, deploy)
    a2 = envelope(ring, s2, inspect)
    with pytest.raises(ValueError, match="EVERY predecessor"):
        b.converge(inbounds=[a1, a2], state=s1, destination="node-d",
                   permissions=Permissions((Capability("deploy", "dev"),
                                            Capability("inspect"))))


def test_a_join_cannot_outlive_its_shortest_branch(ring, keys, state, perms):
    b = boundary(ring, keys, successor_ttl_ms=10_000_000)
    slow = envelope(ring, state, perms, ttl_ms=600_000)
    quick = envelope(ring, state, perms, ttl_ms=2_000)
    j = b.converge(inbounds=[slow, quick], state=state, destination="node-d",
                   permissions=perms)
    assert j.expires_ms <= quick.expires_ms


def test_receipts_carry_every_parent(ring, keys, state, perms):
    b = boundary(ring, keys)
    a1, a2 = envelope(ring, state, perms), envelope(ring, state, perms)
    j = b.converge(inbounds=[a1, a2], state=state, destination="node-d",
                   permissions=perms)
    r = b.handle(inbound=j, state=ExecutionState(
        state.payload_digest, state.action, state.target, state.artifact,
        permissions=perms), destination_instrumented=True)
    assert set(r.receipt.parent_commitments) == {a1.commitment(), a2.commitment()}


# ================================================ V9: trace context

def test_a_forged_trace_header_cannot_mint_authority(ring, keys, state, perms):
    """OTel warns that inbound trace context may be forged. It is correlation
    metadata; the moment it can influence a verdict it is a bypass."""
    from mira_agent.msep import parse_traceparent
    forged = parse_traceparent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    b = boundary(ring, keys)
    bad = b.handle(inbound=envelope(ring, state, perms, scope="elsewhere"),
                   state=state, trace=forged)
    assert bad.disposition is Disposition.INTERDICT
    assert bad.receipt.trace["traceId"] == forged.trace_id  # kept as evidence
    # and it is nowhere in the signed authority
    body = envelope(ring, state, perms).signing_body()
    assert forged.trace_id not in str(body)


@pytest.mark.parametrize("header", [
    None, "", "garbage", "00-" + "0" * 32 + "-00f067aa0ba902b7-01",
    "ff-" + "a" * 32 + "-" + "b" * 16 + "-01", "00-tooshort-x-01",
    "00-4bf92f3577b34da6a3ce929d0e0e4736-" + "0" * 16 + "-01",
])
def test_malformed_trace_context_is_dropped_not_repaired(header):
    """A tolerant parser propagates an attacker's chosen identifier into the
    evidence view. Since the value is never load-bearing, dropping it costs
    nothing."""
    from mira_agent.msep import parse_traceparent
    assert parse_traceparent(header) is None


# ================================================ V9: sealing and custody

def test_the_evidence_plane_never_receives_the_payload(ring):
    """Data sovereignty is the claim; the lodgement is where it is kept or
    broken. It must carry a commitment and a pointer, not content."""
    from mira_agent.msep import LocalWrapper, seal
    secret = b'{"applicant":"real person","tfn":"123456789"}'
    _, lodgement = seal(secret, storage_ref="s3://customer/rec/1",
                        wrappers=[LocalWrapper("liora"), LocalWrapper("customer")])
    blob = str(lodgement.to_jcs()).encode()
    assert b"real person" not in blob and b"123456789" not in blob


def test_the_customer_can_reconstruct_without_liora(ring):
    """The commercial invariant: ending the service relationship must not
    strand a customer with ciphertext it can no longer read."""
    from mira_agent.msep import LocalWrapper, reconstruct, seal
    liora, customer = LocalWrapper("liora"), LocalWrapper("customer")
    sealed, lodgement = seal(b"retained execution state",
                             storage_ref="s3://customer/rec/1",
                             wrappers=[liora, customer])
    assert lodgement.dual_wrapped
    assert reconstruct(sealed, lodgement, wrapper=customer) == b"retained execution state"


def test_a_holder_with_no_wrapped_key_is_told_so_plainly(ring):
    from mira_agent.msep import LocalWrapper, reconstruct, seal
    sealed, lodgement = seal(b"x", storage_ref="s3://c/1",
                             wrappers=[LocalWrapper("liora")])
    assert lodgement.dual_wrapped is False
    with pytest.raises(KeyError, match="cannot recover"):
        reconstruct(sealed, lodgement, wrapper=LocalWrapper("customer"))


def test_altered_ciphertext_fails_authentication(ring):
    from dataclasses import replace as dc_replace
    from mira_agent.msep import LocalWrapper, reconstruct, seal
    w = LocalWrapper("liora")
    sealed, lodgement = seal(b"retained state", storage_ref="s3://c/1", wrappers=[w])
    # Storage hands back different bytes while the object still claims the
    # original commitment. Recomputing is what catches it.
    tampered = dc_replace(sealed, ciphertext=b"\x00" + sealed.ciphertext[1:])
    assert tampered.commitment != tampered.recompute_commitment()
    with pytest.raises(ValueError, match="commitment does not match"):
        reconstruct(tampered, lodgement, wrapper=w)


def test_sealing_without_a_wrapper_is_refused(ring):
    """A data key nobody can unwrap is indistinguishable from discarding the
    record, and would look like retention while being deletion."""
    from mira_agent.msep import seal
    with pytest.raises(ValueError, match="at least one key wrapper"):
        seal(b"x", storage_ref="s3://c/1", wrappers=[])


# ================================================ V9 appendix F: failure modes

def test_a_ledger_outage_does_not_stop_decisions(ring, keys, state, perms):
    """Appendix F: local decision continues under valid state; receipts queue."""
    b = boundary(ring, keys)
    for _ in range(100):
        assert b.handle(inbound=envelope(ring, state, perms),
                        state=state).disposition is Disposition.RELEASE
    assert b.queue.depth() == 100      # nothing was sent; nothing stopped


def test_receipt_backlog_pressure_is_bounded_and_counted(ring, keys, state, perms):
    q = ReceiptQueue(capacity=32)
    b = boundary(ring, keys, queue=q)
    for _ in range(200):
        b.handle(inbound=envelope(ring, state, perms), state=state)
    assert q.depth() == 32 and q.dropped == 168


def test_key_rotation_invalidates_what_the_old_key_signed(ring, keys, state, perms):
    """Appendix F: compromised boundary -> attestation/key exclusion."""
    e = envelope(ring, state, perms)
    b = boundary(ring, keys)
    assert b.handle(inbound=e, state=state).disposition is Disposition.RELEASE
    keys.exclude(e.key_id)
    later = b.handle(inbound=envelope(ring, state, perms), state=state)
    assert Reject.UNKNOWN_KEY in later.verdict.reasons


def test_a_long_partition_is_bounded_by_ttl_not_by_hope(ring, keys, state, perms):
    """A node cannot learn of a revocation it has not received, so staleness is
    bounded by policy instead of pretended away."""
    e = envelope(ring, state, perms, ttl_ms=30_000)
    b = boundary(ring, keys)
    r = b.handle(inbound=e, state=state, now_ms=e.issued_ms + 3_600_000)
    assert Reject.EXPIRED in r.verdict.reasons


def test_an_epoch_bump_retires_authority_minted_before_it(ring, keys, state, perms):
    e = envelope(ring, state, perms, epoch=1)
    b = boundary(ring, keys, epoch=TrustEpoch(2))
    assert Reject.STALE_EPOCH in b.handle(inbound=e, state=state).verdict.reasons
