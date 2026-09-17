"""Reroute at the execution boundary: released, but not where it was aimed.

The rulebook has had reroute for a while — a rule can say a production
deployment goes to development instead. What was missing is the other half:
the boundary that actually mints the successor and writes the receipt had no
idea a redirection had happened, so the evidence recorded a deployment to
wherever the agent asked, and the successor carried that target onward.

The white paper is specific about both halves (Appendix B steps 2, 5 and 8,
and Appendix C.2): the selected destination may differ from the requested one
but must remain within policy and cannot widen authority, the successor binds
to the newly authorised destination, and the receipt preserves *both* — what
was asked for and what was released — "so the governance intervention is
explicit rather than hidden".

Two failure-closed properties carry it here, the same two the rulebook
applies: a reroute the inbound authority does not already cover releases
nothing, and a reroute on an outcome that was not going to run changes
nothing.
"""

import pytest

from _msep_keys import KeyRing
from mira_agent.msep import (Capability, Disposition, ExecutionBoundary, ExecutionState,
                             KeyCache, Permissions, PolicyOutcome, Reject, TrustEpoch,
                             new_envelope)

POLICY = "sha256:policy-v1"


@pytest.fixture
def ring():
    return KeyRing()


@pytest.fixture
def keys(ring):
    kc = KeyCache()
    kc.add_keyring(ring, ["msep/a", "msep/b", "msep/c"])
    return kc


@pytest.fixture
def perms():
    """Authority over both instances. A reroute can only reach inside this."""
    return Permissions((Capability("deploy", "dev"), Capability("deploy", "prod"),
                        Capability("inspect")))


@pytest.fixture
def state(perms):
    return ExecutionState("sha256:payload", "deploy", "prod", "update_set",
                          permissions=perms)


def envelope(ring, state, perms, **kw):
    args = dict(identity="spiffe://acme/agent/1", state=state, scope="node-b",
                permissions=perms, epoch=1, policy_digest=POLICY,
                key=ring.get("msep/a"))
    args.update(kw)
    return new_envelope(**args)


def boundary(ring, keys, decide, name="node-b"):
    return ExecutionBoundary(name=name, key=ring.get("msep/b"), keys=keys,
                             epoch=TrustEpoch(1), policy_digest=POLICY, decide=decide)


def redirect(to, disposition=Disposition.RELEASE, reason=""):
    return lambda env, st: PolicyOutcome(disposition=disposition, reroute_to=to,
                                         reason=reason)


# ------------------------------------------------------------------ release
def test_a_redirected_action_runs_against_the_new_target(ring, keys, state, perms):
    b = boundary(ring, keys, redirect("dev", reason="production is redirected to dev"))
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c")
    assert r.disposition is Disposition.RELEASE and r.rerouted
    assert r.reroute_to == "dev" and r.requested_target == "prod"
    # the successor speaks about the target that was authorised, not the one
    # the agent named
    assert r.successor_state.target == "dev"


def test_the_receipt_preserves_both_the_request_and_the_release(ring, keys, state, perms):
    """C.2: "the receipt also preserves the requested action/destination and
    the action/destination actually released"."""
    b = boundary(ring, keys, redirect("dev"))
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c")
    assert r.receipt.requested_target == "prod"
    assert r.receipt.released_target == "dev"
    j = r.receipt.to_jcs()
    assert j["requestedTarget"] == "prod" and j["releasedTarget"] == "dev"


def test_an_ordinary_receipt_hashes_to_exactly_what_it_always_did(ring, keys, state, perms):
    """The conformance vector pins the canonical receipt. Two new fields that
    appeared on every receipt would move the canonical form of every receipt
    ever sealed, so they appear only when there was an intervention to record."""
    b = boundary(ring, keys, lambda env, st: PolicyOutcome())
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c")
    assert "requestedTarget" not in r.receipt.to_jcs()
    assert "releasedTarget" not in r.receipt.to_jcs()


def test_a_hop_that_was_not_redirected_says_nothing_about_targets(ring, keys, state, perms):
    """The fields are an intervention record. Present on every receipt they
    would stop meaning one."""
    b = boundary(ring, keys, lambda env, st: PolicyOutcome())
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c")
    assert not r.rerouted
    assert r.receipt.requested_target is None and r.receipt.released_target is None


# ------------------------------------------------------------------ refusal
def test_a_reroute_outside_the_inbound_authority_releases_nothing(ring, keys, state):
    """The property that makes a policy hook safe. Without it, a hook could
    reach a destination the envelope never carried authority for simply by
    naming it — authority widening through the back door."""
    narrow = Permissions((Capability("deploy", "prod"),))
    st = ExecutionState("sha256:payload", "deploy", "prod", "update_set",
                        permissions=narrow)
    b = boundary(ring, keys, redirect("dev"))
    r = b.handle(inbound=envelope(ring, st, narrow), state=st, next_destination="node-c")
    assert r.disposition is Disposition.INTERDICT and not r.rerouted
    assert Reject.NOT_PERMITTED in r.verdict.reasons
    assert "reroute may send work where the rules already allow it" in r.verdict.detail
    assert r.successor is None


@pytest.mark.parametrize("disposition", [Disposition.GATE, Disposition.ELEVATE,
                                         Disposition.INTERDICT, Disposition.RECOVER])
def test_a_reroute_cannot_release_something_the_boundary_held_or_refused(
        ring, keys, state, perms, disposition):
    """A reroute modifies where an action runs. It is not a way to turn a
    hold into a release, so on anything that does not execute it is simply
    dropped and the original outcome stands."""
    b = boundary(ring, keys, redirect("dev", disposition=disposition))
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c")
    assert r.disposition is disposition and not r.rerouted
    assert r.receipt.released_target is None


def test_redirecting_to_where_it_was_already_going_is_not_an_intervention(
        ring, keys, state, perms):
    b = boundary(ring, keys, redirect("prod"))
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c")
    assert r.disposition is Disposition.RELEASE and not r.rerouted
    assert r.receipt.requested_target is None


# --------------------------------------------------------------- invariants
def test_a_redirected_successor_still_cannot_widen_authority(ring, keys, state, perms):
    """The central invariant survives the new path: the successor minted for a
    rerouted action is still bounded by what came in."""
    b = boundary(ring, keys, redirect("dev"))
    inbound = envelope(ring, state, perms)
    r = b.handle(inbound=inbound, state=state, next_destination="node-c",
                 next_permissions=Permissions((Capability("deploy", "dev"),)))
    assert r.rerouted
    assert inbound.permissions.subsumes(r.successor.permissions)
    assert r.successor.expires_ms <= inbound.expires_ms


def test_the_reroute_does_not_move_the_successors_destination(ring, keys, state, perms):
    """Target and destination are different fields. Policy is written about
    resources; re-pointing a permission check at a node name would quietly
    stop every such rule matching."""
    b = boundary(ring, keys, redirect("dev"))
    r = b.handle(inbound=envelope(ring, state, perms), state=state,
                 next_destination="node-c")
    assert r.successor.scope == "node-c"
    assert r.successor_state.target == "dev"


# ------------------------------------------- redirected by the boundary before
def test_a_receiving_boundary_records_a_reroute_the_previous_one_made(
        ring, keys, state, perms):
    """Appendix B step 2: the *originating* boundary applies the disposition
    and mints the successor for the selected destination. By the time the
    state arrives here it names the authorised target — the receiving boundary
    has no authority over the one that was refused and could not verify it if
    it did. So the target asked for travels alongside, and the receipt carries
    both."""
    dev = ExecutionState("sha256:payload", "deploy", "dev", "update_set",
                         permissions=perms)
    b = boundary(ring, keys, None)
    r = b.handle(inbound=envelope(ring, dev, perms), state=dev,
                 next_destination="node-c", requested_target="prod")
    assert r.disposition is Disposition.RELEASE
    assert r.requested_target == "prod"
    assert r.receipt.requested_target == "prod"
    assert r.receipt.released_target == "dev"


def test_a_requested_target_equal_to_the_released_one_is_not_an_intervention(
        ring, keys, perms):
    dev = ExecutionState("sha256:payload", "deploy", "dev", "update_set",
                         permissions=perms)
    b = boundary(ring, keys, None)
    r = b.handle(inbound=envelope(ring, dev, perms), state=dev,
                 next_destination="node-c", requested_target="dev")
    assert r.requested_target is None
    assert "releasedTarget" not in r.receipt.to_jcs()


def test_an_upstream_reroute_still_cannot_reach_outside_the_authority(ring, keys):
    """Saying "I was asked for prod" is a statement about history, not a
    permission. The action still has to be inside the envelope's bound."""
    narrow = Permissions((Capability("deploy", "dev"),))
    st = ExecutionState("sha256:payload", "deploy", "prod", "update_set",
                        permissions=narrow)
    b = boundary(ring, keys, None)
    r = b.handle(inbound=envelope(ring, st, narrow), state=st,
                 next_destination="node-c", requested_target="uat")
    assert r.disposition is Disposition.INTERDICT
    assert Reject.NOT_PERMITTED in r.verdict.reasons
