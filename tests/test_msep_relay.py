"""Evidence that travels with the next interaction when the ledger is out.

Section 9: "If the ledger is unreachable, the receipt remains durably queued.
A bounded relay extension can carry limited outstanding evidence with a later
interaction; excess evidence remains queued rather than allowing the execution
envelope to grow without bound."

The queue half of that was built and the carrying half was not: `relay_batch`
existed and nothing ever called it. These tests pin both halves and the bound
between them.
"""
import pytest

from _msep_keys import KeyRing
from mira_agent.msep import (Capability, Disposition, ExecutionBoundary, ExecutionState,
                             KeyCache, Permissions, ReceiptQueue, TrustEpoch, new_envelope)

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
    return Permissions((Capability("deploy", "dev"), Capability("inspect")))


@pytest.fixture
def state(perms):
    return ExecutionState("sha256:payload", "deploy", "dev", "update_set",
                          permissions=perms)


def boundary(ring, keys, name="node-b", key="msep/b"):
    return ExecutionBoundary(name=name, key=ring.get(key), keys=keys,
                             epoch=TrustEpoch(1), policy_digest=POLICY,
                             queue=ReceiptQueue())


def envelope(ring, state, perms, **kw):
    args = dict(identity="spiffe://acme/agent/1", state=state, scope="node-b",
                permissions=perms, epoch=1, policy_digest=POLICY,
                key=ring.get("msep/a"))
    args.update(kw)
    return new_envelope(**args)


def test_a_partitioned_boundary_hands_its_backlog_to_the_next_hop(ring, keys, state, perms):
    cut_off = boundary(ring, keys)
    for _ in range(3):
        cut_off.handle(inbound=envelope(ring, state, perms), state=state)
    assert cut_off.queue.depth() == 3

    onward = boundary(ring, keys, name="node-c", key="msep/c")
    carried = cut_off.relay()
    assert cut_off.queue.depth() == 0, "relayed receipts are handed over, not copied"
    assert onward.absorb(carried) == 3
    assert onward.queue.depth() == 3
    # and the receipts still name the boundary that actually decided
    assert {r.boundary for r in onward.queue.drain()} == {"node-b"}


def test_the_relay_is_bounded_and_the_rest_stays_queued(ring, keys, state, perms):
    """The property that keeps an outage from growing the hot path: a boundary
    that has been cut off for an hour hands on a batch, not an hour."""
    b = boundary(ring, keys)
    for _ in range(20):
        b.handle(inbound=envelope(ring, state, perms), state=state)
    assert len(b.relay(limit=8)) == 8
    assert b.queue.depth() == 12


def test_relaying_an_empty_queue_carries_nothing(ring, keys):
    assert boundary(ring, keys).relay() == []


def test_absorbed_receipts_can_be_relayed_on_again(ring, keys, state, perms):
    """A three-hop partition: the middle boundary is no better connected than
    the first, and the backlog keeps moving rather than stopping with it."""
    a = boundary(ring, keys)
    a.handle(inbound=envelope(ring, state, perms), state=state)
    b = boundary(ring, keys, name="node-c", key="msep/c")
    b.absorb(a.relay())
    c = boundary(ring, keys, name="node-d", key="msep/a")
    assert c.absorb(b.relay()) == 1
    assert b.queue.depth() == 0 and c.queue.depth() == 1


def test_carrying_a_neighbours_receipt_is_not_agreeing_with_it(ring, keys, state, perms):
    """A relayed receipt keeps its own signer. If carrying one re-attributed
    the decision, a boundary could launder another's refusal into its own
    release simply by offering to help."""
    refuser = boundary(ring, keys)
    from mira_agent.msep import PolicyOutcome
    refuser.decide = lambda e, s: PolicyOutcome(Disposition.INTERDICT, reason="no")
    refuser.handle(inbound=envelope(ring, state, perms), state=state)
    helper = boundary(ring, keys, name="node-c", key="msep/c")
    helper.absorb(refuser.relay())
    carried = helper.queue.drain()[0]
    assert carried.boundary == "node-b"
    assert carried.disposition is Disposition.INTERDICT
