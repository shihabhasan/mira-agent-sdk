"""The middle severity, which until now did nothing.

`Severity.RESTRICTED` has always carried the docstring "Authority narrows:
high-consequence capabilities are withheld", and the white paper says a
downstream boundary can "stop execution, narrow authority, withhold
credentials, recover to a trusted checkpoint, substitute a clean agent or
require explicit authorised risk acceptance" (§6, D.3). Only the first of
those was wired: verification refused a TERMINAL card and ignored everything
milder, so a restricted actor and an unblemished one were indistinguishable.

Appendix D.3 also lists `scope` among the things an adverse assertion
identifies. Without it "narrow authority" has no way to say how far, so the
two arrive together: an explicit scope withdraws exactly what it names, and
an empty one falls back to whatever the boundary calls high-consequence.
"""

import pytest

from _msep_keys import KeyRing
from mira_agent.msep import (Capability, Disposition, ExecutionBoundary, ExecutionState,
                             KeyCache, Permissions, Reject, Severity, TrustEpoch,
                             issue_red_card, new_envelope, reinstate)
from mira_agent.msep.trust import AdverseTrustAssertion

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
    return Permissions((Capability("deploy", "prod"), Capability("deploy", "dev"),
                        Capability("inspect")))


def card(ring, severity=Severity.RESTRICTED, scope=(), subject="spiffe://acme/agent/1"):
    return issue_red_card(subject=subject, reason="prohibited_exfiltration",
                          trigger_commitment="sha256:trigger", issued_by="node-a",
                          epoch=1, key=ring.get("msep/a"), severity=severity,
                          scope=scope, now_ms=1_700_000_000_000)


def state(action="deploy", target="prod", perms=None):
    return ExecutionState("sha256:payload", action, target, "update_set",
                          permissions=perms or Permissions(()))


def envelope(ring, st, perms, **kw):
    args = dict(identity="spiffe://acme/agent/1", state=st, scope="node-b",
                permissions=perms, epoch=1, policy_digest=POLICY,
                key=ring.get("msep/a"))
    args.update(kw)
    return new_envelope(**args)


def boundary(ring, keys, name="node-b"):
    return ExecutionBoundary(name=name, key=ring.get("msep/b"), keys=keys,
                             epoch=TrustEpoch(1), policy_digest=POLICY)


# ------------------------------------------------------------------- scoping
def test_an_explicit_scope_withdraws_exactly_what_it_names(ring):
    c = card(ring, scope=("deploy",))
    assert c.restricts("deploy", "dev")
    assert c.restricts("deploy", "prod")
    assert not c.restricts("inspect", "prod")


def test_an_action_target_pair_withdraws_only_that_target(ring):
    c = card(ring, scope=("deploy:prod",))
    assert c.restricts("deploy", "prod")
    assert not c.restricts("deploy", "dev")


def test_an_unscoped_restriction_falls_back_to_high_consequence(ring):
    """Deliberately the boundary's own classifier rather than a second
    definition of "serious" living here. `consequence_of` calls anything
    touching production high-consequence, reads included — which for an actor
    that just exfiltrated data is the direction to err in."""
    c = card(ring)
    assert c.restricts("deploy", "prod")
    assert c.restricts("inspect", "prod")
    assert not c.restricts("deploy", "dev")    # ordinary non-production write
    assert not c.restricts("inspect", "dev")


@pytest.mark.parametrize("severity", [Severity.NOTED, Severity.TERMINAL])
def test_only_a_restricted_card_narrows(ring, severity):
    """TERMINAL stops everything and is refused before this is reached; NOTED
    is recorded and carried but changes nothing."""
    assert not card(ring, severity=severity).restricts("deploy", "prod")


def test_a_scope_on_a_card_that_cannot_narrow_is_refused(ring):
    with pytest.raises(ValueError, match="cannot carry a scope"):
        card(ring, severity=Severity.TERMINAL, scope=("deploy",))


# ------------------------------------------------------------- the signature
def test_a_card_without_a_scope_signs_exactly_what_it_always_did(ring):
    """Every card signed before the field existed still verifies."""
    c = card(ring)
    assert "scope" not in c.signing_body()
    assert c.signature_valid(ring.get("msep/a").public_bytes)


def test_a_scope_cannot_be_stripped_in_transit(ring):
    """The obvious attack: drop the field and the narrowing disappears. It is
    covered by the signature like everything else."""
    from dataclasses import replace
    c = card(ring, scope=("deploy",))
    assert c.signature_valid(ring.get("msep/a").public_bytes)
    widened = replace(c, scope=())
    assert not widened.signature_valid(ring.get("msep/a").public_bytes)
    assert AdverseTrustAssertion.from_wire(c.to_wire()).scope == ("deploy",)


# ------------------------------------------------------------ at the boundary
def test_a_restricted_actor_is_refused_the_action_that_was_withdrawn(ring, keys, perms):
    b = boundary(ring, keys)
    b.record_adverse(card(ring, scope=("deploy:prod",)))
    st = state("deploy", "prod", perms)
    r = b.handle(inbound=envelope(ring, st, perms), state=st)
    assert r.disposition is Disposition.INTERDICT
    assert Reject.ADVERSE_RESTRICTED in r.verdict.reasons
    assert "deploy -> prod is withdrawn" in r.verdict.detail


def test_the_same_actor_may_still_do_what_was_not_withdrawn(ring, keys, perms):
    b = boundary(ring, keys)
    b.record_adverse(card(ring, scope=("deploy:prod",)))
    st = state("deploy", "dev", perms)
    r = b.handle(inbound=envelope(ring, st, perms), state=st)
    assert r.disposition is Disposition.RELEASE, r.verdict.reasons


def test_a_card_riding_on_the_envelope_restricts_too(ring, keys, perms):
    """A boundary that has not heard from the control plane still honours the
    card travelling with the action — which is what makes standing enforceable
    off-premises."""
    b = boundary(ring, keys)
    st = state("deploy", "prod", perms)
    env = envelope(ring, st, perms, adverse=card(ring, scope=("deploy",)).to_wire())
    r = b.handle(inbound=env, state=st)
    assert Reject.ADVERSE_RESTRICTED in r.verdict.reasons


def test_a_restriction_narrows_the_successor_and_not_just_this_hop(ring, keys, perms):
    """Otherwise the card lasts exactly one hop: the next boundary would be
    handed the full capability vector again."""
    b = boundary(ring, keys)
    b.record_adverse(card(ring, scope=("deploy:prod",)))
    st = state("inspect", "dev", perms)
    r = b.handle(inbound=envelope(ring, st, perms), state=st,
                 next_destination="node-c", next_action="inspect")
    assert r.disposition is Disposition.RELEASE, r.verdict.reasons
    onward = [(c.action, c.target) for c in r.successor.permissions.caps]
    assert ("deploy", "prod") not in onward
    assert ("deploy", "dev") in onward


def test_reinstatement_drops_the_scope_with_the_restriction(ring, keys, perms):
    c = card(ring, scope=("deploy:prod",))
    back = reinstate(c, authorised_by="ciso@acme.example", key=ring.get("msep/a"))
    assert back.severity is Severity.NOTED and back.scope == ()
    assert not back.restricts("deploy", "prod")
    b = boundary(ring, keys)
    b.record_adverse(back)
    st = state("deploy", "prod", perms)
    assert b.handle(inbound=envelope(ring, st, perms), state=st).disposition \
        is Disposition.RELEASE


def test_a_scope_survives_the_estate_wide_channel(ring, keys):
    """D.4: the control plane distributes actor-level trust changes to
    boundaries that never saw the workflow. A scope that did not survive that
    trip would arrive as an unscoped restriction and withdraw more than the
    issuing boundary decided."""
    from mira_agent.msep.signals import emit_red_card, ingest
    c = card(ring, scope=("deploy:prod",))
    tok = emit_red_card(c, issuer="mira/control-plane", audience="node-c",
                        key=ring.get("msep/a"), now_ms=1_700_000_000_000)
    back = ingest(tok.compact(), resolve_key=keys.get, expected_audience="node-c",
                  now_ms=1_700_000_001_000)
    assert back.scope == ("deploy:prod",)
    assert back.restricts("deploy", "prod") and not back.restricts("deploy", "dev")


def test_a_boundary_that_never_saw_the_workflow_enforces_the_scope(ring, keys, perms):
    from mira_agent.msep.signals import emit_red_card
    b = boundary(ring, keys, name="node-c")
    tok = emit_red_card(card(ring, scope=("deploy:prod",)), issuer="mira/control-plane",
                        audience="node-c", key=ring.get("msep/a"),
                        now_ms=1_700_000_000_000)
    b.apply_signal(tok.compact(), now_ms=1_700_000_001_000)
    st = state("deploy", "prod", perms)
    r = b.handle(inbound=envelope(ring, st, perms, scope="node-c"), state=st)
    assert Reject.ADVERSE_RESTRICTED in r.verdict.reasons
