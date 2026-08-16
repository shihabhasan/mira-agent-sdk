"""The Cedar front-end.

Half these tests assert the compiler REFUSES something. That is the point: a
policy compiler that silently drops a clause it does not understand will one
day drop a `forbid`. Refusing at compile time, where a human is watching, is
the only safe failure mode.
"""

from __future__ import annotations

import pytest

from mira_agent import CedarError, compile_cedar
from mira_agent.policy import evaluate

CHANGE_CONTROL = '''
// Production is off limits to autonomous agents.
@id("BOD-1.1")
@description("No autonomous deployment to Production.")
forbid (principal, action == Action::"deploy", resource)
when { resource.target_instance == "prod" };

@id("BOD-1.2")
@description("No destructive operations on Production.")
forbid (principal, action in [Action::"drop_table", Action::"purge"], resource)
when { resource.target_instance == "prod" };

@id("BOD-2.1")
@description("Agents may deploy freely below Production.")
permit (principal, action == Action::"deploy", resource)
when { resource.target_instance in ["dev", "test", "uat"] };

@id("BOD-2.2")
@description("Read-only inspection is always permitted.")
permit (principal, action == Action::"inspect", resource);
'''


@pytest.fixture
def bundle():
    return compile_cedar(CHANGE_CONTROL, bundle_id="cedar/test", version="1.0.0")


def test_it_compiles_to_a_usable_bundle(bundle):
    assert bundle.bundle_id == "cedar/test"
    assert bundle.default_effect == "deny"
    assert {r.id for r in bundle.rules} == {"BOD-1.1", "BOD-1.2", "BOD-2.1", "BOD-2.2"}


def test_annotations_carry_through(bundle):
    r = bundle.rule("BOD-1.1")
    assert r.effect == "deny"
    assert "Production" in r.description


def test_forbids_are_emitted_before_permits(bundle):
    """Cedar is forbid-overrides and order-independent; the gate is
    first-match. Ordering is what makes the two agree."""
    effects = [r.effect for r in bundle.rules]
    assert effects == sorted(effects, key=lambda e: e != "deny")
    assert effects[0] == "deny"


@pytest.mark.parametrize("proposal,expected_rule,allowed", [
    ({"action": "deploy", "target_instance": "prod"}, "BOD-1.1", False),
    ({"action": "drop_table", "target_instance": "prod"}, "BOD-1.2", False),
    ({"action": "purge", "target_instance": "prod"}, "BOD-1.2", False),
    ({"action": "deploy", "target_instance": "dev"}, "BOD-2.1", True),
    ({"action": "deploy", "target_instance": "uat"}, "BOD-2.1", True),
    ({"action": "inspect", "target_instance": "prod"}, "BOD-2.2", True),
    ({"action": "unheard_of", "target_instance": "dev"}, "DEFAULT", False),
])
def test_compiled_policy_decides_correctly(bundle, proposal, expected_rule, allowed):
    d = evaluate(proposal, bundle)
    assert d.rule_id == expected_rule
    assert d.allowed is allowed


def test_the_bundle_is_content_addressed(bundle):
    again = compile_cedar(CHANGE_CONTROL, bundle_id="cedar/test", version="1.0.0")
    assert bundle.digest == again.digest

    edited = CHANGE_CONTROL.replace('"prod"', '"production"', 1)
    other = compile_cedar(edited, bundle_id="cedar/test", version="1.0.0")
    assert other.digest != bundle.digest


# ------------------------------------------------------ what it refuses

@pytest.mark.parametrize("policy,why", [
    ('permit (principal, action, resource) unless { resource.x == "y" };', "unless"),
    ('permit (principal, action, resource) when { resource has target };', "has"),
    ('permit (principal, action, resource) when { resource.t like "pro*" };', "like"),
    ('permit (principal, action, resource) when { resource.t != "prod" };', "inequality"),
    ('permit (principal, action, resource) when { resource.a == "x" || resource.b == "y" };', "||"),
    ('permit (principal, action, resource) when { context.mfa == "yes" };', "context"),
    ('permit (principal in Group::"ops", action, resource) when { resource.t == "dev" };', "principal"),
])
def test_unsupported_cedar_is_refused_not_approximated(policy, why):
    with pytest.raises(CedarError):
        compile_cedar(policy, bundle_id="x", version="1")


def test_an_unconditional_permit_is_refused():
    """It would allow every action. If that is genuinely intended, it should
    be written explicitly rather than falling out of a compiler."""
    with pytest.raises(CedarError, match="constrains nothing"):
        compile_cedar("permit (principal, action, resource);", bundle_id="x", version="1")


def test_garbage_is_refused():
    with pytest.raises(CedarError):
        compile_cedar("this is not cedar at all", bundle_id="x", version="1")


def test_empty_source_is_refused():
    with pytest.raises(CedarError, match="no Cedar policies"):
        compile_cedar("   // just a comment\n", bundle_id="x", version="1")


def test_an_untranslatable_condition_fragment_is_refused():
    with pytest.raises(CedarError, match="could not translate"):
        compile_cedar(
            'permit (principal, action == Action::"x", resource)\n'
            'when { resource.a == "b" && resource.count };',
            bundle_id="x", version="1",
        )
