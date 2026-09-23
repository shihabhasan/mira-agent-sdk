"""A disposition the client does not act on is a suggestion.

`guarded_tool` is what a customer's agent actually calls. It read one field of
the decision — `allowed` — and then ran the original function with the original
arguments. A reroute has `allowed=True`, so the rulebook said "send it to Dev"
and the SDK sent it to Prod: authority widening at the boundary, performed by
the component whose job is to prevent exactly that. A redact decision released
the un-redacted call the same way.

The record was no better. `Run.authorize` hand-built a six-field predicate and
dropped `disposition`, `rerouteTo`, `askedFor`, `modifications` and `released`,
so the permanent signed evidence said `decision: allow` under the id of the
rule that had ordered an intervention. The full predicate went only into
`content`, which is the hot tier that retention deletes.
"""
import pytest

from mira_agent.client import CannotEnforce, Interdicted, _enforce
from mira_agent.policy import PolicyBundle, evaluate

REROUTE = {
    "bundle_id": "t", "version": "1", "default_effect": "deny",
    "rules": [
        {"id": "RR-1", "disposition": "release", "reroute_to": "dev",
         "description": "Production deployments are redirected to Dev.",
         "match": {"action": "deploy", "target_instance": "prod"}},
        {"id": "OK", "disposition": "release", "description": "Dev is permitted.",
         "match": {"action": "deploy", "target_instance": "dev"}},
    ],
}

CAP = {
    "bundle_id": "t", "version": "1", "default_effect": "deny",
    "rules": [
        {"id": "M-1", "disposition": "redact",
         "description": "Dev changes proceed with the artifact masked.",
         "match": {"action": "deploy", "target_instance": "dev"},
         "modify": [{"field": "artifact", "treatment": "mask"}]},
    ],
}


def _decide(wire, proposal):
    return evaluate(proposal, PolicyBundle.from_dict(wire))


# ----------------------------------------------------------------- reroute
def test_a_rerouted_call_is_rewritten_to_the_target_the_rulebook_chose():
    d = _decide(REROUTE, {"action": "deploy", "target_instance": "prod",
                          "artifact_type": "update_set"})
    assert d.allowed and d.rerouted and d.reroute_to == "dev"
    out = _enforce(d, {"instance": "prod", "payload": "x"},
                   target="instance", resource=None)
    assert out["instance"] == "dev", "the call must go where the rulebook sent it"
    assert out["payload"] == "x", "nothing else is touched"


def test_a_plain_release_does_not_touch_the_call():
    d = _decide(REROUTE, {"action": "deploy", "target_instance": "dev",
                          "artifact_type": "update_set"})
    assert d.allowed and not d.rerouted
    kwargs = {"instance": "dev"}
    assert _enforce(d, kwargs, target="instance", resource=None) == kwargs


# ------------------------------------------------------------------ redact
def test_a_redacted_call_is_rewritten_to_what_was_released():
    d = _decide(CAP, {"action": "deploy", "target_instance": "dev",
                      "artifact_type": "update_set", "artifact": "secret-set"})
    assert d.allowed and d.modified
    out = _enforce(d, {"instance": "dev", "art": "secret-set"},
                   target="instance", resource="art")
    assert out["art"] == "[REDACTED]"


def test_a_change_the_decorator_cannot_apply_refuses_rather_than_releasing():
    """The property that makes this safe. If the rulebook changed a field the
    decorator has no argument for, running the original call while the sealed
    record claims an intervention is worse than refusing."""
    d = _decide(CAP, {"action": "deploy", "target_instance": "dev",
                      "artifact_type": "update_set", "artifact": "secret-set"})
    assert d.modified
    with pytest.raises(CannotEnforce):
        _enforce(d, {"instance": "dev"}, target="instance", resource=None)


def test_cannot_enforce_is_a_refusal_not_a_new_category():
    """Callers already catch Interdicted to mean "it did not happen"."""
    assert issubclass(CannotEnforce, Interdicted)


# ------------------------------------------------------------------ record
def _authorization(monkeypatch, wire, proposal):
    """What Run.authorize seals, without needing a server."""
    from mira_agent import client as C

    sealed = {}

    class FakeRun(C.Run):
        def __init__(self, mira):
            self.mira = mira
            self.decisions = []

        def record(self, _type, *, node, predicate, subject=None, content=None):
            sealed.update(predicate)

    class FakeMira:
        def _decide(self, p, **_):
            return evaluate(p, PolicyBundle.from_dict(wire)), None

    FakeRun(FakeMira()).authorize(**proposal)
    return sealed["authorization"]


def test_a_plain_release_seals_exactly_the_fields_it_always_did(monkeypatch):
    a = _authorization(monkeypatch, REROUTE, {
        "action": "deploy", "target_instance": "dev", "artifact_type": "update_set"})
    assert set(a) == {"decision", "ruleId", "policyBundleId", "policyBundleVersion",
                      "policyBundleSha256", "decideUs"}
    assert a["decision"] == "allow"


def test_a_reroute_is_in_the_permanent_record(monkeypatch):
    a = _authorization(monkeypatch, REROUTE, {
        "action": "deploy", "target_instance": "prod", "artifact_type": "update_set"})
    assert a["rerouteTo"] == "dev"
    assert a["askedFor"]["target_instance"] == "prod"
    assert a["ruleId"] == "RR-1"


def test_a_redaction_is_in_the_permanent_record(monkeypatch):
    a = _authorization(monkeypatch, CAP, {
        "action": "deploy", "target_instance": "dev", "artifact_type": "update_set",
        "artifact": "secret-set"})
    assert a["disposition"] == "redact"
    assert a["modifications"] == ["artifact masked"]
    assert a["released"]["artifact"] == "[REDACTED]"
