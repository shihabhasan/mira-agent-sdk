"""Schema v2 in the SDK's local gate: identical semantics to the control
plane — conditions on examiner signals, six dispositions, v1 digests
byte-for-byte unchanged, signals only from the verified argument."""
import hashlib
import json

from mira_agent.policy import Condition, PolicyBundle, evaluate
from mira_agent_core.records import canonical

BUNDLE_V1 = {"bundle_id": "t/v1", "version": "1", "default_effect": "deny", "rules": [
    {"id": "D", "effect": "deny", "description": "no prod", "match": {"action": "deploy", "target_instance": "prod"}},
    {"id": "A", "effect": "allow", "description": "non-prod", "match": {"action": "deploy", "target_instance": ["dev", "test"]}},
]}


def _b(*rules):
    return PolicyBundle.from_dict({"bundle_id": "t/b", "version": "1", "default_effect": "deny", "rules": list(rules)})


def _v1_digest(d):
    jcs = {"bundleId": d["bundle_id"], "version": d["version"], "defaultEffect": d["default_effect"],
           "rules": [{"id": r["id"], "effect": r["effect"], "description": r["description"],
                      "match": {k: sorted(v) if isinstance(v, list) else v for k, v in sorted(r["match"].items())}}
                     for r in d["rules"]]}
    return "sha256:" + hashlib.sha256(canonical(jcs)).hexdigest()


def test_v1_digest_is_unchanged_under_v2():
    assert PolicyBundle.from_dict(BUNDLE_V1).digest == _v1_digest(BUNDLE_V1)


def test_default_disposition_spelled_out_hashes_the_same():
    a = _b({"id": "R", "effect": "deny", "description": "d", "match": {"action": "x"}})
    b = _b({"id": "R", "effect": "deny", "disposition": "interdict", "description": "d", "match": {"action": "x"}})
    assert a.digest == b.digest


def test_v2_fields_change_the_digest_and_survive_the_wire():
    r = {"id": "R", "disposition": "elevate", "escalate_to": "cab", "description": "d", "match": {"action": "x"},
         "conditions": [{"field": "signal.pii_medical", "op": ">=", "value": 0.4}], "evidence": ["payload_hash"],
         "examiners": ["mira-basic"], "provenance": {"authored_by": "nl-draft"}}
    b = _b(r)
    assert b.digest != _b({"id": "R", "effect": "deny", "description": "d", "match": {"action": "x"}}).digest
    assert b.rules[0].effect == "deny" and b.rules[0].resolved_disposition == "elevate"
    assert b.signals == ("signal.pii_medical",)


def test_threshold_conditions_and_dispositions():
    b = _b({"id": "INJ", "disposition": "elevate", "escalate_to": "security-desk", "description": "quarantine",
            "match": {"action": "ingest"}, "conditions": [{"field": "signal.prompt_injection", "op": ">=", "value": 0.8}]},
           {"id": "OK", "disposition": "release", "description": "clean", "match": {"action": "ingest"},
            "conditions": [{"field": "signal.prompt_injection", "op": "<", "value": 0.8}]})
    hot = evaluate({"action": "ingest"}, b, signals={"prompt_injection": 0.93})
    assert hot.rule_id == "INJ" and hot.disposition == "elevate" and hot.held and not hot.allowed
    assert hot.escalate_to == "security-desk" and hot.to_predicate()["escalateTo"] == "security-desk"
    ok = evaluate({"action": "ingest"}, b, signals={"prompt_injection": 0.1})
    assert ok.rule_id == "OK" and ok.allowed and ok.disposition == "release"
    # no examiner spoke: neither rule fires, default-deny
    assert evaluate({"action": "ingest"}, b).rule_id == "DEFAULT"


def test_signals_come_only_from_the_argument():
    b = _b({"id": "OK", "disposition": "release", "description": "clean", "match": {"action": "ingest"},
            "conditions": [{"field": "signal.pii_present", "op": "<", "value": 0.2}]})
    d = evaluate({"action": "ingest", "signal.pii_present": 0.0}, b)
    assert not d.allowed and "signal.pii_present" not in d.request


def test_examiner_scoped_rules_hear_only_their_examiners():
    b = _b({"id": "ACME", "disposition": "interdict", "description": "acme only", "match": {"action": "ingest"},
            "examiners": ["acme"], "conditions": [{"field": "signal.prompt_injection", "op": ">=", "value": 0.8}]})
    s = {"signal.prompt_injection": 0.99}
    assert evaluate({"action": "ingest"}, b, signals=s, readings={"signal.prompt_injection": {"acme": 0.99}}).rule_id == "ACME"
    assert evaluate({"action": "ingest"}, b, signals=s, readings={"signal.prompt_injection": {"mira-basic": 0.99}}).rule_id == "DEFAULT"


def test_condition_semantics():
    assert Condition("signal.x", ">=", 0.5).holds({"signal.x": "0.75"})
    assert not Condition("signal.x", ">=", 0.5).holds({"signal.x": "high"})
    assert Condition("signal.c", "==", "medical").holds({"signal.c": "medical"})
    assert not Condition("signal.c", "!=", "medical").holds({"signal.c": "medical"})


def test_v1_predicate_shape_is_intact():
    p = evaluate({"action": "deploy", "target_instance": "prod"}, PolicyBundle.from_dict(BUNDLE_V1)).to_predicate()
    for key in ("decision", "ruleId", "reason", "policyBundleSha256", "policyBundleVersion", "request", "decideUs", "rulesEvaluated"):
        assert key in p
    assert p["decision"] == "deny" and p["disposition"] == "interdict"
    assert json.dumps(p)  # JSON-able


# --------------------------------------------------------------- reroute
# A reroute releases the action somewhere other than it was aimed. The agent's
# own gate must honour it: an SDK that ignored the field would read a reroute
# as a plain permission for the target the agent asked for, and release exactly
# the thing the rulebook was redirecting.
REROUTE = {
    "id": "RR-1", "disposition": "release", "reroute_to": "dev",
    "description": "A Production deployment is redirected to Dev rather than refused.",
    "match": {"action": "deploy", "target_instance": "prod"},
}
PROD = {"action": "deploy", "target_instance": "prod", "artifact_type": "update_set"}


def _bundle(*rules, default="deny"):
    return PolicyBundle.from_dict({"bundle_id": "t/reroute", "version": "1",
                                   "default_effect": default,
                                   "rules": [dict(r) for r in rules]})


def test_the_local_gate_honours_a_reroute_and_names_both_targets():
    b = _bundle(REROUTE, {"id": "OK", "disposition": "release",
                          "description": "Dev is permitted.",
                          "match": {"action": "deploy", "target_instance": "dev"}})
    d = evaluate(PROD, b)
    assert d.allowed and d.rerouted and d.reroute_to == "dev"
    assert d.request["target_instance"] == "dev"
    assert d.asked_for["target_instance"] == "prod"
    p = d.to_predicate()
    assert p["rerouteTo"] == "dev" and p["askedFor"]["target_instance"] == "prod"


def test_the_local_gate_fails_closed_when_the_new_target_is_not_permitted():
    d = evaluate(PROD, _bundle(REROUTE))          # nothing permits dev
    assert not d.allowed and d.disposition == "interdict" and not d.rerouted
    assert d.request["target_instance"] == "prod"


def test_the_local_gate_follows_a_reroute_once_only():
    b = _bundle(REROUTE,
                {"id": "B", "disposition": "release", "reroute_to": "test",
                 "description": "dev to test", "match": {"action": "deploy", "target_instance": "dev"}},
                {"id": "C", "disposition": "release", "description": "test is permitted",
                 "match": {"action": "deploy", "target_instance": "test"}})
    d = evaluate(PROD, b)
    assert not d.allowed and "followed once only" in d.reason


def test_a_reroute_is_in_the_canonical_form_and_absent_when_unset():
    b = _bundle(REROUTE)
    assert b.rules[0].to_jcs()["rerouteTo"] == "dev"
    plain = _bundle({"id": "A", "disposition": "release", "description": "x",
                     "match": {"action": "inspect"}})
    assert "rerouteTo" not in plain.rules[0].to_jcs()
