"""The gate, evaluated locally.

This is the same algorithm the control plane runs, deliberately duplicated on
the client so a decision costs microseconds instead of a network round trip. A
governed tool call that waits 10-100ms for a remote answer is a governance
layer nobody keeps switched on.

What makes duplication safe is that the bundle is *content-addressed*: the
client pins a digest, every decision records that digest, and the control
plane can prove after the fact which ruleset each decision actually used. The
client cannot quietly diverge without it being visible in the evidence.

Three properties carry the whole boundary:
  - deterministic: pure function of (bundle, request). No model, no clock.
  - ordered: deny clauses before allow clauses, first match wins.
  - default-deny: an action nobody wrote a rule for is refused.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from mira_core.records import canonical, sha256_hex

# The only fields that may influence an outcome. Everything else on a proposal
# is carried into the record but CANNOT change the answer — a gate an agent can
# argue with is not a boundary.
DECISION_FIELDS = ("action", "target_instance", "artifact_type")


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str  # "allow" | "deny"
    description: str
    match: dict[str, Any] = field(default_factory=dict)

    def matches(self, request: dict[str, Any]) -> bool:
        for key, permitted in self.match.items():
            if key not in request:
                return False
            allowed = permitted if isinstance(permitted, (list, tuple, set)) else [permitted]
            if request[key] not in allowed:
                return False
        return True

    def to_jcs(self) -> dict:
        return {
            "id": self.id,
            "effect": self.effect,
            "description": self.description,
            "match": {
                k: sorted(v) if isinstance(v, (list, tuple, set)) else v
                for k, v in sorted(self.match.items())
            },
        }


@dataclass(frozen=True)
class PolicyBundle:
    bundle_id: str
    version: str
    rules: tuple[Rule, ...]
    default_effect: str = "deny"

    @classmethod
    def from_dict(cls, d: dict) -> "PolicyBundle":
        return cls(
            bundle_id=d["bundle_id"],
            version=d["version"],
            default_effect=d.get("default_effect", "deny"),
            rules=tuple(
                Rule(
                    id=r["id"], effect=r["effect"],
                    description=r.get("description", ""), match=r.get("match", {}),
                )
                for r in d["rules"]
            ),
        )

    def to_jcs(self) -> dict:
        # rule ORDER is significant (first match wins), so this preserves it
        return {
            "bundleId": self.bundle_id,
            "version": self.version,
            "defaultEffect": self.default_effect,
            "rules": [r.to_jcs() for r in self.rules],
        }

    @property
    def digest(self) -> str:
        return "sha256:" + sha256_hex(canonical(self.to_jcs()))

    def rule(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    effect: str
    rule_id: str
    reason: str
    bundle_id: str
    bundle_version: str
    bundle_digest: str
    request: dict[str, Any]
    decide_us: float
    evaluated: list[str] = field(default_factory=list)

    def to_predicate(self) -> dict:
        """The shape sealed into the record — what an auditor reads to answer
        'permitted under exactly which policy?'."""
        return {
            "decision": self.effect,
            "ruleId": self.rule_id,
            "reason": self.reason,
            "policyBundleId": self.bundle_id,
            "policyBundleVersion": self.bundle_version,
            "policyBundleSha256": self.bundle_digest,
            "request": self.request,
            "decideUs": round(self.decide_us, 1),
            "rulesEvaluated": self.evaluated,
        }


def decision_request(proposal: dict[str, Any]) -> dict[str, Any]:
    """Project a proposal down to the fields the gate is allowed to judge."""
    return {k: proposal[k] for k in DECISION_FIELDS if k in proposal}


def evaluate(proposal: dict[str, Any], bundle: PolicyBundle) -> Decision:
    """Authorize, or refuse, one proposed action. Pure and side-effect free."""
    request = decision_request(proposal)

    t0 = time.perf_counter_ns()
    matched = None
    evaluated: list[str] = []
    for rule in bundle.rules:
        evaluated.append(rule.id)
        if rule.matches(request):
            matched = rule
            break
    effect = matched.effect if matched else bundle.default_effect
    decide_us = (time.perf_counter_ns() - t0) / 1_000.0

    reason = (
        matched.description
        if matched
        else (
            f"No rule in {bundle.bundle_id}@{bundle.version} permits this action; "
            f"the basis of design is default-{bundle.default_effect}."
        )
    )
    return Decision(
        allowed=(effect == "allow"),
        effect=effect,
        rule_id=matched.id if matched else "DEFAULT",
        reason=reason,
        bundle_id=bundle.bundle_id,
        bundle_version=bundle.version,
        bundle_digest=bundle.digest,
        request=request,
        decide_us=decide_us,
        evaluated=evaluated,
    )
