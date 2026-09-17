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
  - ordered: holds and refusals before releases, first match wins.
  - default-deny: an action nobody wrote a rule for is refused.

Schema v2 adds, without changing what a v1 rule means or hashes to:

  - conditions: threshold tests on examiner *signals*
    (`signal.prompt_injection >= 0.8`). Signals enter only through the
    `signals` argument — verified assertions from registered examiners —
    never from the agent's own proposal.
  - disposition: release / redact execute; gate / elevate hold; interdict /
    recover refuse. `effect` stays the allow/deny summary.
  - escalate_to, evidence, examiners, provenance.

Every v2 field is left out of the canonical form when empty or equal to the
v1 default, so a bundle written before v2 has exactly the digest it had.
"""

from __future__ import annotations

import functools
import time
from dataclasses import dataclass, field
from typing import Any

from mira_agent_core.records import canonical, sha256_hex

# The only fields that may influence an outcome. Everything else on a proposal
# is carried into the record but CANNOT change the answer — a gate an agent can
# argue with is not a boundary.
DECISION_FIELDS = ("action", "target_instance", "artifact_type")

DISPOSITIONS = ("release", "redact", "gate", "elevate", "interdict", "recover")
RELEASING = frozenset({"release", "redact"})
NUMERIC_OPS = (">=", ">", "<=", "<")
CONDITION_OPS = NUMERIC_OPS + ("==", "!=")
SIGNAL_PREFIX = "signal."


def effect_for(disposition: str) -> str:
    return "allow" if disposition in RELEASING else "deny"


def default_disposition(effect: str) -> str:
    return "release" if effect == "allow" else "interdict"


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: Any

    def holds(self, request: dict[str, Any]) -> bool:
        if self.field not in request:
            return False
        actual = request[self.field]
        if self.op in NUMERIC_OPS:
            a, b = _num(actual), _num(self.value)
            if a is None or b is None:
                return False
            return {">=": a >= b, ">": a > b, "<=": a <= b, "<": a < b}[self.op]
        same = actual == self.value or (_num(actual) is not None and _num(actual) == _num(self.value))
        return same if self.op == "==" else (not same if self.op == "!=" else False)

    def to_jcs(self) -> dict:
        return {"field": self.field, "op": self.op, "value": self.value}


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str  # "allow" | "deny"
    description: str
    match: dict[str, Any] = field(default_factory=dict)
    conditions: tuple[Condition, ...] = ()
    disposition: str | None = None
    escalate_to: str | None = None
    # Release the action, but against a different target than the one asked
    # for. A modifier on a releasing rule, not a disposition: the answer to
    # "does this run now" is unchanged, only where it runs. An SDK that
    # ignored this field would read a reroute as a plain permission for the
    # target the agent asked for, which is the opposite of what it says.
    reroute_to: str | None = None
    evidence: tuple[str, ...] = ()
    examiners: tuple[str, ...] = ()
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def resolved_disposition(self) -> str:
        return self.disposition or default_disposition(self.effect)

    def matches(self, request: dict[str, Any]) -> bool:
        for key, permitted in self.match.items():
            if key not in request:
                return False
            allowed = permitted if isinstance(permitted, (list, tuple, set)) else [permitted]
            if request[key] not in allowed:
                return False
        return all(c.holds(request) for c in self.conditions)

    def to_jcs(self) -> dict:
        out: dict[str, Any] = {
            "id": self.id,
            "effect": self.effect,
            "description": self.description,
            "match": {
                k: sorted(v) if isinstance(v, (list, tuple, set)) else v
                for k, v in sorted(self.match.items())
            },
        }
        if self.conditions:
            out["conditions"] = [c.to_jcs() for c in sorted(
                self.conditions, key=lambda c: (c.field, c.op, str(c.value)))]
        if self.disposition and self.disposition != default_disposition(self.effect):
            out["disposition"] = self.disposition
        if self.escalate_to:
            out["escalateTo"] = self.escalate_to
        if self.reroute_to:
            out["rerouteTo"] = self.reroute_to
        if self.evidence:
            out["evidence"] = sorted(self.evidence)
        if self.examiners:
            out["examiners"] = sorted(self.examiners)
        if self.provenance:
            out["provenance"] = {k: self.provenance[k] for k in sorted(self.provenance)}
        return out

    @classmethod
    def from_dict(cls, r: dict) -> "Rule":
        disposition = r.get("disposition") or None
        effect = r.get("effect") or (effect_for(disposition) if disposition else None)
        if effect is None:
            raise ValueError(f"rule {r.get('id')!r} has neither effect nor disposition")
        return cls(
            id=r["id"], effect=effect, description=r.get("description", ""),
            match=r.get("match", {}) or {},
            conditions=tuple(Condition(str(c["field"]), str(c["op"]), c.get("value"))
                             for c in (r.get("conditions") or [])),
            disposition=disposition,
            escalate_to=(r.get("escalate_to") or None),
            reroute_to=(r.get("reroute_to") or r.get("rerouteTo") or None),
            evidence=tuple(r.get("evidence") or ()),
            examiners=tuple(r.get("examiners") or ()),
            provenance=dict(r.get("provenance") or {}),
        )


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
            rules=tuple(Rule.from_dict(r) for r in d["rules"]),
        )

    def to_jcs(self) -> dict:
        # rule ORDER is significant (first match wins), so this preserves it
        return {
            "bundleId": self.bundle_id,
            "version": self.version,
            "defaultEffect": self.default_effect,
            "rules": [r.to_jcs() for r in self.rules],
        }

    # Cached because a bundle is frozen and the digest is read on every
    # decision, to be sealed into the record. Recomputing the canonical form
    # and its SHA-256 per authorization cost ~70us against rule matching under
    # 1us, making the digest the most expensive part of deciding.
    # cached_property writes through to __dict__, which a frozen dataclass
    # still has, so nothing needs unfreezing.
    @functools.cached_property
    def digest(self) -> str:
        return "sha256:" + sha256_hex(canonical(self.to_jcs()))

    def rule(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    @property
    def signals(self) -> tuple[str, ...]:
        return tuple(sorted({c.field for r in self.rules for c in r.conditions
                             if c.field.startswith(SIGNAL_PREFIX)}))


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
    disposition: str = "interdict"
    escalate_to: str | None = None
    reroute_to: str | None = None
    asked_for: dict[str, Any] | None = None
    evidence: tuple[str, ...] = ()

    @property
    def held(self) -> bool:
        return self.disposition in ("gate", "elevate")

    def to_predicate(self) -> dict:
        """The shape sealed into the record — what an auditor reads to answer
        'permitted under exactly which policy?'."""
        out = {
            "decision": self.effect,
            "disposition": self.disposition,
            "ruleId": self.rule_id,
            "reason": self.reason,
            "policyBundleId": self.bundle_id,
            "policyBundleVersion": self.bundle_version,
            "policyBundleSha256": self.bundle_digest,
            "request": self.request,
            "decideUs": round(self.decide_us, 1),
            "rulesEvaluated": self.evaluated,
        }
        if self.escalate_to:
            out["escalateTo"] = self.escalate_to
        if self.evidence:
            out["evidence"] = list(self.evidence)
        if self.reroute_to:
            out["rerouteTo"] = self.reroute_to
            out["askedFor"] = self.asked_for
        return out

    @property
    def rerouted(self) -> bool:
        return self.reroute_to is not None


def decision_request(proposal: dict[str, Any],
                     signals: dict[str, Any] | None = None) -> dict[str, Any]:
    """Project a proposal down to the fields the gate is allowed to judge.
    Signals come only from the verified argument; a `signal.*` key the
    proposal itself carries is discarded."""
    request = {k: proposal[k] for k in DECISION_FIELDS if k in proposal}
    for name, value in (signals or {}).items():
        request[name if name.startswith(SIGNAL_PREFIX) else SIGNAL_PREFIX + name] = value
    return request


def _heard_by(rule: Rule, request: dict[str, Any],
              readings: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    """A rule that names its examiners is judged on their readings alone;
    when they disagree on a score the higher is used. With nothing
    attributed, the merged signals stand."""
    if not rule.examiners or not readings:
        return request
    out = {k: v for k, v in request.items() if not k.startswith(SIGNAL_PREFIX)}
    for k in request:
        if k.startswith(SIGNAL_PREFIX) and k in readings:
            heard = [readings[k][e] for e in rule.examiners if e in readings[k]]
            if heard:
                nums = [h for h in heard if isinstance(h, (int, float)) and not isinstance(h, bool)]
                out[k] = max(nums) if len(nums) == len(heard) else heard[0]
    return out


def evaluate(proposal: dict[str, Any], bundle: PolicyBundle, *,
             signals: dict[str, Any] | None = None,
             readings: dict[str, dict[str, Any]] | None = None) -> Decision:
    """Authorize, or refuse, one proposed action. Pure and side-effect free."""
    request = decision_request(proposal, signals)
    t0 = time.perf_counter_ns()
    matched = None
    evaluated: list[str] = []
    for rule in bundle.rules:
        evaluated.append(rule.id)
        if rule.matches(_heard_by(rule, request, readings)):
            matched = rule
            break
    disposition = matched.resolved_disposition if matched else default_disposition(bundle.default_effect)
    effect = effect_for(disposition)
    decide_us = (time.perf_counter_ns() - t0) / 1_000.0
    reason = (
        matched.description
        if matched
        else (
            f"No rule in {bundle.bundle_id}@{bundle.version} permits this action; "
            f"the basis of design is default-{bundle.default_effect}."
        )
    )
    # A reroute releases the action somewhere other than where it was aimed.
    # The redirected action is judged against the whole bundle as if it had
    # been proposed that way, and released only if the rules permit it there;
    # a reroute that lands on another reroute is refused rather than followed.
    # Identical to the control plane's gate, and the conformance vectors hold
    # both to the same bytes.
    if matched is not None and matched.reroute_to and disposition in RELEASING:
        asked_for = dict(request)
        onward = evaluate({**proposal, "target_instance": matched.reroute_to}, bundle,
                          signals=signals, readings=readings)
        decide_us = (time.perf_counter_ns() - t0) / 1_000.0
        if not onward.allowed or onward.rerouted:
            detail = ("the redirected action is refused there too" if not onward.allowed
                      else "the redirected action would be rerouted again, and a reroute "
                           "is followed once only")
            return Decision(
                allowed=False, effect="deny", rule_id=matched.id,
                reason=(f"{matched.description} The reroute to {matched.reroute_to!r} was "
                        f"not taken: {detail} ({onward.rule_id}). Nothing is released."),
                bundle_id=bundle.bundle_id, bundle_version=bundle.version,
                bundle_digest=bundle.digest, request=asked_for, decide_us=decide_us,
                evaluated=evaluated + onward.evaluated, disposition="interdict",
                evidence=matched.evidence)
        return Decision(
            allowed=True, effect="allow", rule_id=matched.id,
            reason=(f"{matched.description} Rerouted from "
                    f"{asked_for.get('target_instance')!r} to {matched.reroute_to!r}, "
                    f"where {onward.rule_id} permits it."),
            bundle_id=bundle.bundle_id, bundle_version=bundle.version,
            bundle_digest=bundle.digest, request=onward.request, decide_us=decide_us,
            evaluated=evaluated + onward.evaluated, disposition=onward.disposition,
            evidence=matched.evidence, reroute_to=matched.reroute_to, asked_for=asked_for)

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
        disposition=disposition,
        escalate_to=matched.escalate_to if matched else None,
        evidence=matched.evidence if matched else (),
    )
