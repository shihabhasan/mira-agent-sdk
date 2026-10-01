"""Authority that travels with the action, checked locally at every hop.

Three boundaries — intake, assessment, submission — and a rulebook plugged
into each one's policy hook. The control plane signs one root envelope; from
then on every boundary verifies what it was handed by itself (signature,
permission bound, state digest), asks the rulebook what to do, and mints a
narrower successor for the next hop. No step calls anyone.

Then the two things a reviewer tries first: widening the authority, and
editing the state in transit. Both are refused at the next hop, locally.

    python examples/02_msep_hops.py
"""
import hashlib
import json
from pathlib import Path

from mira_agent import PolicyBundle, evaluate
from mira_agent.msep import (Capability, Disposition, ExecutionBoundary, ExecutionState,
                             KeyCache, Permissions, PolicyOutcome, Reject, TrustEpoch,
                             new_envelope, verify_succession)
from mira_agent_core.keys import SigningKey

HERE = Path(__file__).parent
bundle = PolicyBundle.from_dict(
    json.loads((HERE / "rulebooks" / "pharmacovigilance-case-handling.json").read_text()))

# Keys: one for the control plane, one per boundary. In a deployment the
# control plane distributes the public halves; here they live in one cache.
control = SigningKey.generate("mira/control-plane")
names = ("intake", "assess", "submit")
boundary_keys = {n: SigningKey.generate(f"msep/{n}") for n in names}
keys = KeyCache()
for k in (control, *boundary_keys.values()):
    keys.add(k.key_id, k.public_bytes)


def ruled(env, state):
    """The rulebook as a boundary's policy hook: consulted only after the
    envelope has verified, so it can never wave through forged authority."""
    d = evaluate({"action": state.action, "target_instance": state.target,
                  "artifact_type": state.artifact}, bundle)
    reason = f"{d.rule_id}: {d.reason}" + (f" — {d.escalate_to} decides" if d.escalate_to else "")
    return PolicyOutcome(Disposition(d.disposition), reason=reason)


def boundaries():
    return {n: ExecutionBoundary(name=n, key=boundary_keys[n], keys=keys, epoch=TrustEpoch(1),
                                 policy_digest=bundle.digest, decide=ruled) for n in names}


# The work item is one serious case report, bound for the regulator. What
# changes from hop to hop is the action; the resource stays the same unless the
# rulebook redirects it.
case_digest = "sha256:" + hashlib.sha256(b"case PV-2026-000417, identifiers withheld").hexdigest()
everything = Permissions((Capability("intake", "regulator", "serious_icsr"),
                          Capability("assess", "regulator", "serious_icsr"),
                          Capability("submit", "regulator", "serious_icsr")))
start = ExecutionState(case_digest, "intake", "regulator", "serious_icsr", permissions=everything)
root = new_envelope(identity="spiffe://example.org/agent/case-pipeline", state=start,
                    scope="intake", permissions=everything, epoch=1,
                    policy_digest=bundle.digest, key=control)

b = boundaries()
print("the chain\n")
r1 = b["intake"].handle(
    inbound=root, state=start, next_destination="assess", next_action="assess",
    next_permissions=Permissions(everything.caps[1:]))
r2 = b["assess"].handle(
    inbound=r1.successor, state=r1.successor_state, next_destination="submit",
    next_action="submit", next_side_effects="external",
    next_permissions=Permissions(everything.caps[2:]))
r3 = b["submit"].handle(inbound=r2.successor, state=r2.successor_state)

for name, r, inbound in (("intake", r1, root), ("assess", r2, r1.successor),
                         ("submit", r3, r2.successor)):
    carried = ", ".join(f"{c.action}→{c.target}" for c in inbound.permissions.caps)
    print(f"  {name:<7} {r.disposition.value:<9} executed={str(r.executed):<5} "
          f"depth {inbound.depth}  carried [{carried}]")
    if r.verdict.detail:
        print(f"          {r.verdict.detail}")
print("\n  The submission was held at its own boundary, by the rulebook, without")
print("  asking anyone. In the platform the QPPV releases it; here it stops.\n")

print("what a reviewer tries first\n")
# 1. A compromised boundary mints a successor wider than what it was given.
wider = Permissions((Capability("submit", "regulator", "serious_icsr"),
                     Capability("delete", "regulator", "locked_case")))
forged = new_envelope(identity="spiffe://example.org/agent/case-pipeline",
                      state=ExecutionState(case_digest, "delete", "regulator", "locked_case",
                                           permissions=wider),
                      scope="submit", permissions=wider, epoch=1,
                      policy_digest=bundle.digest, key=boundary_keys["assess"],
                      predecessor=r1.successor.commitment(), depth=r1.successor.depth + 1)
v = verify_succession(r1.successor, forged)
print(f"  widened successor     ok={v.ok}  {[str(x) for x in v.reasons]}")

# 2. The state is edited in transit: the case is retargeted after it was sealed.
b2 = boundaries()
s1 = b2["intake"].handle(
    inbound=new_envelope(identity="spiffe://example.org/agent/case-pipeline", state=start,
                         scope="intake", permissions=everything, epoch=1,
                         policy_digest=bundle.digest, key=control),
    state=start, next_destination="assess", next_action="assess",
    next_permissions=Permissions(everything.caps[1:]))
edited = ExecutionState(case_digest, "assess", "public_web", "serious_icsr",
                        permissions=s1.successor_state.permissions)
t = b2["assess"].handle(inbound=s1.successor, state=edited)
print(f"  edited in transit     {t.disposition.value}, executed={t.executed}  "
      f"{[str(x) for x in t.verdict.reasons]}")
assert not v.ok and Reject.AUTHORITY_WIDENED in v.reasons
assert not t.executed

receipts = sum(len(x.queue.drain()) for x in (*b.values(), *b2.values()))
print(f"\n{receipts} signed receipts queued for the evidence plane, out of band.")
