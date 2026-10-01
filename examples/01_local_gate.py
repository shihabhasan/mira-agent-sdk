"""Decide locally, with no account and no network.

The gate is a pure function: a proposed action and a rulebook in, a decision
out, in microseconds. The rulebook here is the pharmacovigilance template, the
same file the console loads — so what this prints is what a published rulebook
would do in a live run.

    python examples/01_local_gate.py
"""
import json
from pathlib import Path

from mira_agent import PolicyBundle, evaluate

HERE = Path(__file__).parent
bundle = PolicyBundle.from_dict(
    json.loads((HERE / "rulebooks" / "pharmacovigilance-case-handling.json").read_text()))

print(f"rulebook {bundle.bundle_id}@{bundle.version}")
print(f"digest   {bundle.digest}   (sealed into every decision made under it)\n")

proposals = [
    ("a serious case report, to the regulator",
     {"action": "submit", "target_instance": "regulator", "artifact_type": "serious_icsr"}),
    ("a non-serious case report, to the regulator",
     {"action": "submit", "target_instance": "regulator", "artifact_type": "non_serious_icsr"}),
    ("an agent amending a locked case",
     {"action": "amend", "artifact_type": "locked_case"}),
    ("routine intake inside the organisation",
     {"action": "intake", "target_instance": "case"}),
    ("something no rule mentions",
     {"action": "export", "target_instance": "partner"}),
]

for label, proposal in proposals:
    d = evaluate(proposal, bundle)
    who = f" — {d.escalate_to} decides" if d.escalate_to else ""
    print(f"{label:<44} {d.disposition:<10} {d.rule_id:<8}{who}")
    print(f"{'':<44} {d.decide_us:.1f} µs, evidence required: {', '.join(d.evidence) or '—'}")

print("\nThe last line is the point of a default: a rulebook that does not mention an")
print("action does not permit it. Nothing here touched a network or a Mira account.")
