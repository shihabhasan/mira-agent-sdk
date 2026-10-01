"""Plug in your own component, and keep the governance.

An examiner is anything that reads a payload and says something about it: a
classifier, a model, a domain rule engine — yours. It signs each reading, bound
to the exact payload it read. The gate only ever sees readings that verify
against a key you registered, about this payload, recently, for a signal the
examiner declared. So your component can be swapped or upgraded freely, and an
unsigned, stale, or misdirected reading still cannot move a decision.

Here the component is a stand-in seriousness classifier; in practice it would
be the team's own model or pharmacovigilance logic.

    python examples/04_your_own_examiner.py
"""
import time

from mira_agent import PolicyBundle, evaluate
from mira_agent.examiners import (Assertion, Roster, payload_hash, sign_assertion,
                                  verified_signals)
from mira_agent_core.keys import SigningKey

EXAMINER = "acme-seriousness"
key = SigningKey.generate(f"examiner/{EXAMINER}")


def seriousness(text: str) -> float:
    """Your component. A real one is a model; this one looks for criteria."""
    criteria = ("hospitalis", "life-threatening", "death", "disability", "congenital")
    return 0.95 if any(c in text.lower() for c in criteria) else 0.1


def read(text: str) -> Assertion:
    """Score, then sign the reading against the exact payload it was about."""
    return sign_assertion(Assertion(
        name="serious_adverse_event", value=seriousness(text),
        examiner_id=EXAMINER, examiner_version="0.1.0",
        payload_hash=payload_hash(text), issued_ms=int(time.time() * 1000)), key)


# Who the gate listens to: your examiner's public key and what it may assert.
roster = Roster(keys={EXAMINER: key.public_bytes},
                declared={EXAMINER: frozenset({"signal.serious_adverse_event"})})

# A rule that uses the signal. Written by the organisation, not by the model.
bundle = PolicyBundle.from_dict({
    "bundle_id": "example/seriousness", "version": "1", "default_effect": "deny",
    "rules": [
        {"id": "SAE-1", "disposition": "elevate", "effect": "deny", "escalate_to": "QPPV",
         "description": "A case the examiner reads as serious waits for the QPPV.",
         "match": {"action": "submit"},
         "conditions": [{"field": "signal.serious_adverse_event", "op": ">=", "value": 0.8}],
         "examiners": [EXAMINER],
         # No trustworthy reading is not the same as "not serious": hold it.
         "on_unavailable": "gate"},
        {"id": "SAE-2", "disposition": "release", "effect": "allow",
         "description": "Other submissions proceed on their routine timeline.",
         "match": {"action": "submit"}},
    ]})


def decide(text: str, assertions: list[Assertion]):
    v = verified_signals(assertions, public_key_for=roster.public_key_for,
                         declared_for=roster.declared_for,
                         now_ms=int(time.time() * 1000), payload_hash=payload_hash(text))
    d = evaluate({"action": "submit"}, bundle, signals=v.signals, sources=v.sources,
                 readings=v.readings)
    return d, v


serious = "68-year-old female, rhabdomyolysis; hospitalised; product withdrawn."
mild = "Mild headache on day 2; resolved without treatment."

for label, text, assertions in [
    ("a serious case, read by your examiner", serious, [read(serious)]),
    ("a mild case, read by your examiner", mild, [read(mild)]),
    ("a serious case, reading about a different payload", serious, [read(mild)]),
    ("a serious case, reading signed by someone else", serious,
     [sign_assertion(read(serious), SigningKey.generate("examiner/impostor"))]),
]:
    d, v = decide(text, assertions)
    print(f"{label:<52} {d.disposition:<8} {d.rule_id}"
          + (f" — {d.escalate_to} decides" if d.escalate_to else ""))
    for r in v.rejected:
        print(f"{'':<52} refused reading: {r['reason']}")

print("\nThe last two are held, not released. A reading that does not verify is not")
print("a reading, and SAE-1 says what to do when its signal does not arrive:")
print("`on_unavailable: gate`. Without that line a missing reading would fall through")
print("to SAE-2 — the rule author decides which failure is acceptable, not the code.")
