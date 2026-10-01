"""Remove identifiers by path, before the record goes anywhere.

Redaction here is deterministic and cheap on purpose: a rule is a JSON pointer
and a treatment, not a classifier, so the same record and the same rules always
release the same thing, and the receipt can name exactly what changed. What the
next agent receives is the released record — never the original.

    python examples/03_redact_at_the_boundary.py
"""
import json

from mira_agent.msep import RedactionRule, Treatment, apply_redactions

# A synthetic adverse event report as it arrives from the reporter.
report = {
    "case_id": "PV-2026-000417",
    "patient_name": "Eleanor Whitfield",
    "nhs_number": "999 401 7726",
    "date_of_birth": "1958-03-14",
    "patient": "Female, 68 years",
    "suspect_product": "Zelvatrine 50 mg tablets",
    "reaction": "Rhabdomyolysis",
    "seriousness": "Serious",
    "reporter": {"role": "Hospital pharmacist", "email": "pharmacy@hospital.example"},
}

rules = [
    RedactionRule("/patient_name"),                                  # masked: present, unreadable
    RedactionRule("/nhs_number", treatment=Treatment.REMOVE),        # gone entirely
    RedactionRule("/date_of_birth"),
    RedactionRule("/reporter/email", treatment=Treatment.HASH),      # matchable, not readable
    RedactionRule("/patient_address"),                               # not in this report
]

released = apply_redactions(report, rules)

print("released to the next agent:\n")
print(json.dumps(released.payload, indent=2))
print(f"\napplied: {list(released.applied)}")
print(f"absent:  {list(released.absent)}   (named in the receipt, not an error)")

assert "999 401 7726" not in json.dumps(released.payload)
assert "Eleanor Whitfield" not in json.dumps(released.payload)
assert report["nhs_number"] == "999 401 7726", "the original is never edited in place"
print("\nThe original report is untouched; only the released copy moves on.")
print("Use MASK or REMOVE for short identifiers: a nine- or ten-digit number can be")
print("recovered from an unsalted hash, so HASH suits only values with real entropy.")
