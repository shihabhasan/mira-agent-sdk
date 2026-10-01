"""Check the evidence yourself, with no network and no account.

An exported run is a bundle: every signed record, its inclusion proof, and the
checkpoint the proofs fold to. Anyone can verify it with this package alone —
which is the point: an auditor who has to ask the vendor's server whether the
vendor's evidence is genuine is being asked to trust them twice.

The same check is a command, `mira-verify bundle.json`, which exits non-zero on
failure so it can gate a pipeline. Pin a witness's key with
`--witness NAME=KEY` to require that a second party co-signed the checkpoint.

    python examples/05_verify_offline.py
"""
import base64
import copy
import json
from pathlib import Path

from mira_agent_core import verify_bundle

bundle = json.loads((Path(__file__).parent / "data" / "sample-bundle.json").read_text())

res = verify_bundle(bundle)
print(f"{bundle['txn_id']}: {'VERIFIED' if res.valid else 'FAILED'} — "
      f"{len(res.records)} records, checkpoint signature "
      f"{'valid' if res.checkpoint_signature_valid else 'INVALID'}")
for r in res.records:
    print(f"  seq {r.seq:>2}  {r.record_type:<13} {r.record_hash[:16]}…  ok")

# Now change one word in one record, the way someone tidying the history might.
edited = copy.deepcopy(bundle)
rec = edited["records"][1]
stmt = json.loads(base64.b64decode(rec["envelope"]["payload"]))
stmt["predicate"]["edited"] = "by someone tidying the history"
rec["envelope"]["payload"] = base64.b64encode(json.dumps(stmt).encode()).decode()

bad = verify_bundle(edited)
print(f"\nafter editing record 1: {'VERIFIED' if bad.valid else 'FAILED'}")
for r in bad.invalid_records:
    print(f"  seq {r.seq}: fails {', '.join(r.failures())}")
assert res.valid and not bad.valid
print("\nOne edited field fails three independent checks — the signature, the record")
print("hash and the inclusion proof — and any one of them would have been enough.")
