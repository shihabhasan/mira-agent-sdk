"""The examples are documentation that runs, so they are tested like code.

An example that silently stops working is worse than none: it is the first
thing a new developer runs, and a failure there reads as a broken product.
Each one runs as a fresh process, as a reader would run it, and must exit
cleanly and say the thing it exists to show.
"""
import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

EXPECT = {
    "01_local_gate.py": ["elevate    PV-3     — QPPV decides", "interdict  DEFAULT"],
    "02_msep_hops.py": ["submit  elevate", "authority_widened", "execution_state_digest_mismatch"],
    "03_redact_at_the_boundary.py": ["applied: ['/patient_name', '/nhs_number'", "absent:  ['/patient_address']"],
    "04_your_own_examiner.py": ["elevate  SAE-1", "gate     SAE-1", "assertion is about a different payload"],
    "05_verify_offline.py": ["VERIFIED — 4 records", "after editing record 1: FAILED"],
}


def test_every_example_is_covered():
    assert sorted(p.name for p in EXAMPLES.glob("0*.py")) == sorted(EXPECT)


@pytest.mark.parametrize("name", sorted(EXPECT))
def test_the_example_runs_and_shows_what_it_says(name):
    r = subprocess.run([sys.executable, str(EXAMPLES / name)], capture_output=True,
                       text=True, timeout=60, cwd=EXAMPLES.parent)
    assert r.returncode == 0, r.stderr
    for line in EXPECT[name]:
        assert line in r.stdout, f"{name} no longer shows {line!r}:\n{r.stdout}"
