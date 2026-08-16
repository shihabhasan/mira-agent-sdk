"""Offline verification, and the tampering it has to catch.

A verifier that only ever says "valid" is worse than none. Every test here
takes a bundle that verifies, breaks exactly one thing, and asserts the
verifier notices — and names the right check.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from mira_agent.core import verify_bundle
from mira_agent.core.cli import main as cli_main

BUNDLE_PATH = Path(__file__).parent / "data" / "bundle.json"


@pytest.fixture
def bundle() -> dict:
    return json.loads(BUNDLE_PATH.read_text())


def test_a_good_bundle_verifies(bundle):
    res = verify_bundle(bundle)
    assert res.valid, f"errors={res.errors} bad={[r.failures() for r in res.invalid_records]}"
    assert res.checkpoint_signature_valid
    assert all(r.valid for r in res.records)


def test_editing_a_record_breaks_its_signature(bundle):
    """Flip one byte inside a payload: the hash no longer matches and the
    signature no longer verifies."""
    rec = bundle["records"][1]
    payload = bytearray(base64.b64decode(rec["envelope"]["payload"]))
    # change a character inside the JSON without changing its length
    idx = payload.find(b"policy_gate")
    if idx == -1:
        idx = payload.find(b"SPAN")
    payload[idx] = payload[idx] + 1
    rec["envelope"]["payload"] = base64.b64encode(bytes(payload)).decode()

    res = verify_bundle(bundle)
    assert not res.valid
    failed = res.records[1].failures()
    assert "record hash" in failed or "signature" in failed


def test_swapping_the_signature_is_caught(bundle):
    bundle["records"][2]["envelope"]["signatures"][0]["sig"] = (
        bundle["records"][1]["envelope"]["signatures"][0]["sig"]
    )
    res = verify_bundle(bundle)
    assert not res.valid
    assert "signature" in res.records[2].failures()


def test_deleting_a_record_breaks_the_chain(bundle):
    del bundle["records"][1]
    res = verify_bundle(bundle)
    assert not res.valid
    # the record that followed the deleted one now links to the wrong parent
    assert any("chain link" in r.failures() or "sequence" in r.failures()
               for r in res.records)


def test_reordering_records_is_caught(bundle):
    bundle["records"][1], bundle["records"][2] = (
        bundle["records"][2], bundle["records"][1]
    )
    res = verify_bundle(bundle)
    assert not res.valid


def test_a_forged_checkpoint_root_is_caught(bundle):
    """Rewriting history means producing a root nobody signed."""
    bundle["checkpoint"]["root_hex"] = "00" * 32
    res = verify_bundle(bundle)
    assert not res.valid
    assert not res.checkpoint_signature_valid


def test_a_record_not_in_the_log_fails_inclusion(bundle):
    """A record can be perfectly signed and still never have been in the
    published log. That is what the inclusion proof is for."""
    bundle["records"][0]["proof"]["path"] = ["11" * 32]
    res = verify_bundle(bundle)
    assert not res.valid
    assert "inclusion proof" in res.records[0].failures()


def test_missing_checkpoint_cannot_prove_inclusion(bundle):
    bundle["checkpoint"] = None
    res = verify_bundle(bundle)
    assert not res.valid
    assert any("no checkpoint" in e for e in res.errors)


def test_an_unknown_signer_is_not_silently_trusted(bundle):
    bundle["keys"] = {}
    res = verify_bundle(bundle)
    assert not res.valid
    assert any("no public key" in e for e in res.errors)


# ------------------------------------------------------------------- the CLI

def test_cli_exits_zero_on_a_good_bundle(capsys):
    assert cli_main([str(BUNDLE_PATH)]) == 0
    assert "VERIFIED" in capsys.readouterr().out


def test_cli_exits_nonzero_on_a_bad_bundle(tmp_path, bundle, capsys):
    bundle["checkpoint"]["root_hex"] = "00" * 32
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(bundle))
    assert cli_main([str(p)]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_cli_json_output_is_machine_readable(capsys):
    assert cli_main([str(BUNDLE_PATH), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True
    assert len(payload["records"]) > 0


def test_cli_handles_a_missing_file(capsys):
    assert cli_main(["/nonexistent/bundle.json"]) == 2
