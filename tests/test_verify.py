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

from mira_agent_core import verify_bundle
from mira_agent_core.cli import main as cli_main

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


# ------------------------------------------------------------------ witnesses
#
# The log's signature proves the log published a root; a witness's proves a
# second party checked that root extends everything it signed before. An
# auditor pins the witness key themselves — a key read out of the bundle would
# make the check prove no more than the file.

def _cosign(bundle: dict, key) -> dict:
    note = bundle["checkpoint"]["note"]
    body = note.split("\n\n", 1)[0] + "\n"
    kid = bytes.fromhex(key.key_id)
    line = f"— {key.name} " + base64.b64encode(kid + key.sign(body.encode())).decode()
    out = copy.deepcopy(bundle)
    out["checkpoint"]["note"] = note.rstrip("\n") + "\n" + line + "\n"
    return out


@pytest.fixture
def witness():
    from mira_agent_core.keys import SigningKey
    return SigningKey.generate("witness/alpha")


def test_a_witnessed_bundle_verifies_against_the_pinned_key(bundle, witness):
    res = verify_bundle(_cosign(bundle, witness),
                        witness_keys={"witness/alpha": witness.public_bytes})
    assert res.valid, res.errors
    assert res.witnessed_by == ["witness/alpha"] and res.witness_threshold == 1


def test_an_unwitnessed_bundle_fails_when_a_witness_is_required(bundle, witness):
    res = verify_bundle(bundle, witness_keys={"witness/alpha": witness.public_bytes})
    assert not res.valid
    assert any("pinned witness" in e for e in res.errors)


def test_a_signature_under_the_right_name_but_another_key_does_not_count(bundle, witness):
    from mira_agent_core.keys import SigningKey
    impostor = SigningKey.generate("witness/alpha")
    res = verify_bundle(_cosign(bundle, impostor),
                        witness_keys={"witness/alpha": witness.public_bytes})
    assert not res.valid and res.witnessed_by == []


def test_a_cosignature_does_not_transfer_to_a_forged_root(bundle, witness):
    signed = _cosign(bundle, witness)
    line = signed["checkpoint"]["note"].strip().split("\n")[-1]
    forged = copy.deepcopy(bundle)
    forged["checkpoint"]["root_hex"] = "00" * 32
    body, sigs = forged["checkpoint"]["note"].split("\n\n", 1)
    lines = body.split("\n")
    lines[2] = base64.b64encode(b"\x00" * 32).decode()
    forged["checkpoint"]["note"] = "\n".join(lines) + "\n\n" + sigs.rstrip("\n") + "\n" + line + "\n"
    res = verify_bundle(forged, witness_keys={"witness/alpha": witness.public_bytes})
    assert not res.valid and res.witnessed_by == []


def test_the_threshold_counts_distinct_pinned_witnesses(bundle, witness):
    from mira_agent_core.keys import SigningKey
    beta = SigningKey.generate("witness/beta")
    keys = {"witness/alpha": witness.public_bytes, "witness/beta": beta.public_bytes}
    one = _cosign(bundle, witness)
    assert verify_bundle(one, witness_keys=keys, witness_threshold=1).valid
    assert not verify_bundle(one, witness_keys=keys, witness_threshold=2).valid
    both = _cosign(one, beta)
    assert verify_bundle(both, witness_keys=keys, witness_threshold=2).valid


def test_witness_lines_are_named_but_not_trusted_without_a_key(bundle, witness):
    res = verify_bundle(_cosign(bundle, witness))
    assert res.valid, "an unpinned witness line must not break the log's own check"
    assert res.witnesses_present == ["witness/alpha"] and res.witnessed_by == []


def test_cli_checks_a_pinned_witness(tmp_path, bundle, witness, capsys):
    p = tmp_path / "w.json"
    p.write_text(json.dumps(_cosign(bundle, witness)))
    pin = f"witness/alpha={base64.b64encode(witness.public_bytes).decode()}"
    assert cli_main([str(p), "--witness", pin]) == 0
    assert "witnessed by witness/alpha" in capsys.readouterr().out
    assert cli_main([str(BUNDLE_PATH), "--witness", pin]) == 1
    assert cli_main([str(p)]) == 0
    assert "not checked" in capsys.readouterr().out
    assert cli_main([str(p), "--witness", "witness/alpha=nope"]) == 2
