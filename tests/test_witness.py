"""Witnessed checkpoints.

The log's own signature proves it published a root. It does not prove the log
never rewrote history — whoever holds the log key can sign a different root for
a different past. Witnesses close that: independent parties that only ever
counter-sign a checkpoint consistent with what they have already seen, so a
fork requires colluding with all of them.
"""

from __future__ import annotations

import base64

import pytest

from mira_agent_core.checkpoint import (
    EM_DASH,
    Checkpoint,
    parse_checkpoint,
    verify_checkpoint,
    verify_witnesses,
)
from mira_agent_core.keys import SigningKey

LOG = SigningKey.from_seed("mira/ledger", bytes(range(32)))
W1 = SigningKey.from_seed("witness/alpha", bytes(range(1, 33)))
W2 = SigningKey.from_seed("witness/beta", bytes(range(2, 34)))
EVIL = SigningKey.from_seed("witness/alpha", bytes(range(9, 41)))  # same name, wrong key

ROOT = "ab" * 32


def note(*signers, root_hex=ROOT, size=19, origin="mira.liora-ai.co/ledger/v1") -> str:
    cp = Checkpoint(origin=origin, mmr_size=size, root_hex=root_hex,
                    key_name=signers[0].name, key_id=signers[0].key_id)
    body = cp.body
    lines = [body, ""]
    for s in signers:
        blob = bytes.fromhex(s.key_id) + s.sign(body.encode())
        lines.append(f"{EM_DASH} {s.name} {base64.b64encode(blob).decode()}")
    return "\n".join([body.rstrip("\n"), "", *lines[2:]]) + "\n"


def test_a_log_only_note_still_verifies():
    n = note(LOG)
    cp = verify_checkpoint(n, "mira/ledger", LOG.public_bytes)
    assert cp is not None
    assert cp.mmr_size == 19
    assert cp.witnesses() == []


def test_witness_signatures_parse_alongside_the_log():
    cp = parse_checkpoint(note(LOG, W1, W2))
    assert [s.key_name for s in cp.signatures] == ["mira/ledger", "witness/alpha", "witness/beta"]
    assert [s.key_name for s in cp.witnesses()] == ["witness/alpha", "witness/beta"]


def test_the_log_signature_still_verifies_with_witnesses_present():
    assert verify_checkpoint(note(LOG, W1, W2), "mira/ledger", LOG.public_bytes) is not None


def test_witnesses_verify_against_their_own_keys():
    ok, names = verify_witnesses(
        note(LOG, W1, W2),
        {"witness/alpha": W1.public_bytes, "witness/beta": W2.public_bytes},
        threshold=2,
    )
    assert ok
    assert names == ["witness/alpha", "witness/beta"]


def test_threshold_is_enforced():
    ok, names = verify_witnesses(
        note(LOG, W1),
        {"witness/alpha": W1.public_bytes, "witness/beta": W2.public_bytes},
        threshold=2,
    )
    assert ok is False
    assert names == ["witness/alpha"]


def test_a_witness_signature_over_a_different_root_does_not_count():
    """The attack this defends against: an operator forks the log and needs a
    witness signature for the fork. A signature over another body must not
    transfer."""
    real = note(LOG, W1)
    forked = note(LOG, root_hex="cd" * 32)
    # graft the genuine witness line onto the forked note
    grafted = forked.rstrip("\n") + "\n" + real.strip().split("\n")[-1] + "\n"

    ok, names = verify_witnesses(grafted, {"witness/alpha": W1.public_bytes})
    assert ok is False
    assert names == []


def test_an_impostor_using_a_known_witness_name_is_rejected():
    ok, names = verify_witnesses(note(LOG, EVIL), {"witness/alpha": W1.public_bytes})
    assert ok is False
    assert names == []


def test_unknown_witnesses_are_ignored_not_trusted():
    """A note may carry witnesses we have no key for. They must neither count
    toward the threshold nor break verification of the ones we do know."""
    ok, names = verify_witnesses(
        note(LOG, W1, W2), {"witness/alpha": W1.public_bytes}, threshold=1
    )
    assert ok
    assert names == ["witness/alpha"]


def test_a_malformed_signature_line_does_not_break_the_others():
    n = note(LOG, W1).rstrip("\n") + "\n— broken-line-without-valid-base64 !!!\n"
    assert verify_checkpoint(n, "mira/ledger", LOG.public_bytes) is not None
    ok, _ = verify_witnesses(n, {"witness/alpha": W1.public_bytes})
    assert ok


def test_no_witness_keys_means_no_witnesses():
    ok, names = verify_witnesses(note(LOG, W1), {})
    assert ok is False
    assert names == []
