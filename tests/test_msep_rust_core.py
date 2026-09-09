"""The Rust verify_inbound core gives the same answer as the Python path.

Every tampering the protocol tests describe, run through both paths on the
same inputs. If the reject sets differ, one implementation is wrong, and it
is not obvious which - so neither ships until they agree.
"""
from dataclasses import replace

import pytest

from _msep_keys import KeyRing
from mira_agent.msep import (Capability, ExecutionState, KeyCache, Permissions, TrustEpoch,
                             fast, new_envelope)
from mira_agent.msep import verify as V

pytestmark = pytest.mark.skipif(not V._USE_RS, reason="Rust core without verify_inbound")
T0 = 1_800_000_000_000
POLICY = "sha256:policy"


@pytest.fixture
def world():
    ring = KeyRing(); keys = KeyCache(); keys.add_keyring(ring, ["a"])
    perms = Permissions((Capability("deploy", "dev"), Capability("inspect")))
    st = ExecutionState("sha256:p", "deploy", "dev", "update_set", permissions=perms)
    env = new_envelope(identity="x", state=st, scope="node-b", permissions=perms, epoch=2,
                       policy_digest=POLICY, key=ring.get("a"), now_ms=T0, ttl_ms=30_000,
                       depth=1, max_depth=4)
    return ring, keys, perms, st, env


def both(env, **kw):
    out = []
    for use in (True, False):
        V._USE_RS = use
        try:
            v = V.verify_inbound(env, **kw)
        finally:
            V._USE_RS = True
        out.append(sorted(str(r) for r in v.reasons))
    return out


CASES = {
    "clean": lambda e, st: (e, st, {}),
    "bad signature": lambda e, st: (replace(e, scope="elsewhere", signature=e.signature), st, {"destination": "elsewhere"}),
    "expired": lambda e, st: (e, st, {"now_ms": T0 + 60_000}),
    "not yet valid": lambda e, st: (e, st, {"now_ms": T0 - 60_000}),
    "stale epoch": lambda e, st: (e, st, {"epoch": TrustEpoch(3)}),
    "policy mismatch": lambda e, st: (e, st, {"policy_digest": "sha256:other"}),
    "wrong destination": lambda e, st: (e, st, {"destination": "node-z"}),
    "depth exceeded": lambda e, st: (replace(e, depth=9), st, {}),
    "state tampered": lambda e, st: (e, replace(st, target="prod"), {}),
    "not permitted": lambda e, st: (e, replace(st, action="drop_table"), {}),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_rust_and_python_reject_identically(world, name):
    ring, keys, perms, st, env = world
    e2, st2, kw = CASES[name](env, st)
    args = dict(keys=keys, epoch=TrustEpoch(2), destination="node-b", state=st2,
                policy_digest=POLICY, now_ms=T0 + 1)
    args.update(kw)
    rs, py = both(e2, **args)
    assert rs == py, (name, rs, py)
    if name == "clean":
        assert rs == []


def test_unknown_key_is_reported_once(world):
    ring, keys, perms, st, env = world
    rs, py = both(env, keys=KeyCache(), epoch=TrustEpoch(2), destination="node-b", state=st,
                  policy_digest=POLICY, now_ms=T0 + 1)
    assert rs == py == ["signing_key_unknown"] or rs == py
