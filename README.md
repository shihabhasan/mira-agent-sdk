# mira-sdk

Governance and verifiable provenance for AI agents.

Mira answers two questions about an autonomous agent, and keeps them separate
on purpose:

- **May this action happen?** — decided locally, in microseconds, against a
  content-addressed ruleset. Before the action runs.
- **What actually happened?** — sealed into a hash-linked, signed, independently
  verifiable log. After the fact, nobody can quietly change it.

```bash
pip install mira-sdk
```

## The gate

```python
from mira_sdk import Mira, Interdicted

mira = Mira()                       # MIRA_API_KEY / MIRA_BASE_URL from env

with mira.run(intent="Deploy CHG-0048817") as run:
    decision = run.authorize(
        action="deploy",
        artifact="update_set:SLA_RECALC_v7",
        target_instance="prod",
    )
    if not decision.allowed:
        print(decision.rule_id)     # 'BOD-1.1'
        print(decision.reason)      # 'No autonomous deployment to Production…'
        raise Interdicted(decision)

    deploy(...)
```

`run.require(...)` is the same call that raises on refusal instead of returning.

## Decorators

```python
@mira.step(name="change_analyzer")
def analyse(change): ...

@mira.guarded_tool(action="deploy", target="target_instance", resource="artifact")
def deploy_update_set(artifact: str, target_instance: str): ...
```

`guarded_tool` authorizes from the call's own arguments, then runs it — or
raises `Interdicted` and never calls the function at all.

## What the decisions cost

The gate is a pure function over a bundle already in memory. There is no
network call on the authorization path.

| operation | where | typical |
|---|---|---|
| authorize | in-process | ~10&nbsp;µs |
| sign a step | in-process | ~50&nbsp;µs |
| ship records | background thread | off the critical path |

## Failure behaviour

This is the part to read before deploying it.

| | on failure |
|---|---|
| **Authorization** | **fails closed.** No bundle, no permission. A gate that fails open is not a gate. |
| **Recording** | **fails open.** Records queue and retry on a daemon thread; a control-plane outage must never take your agent down. |

Construct with `fail_closed=False` only if you have genuinely decided that
availability outranks the boundary, and `offline=True` to run the gate with a
locally supplied bundle and no control plane at all.

The record queue is bounded (10,000 by default). On overflow the **oldest**
record is dropped and counted in `mira.stats` — the newest evidence is the
evidence you most likely still need.

## Verifying, offline

Every install ships a verifier that needs no network and no Mira account:

```bash
mira-verify bundle.json
```

```
✓ VERIFIED  txn-834ca821292e

  ✓ checkpoint signature
  11 record(s)

  Every record's signature, chain link, sequence and inclusion
  proof checks out against the signed checkpoint root.
```

Exit code is 0 when everything verifies and 1 when it does not, so it works as
a CI gate. Five independent checks run per record — signature over the stored
bytes, chain link, sequence, inclusion proof against the signed root, and the
checkpoint note's own signature. All five must pass.

An auditor who has to call our API to check our claims is being asked to trust
us twice. This is the answer to that.

## Identity

Each step is signed **by the client** before it leaves your process, so a
record attests to what your agent did rather than to what a server received.
The control plane counter-signs and sequences it into the log.

By default the key is ephemeral per process — self-consistent evidence, but not
yet tied to a durable identity. For non-repudiation across restarts, supply
one:

```python
Mira(signing_key="/etc/mira/agent.pem")     # or MIRA_AGENT_SEED=<32-byte hex>
```

## Packages

| module | contains |
|---|---|
| `mira_core` | canonical records, DSSE, Ed25519, MMR proofs, checkpoints, the offline verifier |
| `mira_sdk` | the client, the local gate, batching transport |

`mira_core` is deliberately dependency-light and is the *same* implementation
the control plane runs. If the two canonicalised differently by one byte, every
signature would verify against bytes nobody stored — `tests/test_conformance.py`
pins that against vectors generated from the server.

## Status

Working: the gate, client-side signing, batched ingest, offline verification.

Not yet: MCP interceptor integration, OpenTelemetry span export, SPIFFE
identity binding, witnessed checkpoints. See the roadmap before assuming.

Apache-2.0.
