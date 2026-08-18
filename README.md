# mira-agent-sdk

Governance and verifiable provenance for AI agents.

Mira answers two questions about an autonomous agent, and keeps them separate
on purpose:

- **May this action happen?** — decided locally, in microseconds, against a
  content-addressed ruleset. Before the action runs.
- **What actually happened?** — sealed into a hash-linked, signed, independently
  verifiable log. After the fact, nobody can quietly change it.

```bash
pip install mira-agent-sdk
```

## The gate

```python
from mira_agent import Mira, Interdicted

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

## Zero-Bypass, and what this library can honestly claim

Everything above governs an agent that calls it. An agent that does not is
ungoverned, and nothing here can change that — a library cannot enforce its own
use. Zero-bypass is a property of the network: run
[Sentry](https://github.com/shihabhasan/liora), restrict egress to the instance
so it is reachable only through Sentry, and never issue an instance credential
to an agent. Then an agent that routes around the gate arrives with nothing to
authenticate as.

`SentryClient` is this side of that arrangement. It does not enforce anything.
It makes the honest mistakes hard, and it produces evidence the gateway cannot
produce on its own.

```python
from mira_agent import Mira, SentryClient, Interdicted

mira = Mira(api_key=..., endpoint="https://app.liora-ai.co")
sn = SentryClient("https://sentry.internal:8790", token=AGENT_TOKEN, mira=mira)

with mira.run("CHG-0048817") as run:
    sn.bind(run)
    try:
        sn.post("acme-prod", "/api/sn_cicd/app/batch/install",
                json={"update_set": "SLA_RECALC_v7"},
                justification="scheduled release for INC0012345")
    except Interdicted as e:
        # the same exception a local require() raises, so existing recovery
        # code needs no new branch for the gateway
        assert e.decision.rule_id == "BOD-1.1"
        sn.post("acme-dev", "/api/sn_cicd/app/batch/install", json={...})
```

**It addresses target names, not URLs.** `sn.post("acme-prod", ...)` works;
passing a URL raises. A client that accepts arbitrary URLs is one typo from
talking to the instance directly, and that mistake is silent — the call
succeeds and the only trace of the ungoverned action is its absence from the
ledger. Reaching an instance directly should require reaching for a different
library, which is a visible act rather than a slip.

**A refusal arrives as `Interdicted`,** carrying the rule, reason and bundle
digest — identical in shape to a local refusal, so a pipeline that already
re-targets after a denial needs no gateway-specific handling.

**It signs the agent's own account of the call.** Sentry's decision is sealed
by the control plane as the *gateway's* claim. Every call through this client
also records the agent's claim, naming the gateway id and the sequence number
Sentry returned:

```
agent  : sentry:post:acme-prod  deny  gw=gw_e2e seq=1 rule=BOD-1.1
gateway: seq 1  deny  BOD-1.1  deploy->prod  agent=spiffe://acme/agent/release-bot
```

Two independent accounts of one action mean a disagreement between them is
detectable. One account is just a log.

**What it costs.** Measured on loopback against a stub instance, 600 calls,
2-core box:

| | p50 | |
|---|---|---|
| Direct, ungoverned | 0.58 ms | baseline |
| Through Sentry, allowed | 1.73 ms | **+1.15 ms** |
| Through Sentry, refused | 0.71 ms | **+0.12 ms**, never reaches the instance |

Only ≈52 µs of that is gateway work — translate 2.1 µs, gate 5.3 µs, inject
the credential 7.0 µs, seal the evidence durably 38 µs. The millisecond is the
extra hop, not the deciding, so where Sentry sits matters more than anything
either side can tune. A refusal is the cheap path: it short-circuits before the
upstream call.

The local preflight (`proposal=...`) costs ~2 µs and can spare the round trip
entirely for an action that was never going to be permitted.

**It raises `PolicySkew` when the two policies differ.** If the pinned bundle's
digest and the gateway's do not match, neither answer means what it appears to,
so the client refuses rather than preferring one silently — which is how a
policy update half-lands across an estate and nobody notices for a month.

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

Strongest available evidence wins, and the record always says which:

```python
Mira(svid_cert="/run/spire/svid.pem", svid_key="/run/spire/svid.key")
Mira(signing_key="/etc/mira/agent.pem")     # or MIRA_AGENT_SEED=<32-byte hex>
Mira()                                       # anonymous, and marked as such
```

With a **SPIFFE** X.509 SVID, the workload's `spiffe://` ID is bound into every
record and the Ed25519 record key is derived from the SVID — so it is stable
for that SVID's lifetime and rotates with it. Mira consumes an identity here
rather than becoming an identity provider: SPIFFE proves *who the agent is*,
Mira proves *what it then did*, and the join is the point.

Without one, records carry `attributable: false`. That is still
self-consistent evidence — it just never implies an attribution it cannot
support.

## Policy in Cedar

Cedar has become the dominant language for agent and MCP authorization, so you
can keep writing it:

```python
from mira_agent import compile_cedar

bundle = compile_cedar(open("change-control.cedar").read(),
                       bundle_id="acme/change-control", version="1.0.0")
mira = Mira(policy=bundle)
```

```cedar
@id("BOD-1.1")
@description("No autonomous deployment to Production.")
forbid (principal, action == Action::"deploy", resource)
when { resource.target_instance == "prod" };
```

**It compiles a strict subset and refuses everything else.** `unless`, `has`,
`like`, `||`, inequalities, context references and entity hierarchies all raise
`CedarError` at compile time. A compiler that silently ignores a clause it does
not understand will one day drop a `forbid` — refusing where a human is
watching is the only safe failure mode.

## OpenTelemetry

Mira attaches to a tracer you already own. It does not replace your
observability stack:

```python
from mira_agent.otel import MiraSpanProcessor

provider.add_span_processor(otlp_processor)           # unchanged
provider.add_span_processor(MiraSpanProcessor(mira))  # + signed evidence
```

By default only GenAI spans and anything marked `mira.record=True` are sealed —
signing every HTTP and DB span buries the evidence that matters in the evidence
that doesn't. Recording is async and a failure inside the processor can never
break the traced application.

## Witnessed checkpoints

The log's signature proves it published a root. It does **not** prove the log
never rewrote history — whoever holds the log key can sign a different root for
a different past. Witnesses close that gap:

```python
from mira_agent_core import verify_witnesses

ok, who = verify_witnesses(note, {"witness/alpha": alpha_pub}, threshold=2)
```

C2SP notes carry many signature lines, so witnessing is additive: a note with
witnesses still verifies for anyone who only knows the log key.

## Packages

Two distributions, so a server or an auditor never has to install a client:

| distribution | import | contains |
|---|---|---|
| `mira-agent-core` | `mira_agent_core` | canonical records, DSSE, Ed25519, MMR proofs, checkpoints, SPIFFE identity, the offline verifier and `mira-verify` |
| `mira-agent-sdk` | `mira_agent` | the client, the local gate, Cedar front-end, OTel processor, batching transport |

`mira-agent-core` has two dependencies and is the *same* implementation the
control plane runs. If the two canonicalised differently by one byte, every
signature would verify against bytes nobody stored — `tests/test_conformance.py`
pins that against vectors generated from the server.

```bash
pip install mira-agent-core     # just the verifier and primitives
pip install mira-agent-sdk      # the full client (pulls core in)
```

There is a third, optional: `core-rs/` is the same core in Rust. Not for speed
(it is ~1.6x end to end, and Python's Ed25519 already calls OpenSSL) but so a
Go or Rust gateway can link **one** implementation rather than becoming a third
one to keep byte-identical. Pure Python stays the default; opt in with
`MIRA_CORE_BACKEND=rust`. It builds against the stable ABI, so one binary
covers CPython 3.11 through 3.14.

The conformance vectors run against both, and they earned their keep on the
first build: every case passed except an integer past 2^53, where Python
carries the value as a string and Rust was canonicalising the raw number. Every
signature over such a record would have verified on one side and failed on the
other.

## Status

Working: the gate, client-side signing, batched ingest, offline verification,
SPIFFE identity binding, the Cedar front-end, the OpenTelemetry span processor,
and witness co-signature verification.

Not yet: the MCP interceptor. SEP-1763 is still a draft with Go and C#
reference implementations first, so the practical path there is a stdio proxy —
deliberately not started rather than half-built.

Apache-2.0.
