# Examples

Five short programs that run with **no Mira account and no network**. Each one
shows one part of the architecture with real code, so you can read it, change
it, and break it on purpose.

| | what it shows |
|---|---|
| [`01_local_gate.py`](01_local_gate.py) | A rulebook deciding proposed actions locally, in microseconds, with default-deny. The rulebook is the pharmacovigilance template the console ships. |
| [`02_msep_hops.py`](02_msep_hops.py) | Three boundaries verifying signed authority locally and narrowing it hop by hop; the rulebook plugged into each boundary's policy hook holds a serious case for the QPPV; a widened successor and a state edited in transit are both refused. |
| [`03_redact_at_the_boundary.py`](03_redact_at_the_boundary.py) | Deterministic redaction by JSON pointer: identifiers removed, masked or hashed before the record moves on, with a receipt of exactly what changed. |
| [`04_your_own_examiner.py`](04_your_own_examiner.py) | Plugging in your own component — a classifier, a model, domain logic — as a signed examiner. Its readings drive a rule; forged, stale or misdirected readings cannot, and the rule says what happens when no trustworthy reading arrives. |
| [`05_verify_offline.py`](05_verify_offline.py) | Verifying an exported run with nothing but this package, and what one edited field does to that. |

## Run them

```bash
python -m venv .venv && . .venv/bin/activate
pip install "mira-agent-core @ git+https://github.com/shihabhasan/mira-agent-sdk@v0.11.1#subdirectory=core"
pip install "mira-agent-sdk @ git+https://github.com/shihabhasan/mira-agent-sdk@v0.11.1"
git clone --depth 1 --branch v0.11.1 https://github.com/shihabhasan/mira-agent-sdk
cd mira-agent-sdk
python examples/01_local_gate.py
```

The packages are not on PyPI yet, so they install straight from this
repository; `mira-agent-core` first, because the SDK depends on it.

## Change the component, keep the governance

Nothing here asks you to use all of it. The gate, the boundary, the redaction,
the examiner seam and the verifier are separate pieces with small interfaces:
keep your own policy tooling, models, orchestration, assurance and audit tools,
and use the execution-authority and evidence pieces underneath them. Example 4
is the clearest case — your own model becomes an examiner by signing what it
says, and nothing else in the architecture changes.

Connecting to a Mira control plane (hosted policy, the console, the shared
ledger) needs an API key, created in the app under **Settings → API keys**.
