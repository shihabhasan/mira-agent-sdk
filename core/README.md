# mira-agent-core

The primitives behind [Mira](https://github.com/shihabhasan/mira-agent-sdk):
canonical provenance records, Ed25519 signing over DSSE, Merkle Mountain Range
inclusion proofs, C2SP checkpoint notes, and offline bundle verification.

Split out as its own distribution for one reason: **the Mira control plane and
every client must run the same canonicalisation.** If they differed by a single
byte, signatures would verify against bytes nobody stored. A server that only
needs to seal and verify records should not have to install an agent SDK to do
it.

```bash
pip install mira-agent-core
mira-verify bundle.json          # no network, no account
```

```python
from mira_agent_core import canonical, verify_bundle, SigningKey
```

Apache-2.0.
