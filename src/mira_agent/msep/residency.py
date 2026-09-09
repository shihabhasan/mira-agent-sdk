"""Where the evidence lives, stated so a buyer can write it into a contract.

Payload storage is customer-selected, and that answers the question people
ask first. It is not the question a sovereign or defence buyer asks. Lineage
metadata on its own — which tools were called, against which systems, by
which agents, and when — is a map of the estate, and a map of the estate is
sensitive whether or not a single payload byte is attached to it.

So the ledger's residency is a declared, queryable property of a deployment,
not something inferred from a hosting bill. The Mira server, ledger included,
runs as a single container the customer can host in its own tenancy; there is
no Liora-side component it must call to seal a record. And where even the
metadata is too sensitive to leave the customer, receipts can be pseudonymised
under a customer-held key before they leave the boundary, so the evidence
still proves the lineage while the names in it mean nothing to anyone without
that key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, replace

from mira_agent.msep.receipt import Receipt


@dataclass(frozen=True)
class Residency:
    ledger_location: str          # e.g. "customer-hosted", "liora-cloud"
    region: str                   # e.g. "au-southeast-2", "on-premises"
    self_hosted: bool
    operator: str                 # who runs the ledger process
    payload_sink: str             # where sealed execution state goes
    metadata_pseudonymised: bool  # whether receipts are pseudonymised before ingest
    ledger_key_custody: str       # who holds the ledger's signing key

    def describe(self) -> dict:
        return {
            "ledger": {"location": self.ledger_location, "region": self.region,
                       "selfHosted": self.self_hosted, "operator": self.operator,
                       "signingKeyCustody": self.ledger_key_custody},
            "payload": {"sink": self.payload_sink, "heldByLiora": False},
            "metadata": {"pseudonymised": self.metadata_pseudonymised},
            "liora": {"callsRequiredToSeal": 0,
                      "holdsDecryptionKeysByDefault": False},
        }

    @classmethod
    def from_env(cls) -> "Residency":
        return cls(
            ledger_location=os.environ.get("MIRA_LEDGER_LOCATION", "customer-hosted"),
            region=os.environ.get("MIRA_REGION", "unspecified"),
            self_hosted=os.environ.get("MIRA_SELF_HOSTED", "true").lower() == "true",
            operator=os.environ.get("MIRA_OPERATOR", "customer"),
            payload_sink=os.environ.get("MIRA_PAYLOAD_SINK", "customer-storage"),
            metadata_pseudonymised=os.environ.get("MIRA_PSEUDONYMISE", "false").lower() == "true",
            ledger_key_custody=os.environ.get("MIRA_LEDGER_KEY_CUSTODY", "customer"),
        )


def _pseudo(key: bytes, label: str, value: str | None) -> str | None:
    if value is None:
        return None
    return "pn:" + hmac.new(key, f"{label}\n{value}".encode(), hashlib.sha256).hexdigest()[:24]


def pseudonymise(receipt: Receipt, key: bytes) -> Receipt:
    """Replace the names in a receipt with keyed pseudonyms.

    Commitments, digests and dispositions are kept: they are what make the
    lineage verifiable. Identity, boundary, action and target are replaced
    with HMAC pseudonyms under a customer key, so the same actor still links
    across receipts but nobody without the key can say who it was or what
    system it touched.
    """
    if len(key) < 32:
        raise ValueError("pseudonymisation key must be at least 32 bytes")
    return replace(
        receipt,
        identity=_pseudo(key, "identity", receipt.identity),
        boundary=_pseudo(key, "boundary", receipt.boundary),
        action_released=_pseudo(key, "action", receipt.action_released),
        reasons=[_pseudo(key, "reason", r) for r in receipt.reasons],
        trace=None,
    )
