"""MSEP — the Mira Stateless Execution Protocol.

Authority travels with the action; evidence travels out of band. The receiving
boundary verifies bounded, signed authority locally instead of asking a central
service what the workflow is already permitted to do.

"Stateless" is about the execution authorisation, not the system: policy, keys
and trust epochs still come from the centre. What the centre stops doing is
answering a question on every hop.
"""

from mira_agent.msep.boundary import ExecutionBoundary, HopResult, PolicyOutcome
from mira_agent.msep.disposition import Disposition
from mira_agent.msep.envelope import (PROTOCOL, Capability, Envelope, ExecutionState,
                                Permissions, new_envelope)
from mira_agent.msep.receipt import Receipt, ReceiptQueue, compile_receipt
from mira_agent.msep.seal import (KeyWrapper, LocalWrapper, Lodgement, SealedState,
                            reconstruct, seal)
from mira_agent.msep.trace import TraceContext, parse_traceparent
from mira_agent.msep.trust_root import (BlastRadius, BoundaryCertificate, CertificateStore,
                                  TrustAnchor, blast_radius, issue_certificate)
from mira_agent.msep.freshness import Consequence, FreshnessPolicy, SyncState, consequence_of
from mira_agent.msep.signals import SecurityEventToken, emit_red_card, ingest as ingest_signal
from mira_agent.msep.redact import RedactionRule, Treatment, apply_redactions
from mira_agent.msep.residency import Residency, pseudonymise
from mira_agent.msep.lineage import Lineage, reconstruct as reconstruct_lineage
from mira_agent.msep.seal import Custody
from mira_agent.msep import fast
from mira_agent.msep.trust import (CRITICAL_TRUST_EVENTS, AdverseTrustAssertion,
                             Severity, TrustEpoch, issue_red_card, reinstate)
from mira_agent.msep.verify import (KeyCache, Reject, ReplayWindow, Verdict,
                              verify_inbound, verify_succession)

__all__ = [
    "PROTOCOL", "Capability", "Permissions", "ExecutionState", "Envelope",
    "new_envelope", "ExecutionBoundary", "HopResult", "PolicyOutcome",
    "Disposition",
    "KeyCache", "ReplayWindow", "Verdict", "Reject", "verify_inbound",
    "verify_succession", "TrustEpoch", "AdverseTrustAssertion", "Severity",
    "issue_red_card", "reinstate", "CRITICAL_TRUST_EVENTS",
    "Receipt", "ReceiptQueue", "compile_receipt",
    "seal", "reconstruct", "SealedState", "Lodgement", "KeyWrapper",
    "LocalWrapper", "TraceContext", "parse_traceparent",
    "TrustAnchor", "BoundaryCertificate", "CertificateStore", "issue_certificate",
    "BlastRadius", "blast_radius", "FreshnessPolicy", "SyncState", "Consequence",
    "consequence_of", "SecurityEventToken", "emit_red_card", "ingest_signal",
    "RedactionRule", "Treatment", "apply_redactions", "Residency", "pseudonymise",
    "Lineage", "reconstruct_lineage", "Custody", "fast",
]
