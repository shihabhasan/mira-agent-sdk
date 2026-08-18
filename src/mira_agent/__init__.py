"""Mira SDK — governance and verifiable provenance for AI agents."""

from mira_agent_core import verify_bundle

from mira_agent_core.identity import AgentIdentity, SpiffeError, SpiffeId

from .cedar import CedarError, cedar_to_bundle, compile_cedar
from .client import Decision, Interdicted, Mira, MiraConfigError, Run, current_run
from .policy import PolicyBundle, Rule, evaluate
from .sentry import PolicySkew, SentryClient

__version__ = "0.2.0"
__all__ = [
    "Mira", "Run", "Decision", "Interdicted", "MiraConfigError", "current_run",
    "PolicyBundle", "Rule", "evaluate", "verify_bundle",
    "AgentIdentity", "SpiffeId", "SpiffeError",
    "compile_cedar", "cedar_to_bundle", "CedarError",
    "SentryClient", "PolicySkew",
]
