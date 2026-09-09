"""How stale a boundary is allowed to be, stated in numbers.

"No central dependency" is really "central dependency amortised over a TTL",
and pretending otherwise is how a design gets caught out in diligence. Every
boundary is fetching policy versions, trust epochs and revocations on a cycle.
That is still far better than a synchronous call per hop, but the question is
what the cycle is and what happens when it slips.

The defaults here are the answer, and the reasoning for each:

  policy / epoch sync interval     60 s   the control plane's push cadence
  revocation sync interval         30 s   a red card should land within a minute
  high-consequence max staleness    5 s   a production change wants live state
  hard limit                      300 s   after five minutes silent, stop

Below the high-consequence bound everything runs on the state it has. Between
that bound and the hard limit, ordinary actions continue and consequential ones
are gated until the boundary hears from the centre, because a node cannot know
about a revocation it has not received and a production deploy is not the
place to find out. Past the hard limit the boundary refuses everything: a node
that has not heard from the control plane in five minutes is either partitioned
or being kept in the dark, and neither is a state to mint authority in.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum

from mira_agent.msep.disposition import Disposition


class Consequence(StrEnum):
    LOW = "low"                # read, inspect, validate
    STANDARD = "standard"      # write to non-production
    HIGH = "high"              # production, money, irreversible


# The default classification. A deployment overrides this with its own; the
# point of having a default is that "we forgot to classify it" lands on the
# careful side.
_HIGH_TARGETS = {"prod", "production", "live"}
_LOW_ACTIONS = {"inspect", "read", "validate", "list", "get"}


def consequence_of(action: str, target: str) -> Consequence:
    if target.lower() in _HIGH_TARGETS:
        return Consequence.HIGH
    if action.lower() in _LOW_ACTIONS:
        return Consequence.LOW
    return Consequence.STANDARD


@dataclass(frozen=True)
class FreshnessPolicy:
    policy_sync_ms: int = 60_000
    epoch_sync_ms: int = 60_000
    revocation_sync_ms: int = 30_000
    high_consequence_max_age_ms: int = 5_000
    hard_limit_ms: int = 300_000


@dataclass
class FreshnessVerdict:
    ok: bool
    degrade_to: Disposition | None = None
    reason: str = ""
    staleness_ms: int = 0


@dataclass
class SyncState:
    """When this boundary last heard from the control plane, per channel."""

    policy_ms: int = 0
    epoch_ms: int = 0
    revocation_ms: int = 0
    policy: FreshnessPolicy = field(default_factory=FreshnessPolicy)

    def record(self, channel: str, now_ms: int | None = None) -> None:
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        setattr(self, f"{channel}_ms", now)

    def record_all(self, now_ms: int | None = None) -> None:
        for c in ("policy", "epoch", "revocation"):
            self.record(c, now_ms)

    def staleness(self, now_ms: int | None = None) -> int:
        """Age of the oldest channel. The boundary is only as fresh as the
        thing it has heard about least recently."""
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        return max(now - self.policy_ms, now - self.epoch_ms, now - self.revocation_ms)

    def assess(self, consequence: Consequence, now_ms: int | None = None) -> FreshnessVerdict:
        age = self.staleness(now_ms)
        p = self.policy
        if age > p.hard_limit_ms:
            return FreshnessVerdict(
                False, Disposition.INTERDICT, staleness_ms=age,
                reason=(f"no contact with the control plane for {age/1000:.0f}s, past the "
                        f"{p.hard_limit_ms/1000:.0f}s hard limit; refusing rather than "
                        "acting on state that may have been revoked"))
        if consequence is Consequence.HIGH and age > p.high_consequence_max_age_ms:
            return FreshnessVerdict(
                False, Disposition.GATE, staleness_ms=age,
                reason=(f"high-consequence action on {age/1000:.1f}s-old trust state; "
                        f"held until the boundary has heard from the control plane "
                        f"within {p.high_consequence_max_age_ms/1000:.0f}s"))
        return FreshnessVerdict(True, staleness_ms=age)

    def due(self, now_ms: int | None = None) -> list[str]:
        """Which channels are overdue for a sync — what a scheduler polls."""
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        p = self.policy
        out = []
        if now - self.policy_ms > p.policy_sync_ms: out.append("policy")
        if now - self.epoch_ms > p.epoch_sync_ms: out.append("epoch")
        if now - self.revocation_ms > p.revocation_sync_ms: out.append("revocation")
        return out
