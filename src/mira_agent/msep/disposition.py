"""What a boundary can do about an interaction.

Allow and block is too coarse for agent workflows. Most failures are not
attacks: a tool call is broader than it needed to be, a sensitive field rides
along in an otherwise reasonable payload, a workflow drifts, or a step is
consequential enough to want a second signature. Collapsing all of that into
"deny" turns every imperfection into an outage, and a governance layer that
causes outages gets switched off.

So the disposition set preserves as much safe work as it can while still being
decisive when it has to be. The six below are the protocol's set; a deployment
may configure others, but these are the ones the boundary itself understands.

The division that matters is whether the governed action is released *now*.
Release and Redact release something. Gate and Elevate release nothing yet —
they park the interaction until a condition resolves or an authority answers.
Interdict and Recover release nothing at all. Getting Elevate onto the wrong
side of that line would mean an action referred to a human for judgement had
already happened by the time anyone read it.
"""

from __future__ import annotations

from enum import StrEnum


class Disposition(StrEnum):
    # released
    RELEASE = "release"        # proceed as requested
    REDACT = "redact"          # remove or replace a defined portion, then proceed
    # held, pending an answer from outside this boundary
    GATE = "gate"              # hold until a condition or corroborating check resolves
    ELEVATE = "elevate"        # refer to a human or another trusted system
    # refused
    INTERDICT = "interdict"    # stop before execution and preserve state
    RECOVER = "recover"        # restore a prior trusted state and retry or substitute

    @property
    def executes(self) -> bool:
        """Whether the governed action is actually released at this hop."""
        return self in (Disposition.RELEASE, Disposition.REDACT)

    @property
    def pending(self) -> bool:
        """Held awaiting a resolution this boundary cannot supply itself.

        Not a refusal: the interaction has not been decided against, it is
        waiting. A caller that treats this as a denial loses the distinction
        policy asked for when it chose Gate or Elevate over Interdict.
        """
        return self in (Disposition.GATE, Disposition.ELEVATE)

    @property
    def refused(self) -> bool:
        """Decided against. The action does not happen at this hop."""
        return self in (Disposition.INTERDICT, Disposition.RECOVER)

    @property
    def terminal(self) -> bool:
        """Whether the workflow stops here rather than carrying on now."""
        return not self.executes
