"""W3C trace context: useful for correlation, never a source of authority.

OpenTelemetry is the right place to put MSEP's evidence context — it already
carries vendor-neutral distributed context and its GenAI conventions now cover
agents and tools. But OTel itself warns that incoming trace context from an
untrusted source may be forged and should be sanitised, and that warning is
the whole reason this module is separate from `envelope`.

A `traceparent` header arrives on the same request as the envelope and looks
just as structured. The difference is that nothing signs it. Anyone who can
reach the endpoint can claim any trace id they like. So trace context is
parsed strictly, kept for correlating evidence, and never reaches the signed
execution state — a forged header can make a trace view misleading, which is
bad, but it must not be able to make an action authorised, which would be
fatal.

The separation is structural rather than a matter of discipline: `TraceContext`
has no path into `Envelope.signing_body()`, so there is no version of "we
forgot" that lets a header influence a verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# version "-" trace-id "-" parent-id "-" flags, all lowercase hex, fixed widths.
_TRACEPARENT = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_ALL_ZERO_TRACE = "0" * 32
_ALL_ZERO_SPAN = "0" * 16


@dataclass(frozen=True)
class TraceContext:
    """Correlation identifiers. Deliberately carries no authority of any kind."""

    trace_id: str
    span_id: str
    sampled: bool = False

    def to_jcs(self) -> dict:
        return {"traceId": self.trace_id, "spanId": self.span_id,
                "sampled": self.sampled}


def parse_traceparent(header: str | None) -> TraceContext | None:
    """Parse a `traceparent`, or return None if it is not well formed.

    Strict on purpose. A tolerant parser that repairs a malformed header
    propagates an attacker's chosen identifier into the evidence view, and
    since this value is never load-bearing for a decision, there is no cost to
    simply dropping anything that does not parse exactly.
    """
    if not header:
        return None
    m = _TRACEPARENT.match(header.strip())
    if not m:
        return None
    version, trace_id, span_id, flags = m.groups()
    # ff is reserved as invalid by the spec; all-zero ids are forbidden.
    if version == "ff" or trace_id == _ALL_ZERO_TRACE or span_id == _ALL_ZERO_SPAN:
        return None
    return TraceContext(trace_id=trace_id, span_id=span_id,
                        sampled=bool(int(flags, 16) & 0x01))
