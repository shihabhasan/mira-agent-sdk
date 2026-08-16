"""Turn OpenTelemetry spans into signed Mira records.

The important design choice is what this is NOT: it is not a tracing
framework. It is a `SpanProcessor` you *add* to whatever TracerProvider you
already have, so Mira coexists with Langfuse, OpenLLMetry, Datadog or a plain
OTLP exporter instead of competing for the tracer. Your existing observability
keeps working unchanged; Mira additionally seals the spans that matter.

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from mira_agent import Mira
    from mira_agent.otel import MiraSpanProcessor

    provider = TracerProvider()          # yours, or one already installed
    provider.add_span_processor(otlp_exporter_processor)   # unchanged
    provider.add_span_processor(MiraSpanProcessor(mira))   # + evidence
    trace.set_tracer_provider(provider)

Two things it deliberately does not do:

- **It does not seal every span.** An agent emits HTTP client spans, DB spans
  and framework noise; signing all of it would bury the evidence that matters
  in the evidence that doesn't, and cost money to retain. By default only
  GenAI spans (`gen_ai.*`) and anything explicitly marked `mira.record=True`
  are recorded. Pass `select=` to change that.
- **It does not block.** `on_end` hands the record to the same bounded, async
  transport the client uses. A span processor that does network I/O inline
  will eventually stall someone's request path.
"""

from __future__ import annotations

import logging
from typing import Callable

from mira_agent_core.records import RecordType, content_hash

log = logging.getLogger("mira.otel")

try:  # pragma: no cover - exercised via the [otel] extra
    from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor
except ImportError:  # pragma: no cover
    ReadableSpan = object  # type: ignore[assignment,misc]

    class SpanProcessor:  # type: ignore[no-redef]
        """Stub so importing this module without the extra gives a clear
        error at construction rather than a confusing ImportError here."""


__all__ = ["MiraSpanProcessor", "genai_spans", "all_spans"]


def genai_spans(span) -> bool:
    """Default selector: GenAI spans, plus anything opted in explicitly."""
    attrs = span.attributes or {}
    if attrs.get("mira.record") is True:
        return True
    return any(str(k).startswith("gen_ai.") for k in attrs)


def all_spans(span) -> bool:
    """Record everything. Rarely what you want in production."""
    return True


class MiraSpanProcessor(SpanProcessor):
    """Seals selected spans into the Mira lineage of the active run.

    Spans emitted outside a `mira.run(...)` context are dropped: a record with
    no transaction has nothing to chain to and nothing to verify against.
    """

    def __init__(
        self,
        mira,
        *,
        select: Callable[[object], bool] = genai_spans,
        capture_content: bool = True,
    ):
        if not hasattr(mira, "decide"):
            raise TypeError("MiraSpanProcessor takes a Mira client as its first argument")
        try:
            from opentelemetry.sdk.trace import SpanProcessor as _Real  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "MiraSpanProcessor needs the OpenTelemetry SDK. "
                "Install it with: pip install 'mira-agent-sdk[otel]'"
            ) from e
        self.mira = mira
        self.select = select
        self.capture_content = capture_content
        self.recorded = 0
        self.skipped = 0

    # ---- SpanProcessor interface -------------------------------------

    def on_start(self, span, parent_context=None) -> None:  # noqa: D102
        return None

    def on_end(self, span: "ReadableSpan") -> None:  # noqa: D102
        from .client import current_run

        run = current_run()
        if run is None:
            self.skipped += 1
            return
        try:
            if not self.select(span):
                self.skipped += 1
                return
            run.record(**self._to_record(span))
            self.recorded += 1
        except Exception:  # noqa: BLE001
            # Evidence capture must never break the traced application.
            log.warning("mira: failed to seal span %r", getattr(span, "name", "?"),
                        exc_info=True)

    def shutdown(self) -> None:  # noqa: D102
        self.mira.close()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:  # noqa: D102
        return bool(self.mira._transport.flush(timeout_millis / 1000.0)
                    if self.mira._transport else True)

    # ---- mapping ------------------------------------------------------

    def _to_record(self, span: "ReadableSpan") -> dict:
        attrs = dict(span.attributes or {})
        ctx = span.get_span_context()

        gen_ai = {k: _plain(v) for k, v in attrs.items() if str(k).startswith("gen_ai.")}
        node = (
            attrs.get("mira.node")
            or gen_ai.get("gen_ai.agent.name")
            or span.name.split(" ")[-1]
        )

        start_ms = (span.start_time or 0) // 1_000_000
        end_ms = (span.end_time or 0) // 1_000_000

        predicate = {
            "otel": {
                "traceId": format(ctx.trace_id, "032x"),
                "spanId": format(ctx.span_id, "016x"),
                "parentSpanId": format(span.parent.span_id, "016x") if span.parent else "",
                "name": span.name,
                "startMs": start_ms,
                "endMs": end_ms,
                "durationUs": max(0, ((span.end_time or 0) - (span.start_time or 0)) // 1_000),
                # the semantic conventions for gen_ai.* are still marked
                # Development upstream, so record which shape we emitted
                "semconv": "gen_ai/development",
            },
            "genAi": gen_ai,
            "status": str(getattr(span.status, "status_code", "")),
        }
        if attrs.get("mira.input_hash"):
            predicate["inputHash"] = str(attrs["mira.input_hash"])

        content = None
        if self.capture_content:
            content = {
                "attributes": {str(k): _plain(v) for k, v in attrs.items()},
                "events": [
                    {"name": e.name, "attributes": {str(k): _plain(v)
                                                    for k, v in dict(e.attributes or {}).items()}}
                    for e in (span.events or [])
                ],
            }

        subject = []
        if attrs.get("mira.output_hash"):
            subject.append({
                "name": "output",
                "digest": {"sha256": str(attrs["mira.output_hash"]).removeprefix("sha256:")},
            })
        elif content is not None:
            subject.append({
                "name": "span",
                "digest": {"sha256": content_hash(content).removeprefix("sha256:")},
            })

        return {
            "record_type": RecordType.SPAN,
            "node": str(node),
            "predicate": predicate,
            "subject": subject,
            "content": content,
            "ts_ms": end_ms or None,
        }


def _plain(v):
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    return str(v)
