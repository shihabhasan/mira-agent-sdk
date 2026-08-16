"""The OpenTelemetry span processor.

The property this has to have is coexistence: Mira attaches to a tracer you
already own, alongside whatever exporter you already run. If installing Mira
means losing your existing traces, nobody installs Mira.
"""

from __future__ import annotations

import pytest

pytest.importorskip("opentelemetry.sdk.trace", reason="needs the [otel] extra")

from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import (  # noqa: E402
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

from mira_agent import Mira, PolicyBundle  # noqa: E402
from mira_agent.otel import MiraSpanProcessor, all_spans  # noqa: E402

BUNDLE = {
    "bundle_id": "t", "version": "1", "default_effect": "deny",
    "rules": [{"id": "A1", "effect": "allow", "description": "ok",
               "match": {"action": "inspect"}}],
}


class CollectingExporter(SpanExporter):
    """Stands in for whatever exporter the user already had installed."""

    def __init__(self):
        self.spans = []

    def export(self, spans):
        self.spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self):
        return None


@pytest.fixture
def mira():
    return Mira(offline=True, policy=PolicyBundle.from_dict(BUNDLE), agent="otel-agent")


@pytest.fixture
def setup(mira):
    provider = TracerProvider()
    theirs = CollectingExporter()
    provider.add_span_processor(SimpleSpanProcessor(theirs))
    ours = MiraSpanProcessor(mira, select=all_spans)
    provider.add_span_processor(ours)
    return provider.get_tracer("test"), theirs, ours, mira


def test_the_existing_exporter_still_receives_everything(setup):
    """Coexistence, not replacement."""
    tracer, theirs, ours, mira = setup
    with mira.run(intent="coexist"):
        with tracer.start_as_current_span("invoke_agent deployer"):
            pass
    assert [s.name for s in theirs.spans] == ["invoke_agent deployer"]
    assert ours.recorded == 1


def test_spans_become_records_in_the_active_run(setup):
    tracer, _, ours, mira = setup
    with mira.run(intent="records") as run:
        before = run._seq
        with tracer.start_as_current_span("chat gpt") as s:
            s.set_attribute("gen_ai.provider.name", "openai")
            s.set_attribute("gen_ai.request.model", "gpt-5.4-mini")
        assert run._seq > before
    assert ours.recorded == 1


def test_spans_outside_a_run_are_dropped_not_orphaned(setup):
    """A record with no transaction has nothing to chain to and nothing to
    verify against — better dropped than written unverifiable."""
    tracer, theirs, ours, _ = setup
    with tracer.start_as_current_span("orphan"):
        pass
    assert ours.recorded == 0
    assert ours.skipped == 1
    assert len(theirs.spans) == 1  # their pipeline is unaffected


def test_the_default_selector_only_takes_genai_spans(mira):
    provider = TracerProvider()
    ours = MiraSpanProcessor(mira)  # default select=genai_spans
    provider.add_span_processor(ours)
    tracer = provider.get_tracer("t")

    with mira.run(intent="selective"):
        with tracer.start_as_current_span("GET /healthz"):
            pass
        with tracer.start_as_current_span("chat") as s:
            s.set_attribute("gen_ai.operation.name", "chat")
            pass
        with tracer.start_as_current_span("explicit") as s:
            s.set_attribute("mira.record", True)

    assert ours.recorded == 2, "http noise should not be sealed"
    assert ours.skipped == 1


def test_a_failing_selector_never_breaks_the_traced_application(mira):
    """Evidence capture must not be able to take down the app it observes."""
    provider = TracerProvider()
    boom = MiraSpanProcessor(mira, select=lambda s: 1 / 0)
    provider.add_span_processor(boom)
    tracer = provider.get_tracer("t")

    with mira.run(intent="resilient"):
        with tracer.start_as_current_span("still fine"):
            pass  # must not raise

    assert boom.recorded == 0


def test_the_record_carries_the_otel_join_keys(setup):
    tracer, _, _, mira = setup
    captured = []
    with mira.run(intent="join") as run:
        orig = run.record
        run.record = lambda **kw: (captured.append(kw), orig(**kw))[1]
        with tracer.start_as_current_span("invoke_agent x") as s:
            s.set_attribute("gen_ai.provider.name", "anthropic")

    otel = captured[0]["predicate"]["otel"]
    assert len(otel["traceId"]) == 32
    assert len(otel["spanId"]) == 16
    assert otel["name"] == "invoke_agent x"
    # the conventions are still pre-stable upstream, so record which shape
    assert otel["semconv"] == "gen_ai/development"
    assert captured[0]["predicate"]["genAi"]["gen_ai.provider.name"] == "anthropic"


def test_it_refuses_a_non_client_first_argument():
    with pytest.raises(TypeError):
        MiraSpanProcessor(object())
