from __future__ import annotations

import asyncio

import httpx
import pytest
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from conftest import TEST_TOKEN, make_event
from incident_response_agent.app import create_app
from incident_response_agent.config import ConfigurationError, Settings
from incident_response_agent.observability import NoopObservability, build_observability, build_test_observability


def _request(app, method: str, path: str, **kwargs):
    async def execute():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(execute())


def _metric_names(reader: InMemoryMetricReader) -> set[str]:
    data = reader.get_metrics_data()
    assert data is not None
    return {
        metric.name
        for resource_metrics in data.resource_metrics
        for scope_metrics in resource_metrics.scope_metrics
        for metric in scope_metrics.metrics
    }


def test_otel_is_disabled_by_default_and_requires_an_explicit_endpoint():
    settings = Settings()
    settings.validate()
    assert isinstance(build_observability(settings), NoopObservability)

    with pytest.raises(ConfigurationError, match="requires OTEL_EXPORTER_OTLP_ENDPOINT"):
        Settings(otel_enabled=True).validate()


@pytest.mark.parametrize(
    "endpoint",
    [
        "ftp://127.0.0.1:4318",
        "http://collector.example:4318",
        "https://user:password@collector.example",  # pragma: allowlist secret
        "https://collector.example/v1/traces",
        "https://collector.example?token=secret",
        "https://collector.example#fragment",
    ],
)
def test_otel_rejects_unsafe_or_ambiguous_endpoints(endpoint):
    with pytest.raises(ConfigurationError):
        Settings(otel_enabled=True, otel_exporter_otlp_endpoint=endpoint).validate()


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:4318", "http://[::1]:4318", "https://collector.example"])
def test_otel_accepts_loopback_http_or_https(endpoint):
    Settings(otel_enabled=True, otel_exporter_otlp_endpoint=endpoint).validate()


def test_lifecycle_traces_metrics_and_attribute_redaction(service):
    incident, _, _ = service
    span_exporter = InMemorySpanExporter()
    metric_reader = InMemoryMetricReader()
    observability = build_test_observability(span_exporter, metric_reader)
    incident.observability = observability
    app = create_app(incident, Settings(bearer_token=TEST_TOKEN, execution_enabled=True, database_path=":memory:"))
    canaries = [
        TEST_TOKEN,
        "otel-bearer-canary",
        "otel-api-key-canary",
        "/Users/private-person/incident.log",
        "10.20.30.40",
    ]
    event = make_event(
        "otel-workflow",
        summary=f"Bearer {canaries[1]} from {canaries[3]} at {canaries[4]}",
        log_lines=[f"api_key={canaries[2]}"],
    ).model_dump(mode="json")
    headers = {"Authorization": f"Bearer {canaries[1]}"}
    headers["User-Agent"] = canaries[1]
    headers["Host"] = canaries[1]

    received = _request(app, "POST", f"/events?access_token={canaries[1]}", json=event, headers=headers)
    assert received.status_code == 401
    received = _request(
        app,
        "POST",
        "/events",
        json=event,
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert received.status_code == 202
    proposal = received.json()["proposal"]
    decision = _request(
        app,
        "POST",
        f"/proposals/{proposal['proposal_id']}/decision",
        json={"decision": "approve", "revision": proposal["revision"], "action_hash": proposal["action_hash"]},
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert decision.status_code == 200
    executed = _request(
        app,
        "POST",
        f"/proposals/{proposal['proposal_id']}/execute",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert executed.status_code == 200

    spans = span_exporter.get_finished_spans()
    names = {span.name for span in spans}
    assert {
        "incident.start_event",
        "incident.telemetry.collect",
        "incident.model.analyze",
        "incident.proposal.create",
        "incident.proposal.decide",
        "incident.remediation.execute",
        "incident.remediation.tool",
    } <= names
    event_server = next(
        span
        for span in spans
        if span.kind.name == "SERVER"
        and span.attributes.get("http.route") == "/events"
        and span.attributes.get("http.status_code") == 202
    )
    lifecycle = next(span for span in spans if span.name == "incident.start_event")
    assert lifecycle.context.trace_id == event_server.context.trace_id
    assert lifecycle.parent is not None and lifecycle.parent.span_id == event_server.context.span_id
    assert {
        "incident.event_to_proposal.duration",
        "incident.model.duration",
        "incident.model.tokens",
        "incident.model.retries",
        "incident.approval_wait.duration",
        "incident.execution.count",
    } <= _metric_names(metric_reader)

    exported = repr(
        [
            {
                "name": span.name,
                "attributes": dict(span.attributes),
                "resource": dict(span.resource.attributes),
                "events": [(event.name, dict(event.attributes)) for event in span.events],
            }
            for span in spans
        ]
    ) + repr(metric_reader.get_metrics_data())
    for canary in canaries:
        assert canary not in exported


def test_expiration_metric_is_emitted(service):
    incident, clock, _ = service
    span_exporter = InMemorySpanExporter()
    metric_reader = InMemoryMetricReader()
    incident.observability = build_test_observability(span_exporter, metric_reader)
    run = incident.start_event(make_event("otel-expiration"))
    assert run.proposal is not None
    clock.advance(61)

    assert incident.expire_due() == 1
    assert "incident.proposal.expirations" in _metric_names(metric_reader)
    assert "incident.proposal.expire_due" in {span.name for span in span_exporter.get_finished_spans()}


def test_exception_messages_are_not_exported(service):
    incident, _, _ = service
    span_exporter = InMemorySpanExporter()
    incident.observability = build_test_observability(span_exporter, InMemoryMetricReader())
    canary = "exception-message-secret-canary"

    class FailingAnalyzer:
        def analyze(self, _evidence):
            raise RuntimeError(canary)

    incident.analyzer = FailingAnalyzer()
    with pytest.raises(RuntimeError, match=canary):
        incident.start_event(make_event("otel-failure"))

    spans = span_exporter.get_finished_spans()
    assert any(span.status.status_code.name == "ERROR" for span in spans)
    assert canary not in repr(
        [
            {
                "attributes": dict(span.attributes),
                "events": [(event.name, dict(event.attributes)) for event in span.events],
            }
            for span in spans
        ]
    )
