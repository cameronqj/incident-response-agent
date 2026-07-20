from __future__ import annotations

from contextlib import AbstractContextManager, contextmanager, nullcontext
import re
from threading import Lock
from typing import Any, Mapping

from fastapi import FastAPI
from opentelemetry import metrics, trace
from opentelemetry.trace import Status, StatusCode
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import MetricReader, PeriodicExportingMetricReader
from opentelemetry.sdk.metrics.view import View
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor, SpanExporter

from .config import ConfigurationError, Settings


AttributeValue = str | bool | int | float
Attributes = Mapping[str, AttributeValue]


def _safe_identifier(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        return value
    return "invalid_attribute"


class NoopSpan:
    def set_attribute(self, _key: str, _value: AttributeValue) -> None:
        return None


class NoopObservability:
    enabled = False

    def span(self, _name: str, _attributes: Attributes | None = None) -> AbstractContextManager[Any]:
        return nullcontext(NoopSpan())

    def record_event_to_proposal(self, _latency_ms: int, _scenario: str, _scenario_kind: str) -> None:
        return None

    def record_model(self, _latency_ms: int, _token_count: int, _retry_count: int, _scenario: str) -> None:
        return None

    def record_decision(self, _wait_seconds: float, _decision: str, _scenario: str) -> None:
        return None

    def record_execution(self, _action_id: str, _scenario: str, _scenario_kind: str, _success: bool, _reason_code: str) -> None:
        return None

    def record_expirations(self, _count: int) -> None:
        return None

    def instrument_fastapi(self, _app: FastAPI) -> None:
        return None

    def force_flush(self, _timeout_millis: int = 10_000) -> bool:
        return True

    def shutdown(self) -> None:
        return None


class OpenTelemetryObservability:
    enabled = True

    def __init__(self, tracer_provider: TracerProvider, meter_provider: MeterProvider):
        self.tracer_provider = tracer_provider
        self.meter_provider = meter_provider
        self.tracer = trace.get_tracer(
            "incident_response_agent.service",
            tracer_provider=tracer_provider,
        )
        meter = metrics.get_meter(
            "incident_response_agent.service",
            meter_provider=meter_provider,
        )
        self.event_to_proposal = meter.create_histogram(
            "incident.event_to_proposal.duration",
            unit="ms",
            description="Time from accepted event to immutable proposal",
        )
        self.model_latency = meter.create_histogram(
            "incident.model.duration",
            unit="ms",
            description="Bounded model analysis latency",
        )
        self.model_tokens = meter.create_counter(
            "incident.model.tokens",
            unit="{token}",
            description="Model tokens reported by the configured provider",
        )
        self.model_retries = meter.create_counter(
            "incident.model.retries",
            unit="{retry}",
            description="Bounded model retry attempts",
        )
        self.approval_wait = meter.create_histogram(
            "incident.approval_wait.duration",
            unit="s",
            description="Time a proposal awaited a human decision",
        )
        self.executions = meter.create_counter(
            "incident.execution.count",
            unit="{execution}",
            description="Claimed remediation execution outcomes",
        )
        self.expirations = meter.create_counter(
            "incident.proposal.expirations",
            unit="{proposal}",
            description="Proposals expired and retained",
        )
        self._shutdown_lock = Lock()
        self._shutdown = False

    @contextmanager
    def span(self, name: str, attributes: Attributes | None = None):
        with self.tracer.start_as_current_span(
            name,
            attributes=dict(attributes or {}),
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            try:
                yield span
            except Exception as exc:
                reason_code = getattr(exc, "reason_code", type(exc).__name__)
                if not isinstance(reason_code, str) or not reason_code.replace("_", "").isalnum():
                    reason_code = type(exc).__name__
                span.set_attribute("incident.reason_code", reason_code[:128])
                span.set_status(Status(StatusCode.ERROR))
                raise

    def record_event_to_proposal(self, latency_ms: int, scenario: str, scenario_kind: str) -> None:
        self.event_to_proposal.record(
            latency_ms,
            {"incident.scenario": scenario, "incident.scenario_kind": scenario_kind},
        )

    def record_model(self, latency_ms: int, token_count: int, retry_count: int, scenario: str) -> None:
        attributes = {"incident.scenario": scenario}
        self.model_latency.record(latency_ms, attributes)
        self.model_tokens.add(token_count, attributes)
        self.model_retries.add(retry_count, attributes)

    def record_decision(self, wait_seconds: float, decision: str, scenario: str) -> None:
        self.approval_wait.record(
            wait_seconds,
            {"incident.decision": decision, "incident.scenario": scenario},
        )

    def record_execution(self, action_id: str, scenario: str, scenario_kind: str, success: bool, reason_code: str) -> None:
        self.executions.add(
            1,
            {
                "incident.action_id": action_id,
                "incident.scenario": scenario,
                "incident.scenario_kind": scenario_kind,
                "incident.result": "succeeded" if success else "failed",
                "incident.reason_code": _safe_identifier(reason_code),
            },
        )

    def record_expirations(self, count: int) -> None:
        if count:
            self.expirations.add(count, {"incident.result": "expired"})

    def instrument_fastapi(self, app: FastAPI) -> None:
        FastAPIInstrumentor.instrument_app(
            app,
            tracer_provider=self.tracer_provider,
            meter_provider=self.meter_provider,
            server_request_hook=self._sanitize_http_span,
            exclude_spans=["receive", "send"],
        )

    @staticmethod
    def _sanitize_http_span(span, scope: dict[str, Any]) -> None:
        if span is None or not span.is_recording():
            return
        path = str(scope.get("path", ""))
        if path in {"/events", "/maintenance/expire"}:
            safe_route = path
        elif re.fullmatch(r"/runs/[^/]+", path):
            safe_route = "/runs/{run_id}"
        elif re.fullmatch(r"/proposals/[^/]+/decision", path):
            safe_route = "/proposals/{proposal_id}/decision"
        elif re.fullmatch(r"/proposals/[^/]+/execute", path):
            safe_route = "/proposals/{proposal_id}/execute"
        else:
            safe_route = "/unmatched"
        replacements = {
            "http.target": safe_route,
            "http.url": safe_route,
            "url.path": safe_route,
            "url.query": "[REDACTED]",
            "url.full": safe_route,
            "http.user_agent": "[REDACTED]",
            "user_agent.original": "[REDACTED]",
            "http.server_name": "local-api",
            "server.address": "local-api",
            "http.host": "local-api",
            "net.host.name": "local-api",
            "net.peer.ip": "[REDACTED]",
            "client.address": "[REDACTED]",
            "http.client_ip": "[REDACTED]",
            "network.peer.address": "[REDACTED]",
        }
        current = span.attributes
        for key, value in replacements.items():
            if key in current:
                span.set_attribute(key, value)

    def force_flush(self, timeout_millis: int = 10_000) -> bool:
        traces_flushed = self.tracer_provider.force_flush(timeout_millis)
        metrics_flushed = self.meter_provider.force_flush(timeout_millis)
        return bool(traces_flushed and metrics_flushed)

    def shutdown(self) -> None:
        with self._shutdown_lock:
            if self._shutdown:
                return
            self._shutdown = True
        self.tracer_provider.shutdown()
        self.meter_provider.shutdown()


def _resource(settings: Settings) -> Resource:
    return Resource.create(
        {
            "service.name": settings.otel_service_name,
            "service.version": "0.1.0",
            "deployment.environment.name": settings.app_mode,
        }
    )


def _metric_views() -> list[View]:
    return [
        View(
            instrument_name="http.server.*",
            attribute_keys={
                "http.method",
                "http.status_code",
                "http.flavor",
                "http.scheme",
                "http.request.method",
                "http.response.status_code",
                "http.route",
                "network.protocol.version",
                "url.scheme",
            },
        )
    ]


def build_observability(settings: Settings) -> NoopObservability | OpenTelemetryObservability:
    if not settings.otel_enabled:
        return NoopObservability()
    if not settings.otel_exporter_otlp_endpoint:
        raise ConfigurationError("OTEL_ENABLED=1 requires OTEL_EXPORTER_OTLP_ENDPOINT")
    endpoint = settings.otel_exporter_otlp_endpoint.rstrip("/")
    timeout = settings.otel_export_timeout_seconds
    resource = _resource(settings)
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces", timeout=timeout))
    )
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=f"{endpoint}/v1/metrics", timeout=timeout),
        export_interval_millis=5_000,
        export_timeout_millis=max(1, int(timeout * 1_000)),
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader], views=_metric_views())
    return OpenTelemetryObservability(tracer_provider, meter_provider)


def build_test_observability(
    span_exporter: SpanExporter,
    metric_reader: MetricReader,
    service_name: str = "incident-response-agent-test",
) -> OpenTelemetryObservability:
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": "0.1.0",
            "deployment.environment.name": "test",
        }
    )
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader], views=_metric_views())
    return OpenTelemetryObservability(tracer_provider, meter_provider)
