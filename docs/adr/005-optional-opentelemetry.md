# ADR 005: Optional OpenTelemetry Export

- Status: accepted
- Date: 2026-07-19

## Decision

Add optional OpenTelemetry tracing and metrics without replacing the existing SQLite audit history. Telemetry is disabled by default and requires both `OTEL_ENABLED=1` and an explicit OTLP/HTTP origin. Unencrypted export is limited to loopback; remote export must use HTTPS. Endpoint credentials, URL paths, query strings, and fragments are rejected.

Instrument FastAPI requests and emit manual spans for event intake, bounded telemetry collection, model analysis, proposal creation and decision, remediation execution and tool invocation, and expiration sweeps. Emit bounded metrics for event-to-proposal duration, model duration/tokens/retries, approval wait, execution outcome, and expiration count.

Only controlled identifiers and enums may be attached: generated run/proposal IDs, proposal revision, scenario, scenario kind, action ID, decision, outcome, and reason code. Never export authorization headers, query strings, event bodies, evidence or model text, prompts, log lines, filesystem paths, arbitrary model output, API keys, or bearer tokens.

## Rationale

The existing audit records answer durable workflow and safety questions, but they do not provide standard distributed trace context, request spans, metric aggregation, or export to common observability tools. A small optional OTel boundary adds portfolio-relevant interoperability while preserving deterministic offline behavior and the repository's bounded POC scope.

## Consequences

OpenTelemetry SDK and FastAPI instrumentation packages become runtime dependencies. Export introduces an optional external data flow and operational failure mode, so it remains off by default, uses short bounded timeouts, and receives only allowlisted attributes. SQLite remains the authoritative retained incident history; collector availability does not authorize actions or alter proposal state.

Offline tests use in-memory span and metric readers. A separately labeled integration test sends OTLP to a digest-pinned disposable collector and verifies receipt and canary-secret absence. This proves the configured local export path, not collector durability, backend dashboards, alerting, production sampling, production transport identity, or cross-service propagation.
