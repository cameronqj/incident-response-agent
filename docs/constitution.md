# Project Constitution

## Purpose

Build a small, inspectable incident-response agent that helps a human decide on bounded remediation. The project values useful behavior, explicit authority, reproducibility, and honest evidence claims.

## Non-negotiable boundaries

- No side effect without an explicit, hash-bound human approval.
- Model output is advisory. Deterministic schemas, policy, permissions, and execution guards are authoritative.
- Diagnostics are scoped and read-only by default.
- No arbitrary commands, model-selected paths, privileged containers, or host-sensitive data in fixtures or logs.
- Expiration is never approval; expired proposals are retained in SQLite and remain auditable.
- HTTP mutations require POC bearer authentication or are disabled, and execution is opt-in.
- Runtime remediation is confined to an internally created disposable container sandbox or an internally created and ownership-validated disposable service container.
- External observability is opt-in and receives only controlled identifiers, enums, counts, and durations; SQLite remains the authoritative audit history.
- Default tests are offline and deterministic.

## Engineering practices

- Prefer small injected interfaces over framework-wide abstractions.
- Use structured, validated records for workflow data and sanitized audit records.
- Keep telemetry attributes on a strict allowlist; do not export event bodies, prompts, logs, paths, headers, credentials, or model text.
- Pair deterministic fault injection with realistic container integration.
- Label synthetic-marker and real-container evidence separately.
- Bind action compatibility to both scenario and evidence kind so synthetic approval cannot authorize a real-container capability.
- Tie README claims to tests, fixtures, ADRs, or clearly labeled experiments.
- Use the project `.venv`; never install dependencies with system pip.
