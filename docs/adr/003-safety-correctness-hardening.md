# ADR 003: Safety and Correctness Hardening

- Status: accepted
- Date: 2026-07-19

## Decision

Protect mutating HTTP endpoints with one environment-configured bearer token and keep the API loopback-only by default. Disable remediation execution by default. When enabled, permit only a digest-pinned Podman/Docker executor operating on an internally created disposable sandbox capability.

Replace arbitrary event payloads with a bounded typed local-simulation schema and sanitize the normalized event before SQLite persistence, including assignment-style and JSON-shaped credential text. Bind proposal approval to scenario, scenario kind, revision, and action option. Enforce the scenario/action matrix deterministically during proposal creation, decision, and execution.

Bound live provider responses to 65,536 bytes before JSON parsing. Bound every model `evidence_refs` item to 500 characters in addition to the existing 20-item list limit. Oversized provider responses fail with a typed reason code and are never parsed or persisted.

Use SQLite immediate transactions and conditional state updates to atomically claim decisions, revisions, expiration, and execution across independent connections. The proposal TTL remains the execution-claim deadline even after approval.

Expired proposals are retained and inspectable in SQLite and audit history. No archive state or automatic deletion is introduced.

## Rationale

These controls close the POC's concrete authorization, stale-execution, duplicate-side-effect, sandbox-root, and raw-persistence risks without adding production identity, orchestration, or incident-management infrastructure.

## Consequences

The HTTP event and model-response shapes are intentionally strict. Legacy arbitrary event content is removed during schema migration, and legacy nonterminal proposals are expired and retained because their new scenario-bound digest cannot be proven. A crash after an execution claim may leave a retained `executing` record; automated recovery remains out of scope because the side effect's outcome cannot be proven and automatic retry could duplicate remediation.
