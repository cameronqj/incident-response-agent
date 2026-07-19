# ADR 003: Safety and Correctness Hardening

- Status: accepted
- Date: 2026-07-19

## Decision

Protect mutating HTTP endpoints with one environment-configured bearer token and keep the API loopback-only by default. Disable remediation execution by default. When enabled, permit only a digest-pinned Podman/Docker executor operating on an internally created disposable sandbox capability.

Replace arbitrary event payloads with a bounded typed local-simulation schema and sanitize the normalized event before SQLite persistence. Bind proposal approval to scenario, scenario kind, revision, and action option. Enforce the scenario/action matrix deterministically during proposal creation, decision, and execution.

Use SQLite immediate transactions and conditional state updates to atomically claim decisions, revisions, expiration, and execution across independent connections. The proposal TTL remains the execution-claim deadline even after approval.

Expired proposals are retained and inspectable in SQLite and audit history. No archive state or automatic deletion is introduced.

## Rationale

These controls close the POC's concrete authorization, stale-execution, duplicate-side-effect, sandbox-root, and raw-persistence risks without adding production identity, orchestration, or incident-management infrastructure.

## Consequences

The HTTP event shape is intentionally stricter. Legacy arbitrary event content is removed during schema migration, and legacy nonterminal proposals are expired and retained because their new scenario-bound digest cannot be proven. A crash after an execution claim may leave a retained `executing` record; automated recovery remains out of scope.
