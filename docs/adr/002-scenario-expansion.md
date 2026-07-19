# ADR 002: Scenario Adapter and Action Expansion

- Status: accepted
- Date: 2026-07-19

## Decision

Add explicit synthetic telemetry adapters for runaway CPU and repeatedly restarting services. Each scenario maps to one deterministic, allowlisted action: `stop_runaway_process` or `restart_disposable_service`.

The model may select only those action identifiers. Deterministic code resolves fixed marker locations under the disposable sandbox. Live execution runs the fixed action script in the bounded non-root container; offline tests use the same action contract with an in-memory service and filesystem executor.

## Rationale

These scenarios exercise process-utilization and service-health evidence without inspecting the host or terminating real processes. They expand the useful incident domain while preserving the approval, action-hash, timeout, and audit boundaries established by the first slice.

## Consequences

CPU and service recovery now have deterministic and container integration evidence. Memory/OOM and log-storm/temp-file scenarios remain separate because they require additional resource-limit and cross-platform fixture design.
