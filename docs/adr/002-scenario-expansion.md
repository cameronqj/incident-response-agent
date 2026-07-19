# ADR 002: Scenario Adapter and Action Expansion

- Status: accepted
- Date: 2026-07-19

## Decision

Add explicit synthetic telemetry adapters for runaway CPU, repeatedly restarting services, memory pressure/OOM, and log storms. Each scenario maps to one deterministic, allowlisted action: `stop_runaway_process`, `restart_disposable_service`, `stop_memory_hog`, or `cleanup_log_storm_temp_files`.

The model may select only those action identifiers. Deterministic code resolves fixed marker locations under the disposable sandbox. Live execution runs the fixed action script in the bounded non-root container; offline tests use the same action contract with an in-memory service and filesystem executor.

## Rationale

These scenarios exercise process-utilization, service-health, memory-pressure, and artifact-growth evidence without inspecting the host or terminating real processes. They expand the useful incident domain while preserving the approval, action-hash, timeout, and audit boundaries established by the first slice.

## Consequences

CPU, service, memory-pressure, and log-storm recovery now have deterministic and container integration evidence. The workflow uses a deterministic memory-pressure fixture, while the container failure lab separately verifies a bounded 32 MiB OOM kill under hard resource limits.
