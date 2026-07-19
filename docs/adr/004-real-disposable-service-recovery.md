# ADR 004: Real Disposable Service Recovery

- Status: accepted
- Date: 2026-07-19

## Decision

Add an explicitly enabled `LAB_MODE=container-service` that creates one hardened disposable HTTP service and wires it through the existing FastAPI, inference, proposal, approval, execution, SQLite, and audit flow. The target deliberately returns HTTP 503 on its first boot and HTTP 200 after one restart, allowing the runtime health check to provide real `unhealthy` to `healthy` evidence without touching a host or pre-existing service.

Bind remediation compatibility to `(scenario, scenario_kind)`. The existing `synthetic_marker` restarting-service scenario retains `restart_disposable_service`, which only resets markers. The new `container_fault` variant permits only `restart_unhealthy_container_service`, which restarts the exact internally generated container ID after verifying its ownership label and mount.

Support both `APP_MODE=demo` and `APP_MODE=live`. The analyzer may explain and select the one permitted action, but it cannot provide an image, target, path, mount, command, or parameter. Keep normal runtime behavior on `LAB_MODE=synthetic`; the real target is created only by explicit operator configuration and requires execution opt-in and bearer authentication.

## Rationale

This supplies one honest end-to-end remediation example at feature parity with the disk workflow: local API intake, optional real inference, immutable human approval, atomic execution claim, a real bounded side effect, verification, persistence, and audit. A distinct scenario-kind action prevents approval of a marker operation from being reused to authorize a container restart.

## Consequences

The service lab depends on a working Podman or Docker engine and a digest-pinned image. It starts no host port, uses no external network, runs non-root with a read-only root filesystem, drops all capabilities, sets CPU/memory/PID limits, and mounts only its owned sandbox. Cleanup removes and verifies the exact target, but abrupt host or container-runtime failure may leave a labeled disposable container requiring manual removal.

The injected fault is deterministic, but the service and restart are real. This is evidence for one disposable-container recovery path, not production discovery, orchestration, host remediation, provider reliability, or general container-management safety.
