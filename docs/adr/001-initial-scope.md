# ADR 001: Initial Vertical Slice

- Status: accepted
- Date: 2026-07-19

## Decision

Implement the first slice in Python 3.12 with FastAPI, Pydantic, and SQLite. The initial scenario is synthetic disk exhaustion caused by failed log rotation. HTTP and CLI interfaces call one application service. Live and offline inference are explicit `APP_MODE` choices.

The model can select only an allowlisted action identifier. Deterministic policy resolves all targets and execution behavior. Approval binds to the immutable proposal revision and canonical action hash. SQLite stores runs, proposal revisions, and sanitized audit records.

Portable tests use deterministic ENOSPC fault injection. Docker/Podman integration is an additional realistic failure-lab check and is not required for the default offline suite.

## Rationale

This provides a real webhook-to-assessment-to-human-approval-to-recovery workflow while keeping the first implementation safe, inspectable, and independent of model or host timing. SQLite and injected adapters leave room for later service and storage changes without adding infrastructure to the experimental slice.

## Consequences

The first release does not implement CPU, memory/OOM, restarting-service, or log-storm scenarios. It also does not claim production safety, autonomous remediation, or general model-provider compatibility.
