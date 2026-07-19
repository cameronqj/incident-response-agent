# Project Constitution

## Purpose

Build a small, inspectable incident-response agent that helps a human decide on bounded remediation. The project values useful behavior, explicit authority, reproducibility, and honest evidence claims.

## Non-negotiable boundaries

- No side effect without an explicit, hash-bound human approval.
- Model output is advisory. Deterministic schemas, policy, permissions, and execution guards are authoritative.
- Diagnostics are scoped and read-only by default.
- No arbitrary commands, model-selected paths, privileged containers, or host-sensitive data in fixtures or logs.
- Expiration is never approval; expired proposals remain auditable.
- Default tests are offline and deterministic.

## Engineering practices

- Prefer small injected interfaces over framework-wide abstractions.
- Use structured, validated records for workflow data and sanitized audit records.
- Pair deterministic fault injection with realistic container integration.
- Tie README claims to tests, fixtures, ADRs, or clearly labeled experiments.
- Use the project `.venv`; never install dependencies with system pip.
