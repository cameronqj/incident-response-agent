# GitHub Issue #1 — Build the first incident-response vertical slice

- Status: completed
- Issue: https://github.com/cameronqj/incident-response-agent/issues/1
- Implementation: commits `6219cc7`, `2141056`, `df3e9e5`, `6dd387c`, `7415051`, `ed33c8c`, and `4ef50f9`

## Goal

Implement the bounded disk-exhaustion workflow described in ADR 001.

## Acceptance criteria

- A simulated event starts an idempotent run.
- Synthetic ENOSPC evidence produces a validated proposal.
- The proposal includes confidence, impact, risk, evidence, preview, revision, and action hash.
- Identical duplicate events return the original run; conflicting payloads return HTTP 409.
- Approve, reject, revise, and expire-and-retain behavior are explicit and auditable.
- Execution rejects unapproved or hash-mismatched proposals.
- The only remediation is deterministic cleanup of rotated artifacts in a disposable sandbox.
- Runaway CPU and restarting-service scenarios use fixed allowlisted actions and bounded recovery fixtures.
- Memory/OOM and log-storm scenarios use fixed allowlisted actions and bounded recovery fixtures.
- Offline tests and the deterministic demo pass without network access or an API key.
- Container integration demonstrates bounded cleanup when a Podman/Docker engine is available.
