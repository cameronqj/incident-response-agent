# Security posture

This repository is a bounded POC, not a production incident-response service.

## Supported boundary

- The API binds to loopback by default.
- One bearer token protects mutations; it does not provide identities, roles, or approval/execution separation.
- Execution is disabled by default and, when enabled, is confined to a validated disposable container sandbox or one internally created disposable service target.
- Event intake accepts only typed local simulations. Production webhook authentication is not implemented.
- Real host and production-service inspection and remediation are not implemented. The opt-in service lab can inspect and restart only its own disposable target.
- OpenTelemetry export is disabled by default, uses a strict attribute allowlist, and does not replace sanitized SQLite audit records.

## Threat model

| Threat | POC mitigation | Remaining limitation |
| --- | --- | --- |
| Unauthorized approval or execution | Header-only bearer authentication, constant-time comparison, execution opt-in | One token grants all mutation authority |
| Sandbox or target escape | Owned sandbox/target capabilities, real-path and ownership-label checks, fixed actions, exact container ID, one bind mount | Container/runtime vulnerabilities and principals with engine-level access remain out of scope |
| Malicious event input | 16 KiB body limit, typed schema, bounded strings/lists, normalization and redaction | This is not production webhook validation |
| Prompt injection through logs | Synthetic bounded evidence and structured model output; deterministic policy is authoritative | Live-model assessment quality is not guaranteed |
| Secret leakage | Tokens never enter service records; events and audit metadata are redacted before persistence | Operators must still protect process environment and local `.env` |
| Stale proposal execution | Scenario-bound digest, TTL recheck, atomic execution claim | Claimed executions are not automatically recovered after process crash |
| Duplicate delivery or requests | Unique idempotency key and transactional create-or-return | Callers must poll an in-progress duplicate run |
| Concurrent decisions | SQLite immediate transactions and conditional updates | SQLite remains a single-node POC store |
| Unauthorized container targeting | Target identity is generated internally; scenario-kind policy separates marker reset from real restart | The POC has no general container inventory or production target authorization model |
| Incomplete cleanup | Exact-ID removal with bounded stop time and post-removal inspection | Abrupt host or runtime failure can leave a labeled disposable container for manual cleanup |
| Telemetry exfiltration | Opt-in exporter, loopback-only HTTP, HTTPS for remote origins, no URL credentials, strict controlled attributes, canary-secret tests | Production collector authentication, backend access control, sampling, and retention policy are not implemented |

Report suspected vulnerabilities privately to the repository owner. Do not include secrets, host logs, or real incident data in reports or fixtures.
