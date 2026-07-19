# Security posture

This repository is a bounded POC, not a production incident-response service.

## Supported boundary

- The API binds to loopback by default.
- One bearer token protects mutations; it does not provide identities, roles, or approval/execution separation.
- Execution is disabled by default and, when enabled, is confined to a validated disposable container sandbox.
- Event intake accepts only typed local simulations. Production webhook authentication is not implemented.
- Real host inspection and remediation are not implemented.

## Threat model

| Threat | POC mitigation | Remaining limitation |
| --- | --- | --- |
| Unauthorized approval or execution | Header-only bearer authentication, constant-time comparison, execution opt-in | One token grants all mutation authority |
| Sandbox escape | Owned sandbox capability, real-path/symlink checks, fixed actions, one bind mount | Container/runtime vulnerabilities remain out of scope |
| Malicious event input | 16 KiB body limit, typed schema, bounded strings/lists, normalization and redaction | This is not production webhook validation |
| Prompt injection through logs | Synthetic bounded evidence and structured model output; deterministic policy is authoritative | Live-model assessment quality is not guaranteed |
| Secret leakage | Tokens never enter service records; events and audit metadata are redacted before persistence | Operators must still protect process environment and local `.env` |
| Stale proposal execution | Scenario-bound digest, TTL recheck, atomic execution claim | Claimed executions are not automatically recovered after process crash |
| Duplicate delivery or requests | Unique idempotency key and transactional create-or-return | Callers must poll an in-progress duplicate run |
| Concurrent decisions | SQLite immediate transactions and conditional updates | SQLite remains a single-node POC store |

Report suspected vulnerabilities privately to the repository owner. Do not include secrets, host logs, or real incident data in reports or fixtures.
