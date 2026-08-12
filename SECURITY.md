# Security posture

This repository is a bounded POC, not a production incident-response service.

## Supported boundary

- The API binds to loopback by default.
- One bearer token protects mutations; it does not provide identities, roles, or approval/execution separation.
- Execution is disabled by default and, when enabled, is confined to a validated disposable container sandbox or one internally created disposable service target.
- Event intake accepts only typed local simulations. Production webhook authentication is not implemented.
- Real host and production-service inspection and remediation are not implemented. The opt-in service lab can inspect and restart only its own disposable target.
- OpenTelemetry export is disabled by default, uses a strict attribute allowlist, and does not replace sanitized SQLite audit records.
- The Deep Agent can inspect only one owned synthetic site through typed read-only tools. Its thread-local virtual filesystem is denied by defensive permissions, and its state backend provides no shell execution capability.
- The capability path is governed end to end: the agent proposes a typed contract, application code owns review, promotion, and executor implementation, and activation requires the existing immutable proposal and hash-bound human approval against one owned disposable worker with verification and rollback.

## Threat model

| Threat | POC mitigation | Remaining limitation |
| --- | --- | --- |
| Unauthorized approval or execution | Header-only bearer authentication, constant-time comparison, execution opt-in | One token grants all mutation authority |
| Sandbox or target escape | Owned sandbox/target capabilities, real-path and ownership-label checks, fixed actions, exact container ID, one bind mount; fixed action directories receive temporary container access and return to owner-only modes | Container/runtime vulnerabilities, local races during the bounded execution window, and principals with engine-level access remain out of scope |
| Malicious event input | 16 KiB body limit, typed schema, bounded strings/lists, normalization and redaction | This is not production webhook validation |
| Prompt injection through logs | Synthetic bounded evidence and structured model output; deterministic policy is authoritative | Live-model assessment quality is not guaranteed |
| Deep Agent prompt injection | Sanitized bounded observations, curated runbooks, strict structured results, observed-evidence validation, and deterministic action policy | A live model may still waste calls, misdiagnose, or decline the task |
| Hidden fixture disclosure | Injected ground truth remains a private lab field and is absent from messages, tool schemas/results, and virtual files; regression tests scan observations | Fixture implementation remains locally inspectable by a developer with source access |
| Filesystem or subagent escalation | Defensive permissions deny virtual-filesystem paths, subagents receive only explicit diagnostic tools, and the state backend exposes no `execute` tool | Deep Agents and LangChain dependency vulnerabilities require ongoing maintenance |
| Excessive agent activity | Provider timeout/retries, diagnostic outputs, schemas, and graph recursion are bounded | Cost budgets and provider-side quotas remain operator responsibilities |
| Secret leakage | Tokens never enter service records; assignment-style and JSON-shaped credentials, home paths, and private IPs are redacted before event/audit persistence | Operators must still protect process environment and local `.env` |
| Oversized or malicious model output | Provider responses are read through a 65,536-byte limit; strict schemas bound text, lists, and fields before persistence; model output cannot define commands or targets | Model assessment quality and provider availability remain variable |
| Capability misuse | The agent proposes only a typed contract; application code owns review, promotion, and executor implementation; concrete runtime values are chosen in code and bound into the action hash; the executor rejects any action, target, or parameter outside approved bounds; promotion grants no execution authority | A containerized worker variant, additional capabilities, and production targets are not implemented; the SQLite registry is not an adversarial integrity boundary |
| Capability activation blast radius | One owned disposable worker target only, deterministic health verification, bounded rollback to the previous value, auditable activation outcome | No fleet or production activation, and no automatic regression-case generation from outcomes |
| Stale proposal execution | Scenario-bound digest, TTL recheck, atomic execution claim | Claimed executions are not automatically recovered after process crash; reconciliation is tracked in [Issue #2](https://github.com/cameronqj/incident-response-agent/issues/2) |
| Duplicate delivery or requests | Unique idempotency key and transactional create-or-return | Callers must poll an in-progress duplicate run |
| Concurrent decisions | SQLite immediate transactions and conditional updates | SQLite remains a single-node POC store |
| Unauthorized container targeting | Target identity is generated internally; scenario-kind policy separates marker reset from real restart | The POC has no general container inventory or production target authorization model |
| Incomplete cleanup | Exact-ID removal with bounded stop time and post-removal inspection | Abrupt host or runtime failure can leave a labeled disposable container for manual cleanup |
| Telemetry exfiltration | Opt-in exporter, loopback-only HTTP, HTTPS for remote origins, no URL credentials, strict controlled attributes, canary-secret tests | Production collector authentication, backend access control, sampling, and retention policy are not implemented |
| Agent trace exfiltration | Canonical OTel spans contain controlled names, labels, counts, and durations only; LangSmith is not enabled by the application | Operators who independently enable LangSmith must configure retention and content redaction |

Report suspected vulnerabilities privately to the repository owner. Do not include secrets, host logs, or real incident data in reports or fixtures.
