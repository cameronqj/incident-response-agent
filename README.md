# incident-response-agent

`incident-response-agent` is a bounded incident-response experiment. It receives a local event, collects bounded evidence, produces a structured remediation proposal, waits for an explicit human decision, and executes only a scenario-and-evidence-kind-compatible allowlisted action inside a disposable environment.

## What it does

- Demonstrates disk exhaustion, CPU pressure, memory pressure, restart-loop, and log-storm workflows using synthetic marker fixtures.
- Provides an opt-in lab that detects a real unhealthy disposable container service, uses demo or live inference, and restarts that exact service only after approval.
- Separately verifies genuine bounded ENOSPC and OOM behavior in disposable containers.
- Enforces idempotent intake, immutable proposal/action-digest approval, atomic SQLite state claims, execution expiry, and expire-and-retain semantics.
- Records sanitized state, model, approval, execution, retry, failure, and actor observations.
- Supports deterministic offline analysis and an optional generic OpenAI-compatible live-inference adapter.

## What it does not do

This is not production incident response. It does not inspect or remediate host or production processes and services, authenticate production webhooks, provide production identity or RBAC, execute model-generated commands, or offer autonomous remediation. Marker removal tests workflow, policy, approval, persistence, and audit behavior; only the explicitly enabled container-service lab performs a real restart, and only against the service it created and owns.

## Quickstart

Use a project virtual environment for every Python command:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m incident_response_agent.cli demo
```

The CLI demo uses a process-owned temporary sandbox and deterministic fake model. It does not require a bearer token, container engine, network, or API key.

For a real disposable-service recovery cycle, use a bearer token and a working Podman/Docker engine. The command displays the immutable proposal and waits for `approve` before restarting anything:

```bash
export INCIDENT_AGENT_BEARER_TOKEN='replace-with-a-local-random-token'
APP_MODE=demo EXECUTION_ENGINE=container \
  .venv/bin/python -m incident_response_agent.cli container-service-demo
```

Set `APP_MODE=live` to use the configured generic inference adapter in the same cycle. Live mode requires its API-key environment variable and never falls back to demo inference.

Run the offline suite:

```bash
.venv/bin/python -m pytest -m 'not integration and not live'
```

## Local API access

The HTTP API binds to `127.0.0.1` by default. All mutating endpoints require one environment-configured POC bearer token. With no token, mutations are disabled; loopback `GET /runs/{run_id}` inspection remains available. Non-loopback binding requires authentication for every endpoint.

```bash
export INCIDENT_AGENT_BEARER_TOKEN='replace-with-a-local-random-token'
HOST=127.0.0.1 EXECUTION_ENABLED=0 APP_MODE=demo \
  .venv/bin/python -m incident_response_agent.cli serve
```

Example local simulation:

```bash
curl -X POST http://127.0.0.1:8000/events \
  -H "Authorization: Bearer ${INCIDENT_AGENT_BEARER_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"idempotency_key":"demo-001","source":"local_simulation","observed_at":"2026-07-19T12:00:00Z","payload":{"scenario":"disk-exhaustion","summary":"synthetic fixture","log_lines":[],"context":[]}}'
```

This single bearer token is POC-level access control only. It provides no users, roles, identity federation, or separation between approval and execution authority. Tokens are accepted only through the `Authorization` header.

Remediation execution is disabled by default. Enabling it requires the bearer token and a Podman/Docker executor:

```bash
EXECUTION_ENABLED=1 EXECUTION_ENGINE=container \
  .venv/bin/python -m incident_response_agent.cli serve
```

The HTTP service never enables the filesystem executor. Runtime execution creates its own disposable sandbox and uses a digest-pinned, non-root, network-isolated, read-only container with CPU, memory, PID, temporary-filesystem, and timeout bounds.

To run the real service scenario through the same local HTTP endpoints, explicitly select the lab mode:

```bash
INCIDENT_AGENT_BEARER_TOKEN='replace-with-a-local-random-token' \
EXECUTION_ENABLED=1 LAB_MODE=container-service APP_MODE=demo \
  .venv/bin/python -m incident_response_agent.cli serve
```

In this mode the service creates one target container internally, waits for its bounded health check to report `unhealthy`, and accepts only the `restarting-service` scenario. Event intake, inference, proposal revision, approval, expiration, execution claim, and audit use the existing API and SQLite workflow. Neither the request nor the model can provide the target, image, mount, path, or command.

## Container failure lab

Initialize Podman once if needed, then run the integration suite:

```bash
podman machine init --rootful podman-machine-default
podman machine start podman-machine-default
RUN_CONTAINER_TESTS=1 .venv/bin/python -m pytest -m 'integration and not live'
```

Docker is used automatically when Podman is unavailable. The pinned multi-architecture image may be fetched by digest when absent. ENOSPC and OOM tests are genuine bounded `container_fault` checks but remain separate from the agent flow. The container-service integration is also `container_fault` evidence: a real service returns HTTP 503, becomes OCI-unhealthy, is restarted after approval, and becomes healthy. The other agent scenarios remain `synthetic_marker` fixtures.

## Generic live inference

The optional live test exercises the configured OpenAI-compatible chat-completions contract. It is not an OpenCode integration or general provider-compatibility claim.

```bash
RUN_LIVE_TESTS=1 .venv/bin/python -m pytest -m live
```

Defaults are base URL `https://opencode.ai/zen/go/v1`, model `deepseek-v4-flash`, and API-key environment variable `OPENCODE_KEY`. They remain configurable through `MODEL_BASE_URL`, `MODEL_NAME`, and `MODEL_API_KEY_ENV`. Live mode fails clearly when its key is absent and never falls back to fake inference.

The combined real-model/real-service cycle is separately opt-in:

```bash
RUN_CONTAINER_TESTS=1 RUN_LIVE_TESTS=1 .venv/bin/python -m pytest -m live
```

## Evidence level

Offline tests provide deterministic evidence for schemas, authentication, sanitization, idempotency, approval gates, atomic claims, expiration, scenario/action-kind compatibility, sandbox validation, persistence, and audit behavior. Container tests provide separately labeled evidence for bounded faults and one real disposable-service restart. Live model behavior is variable integration evidence, not deterministic test evidence. See `docs/evidence.md` and `SECURITY.md`.
