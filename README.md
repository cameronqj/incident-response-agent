# incident-response-agent

`incident-response-agent` is a bounded incident-response experiment. It receives a local simulated event, collects synthetic evidence, produces a structured remediation proposal, waits for an explicit human decision, and executes only a scenario-compatible allowlisted action inside a disposable sandbox.

## What it does

- Demonstrates disk exhaustion, CPU pressure, memory pressure, restart-loop, and log-storm workflows using synthetic marker fixtures.
- Separately verifies genuine bounded ENOSPC and OOM behavior in disposable containers.
- Enforces idempotent intake, immutable proposal/action-digest approval, atomic SQLite state claims, execution expiry, and expire-and-retain semantics.
- Records sanitized state, model, approval, execution, retry, failure, and actor observations.
- Supports deterministic offline analysis and an optional generic OpenAI-compatible live-inference adapter.

## What it does not do

This is not production incident response. It does not inspect or remediate real host processes or services, authenticate production webhooks, provide production identity or RBAC, execute model-generated commands, or offer autonomous remediation. Marker removal tests workflow, policy, approval, persistence, and audit behavior; it is not evidence of real process or service recovery.

## Quickstart

Use a project virtual environment for every Python command:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m incident_response_agent.cli demo
```

The CLI demo uses a process-owned temporary sandbox and deterministic fake model. It does not require a bearer token, container engine, network, or API key.

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

## Container failure lab

Initialize Podman once if needed, then run the integration suite:

```bash
podman machine init --rootful podman-machine-default
podman machine start podman-machine-default
RUN_CONTAINER_TESTS=1 .venv/bin/python -m pytest -m integration
```

Docker is used automatically when Podman is unavailable. The pinned multi-architecture image may be fetched by digest when absent. ENOSPC and OOM tests are genuine bounded `container_fault` checks. The agent workflow scenarios remain `synthetic_marker` fixtures.

## Generic live inference

The optional live test exercises the configured OpenAI-compatible chat-completions contract. It is not an OpenCode integration or general provider-compatibility claim.

```bash
RUN_LIVE_TESTS=1 .venv/bin/python -m pytest -m live
```

Defaults are base URL `https://opencode.ai/zen/go/v1`, model `deepseek-v4-flash`, and API-key environment variable `OPENCODE_KEY`. They remain configurable through `MODEL_BASE_URL`, `MODEL_NAME`, and `MODEL_API_KEY_ENV`. Live mode fails clearly when its key is absent and never falls back to fake inference.

## Evidence level

Offline tests provide deterministic evidence for schemas, authentication, sanitization, idempotency, approval gates, atomic claims, expiration, scenario/action compatibility, sandbox validation, persistence, and audit behavior. Container tests provide separately labeled integration evidence. Live model behavior is variable integration evidence, not deterministic test evidence. See `docs/evidence.md` and `SECURITY.md`.
