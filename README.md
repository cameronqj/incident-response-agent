# incident-response-agent

`incident-response-agent` is a bounded incident-response experiment. It receives an event, collects scoped synthetic evidence, produces a structured assessment and remediation proposal, waits for an explicit human decision, and executes only an allowlisted action inside a disposable sandbox.

## What it does

- Demonstrates failed log rotation leading to disk exhaustion, runaway CPU, a repeatedly restarting service, memory pressure/OOM, and a log storm.
- Enforces idempotent event intake and immutable proposal/action-hash approval.
- Supports explicit approve, reject, revise, expire, and execute transitions.
- Records sanitized state, model, approval, execution, retry, and failure observations.
- Runs offline with deterministic telemetry and analysis, or in `APP_MODE=live` with the configured OpenAI-compatible adapter.

## What it does not do

This is not production-safe autonomous remediation. It does not inspect the host, execute arbitrary model-generated commands, use privileged containers, route among models, or provide a production incident-management platform.

## Quickstart

Use the project virtual environment for all Python commands:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m incident_response_agent.cli demo
```

The demo uses no network or API key. It creates a disposable synthetic rotated log, displays the proposal, approves the exact proposal revision/action hash, and executes the fixed cleanup action.

Live mode defaults to a container-backed executor, preferring Podman and falling back to Docker. It uses a non-root, network-isolated, read-only container with only the bounded disposable sandbox mounted read-write. Demo mode defaults to the filesystem executor so the offline demo remains independent of a container engine. Override this with `EXECUTION_ENGINE=filesystem|container|podman|docker`.

Run the offline suite:

```bash
.venv/bin/python -m pytest
```

Run the required container failure-lab check when Podman is available:

```bash
podman machine init --rootful podman-machine-default
podman machine start podman-machine-default
RUN_CONTAINER_TESTS=1 .venv/bin/python -m pytest
```

The integration test uses a non-root, network-isolated container with a bounded tmpfs, forces `ENOSPC`, and verifies rotated-artifact recovery. When `RUN_CONTAINER_TESTS=1` is set, an unavailable engine is a test failure rather than a skip.

The live cycle is opt-in because it calls the external model and may consume provider quota:

```bash
RUN_LIVE_TESTS=1 .venv/bin/python -m pytest -m live
```

Run the service in demo mode:

```bash
APP_MODE=demo .venv/bin/uvicorn incident_response_agent.app:app --reload
```

Run the live adapter explicitly. The local `.env` is gitignored and is loaded without printing its contents:

```bash
APP_MODE=live .venv/bin/uvicorn incident_response_agent.app:app
```

Live inference defaults are `https://opencode.ai/zen/go/v1`, model `deepseek-v4-flash`, and key environment variable `OPENCODE_KEY`. They can be changed with `MODEL_BASE_URL`, `MODEL_NAME`, and `MODEL_API_KEY_ENV`. Live mode fails clearly when the configured key is absent; it never silently switches to fake inference.

## Evidence level

The offline suite is evidence for workflow, schema, idempotency, approval gating, expiration, action binding, audit redaction, and deterministic CPU/service/memory/log-storm/ENOSPC fixtures. Container integration is separately labeled and requires a working Podman or Docker engine. No claim of production safety or model reliability is made.
