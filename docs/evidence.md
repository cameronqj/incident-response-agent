# Verification evidence

- Date: 2026-07-19
- Scope: bounded local POC
- Python: 3.12 project virtual environment

## Reproducible checks

| Evidence | Command | Result | Scenario kind |
| --- | --- | --- | --- |
| Offline workflow, security, persistence, and concurrency | `.venv/bin/python -m pytest -m 'not integration and not live'` | 76 passed | `synthetic_marker` |
| Podman/Docker failure lab and remediation container | `RUN_CONTAINER_TESTS=1 .venv/bin/python -m pytest -m integration` | 11 passed | `container_fault` and `synthetic_marker` |
| Generic OpenAI-compatible inference | `RUN_LIVE_TESTS=1 .venv/bin/python -m pytest -m live` | 1 passed | live integration |

The ENOSPC and OOM failure-lab checks are genuine bounded container faults. CPU, service, memory, disk-remediation, and log-storm agent workflows use marker files and prove workflow, policy, approval, execution, persistence, and audit behavior only.

## Live-inference observation

- Endpoint label: `configured-openai-compatible-chat-completions`
- Configured endpoint: `https://opencode.ai/zen/go/v1`
- Model: `deepseek-v4-flash`
- Real external model: yes
- Successful run: 4,722 ms, 988 tokens, 0 retries
- Observed variability: an earlier run passed; a subsequent run failed after three bounded attempts returned empty content; the final verification passed without retry after increasing the bounded response allowance.

This proves one configured OpenAI-compatible request/assessment/approval/container-execution cycle. It does not prove provider reliability, general compatibility, deterministic model behavior, production webhook handling, real-host detection, or production remediation safety.
