#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_EXECUTABLE="${PYTHON_EXECUTABLE:-python3.12}"

cd "$REPOSITORY_ROOT"

if ! command -v "$PYTHON_EXECUTABLE" >/dev/null 2>&1; then
  echo "Python 3.12 is required; set PYTHON_EXECUTABLE to its executable." >&2
  exit 1
fi

if [[ ! -x .venv/bin/python ]]; then
  "$PYTHON_EXECUTABLE" -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m incident_response_agent.cli init-db --database-path .data/incident-response.sqlite3
.venv/bin/python -m pytest -m 'not integration and not live'
