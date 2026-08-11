#!/bin/sh
set -eu

export LANGSMITH_TRACING="${LANGSMITH_TRACING:-false}"
export LANGGRAPH_CLI_NO_ANALYTICS=1
export PYTHONPATH="${PWD}${PYTHONPATH:+:${PYTHONPATH}}"

exec uvx \
  --from 'langgraph-cli[inmem]>=0.4,<1' \
  --with 'deepagents>=0.7.5,<0.8' \
  --with 'langchain-openai>=1.4.3,<2' \
  --with 'fastapi>=0.115,<1' \
  --with 'opentelemetry-instrumentation-fastapi>=0.58b0,<0.59' \
  langgraph dev "$@"
