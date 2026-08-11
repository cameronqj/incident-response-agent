# ADR 006: Deep Agent Site Investigation

- Status: accepted
- Date: 2026-08-10

## Decision

Add a separate `site-unhealthy` investigation path using the Deep Agents SDK. Existing scenario-specific events remain supported as deterministic, pre-triaged control-plane demonstrations. The new path receives only a generic health-check failure, uses typed read-only diagnostics against one owned disposable site, and returns a structured diagnosis before entering the existing proposal, approval, and execution workflow.

The lab retains the injected scenario as test-only ground truth. It is not included in agent messages, filesystem state, tool descriptions, or diagnostic results. The first slice injects synthetic failed log rotation and disk pressure. The agent can inspect bounded health, resource, service, process, and log observations. It has a thread-scoped `StateBackend` and two configured focused subagent profiles, but the first provider-compatible slice hides delegation along with filesystem and shell tools at the model boundary. This prevents nested-agent loops while retaining a narrow, testable Deep Agents harness.

Deep Agents owns model/tool orchestration, context management, structured output, and checkpointing. Delegation profiles are defined but not exposed in this first live slice because the configured model repeatedly delegated or browsed irrelevant virtual files instead of terminating. Deterministic code remains authoritative for evidence-reference validation, scenario/action compatibility, immutable proposals, approval hashes, execution claims, targets, side effects, and recovery verification. The existing hash-bound application approval is retained instead of duplicating it with generic tool-call approval.

The configured OpenAI-compatible model must support tool calling. Offline tests use a scripted chat model; live compatibility is separately marked and opt-in. Existing OpenTelemetry spans and metrics remain canonical. Agent telemetry exports only controlled tool names, result labels, counts, and durations; raw prompts, messages, observations, runbooks, scratch files, and model text are excluded. SQLite remains the durable audit source.

## Rationale

The original scenarios begin after an incident category is known. They demonstrate bounded remediation safely, but they do not require the agent to discover why a site is unhealthy. A generic alert makes planning, diagnostic tool use, context isolation, and delegation functionally relevant while preserving the mature control-plane invariants.

Capability-scoped diagnostic tools are used for the first slice instead of a sandbox shell. This keeps outputs portable, bounded, auditable, and independent of host utilities. An isolated shell-backed lab may be evaluated later as a separate boundary expansion.

## Consequences

The disk lab is synthetic and does not prove real-host diagnosis. Live model conclusions remain variable. The Deep Agent cannot remediate directly and cannot access arbitrary files, processes, containers, networks, or commands. Adding new fault types requires observable fixtures, diagnostic evidence, hidden-ground-truth tests, deterministic policy compatibility, and updated evidence claims.
