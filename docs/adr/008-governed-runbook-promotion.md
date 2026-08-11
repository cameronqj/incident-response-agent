# ADR 008: Governed Runbook Promotion and Retrieval

- Status: accepted
- Date: 2026-08-11

## Decision

Add a discrete runbook-learning lifecycle beside the existing incident workflow. A Deep Agent may investigate an unfamiliar disposable incident through typed, read-only diagnostic tools and propose structured diagnostic knowledge. The application persists the candidate and its digest, but only an application-owned reviewer may reject it, revise it, or approve it for a deterministic hidden-case gate. Passing revisions become versioned promoted records; approval alone does not promote a failing candidate.

A later fresh Deep Agent can discover promoted knowledge only through `search_approved_runbooks` and can read a returned version only through `open_approved_runbook`. Search excludes every candidate lifecycle state and returns only digest-verified promoted records. Open is thread-scoped to versions returned by that thread's search. The final structured diagnosis must reproduce the exact opened ID, version, and digest for the application to accept its citation.

LangSmith records separate before- and after-promotion experiments over the same synthetic incident. Deterministic evaluators compare diagnosis, required evidence, distractor avoidance, diagnostic coverage, and exact runbook citation; summaries also retain tool trajectories, latency, and tokens. Review remains application-owned rather than a Studio approval dependency.

## Rationale

This separates generated knowledge from trusted knowledge and keeps diagnostic guidance separate from executable authority. The lifecycle demonstrates a bounded learning mechanism without allowing model output to mutate the remediation whitelist. Exact version citations make later use inspectable, while the before/after experiment exposes both trajectory changes and their cost.

## Consequences

The current evidence proves that a later agent can find, open, and exactly cite reviewed knowledge. It does not prove that the runbook improved an already-correct diagnosis or that retrieval caused a behavioral improvement. The one-case live comparison added an open call, latency, and tokens while diagnosis-quality scores remained unchanged.

The reviewer, incident, and promotion cases are simulated POC components. SHA-256 detects content corruption when the stored digest is unchanged, but the SQLite registry is not an adversarial integrity boundary. Promoting a runbook grants no shell access, remediation action, or capability. A complete scripted orchestration test covers before investigation, research, revision, promotion, and the fresh cited investigation without relying on live inference or LangSmith retention.
