# ADR 009: Governed Capability Registry and One-Target Activation

- Status: accepted
- Date: 2026-08-12

## Decision

Add a discrete capability lifecycle beside the runbook lifecycle (ADR 008). A Deep Agent may investigate an unfamiliar disposable worker incident through typed read-only diagnostic tools and propose a structured capability contract that defines parameters, allowed targets, prerequisites, required evidence, a maximum blast radius, an approval policy, idempotency, a bounded timeout, verification steps, and rollback steps. The application persists the candidate and its digest, but only an application-owned reviewer may reject it, revise it, or approve it for a deterministic hidden-case gate that also checks policy bounds (timeout ceiling, parameter bounds, single-owned-target blast radius, verification and rollback presence, confidence floor). Passing revisions become versioned promoted records; approval alone does not promote a failing candidate.

Promotion changes only the capability registry. It grants no execution authority: activating a capability still requires the existing immutable remediation proposal, a hash-bound human approval, and the application-owned executor, exactly as every existing remediation action does. The `reduce_worker_concurrency` capability is the first promoted capability.

Promotion is technically bound to execution. The immutable remediation proposal carries a `CapabilityBinding` — the promoted capability id, version, and content digest — alongside the complete concrete contract: the executed parameter set, the owned target id, and the target-class authorization. These are chosen by application code at proposal construction and bound into the existing action hash, so approval covers the exact promoted record and the exact parameters, and the model never supplies a command, path, target, or runtime value. At execution the trusted executor revalidates the binding against the capability registry: the record must still exist at that exact version with that exact digest, the executed parameter set must match the promoted parameter schema and bounds, and the target class must be authorized. A stale, tampered, or unpromoted record, a mismatched parameter set, or an unauthorized target fails closed before any side effect. `allowed_targets` is a target-class contract (`owned_disposable_worker`) enforced at execution, not an evidence reference.

Activation runs against one owned disposable worker lab (synthetic-marker evidence kind only) and is followed by deterministic health verification. A failed verification triggers bounded rollback to the previous concurrency value and records an auditable activation outcome. The capability registry and the runbook registry remain separate: promoting a runbook never grants an action, and promoting a capability never grants diagnostic knowledge retrieval.

## Evidence-scope enforcement

The `required_evidence_categories` of a promoted capability are a deterministic boundary, not a suggestion. In the application evals, when an agent has opened a promoted capability, application code rejects any final diagnosis that cites an evidence category outside the promoted required set. The `evidence_scope` directive in the opened-tool output and the system prompt steer the model; the application validation makes out-of-scope citations a hard failure. The runbook loop applies the identical deterministic rule.

## Contract-violation salvage

When a live researcher's proposal violates the observed-evidence contract, the application first attempts `contract_violation_revision`: it strips the unobserved prerequisites, categories, and evidence refs from the model's own proposal and submits that salvaged proposal to the review gate. Only when the model proposal cannot be salvaged (too few remaining signals) does the application substitute the reference contract (`reviewer_corrected_capability_proposal`). This keeps review continuity model-derived rather than a hardcoded replacement, and the demo reports which path was taken.

## Rationale

This is the roadmap's follow-on capability POC: it grows action authority the controlled way. The typed capability contract, separate registry, review gate, and one-target activation with rollback keep model output advisory and deterministic application code authoritative, while demonstrating the decision-side autonomy the runbook loop intentionally stopped short of. Reusing the existing immutable proposal and hash-bound approval means no new execution boundary exists; only the executor and the parameter provider are new.

## Consequences

The current evidence proves one governed capability promotion, one one-target activation with rollback on a synthetic lab, deterministic binding revalidation at execution, and deterministic evidence-scope enforcement in the application evals. It does not prove fleet-wide safety, production capability activation, or that the promoted capability improved an already-correct diagnosis. The reviewer, promotion cases, and activation target are simulated POC components. SHA-256 detects content corruption when the stored digest is unchanged, but the SQLite registry is not an adversarial integrity boundary. The capability is synthetic-marker only; a containerized worker variant and SREGym integration are explicitly deferred and would require their own scenario/evidence-kind binding. The option binding provider is optional in `IncidentService`; services that do not set it behave exactly as before and cannot construct parameterized or capability-bound actions.
