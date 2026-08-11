# ADR 007: LangSmith Reflection Evaluation

- Status: accepted
- Date: 2026-08-11

## Decision

Add a discrete `reflection-eval` mode rather than changing the approval workflow or the default investigator. A versioned LangSmith dataset contains five synthetic site-health cases with hidden reference diagnoses, actions, causal evidence, distractors, required diagnostic tools, and a maximum tool budget. Both targets receive the same generic alert and typed read-only observations.

The direct target runs one bounded Deep Agent investigation. The reflective target runs the same investigation, one tool-less structured critic over already observed evidence, and at most one tool-less structured revision. The critic classifies each cited observation under a causal-citation rubric; application code derives whether revision is required. Incomplete provider classifications conservatively retain evidence instead of failing or silently treating it as unsupported. Neither critic nor reviser receives LangSmith reference outputs.

LangSmith records the dataset, experiment runs, model/tool traces, and six deterministic code evaluators: diagnosis correctness, action correctness, evidence precision, distractor rejection, required-tool coverage, and tool-budget compliance. Evaluation requests use a 120-second minimum request timeout and three retries because observed provider latency exceeded the normal interactive timeout; this does not alter application runtime defaults.

## Rationale

A separate mode makes the comparison reproducible without turning every incident into a slower multi-pass workflow. The bounded cycle demonstrates LangSmith datasets and experiments, LangChain structured output, Deep Agents tool trajectories, and an evaluator-guided prompt iteration while retaining deterministic authority at the action boundary.

## Consequences

The five cases are project fixtures, not an industry benchmark. A single repetition can demonstrate wiring and expose regressions but cannot establish statistical improvement. The critic adds model calls, latency, and cost, and it improves citation selection rather than adding new observations or self-modifying code. Prompt revisions remain developer-reviewed and versioned; the agent does not rewrite or deploy its own prompt. Failed and flat experiments remain part of the evidence chronology.
