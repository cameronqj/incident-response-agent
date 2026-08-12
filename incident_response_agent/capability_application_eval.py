from __future__ import annotations

import time
from dataclasses import replace
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid4, uuid5

from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends import StateBackend
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.checkpoint.memory import InMemorySaver
from langsmith import Client
from langsmith.schemas import Example
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .capability_learning import (
    CapabilityCitation,
    CapabilityKnowledgeTrace,
    CapabilityRegistry,
    CapabilityReviewDecision,
    ConcurrencyWorkerLab,
    DeterministicCapabilityEvaluator,
    PromotedCapability,
    build_capability_tools,
    create_capability_research_agent,
    research_capability_with_recovery,
    reviewer_corrected_capability_proposal,
    simulated_reviewer_revision,
)
from .config import Settings
from .runbook_application_eval import _trace_usage
from .site_investigation import InvestigationTrace, build_diagnostic_tools, create_live_investigation_model


DATASET_NAME = "incident-response-agent-capability-application-v1"
BEFORE_EXPERIMENT = "capability-before-learning-v1"
AFTER_EXPERIMENT = "capability-after-learning-v1"


class CapabilityAwareDiagnosis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    primary_resource: Literal["memory", "cpu", "filesystem", "service", "unknown"]
    trigger: Literal["worker_concurrency_increase", "deployment", "memory_leak", "unknown"]
    summary: str = Field(min_length=10, max_length=1000)
    confidence: float = Field(ge=0, le=1)
    evidence_refs: list[str] = Field(min_length=2, max_length=12)
    conclusion: str = Field(min_length=10, max_length=1000)
    proposed_capability_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    applied_capability_id: str | None = Field(default=None, max_length=128)
    applied_capability_version: int | None = Field(default=None, ge=1)
    applied_capability_digest: str | None = Field(default=None, min_length=64, max_length=64)

    @model_validator(mode="after")
    def citation_fields_are_all_present_or_absent(self) -> "CapabilityAwareDiagnosis":
        values = (self.applied_capability_id, self.applied_capability_version, self.applied_capability_digest)
        if any(value is not None for value in values) and not all(value is not None for value in values):
            raise ValueError("applied capability citation fields must be all present or all absent")
        return self

    def citation(self) -> CapabilityCitation | None:
        if self.applied_capability_id is None:
            return None
        return CapabilityCitation(
            capability_id=self.applied_capability_id,
            version=self.applied_capability_version,
            content_digest=self.applied_capability_digest,
        )


CAPABILITY_AWARE_PROMPT = """Investigate one unfamiliar failure affecting an owned disposable worker service. Gather health, resource, recent-change, and bounded-log evidence before concluding. After gathering evidence, call search_approved_capabilities. If it returns a candidate, open the best matching version with open_approved_capability and apply its safety contract to shape your proposed capability. When you have opened a capability, its required_evidence_categories define the evidence scope: cite only observations whose category is in that required set, and do not cite observations outside it — a generic health status or other symptom is not part of the supported mechanism. Cite only observations that support the causal explanation; do not cite generic symptoms or normal-state observations merely used to reject alternatives. Return a structured diagnosis. primary_resource and trigger must describe the supported mechanism. proposed_capability_id must be the capability you would propose for one bounded remediation. If you opened a capability, copy its citation into the three flat fields applied_capability_id, applied_capability_version, and applied_capability_digest. If no promoted capability matched, leave all three fields null. Capabilities are governed contracts; they grant no execution authority without a hash-bound human approval."""


def create_capability_aware_agent(
    model: BaseChatModel,
    target: ConcurrencyWorkerLab,
    registry: CapabilityRegistry,
    investigation_trace: InvestigationTrace,
    knowledge_trace: CapabilityKnowledgeTrace,
):
    return create_deep_agent(
        model=model,
        tools=[
            *build_diagnostic_tools(target, investigation_trace),
            *build_capability_tools(registry, investigation_trace, knowledge_trace),
        ],
        system_prompt=CAPABILITY_AWARE_PROMPT,
        response_format=CapabilityAwareDiagnosis,
        backend=StateBackend(),
        permissions=[FilesystemPermission(operations=["read", "write"], paths=["/**"], mode="deny")],
        checkpointer=InMemorySaver(),
    )


def _required_categories_for(registry: CapabilityRegistry, citation) -> set[str] | None:
    try:
        capability = registry.get_promoted(citation.capability_id, citation.version)
    except KeyError:
        return None
    return set(capability.proposal.required_evidence_categories)


def investigate_with_capabilities(
    agent,
    registry: CapabilityRegistry,
    investigation_trace: InvestigationTrace,
    knowledge_trace: CapabilityKnowledgeTrace,
    thread_id: str,
    *,
    require_capability: bool,
) -> dict[str, Any]:
    started = time.monotonic()
    output = agent.invoke(
        {"messages": [{"role": "user", "content": "The owned disposable worker service has an unfamiliar recurring failure. Diagnose the mechanism and propose one bounded capability using approved evidence and knowledge."}]},
        config={"configurable": {"thread_id": thread_id}, "recursion_limit": 18},
    )
    diagnosis = CapabilityAwareDiagnosis.model_validate(output["structured_response"])
    observations = investigation_trace.observations_for(thread_id)
    if set(diagnosis.evidence_refs) - set(observations):
        raise ValueError("diagnosis cited evidence that was not observed")
    opened = knowledge_trace.opened_for(thread_id)
    if opened:
        required_categories = set()
        for citation in opened:
            categories = _required_categories_for(registry, citation)
            if categories is not None:
                required_categories |= categories
        if required_categories:
            cited_categories = {observations[ref].category for ref in diagnosis.evidence_refs if ref in observations}
            out_of_scope = cited_categories - required_categories
            if out_of_scope:
                raise ValueError(f"diagnosis cited evidence outside the promoted capability scope: {sorted(out_of_scope)}")
    citation = diagnosis.citation()
    citation_valid = citation is None and not opened
    if citation is not None:
        citation_valid = citation in opened and citation.capability_id == diagnosis.proposed_capability_id
    if require_capability and (not opened or citation is None):
        raise ValueError("learned investigation must open and cite a promoted capability")
    if not citation_valid:
        raise ValueError("diagnosis capability citation was not opened in this investigation")
    diagnostic_calls = investigation_trace.tool_calls_for(thread_id)
    capability_calls = knowledge_trace.tool_calls_for(thread_id)
    return {
        **diagnosis.model_dump(mode="json"),
        "capability_citation": citation.model_dump(mode="json") if citation else None,
        "diagnostic_tool_calls": diagnostic_calls,
        "capability_tool_calls": capability_calls,
        "tool_calls": [*diagnostic_calls, *capability_calls],
        "capability_citation_valid": citation_valid,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def diagnosis_correct(inputs: dict, outputs: dict, reference_outputs: dict) -> bool:
    del inputs
    return outputs.get("primary_resource") == reference_outputs["expected_resource"] and outputs.get("trigger") == reference_outputs["expected_trigger"]


def required_evidence_recall(inputs: dict, outputs: dict, reference_outputs: dict) -> float:
    del inputs
    cited = set(outputs.get("evidence_refs") or [])
    required = set(reference_outputs["required_evidence"])
    return len(cited & required) / len(required)


def distractor_avoidance(inputs: dict, outputs: dict, reference_outputs: dict) -> bool:
    del inputs
    cited = outputs.get("evidence_refs")
    return cited is not None and not bool(set(cited) & set(reference_outputs["distractor_evidence"]))


def required_diagnostic_coverage(inputs: dict, outputs: dict, reference_outputs: dict) -> float:
    del inputs
    called = set(outputs.get("diagnostic_tool_calls") or [])
    required = set(reference_outputs["required_diagnostics"])
    return len(called & required) / len(required)


def capability_correct(inputs: dict, outputs: dict, reference_outputs: dict) -> bool:
    del inputs
    return outputs.get("proposed_capability_id") == reference_outputs["expected_capability"]


def explicit_capability_citation(inputs: dict, outputs: dict, reference_outputs: dict) -> bool:
    del inputs, reference_outputs
    return bool(outputs.get("capability_citation")) and outputs.get("capability_citation_valid") is True and "open_approved_capability" in (outputs.get("capability_tool_calls") or [])


EVALUATORS = [diagnosis_correct, required_evidence_recall, distractor_avoidance, required_diagnostic_coverage, capability_correct, explicit_capability_citation]


REFERENCE_OUTPUT = {
    "expected_resource": "memory",
    "expected_trigger": "worker_concurrency_increase",
    "required_evidence": ["resources-1", "changes-1", "logs-1"],
    "distractor_evidence": ["health-1"],
    "required_diagnostics": ["check_site_health", "inspect_resources", "inspect_recent_changes", "inspect_recent_logs"],
    "expected_capability": "reduce_worker_concurrency",
}


def ensure_dataset(client: Client) -> str:
    if not client.has_dataset(dataset_name=DATASET_NAME):
        client.create_dataset(
            DATASET_NAME,
            description="One synthetic unfamiliar incident evaluated before and after governed capability promotion.",
            metadata={"project": "incident-response-agent", "evidence_kind": "synthetic_marker", "version": 1},
        )
    example_id = uuid5(NAMESPACE_URL, f"{DATASET_NAME}:worker-memory-pressure")
    expected_inputs = {"case_id": "worker-memory-pressure", "alert": "An owned disposable worker service has an unfamiliar recurring failure."}
    expected_outputs = REFERENCE_OUTPUT
    existing = {str(example.id): example for example in client.list_examples(dataset_name=DATASET_NAME)}
    current = existing.get(str(example_id))
    if current is None:
        client.create_examples(dataset_name=DATASET_NAME, examples=[{
            "id": example_id,
            "inputs": expected_inputs,
            "outputs": expected_outputs,
            "metadata": {"scenario_kind": "synthetic_marker"},
        }])
    elif current.inputs != expected_inputs or current.outputs != expected_outputs:
        raise ValueError("LangSmith capability-application dataset does not match the local version")
    return DATASET_NAME


def _local_dataset() -> list[Example]:
    return [Example(
        id=uuid5(NAMESPACE_URL, f"local:{DATASET_NAME}:worker-memory-pressure"),
        inputs={"case_id": "worker-memory-pressure"},
        outputs=REFERENCE_OUTPUT,
        metadata={"scenario_kind": "synthetic_marker"},
    )]


def summarize_experiment(results, client: Client, *, include_remote_usage: bool) -> dict[str, Any]:
    rows = list(results)
    cases: list[dict[str, Any]] = []
    score_values: dict[str, list[float]] = {evaluator.__name__: [] for evaluator in EVALUATORS}
    for row in rows:
        scores = {key: 0.0 for key in score_values}
        for evaluation in row["evaluation_results"]["results"]:
            scores[evaluation.key] = evaluation.score
        for key, score in scores.items():
            score_values[key].append(float(score) if isinstance(score, (int, float)) else 0.0)
        outputs = row["run"].outputs or {}
        usage = _trace_usage(client, row["run"]) if include_remote_usage else {
            "latency_ms": outputs.get("duration_ms"),
            "total_tokens": getattr(row["run"], "total_tokens", None),
            "total_cost": getattr(row["run"], "total_cost", None),
        }
        if usage["latency_ms"] is None:
            usage["latency_ms"] = outputs.get("duration_ms")
        cases.append({
            "case_id": (row["example"].inputs or {}).get("case_id"),
            "error": row["run"].error,
            "diagnosis": {"primary_resource": outputs.get("primary_resource"), "trigger": outputs.get("trigger")},
            "evidence_refs": outputs.get("evidence_refs"),
            "tool_calls": outputs.get("tool_calls"),
            "capability_citation": outputs.get("capability_citation"),
            "usage": usage,
            "scores": scores,
        })
    def _experiment_metadata(results) -> dict[str, Any]:
        """Return experiment metadata when a remote experiment exists (upload mode)."""
        name = getattr(results, "experiment_name", None)
        experiment_id = None
        try:
            experiment_id = str(results.experiment_id)
        except (AttributeError, ValueError):
            pass
        url = None
        try:
            url = getattr(results, "url", None)
        except ValueError:
            pass
        return {"experiment_name": name, "experiment_id": experiment_id, "url": url}

    return {
        **_experiment_metadata(results),
        "averages": {key: sum(values) / len(values) for key, values in score_values.items()},
        "cases": cases,
    }


def run_capability_application_evaluation(settings: Settings, *, upload_results: bool = True) -> dict[str, Any]:
    client = Client()
    data = ensure_dataset(client) if upload_results else _local_dataset()
    evaluation_settings = replace(
        settings,
        model_timeout_seconds=max(settings.model_timeout_seconds, 120.0),
        model_max_retries=max(settings.model_max_retries, 3),
    )
    baseline_registry = CapabilityRegistry(":memory:")
    learned_registry = CapabilityRegistry(":memory:")

    def target(registry: CapabilityRegistry, *, require_capability: bool):
        def invoke(inputs: dict) -> dict[str, Any]:
            del inputs
            investigation_trace = InvestigationTrace()
            knowledge_trace = CapabilityKnowledgeTrace()
            model = create_live_investigation_model(evaluation_settings)
            thread_id = f"capability-application-{uuid4().hex}"
            return investigate_with_capabilities(
                create_capability_aware_agent(model, ConcurrencyWorkerLab(), registry, investigation_trace, knowledge_trace),
                registry,
                investigation_trace,
                knowledge_trace,
                thread_id,
                require_capability=require_capability,
            )
        return invoke

    common = {
        "data": data,
        "evaluators": EVALUATORS,
        "max_concurrency": 1,
        "upload_results": upload_results,
        "error_handling": "log",
    }
    try:
        before_results = client.evaluate(
            target(baseline_registry, require_capability=False),
            experiment_prefix=BEFORE_EXPERIMENT,
            description="Unfamiliar incident with an empty approved-capability registry.",
            metadata={"phase": "before-learning", "model": settings.deep_agent_model},
            **common,
        )
        before = summarize_experiment(before_results, client, include_remote_usage=upload_results)

        research_trace = InvestigationTrace()
        research_model = create_live_investigation_model(evaluation_settings)
        try:
            proposal, recovered = research_capability_with_recovery(
                create_capability_research_agent(research_model, ConcurrencyWorkerLab(), research_trace),
                research_trace,
                f"capability-promotion-{uuid4().hex}",
            )
        except Exception as exc:
            # The model could not produce a valid structured proposal at all.
            proposal = reviewer_corrected_capability_proposal()
            recovered = True
        original = learned_registry.submit(proposal)
        revision = learned_registry.revise(
            original.candidate_id,
            simulated_reviewer_revision(proposal),
            actor="simulated-sre-reviewer",
            note="Remove generic symptoms and normal-state context from the reusable capability prerequisites.",
        )
        promoted = learned_registry.review(
            revision.candidate_id,
            CapabilityReviewDecision.APPROVE,
            actor="simulated-sre-reviewer",
            evaluator=DeterministicCapabilityEvaluator(),
            note="Approve the reviewed revision for hidden evaluation.",
        )
        if not isinstance(promoted, PromotedCapability):
            raise ValueError("reviewed capability failed the promotion gate")

        after_results = client.evaluate(
            target(learned_registry, require_capability=True),
            experiment_prefix=AFTER_EXPERIMENT,
            description="Fresh incident with search, open, and exact citation of one reviewed, evaluated, promoted capability.",
            metadata={"phase": "after-learning", "model": settings.deep_agent_model, "capability_version": promoted.version},
            **common,
        )
        after = summarize_experiment(after_results, client, include_remote_usage=upload_results)
        metrics = sorted(set(before["averages"]) | set(after["averages"]))
        return {
            "dataset": DATASET_NAME if upload_results else "local-iterator",
            "promotion": {
                "original_candidate_id": original.candidate_id,
                "revised_candidate_id": revision.candidate_id,
                "capability_id": promoted.capability_id,
                "version": promoted.version,
                "researcher_contract_violation": recovered,
                "evaluation": promoted.evaluation.model_dump(mode="json"),
            },
            "before": before,
            "after": after,
            "after_minus_before": {
                metric: after["averages"].get(metric, 0.0) - before["averages"].get(metric, 0.0)
                for metric in metrics
            },
        }
    finally:
        baseline_registry.close()
        learned_registry.close()
