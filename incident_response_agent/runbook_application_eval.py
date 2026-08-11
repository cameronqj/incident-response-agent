from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid4, uuid5

from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends import StateBackend
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.tools import StructuredTool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.config import get_config
from langsmith import Client
from langsmith.schemas import Example
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings
from .runbook_learning import (
    DeterministicRunbookEvaluator,
    PromotedRunbook,
    RunbookRegistry,
    RunbookReviewDecision,
    WorkerMemoryPressureLab,
    create_runbook_research_agent,
    research_runbook,
    simulated_reviewer_revision,
)
from .site_investigation import InvestigationTrace, SiteDiagnosticTarget, build_diagnostic_tools, create_live_investigation_model


DATASET_NAME = "incident-response-agent-runbook-application-v1"
BEFORE_EXPERIMENT = "runbook-before-learning-v1"
AFTER_EXPERIMENT = "runbook-after-learning-v1"


class RunbookCitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    runbook_id: str = Field(min_length=3, max_length=128)
    version: int = Field(ge=1)
    content_digest: str = Field(min_length=64, max_length=64)


class RunbookAwareDiagnosis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    primary_resource: Literal["memory", "cpu", "filesystem", "service", "unknown"]
    trigger: Literal["worker_concurrency_increase", "deployment", "memory_leak", "unknown"]
    summary: str = Field(min_length=10, max_length=1000)
    confidence: float = Field(ge=0, le=1)
    evidence_refs: list[str] = Field(min_length=2, max_length=12)
    conclusion: str = Field(min_length=10, max_length=1000)
    runbook_citation: RunbookCitation | None = None


@dataclass
class RunbookKnowledgeTrace:
    _search_results: dict[str, list[tuple[str, int]]] = field(default_factory=dict, repr=False)
    _opened: dict[str, list[RunbookCitation]] = field(default_factory=dict, repr=False)
    _tool_calls: dict[str, list[str]] = field(default_factory=dict, repr=False)
    _lock: RLock = field(default_factory=RLock, repr=False)

    def record_search(self, thread_id: str, matches: list[PromotedRunbook]) -> None:
        with self._lock:
            self._search_results[thread_id] = [(match.runbook_id, match.version) for match in matches]
            self._tool_calls.setdefault(thread_id, []).append("search_approved_runbooks")

    def may_open(self, thread_id: str, runbook_id: str, version: int) -> bool:
        with self._lock:
            return (runbook_id, version) in self._search_results.get(thread_id, [])

    def record_open(self, thread_id: str, runbook: PromotedRunbook) -> RunbookCitation:
        citation = RunbookCitation(
            runbook_id=runbook.runbook_id,
            version=runbook.version,
            content_digest=runbook.content_digest,
        )
        with self._lock:
            self._opened.setdefault(thread_id, []).append(citation)
            self._tool_calls.setdefault(thread_id, []).append("open_approved_runbook")
        return citation

    def opened_for(self, thread_id: str) -> list[RunbookCitation]:
        with self._lock:
            return list(self._opened.get(thread_id, []))

    def tool_calls_for(self, thread_id: str) -> list[str]:
        with self._lock:
            return list(self._tool_calls.get(thread_id, []))


def build_runbook_tools(
    registry: RunbookRegistry,
    investigation_trace: InvestigationTrace,
    knowledge_trace: RunbookKnowledgeTrace,
) -> list[StructuredTool]:
    def search_approved_runbooks() -> str:
        """Search only promoted runbooks using signals already observed in this investigation."""
        thread_id = str(get_config().get("configurable", {}).get("thread_id", "unscoped"))
        observations = investigation_trace.observations_for(thread_id).values()
        signals = {signal for observation in observations for signal in observation.signals}
        categories = {observation.category for observation in investigation_trace.observations_for(thread_id).values()}
        matches = registry.find_applicable(signals, categories)
        knowledge_trace.record_search(thread_id, matches)
        return json.dumps([
            {
                "runbook_id": match.runbook_id,
                "version": match.version,
                "title": match.proposal.title,
                "summary": match.proposal.summary,
            }
            for match in matches
        ], separators=(",", ":"), sort_keys=True)

    def open_approved_runbook(runbook_id: str, version: int) -> str:
        """Open one promoted runbook version returned by the current thread's search."""
        thread_id = str(get_config().get("configurable", {}).get("thread_id", "unscoped"))
        if not knowledge_trace.may_open(thread_id, runbook_id, version):
            raise ValueError("runbook was not returned by the current investigation search")
        runbook = registry.get_promoted(runbook_id, version)
        citation = knowledge_trace.record_open(thread_id, runbook)
        return json.dumps({
            "citation": citation.model_dump(mode="json"),
            "title": runbook.proposal.title,
            "applicability_signals": runbook.proposal.applicability_signals,
            "required_evidence_categories": runbook.proposal.required_evidence_categories,
            "diagnostic_steps": runbook.proposal.diagnostic_steps,
            "conclusion": runbook.proposal.conclusion,
        }, separators=(",", ":"), sort_keys=True)

    return [
        StructuredTool.from_function(search_approved_runbooks),
        StructuredTool.from_function(open_approved_runbook),
    ]


RUNBOOK_AWARE_PROMPT = """Investigate one unfamiliar failure affecting an owned disposable worker service. Gather health, resource, recent-change, and bounded-log evidence before concluding. After gathering evidence, call search_approved_runbooks. If it returns a candidate, open the best matching version with open_approved_runbook and apply its diagnostic guidance. Cite only observations that support the causal explanation; do not cite generic symptoms or normal-state observations merely used to reject alternatives. Return a structured diagnosis. primary_resource and trigger must describe the supported mechanism. If you opened a runbook, runbook_citation must exactly reproduce its returned citation. If no promoted runbook matched, return runbook_citation=null. Runbooks are diagnostic knowledge only and grant no executable authority."""


def create_runbook_aware_agent(
    model: BaseChatModel,
    target: SiteDiagnosticTarget,
    registry: RunbookRegistry,
    investigation_trace: InvestigationTrace,
    knowledge_trace: RunbookKnowledgeTrace,
):
    tools = [
        *build_diagnostic_tools(target, investigation_trace),
        *build_runbook_tools(registry, investigation_trace, knowledge_trace),
    ]
    return create_deep_agent(
        model=model,
        tools=tools,
        system_prompt=RUNBOOK_AWARE_PROMPT,
        response_format=RunbookAwareDiagnosis,
        backend=StateBackend(),
        permissions=[FilesystemPermission(operations=["read", "write"], paths=["/**"], mode="deny")],
        checkpointer=InMemorySaver(),
    )


def investigate_with_runbooks(
    agent,
    investigation_trace: InvestigationTrace,
    knowledge_trace: RunbookKnowledgeTrace,
    thread_id: str,
    *,
    require_runbook: bool,
) -> dict[str, Any]:
    started = time.monotonic()
    output = agent.invoke(
        {"messages": [{"role": "user", "content": "The owned disposable worker service has an unfamiliar recurring failure. Diagnose the mechanism using approved evidence and knowledge."}]},
        config={"configurable": {"thread_id": thread_id}, "recursion_limit": 18},
    )
    diagnosis = RunbookAwareDiagnosis.model_validate(output["structured_response"])
    observations = investigation_trace.observations_for(thread_id)
    if set(diagnosis.evidence_refs) - set(observations):
        raise ValueError("diagnosis cited evidence that was not observed")
    opened = knowledge_trace.opened_for(thread_id)
    citation_valid = diagnosis.runbook_citation is None and not opened
    if diagnosis.runbook_citation is not None:
        citation_valid = diagnosis.runbook_citation in opened
    if require_runbook and (not opened or diagnosis.runbook_citation is None):
        raise ValueError("learned investigation must open and cite a promoted runbook")
    if not citation_valid:
        raise ValueError("diagnosis runbook citation was not opened in this investigation")
    diagnostic_calls = investigation_trace.tool_calls_for(thread_id)
    runbook_calls = knowledge_trace.tool_calls_for(thread_id)
    return {
        **diagnosis.model_dump(mode="json"),
        "diagnostic_tool_calls": diagnostic_calls,
        "runbook_tool_calls": runbook_calls,
        "tool_calls": [*diagnostic_calls, *runbook_calls],
        "runbook_citation_valid": citation_valid,
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


def explicit_runbook_citation(inputs: dict, outputs: dict, reference_outputs: dict) -> bool:
    del inputs, reference_outputs
    return bool(outputs.get("runbook_citation")) and outputs.get("runbook_citation_valid") is True and "open_approved_runbook" in (outputs.get("runbook_tool_calls") or [])


EVALUATORS = [diagnosis_correct, required_evidence_recall, distractor_avoidance, required_diagnostic_coverage, explicit_runbook_citation]


REFERENCE_OUTPUT = {
    "expected_resource": "memory",
    "expected_trigger": "worker_concurrency_increase",
    "required_evidence": ["resources-1", "changes-1", "logs-1"],
    "distractor_evidence": ["health-1"],
    "required_diagnostics": ["check_site_health", "inspect_resources", "inspect_recent_changes", "inspect_recent_logs"],
}


def ensure_dataset(client: Client) -> str:
    if not client.has_dataset(dataset_name=DATASET_NAME):
        client.create_dataset(
            DATASET_NAME,
            description="One synthetic unfamiliar incident evaluated before and after governed runbook promotion.",
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
        raise ValueError("LangSmith runbook-application dataset does not match the local version")
    return DATASET_NAME


def _local_dataset() -> list[Example]:
    return [Example(
        id=uuid5(NAMESPACE_URL, f"local:{DATASET_NAME}:worker-memory-pressure"),
        inputs={"case_id": "worker-memory-pressure"},
        outputs=REFERENCE_OUTPUT,
        metadata={"scenario_kind": "synthetic_marker"},
    )]


def _trace_usage(client: Client, root_run) -> dict[str, int | float | None]:
    latency_ms = None
    if root_run.end_time and root_run.start_time:
        latency_ms = int((root_run.end_time - root_run.start_time).total_seconds() * 1000)
    total_tokens = root_run.total_tokens
    if total_tokens is None:
        llm_runs = list(client.list_runs(trace_id=root_run.trace_id, run_type="llm"))
        totals = [run.total_tokens for run in llm_runs if run.total_tokens is not None]
        total_tokens = sum(totals) if totals else None
    return {"latency_ms": latency_ms, "total_tokens": total_tokens, "total_cost": root_run.total_cost}


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
            "total_tokens": row["run"].total_tokens,
            "total_cost": row["run"].total_cost,
        }
        cases.append({
            "case_id": (row["example"].inputs or {}).get("case_id"),
            "error": row["run"].error,
            "diagnosis": {"primary_resource": outputs.get("primary_resource"), "trigger": outputs.get("trigger")},
            "evidence_refs": outputs.get("evidence_refs"),
            "tool_calls": outputs.get("tool_calls"),
            "runbook_citation": outputs.get("runbook_citation"),
            "usage": usage,
            "scores": scores,
        })
    return {
        "experiment_name": results.experiment_name,
        "experiment_id": str(results.experiment_id),
        "url": results.url,
        "averages": {key: sum(values) / len(values) for key, values in score_values.items()},
        "cases": cases,
    }


def run_runbook_application_evaluation(settings: Settings, *, upload_results: bool = True) -> dict[str, Any]:
    client = Client()
    data = ensure_dataset(client) if upload_results else _local_dataset()
    evaluation_settings = replace(
        settings,
        model_timeout_seconds=max(settings.model_timeout_seconds, 120.0),
        model_max_retries=max(settings.model_max_retries, 3),
    )
    baseline_registry = RunbookRegistry(":memory:")
    learned_registry = RunbookRegistry(":memory:")

    def target(registry: RunbookRegistry, *, require_runbook: bool):
        def invoke(inputs: dict) -> dict[str, Any]:
            del inputs
            investigation_trace = InvestigationTrace()
            knowledge_trace = RunbookKnowledgeTrace()
            model = create_live_investigation_model(evaluation_settings)
            thread_id = f"runbook-application-{uuid4().hex}"
            return investigate_with_runbooks(
                create_runbook_aware_agent(model, WorkerMemoryPressureLab(), registry, investigation_trace, knowledge_trace),
                investigation_trace,
                knowledge_trace,
                thread_id,
                require_runbook=require_runbook,
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
            target(baseline_registry, require_runbook=False),
            experiment_prefix=BEFORE_EXPERIMENT,
            description="Unfamiliar incident with an empty approved-runbook registry.",
            metadata={"phase": "before-learning", "model": settings.deep_agent_model},
            **common,
        )
        before = summarize_experiment(before_results, client, include_remote_usage=upload_results)

        research_trace = InvestigationTrace()
        research_model = create_live_investigation_model(evaluation_settings)
        proposal = research_runbook(
            create_runbook_research_agent(research_model, WorkerMemoryPressureLab(), research_trace),
            research_trace,
            f"runbook-promotion-{uuid4().hex}",
        )
        original = learned_registry.submit(proposal)
        revision = learned_registry.revise(
            original.candidate_id,
            simulated_reviewer_revision(proposal),
            actor="simulated-sre-reviewer",
            note="Remove generic symptoms and normal-state context from the reusable applicability contract.",
        )
        promoted = learned_registry.review(
            revision.candidate_id,
            RunbookReviewDecision.APPROVE,
            actor="simulated-sre-reviewer",
            evaluator=DeterministicRunbookEvaluator(),
            note="Approve the reviewed revision for hidden evaluation.",
        )
        if not isinstance(promoted, PromotedRunbook):
            raise ValueError("reviewed runbook failed the promotion gate")

        after_results = client.evaluate(
            target(learned_registry, require_runbook=True),
            experiment_prefix=AFTER_EXPERIMENT,
            description="Fresh incident with search and explicit application of one reviewed, evaluated, promoted runbook.",
            metadata={"phase": "after-learning", "model": settings.deep_agent_model, "runbook_version": promoted.version},
            **common,
        )
        after = summarize_experiment(after_results, client, include_remote_usage=upload_results)
        metrics = sorted(set(before["averages"]) | set(after["averages"]))
        return {
            "dataset": DATASET_NAME if upload_results else "local-iterator",
            "promotion": {
                "original_candidate_id": original.candidate_id,
                "revised_candidate_id": revision.candidate_id,
                "runbook_id": promoted.runbook_id,
                "version": promoted.version,
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
