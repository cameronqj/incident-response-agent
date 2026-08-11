"""Small LangSmith evaluation suite for direct versus reflective investigation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol
from uuid import NAMESPACE_URL, uuid4, uuid5

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langsmith import Client
from langsmith.schemas import Example
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings
from .schemas import Scenario
from .site_investigation import (
    DiagnosticObservation,
    InvestigationResult,
    InvestigationTrace,
    SiteDiagnosticTarget,
    SiteHealthAlert,
    create_incident_deep_agent,
    create_live_investigation_model,
    investigate_site,
    validate_investigation_result,
)


DATASET_NAME = "incident-response-agent-reflection-eval-v1"
DIRECT_EXPERIMENT = "direct-investigator-v1"
REFLECTIVE_EXPERIMENT = "critique-investigator-v1"
MAX_REFLECTIVE_TOOL_CALLS = 8


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    health: DiagnosticObservation
    resources: DiagnosticObservation
    changes: DiagnosticObservation
    logs: DiagnosticObservation
    expected_scenario: Scenario
    expected_action: str
    causal_evidence: tuple[str, ...]
    distractor_evidence: tuple[str, ...]
    required_tools: tuple[str, ...]


def _observation(evidence_id: str, category: Literal["health", "resources", "changes", "logs"], summary: str, signals: list[str], **measurements: int | float | str | bool | None) -> DiagnosticObservation:
    return DiagnosticObservation(evidence_id=evidence_id, category=category, summary=summary, signals=signals, measurements=measurements)


EVALUATION_CASES: dict[str, EvaluationCase] = {
    "disk-with-cpu-and-deploy-distractors": EvaluationCase(
        case_id="disk-with-cpu-and-deploy-distractors",
        health=_observation("health-1", "health", "The bounded site health check returns HTTP 503.", ["http_503", "healthcheck_failed"], status_code=503),
        resources=_observation("resources-1", "resources", "Free space is critical; CPU is elevated and memory remains normal.", ["low_free_space", "elevated_cpu"], free_bytes=4096, cpu_percent=78.0, memory_percent=38.0),
        changes=_observation("changes-1", "changes", "A recent deployment completed successfully with no configuration error or rollback.", ["deployment_completed", "no_deployment_error"], minutes_before_failure=18, rollback_count=0),
        logs=_observation("logs-1", "logs", "Log rotation failed after writes returned no space left on device.", ["rotation_error", "no_space_left"], affected_file_count=3, log_growth_bytes_per_minute=262144),
        expected_scenario=Scenario.DISK_EXHAUSTION,
        expected_action="cleanup_rotated_logs",
        causal_evidence=("health-1", "resources-1", "logs-1"),
        distractor_evidence=("changes-1",),
        required_tools=("inspect_resources", "inspect_recent_logs"),
    ),
    "runaway-cpu-with-disk-noise": EvaluationCase(
        case_id="runaway-cpu-with-disk-noise",
        health=_observation("health-1", "health", "The bounded site health check times out and returns HTTP 503.", ["http_503", "healthcheck_timeout"], status_code=503),
        resources=_observation("resources-1", "resources", "CPU is saturated while memory is normal and filesystem capacity remains above the critical threshold.", ["cpu_saturation", "disk_warning_only"], free_bytes=268435456, cpu_percent=99.0, memory_percent=41.0),
        changes=_observation("changes-1", "changes", "No deployment or configuration change occurred during the preceding six hours.", ["no_recent_change"], change_count=0),
        logs=_observation("logs-1", "logs", "A bounded worker repeatedly reports a hot-loop watchdog warning without storage or allocation errors.", ["hot_loop", "watchdog_warning"], affected_worker_count=1, storage_error_count=0),
        expected_scenario=Scenario.RUNAWAY_CPU,
        expected_action="stop_runaway_process",
        causal_evidence=("health-1", "resources-1", "logs-1"),
        distractor_evidence=("changes-1",),
        required_tools=("inspect_resources", "inspect_recent_logs"),
    ),
    "memory-pressure-with-successful-change": EvaluationCase(
        case_id="memory-pressure-with-successful-change",
        health=_observation("health-1", "health", "The bounded site health check returns HTTP 503 after a worker disappears.", ["http_503", "worker_missing"], status_code=503),
        resources=_observation("resources-1", "resources", "Memory is critically high while CPU, filesystem capacity, and inode availability remain normal.", ["critical_memory_pressure"], free_bytes=536870912, cpu_percent=22.0, memory_percent=97.0),
        changes=_observation("changes-1", "changes", "A configuration rollout completed successfully and its values match the previous effective limits.", ["configuration_applied", "limits_unchanged"], minutes_before_failure=25),
        logs=_observation("logs-1", "logs", "The bounded kernel-event view records an OOM kill for the disposable worker.", ["oom_kill", "allocation_failure"], oom_kill_count=1),
        expected_scenario=Scenario.MEMORY_OOM,
        expected_action="stop_memory_hog",
        causal_evidence=("health-1", "resources-1", "logs-1"),
        distractor_evidence=("changes-1",),
        required_tools=("inspect_resources", "inspect_recent_logs"),
    ),
    "restarting-service-with-normal-resources": EvaluationCase(
        case_id="restarting-service-with-normal-resources",
        health=_observation("health-1", "health", "The site alternates between connection refusal and HTTP 503 during bounded checks.", ["connection_refused", "http_503"], status_code=503),
        resources=_observation("resources-1", "resources", "CPU, memory, and filesystem capacity are all normal.", ["resources_normal"], free_bytes=805306368, cpu_percent=11.0, memory_percent=33.0),
        changes=_observation("changes-1", "changes", "No deployment or configuration change occurred before the health degradation.", ["no_recent_change"], change_count=0),
        logs=_observation("logs-1", "logs", "The disposable service exits during startup and has entered a bounded restart loop.", ["startup_failure", "restart_loop"], restart_count=5),
        expected_scenario=Scenario.RESTARTING_SERVICE,
        expected_action="restart_disposable_service",
        causal_evidence=("health-1", "logs-1"),
        distractor_evidence=("changes-1", "resources-1"),
        required_tools=("check_site_health", "inspect_recent_logs"),
    ),
    "log-storm-with-cpu-noise": EvaluationCase(
        case_id="log-storm-with-cpu-noise",
        health=_observation("health-1", "health", "The site responds slowly and intermittently returns HTTP 503.", ["http_503", "latency_high"], status_code=503),
        resources=_observation("resources-1", "resources", "CPU is moderately elevated, while memory and filesystem free space remain outside critical ranges.", ["moderate_cpu", "disk_not_critical"], free_bytes=402653184, cpu_percent=69.0, memory_percent=44.0),
        changes=_observation("changes-1", "changes", "A feature flag changed earlier but was reverted successfully before symptoms began.", ["feature_flag_reverted", "change_precedes_healthy_period"], minutes_before_failure=90),
        logs=_observation("logs-1", "logs", "Temporary diagnostic files are growing rapidly and repeated messages dominate the bounded log sample.", ["log_storm", "temporary_file_growth"], temp_file_count=240, log_growth_bytes_per_minute=8388608),
        expected_scenario=Scenario.LOG_STORM,
        expected_action="cleanup_log_storm_temp_files",
        causal_evidence=("health-1", "logs-1"),
        distractor_evidence=("changes-1", "resources-1"),
        required_tools=("inspect_recent_logs",),
    ),
}


@dataclass(frozen=True)
class EvaluationTarget(SiteDiagnosticTarget):
    case: EvaluationCase

    def check_health(self) -> DiagnosticObservation:
        return self.case.health.model_copy(deep=True)

    def inspect_resources(self) -> DiagnosticObservation:
        return self.case.resources.model_copy(deep=True)

    def inspect_recent_changes(self) -> DiagnosticObservation:
        return self.case.changes.model_copy(deep=True)

    def inspect_recent_logs(self) -> DiagnosticObservation:
        return self.case.logs.model_copy(deep=True)


class CritiqueResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    needs_revision: bool
    unsupported_evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    missing_evidence_categories: list[Literal["health", "resources", "changes", "logs"]] = Field(default_factory=list, max_length=4)
    explanation: str = Field(min_length=1, max_length=1000)


class DiagnosisCritic(Protocol):
    def critique(self, result: InvestigationResult, observations: dict[str, DiagnosticObservation]) -> CritiqueResult: ...


class LiveDiagnosisCritic:
    def __init__(self, model: BaseChatModel):
        self.model = model.with_structured_output(CritiqueResult)

    def critique(self, result: InvestigationResult, observations: dict[str, DiagnosticObservation]) -> CritiqueResult:
        payload = {
            "diagnosis": result.model_dump(mode="json"),
            "observations": {key: value.model_dump(mode="json") for key, value in observations.items()},
        }
        response = self.model.invoke([
            SystemMessage(content=(
                "Review an incident diagnosis using only the supplied observations. Evidence references in the final diagnosis must support the causal explanation; observations used only to exclude a hypothesis or describe a concurrent symptom are unsupported final citations. Mark needs_revision when the diagnosis, action, or evidence citations need correction. Identify missing evidence categories only when another available observation is necessary. Do not invent evidence, scenarios, actions, or tool names."
            )),
            HumanMessage(content=json.dumps(payload, separators=(",", ":"), sort_keys=True)),
        ])
        return CritiqueResult.model_validate(response)


def reference_output(case: EvaluationCase) -> dict[str, Any]:
    return {
        "expected_scenario": case.expected_scenario.value,
        "expected_action": case.expected_action,
        "causal_evidence": list(case.causal_evidence),
        "distractor_evidence": list(case.distractor_evidence),
        "required_tools": list(case.required_tools),
        "max_tool_calls": MAX_REFLECTIVE_TOOL_CALLS,
    }


def _output(result: InvestigationResult, trace: InvestigationTrace, thread_id: str, critique: CritiqueResult | None = None) -> dict[str, Any]:
    return {
        **result.model_dump(mode="json"),
        "tool_calls": trace.tool_calls_for(thread_id),
        "critique_used": critique is not None,
        "critique": critique.model_dump(mode="json") if critique else None,
    }


def run_direct_case(case_id: str, model: BaseChatModel) -> dict[str, Any]:
    case = EVALUATION_CASES[case_id]
    trace = InvestigationTrace()
    thread_id = f"eval-direct-{case_id}-{uuid4().hex}"
    result = investigate_site(
        create_incident_deep_agent(model, EvaluationTarget(case), trace),
        SiteHealthAlert(idempotency_key=thread_id, observed_at=datetime.now(timezone.utc)),
        trace,
    )
    return _output(result, trace, thread_id)


def run_reflective_case(case_id: str, model: BaseChatModel, critic: DiagnosisCritic) -> dict[str, Any]:
    case = EVALUATION_CASES[case_id]
    trace = InvestigationTrace()
    thread_id = f"eval-reflect-{case_id}-{uuid4().hex}"
    agent = create_incident_deep_agent(model, EvaluationTarget(case), trace)
    alert = SiteHealthAlert(idempotency_key=thread_id, observed_at=datetime.now(timezone.utc))
    result = investigate_site(agent, alert, trace)
    critique = critic.critique(result, trace.observations_for(thread_id))
    observed = trace.observations_for(thread_id)
    if set(critique.unsupported_evidence_refs) - set(observed):
        raise ValueError("critic referenced evidence that was not observed")
    if critique.needs_revision:
        feedback = (
            "An independent bounded critic found that the diagnosis needs revision. "
            f"Unsupported evidence refs: {critique.unsupported_evidence_refs}. "
            f"Missing evidence categories: {critique.missing_evidence_categories}. "
            f"Reason: {critique.explanation}. Reassess using available read-only diagnostics and return a corrected structured diagnosis. Cite only evidence that supports the causal explanation."
        )
        revised = agent.invoke({"messages": [{"role": "user", "content": feedback}]}, config={"configurable": {"thread_id": thread_id}, "recursion_limit": 16})
        result = validate_investigation_result(revised["structured_response"], thread_id, trace)
    if len(trace.tool_calls_for(thread_id)) > MAX_REFLECTIVE_TOOL_CALLS:
        raise ValueError("reflective investigation exceeded its diagnostic tool budget")
    return _output(result, trace, thread_id, critique)


def diagnosis_correct(_inputs: dict, outputs: dict, reference_outputs: dict) -> bool:
    return outputs["diagnosed_scenario"] == reference_outputs["expected_scenario"]


def action_correct(_inputs: dict, outputs: dict, reference_outputs: dict) -> bool:
    return outputs["proposed_action_id"] == reference_outputs["expected_action"]


def evidence_precision(_inputs: dict, outputs: dict, reference_outputs: dict) -> float:
    cited = set(outputs["evidence_refs"])
    causal = set(reference_outputs["causal_evidence"])
    return len(cited & causal) / max(len(cited), 1)


def distractor_rejection(_inputs: dict, outputs: dict, reference_outputs: dict) -> bool:
    return not bool(set(outputs["evidence_refs"]) & set(reference_outputs["distractor_evidence"]))


def trajectory_coverage(_inputs: dict, outputs: dict, reference_outputs: dict) -> float:
    called = set(outputs["tool_calls"])
    required = set(reference_outputs["required_tools"])
    return len(called & required) / max(len(required), 1)


def within_tool_budget(_inputs: dict, outputs: dict, reference_outputs: dict) -> bool:
    return len(outputs["tool_calls"]) <= reference_outputs["max_tool_calls"]


EVALUATORS = [diagnosis_correct, action_correct, evidence_precision, distractor_rejection, trajectory_coverage, within_tool_budget]


def ensure_langsmith_dataset(client: Client) -> str:
    if not client.has_dataset(dataset_name=DATASET_NAME):
        client.create_dataset(
            DATASET_NAME,
            description="Five synthetic, bounded site-investigation cases for direct-versus-critique evaluation. No production or personal data.",
            metadata={"project": "incident-response-agent", "evidence_kind": "synthetic_marker", "version": 1},
        )
    examples = []
    for case in EVALUATION_CASES.values():
        examples.append({
            "id": uuid5(NAMESPACE_URL, f"{DATASET_NAME}:{case.case_id}"),
            "inputs": {"case_id": case.case_id, "alert": "The owned disposable site is unhealthy. Investigate the cause and propose one bounded remediation."},
            "outputs": reference_output(case),
            "metadata": {"scenario_kind": "synthetic_marker", "case_id": case.case_id},
        })
    client.create_examples(dataset_name=DATASET_NAME, examples=examples)
    return DATASET_NAME


def run_langsmith_reflection_evaluation(settings: Settings, *, upload_results: bool = True, repetitions: int = 1) -> dict[str, Any]:
    client = Client()
    dataset = ensure_langsmith_dataset(client) if upload_results else [
        Example(
            id=uuid5(NAMESPACE_URL, f"local:{DATASET_NAME}:{case.case_id}"),
            inputs={"case_id": case.case_id},
            outputs=reference_output(case),
            metadata={"scenario_kind": "synthetic_marker"},
        )
        for case in EVALUATION_CASES.values()
    ]

    def direct_target(inputs: dict) -> dict[str, Any]:
        return run_direct_case(inputs["case_id"], create_live_investigation_model(settings))

    def reflective_target(inputs: dict) -> dict[str, Any]:
        model = create_live_investigation_model(settings)
        return run_reflective_case(inputs["case_id"], model, LiveDiagnosisCritic(model))

    common = {
        "data": dataset,
        "evaluators": EVALUATORS,
        "max_concurrency": 1,
        "num_repetitions": repetitions,
        "upload_results": upload_results,
        "error_handling": "log",
    }
    direct = client.evaluate(
        direct_target,
        experiment_prefix=DIRECT_EXPERIMENT,
        description="Direct Deep Agents investigator without critique.",
        metadata={"models": [settings.deep_agent_model], "prompts": ["direct-v1"], "tools": ["bounded-site-diagnostics"]},
        **common,
    )
    reflective = client.evaluate(
        reflective_target,
        experiment_prefix=REFLECTIVE_EXPERIMENT,
        description="Same investigator with one bounded structured critique cycle.",
        metadata={"models": [settings.deep_agent_model], "prompts": ["critique-v1"], "tools": ["bounded-site-diagnostics"]},
        **common,
    )
    return {
        "dataset": DATASET_NAME if upload_results else "local-iterator",
        "direct_experiment": getattr(direct, "experiment_name", DIRECT_EXPERIMENT),
        "reflective_experiment": getattr(reflective, "experiment_name", REFLECTIVE_EXPERIMENT),
        "direct_results": list(direct),
        "reflective_results": list(reflective),
    }
