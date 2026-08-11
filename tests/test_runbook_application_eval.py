from __future__ import annotations

import inspect
from typing import Any, Sequence

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from incident_response_agent.runbook_application_eval import (
    EVALUATORS,
    RunbookAwareDiagnosis,
    RunbookCitation,
    RunbookKnowledgeTrace,
    create_runbook_aware_agent,
    diagnosis_correct,
    distractor_avoidance,
    explicit_runbook_citation,
    investigate_with_runbooks,
    required_diagnostic_coverage,
    required_evidence_recall,
)
from incident_response_agent.runbook_learning import (
    DeterministicRunbookEvaluator,
    PromotedRunbook,
    RunbookCandidateState,
    RunbookRegistry,
    RunbookResearchProposal,
    RunbookReviewDecision,
    WorkerMemoryPressureLab,
)
from incident_response_agent.site_investigation import InvestigationTrace


class ScriptedApplicationModel(BaseChatModel):
    responses: list[AIMessage]
    call_number: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted-runbook-application"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {}

    def bind_tools(self, _tools: Sequence[Any], **_kwargs: Any) -> "ScriptedApplicationModel":
        return self

    def _generate(self, _messages: list[BaseMessage], stop: list[str] | None = None, run_manager: Any = None, **_kwargs: Any) -> ChatResult:
        del stop, run_manager
        message = self.responses[self.call_number]
        self.call_number += 1
        return ChatResult(generations=[ChatGeneration(message=message)])


def _tool(name: str, args: dict[str, Any] | None = None) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args or {}, "id": f"call-{name}"}])


def _proposal() -> RunbookResearchProposal:
    return RunbookResearchProposal(
        problem_signature="worker-concurrency-memory-pressure",
        title="Worker concurrency drives memory exhaustion",
        summary="Memory pressure and OOM kills correlate with a recent worker-concurrency increase.",
        applicability_signals=["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom"],
        required_evidence_categories=["resources", "changes", "logs"],
        diagnostic_steps=[
            "Confirm memory pressure while CPU and filesystem capacity remain normal.",
            "Compare current concurrency with the last healthy value.",
            "Confirm OOM kills correlate with the concurrency increase.",
        ],
        conclusion="Treat the condition as concurrency-related memory exhaustion only when all three causal observations are present.",
        source_evidence_refs=["resources-1", "changes-1", "logs-1"],
        confidence=0.93,
    )


def _promote(registry: RunbookRegistry) -> PromotedRunbook:
    candidate = registry.submit(_proposal())
    promoted = registry.review(
        candidate.candidate_id,
        RunbookReviewDecision.APPROVE,
        actor="simulated-sre-reviewer",
        evaluator=DeterministicRunbookEvaluator(),
    )
    assert isinstance(promoted, PromotedRunbook)
    return promoted


def _diagnosis_message(citation: RunbookCitation | None) -> AIMessage:
    diagnosis = RunbookAwareDiagnosis(
        primary_resource="memory",
        trigger="worker_concurrency_increase",
        summary="Memory exhaustion follows the worker-concurrency increase and causes correlated OOM kills.",
        confidence=0.95,
        evidence_refs=["resources-1", "changes-1", "logs-1"],
        conclusion="The causal chain is increased worker concurrency, memory pressure, and correlated OOM termination.",
        runbook_citation=citation,
    )
    return AIMessage(content="", tool_calls=[{
        "name": "RunbookAwareDiagnosis",
        "args": diagnosis.model_dump(mode="json"),
        "id": "diagnosis",
    }])


def _diagnostic_responses() -> list[AIMessage]:
    return [
        _tool("check_site_health"),
        _tool("inspect_resources"),
        _tool("inspect_recent_changes"),
        _tool("inspect_recent_logs"),
    ]


def test_before_learning_investigation_searches_empty_registry_without_citation():
    registry = RunbookRegistry(":memory:")
    investigation_trace = InvestigationTrace()
    knowledge_trace = RunbookKnowledgeTrace()
    model = ScriptedApplicationModel(responses=[*_diagnostic_responses(), _tool("search_approved_runbooks"), _diagnosis_message(None)])
    output = investigate_with_runbooks(
        create_runbook_aware_agent(model, WorkerMemoryPressureLab(), registry, investigation_trace, knowledge_trace),
        investigation_trace,
        knowledge_trace,
        "before-learning",
        require_runbook=False,
    )
    assert output["primary_resource"] == "memory"
    assert output["runbook_citation"] is None
    assert output["runbook_tool_calls"] == ["search_approved_runbooks"]


def test_after_learning_investigation_searches_opens_applies_and_cites_promoted_version():
    registry = RunbookRegistry(":memory:")
    promoted = _promote(registry)
    citation = RunbookCitation(runbook_id=promoted.runbook_id, version=promoted.version, content_digest=promoted.content_digest)
    investigation_trace = InvestigationTrace()
    knowledge_trace = RunbookKnowledgeTrace()
    model = ScriptedApplicationModel(responses=[
        *_diagnostic_responses(),
        _tool("search_approved_runbooks"),
        _tool("open_approved_runbook", {"runbook_id": promoted.runbook_id, "version": promoted.version}),
        _diagnosis_message(citation),
    ])
    output = investigate_with_runbooks(
        create_runbook_aware_agent(model, WorkerMemoryPressureLab(), registry, investigation_trace, knowledge_trace),
        investigation_trace,
        knowledge_trace,
        "after-learning",
        require_runbook=True,
    )
    assert output["runbook_citation"] == citation.model_dump(mode="json")
    assert output["runbook_citation_valid"] is True
    assert output["runbook_tool_calls"] == ["search_approved_runbooks", "open_approved_runbook"]


def test_unopened_or_forged_runbook_citation_is_rejected():
    registry = RunbookRegistry(":memory:")
    promoted = _promote(registry)
    forged = RunbookCitation(runbook_id=promoted.runbook_id, version=promoted.version, content_digest="0" * 64)
    investigation_trace = InvestigationTrace()
    knowledge_trace = RunbookKnowledgeTrace()
    model = ScriptedApplicationModel(responses=[*_diagnostic_responses(), _tool("search_approved_runbooks"), _diagnosis_message(forged)])
    with pytest.raises(ValueError, match="must open and cite"):
        investigate_with_runbooks(
            create_runbook_aware_agent(model, WorkerMemoryPressureLab(), registry, investigation_trace, knowledge_trace),
            investigation_trace,
            knowledge_trace,
            "forged-citation",
            require_runbook=True,
        )


def test_only_promoted_untampered_versions_are_visible():
    registry = RunbookRegistry(":memory:")
    signals = {"memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"}
    categories = {"health", "resources", "changes", "logs"}

    pending = registry.submit(_proposal())
    rejected = registry.submit(_proposal().model_copy(update={"title": "Rejected candidate"}))
    registry.review(rejected.candidate_id, RunbookReviewDecision.REJECT, "simulated-sre-reviewer", DeterministicRunbookEvaluator())
    superseded = registry.submit(_proposal().model_copy(update={"title": "Superseded candidate"}))
    registry.revise(superseded.candidate_id, _proposal().model_copy(update={"title": "Pending revision"}), "simulated-sre-reviewer")
    broad = _proposal().model_copy(update={"applicability_signals": ["memory_pressure", "oom_kill"], "required_evidence_categories": ["resources", "logs"]})
    evaluation_failed = registry.submit(RunbookResearchProposal.model_validate(broad))
    registry.review(evaluation_failed.candidate_id, RunbookReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicRunbookEvaluator())

    assert registry.get_candidate(pending.candidate_id).state == RunbookCandidateState.PENDING_REVIEW
    assert registry.get_candidate(rejected.candidate_id).state == RunbookCandidateState.REJECTED
    assert registry.get_candidate(superseded.candidate_id).state == RunbookCandidateState.SUPERSEDED
    assert registry.get_candidate(evaluation_failed.candidate_id).state == RunbookCandidateState.EVALUATION_FAILED
    assert registry.find_applicable(signals, categories) == []

    promoted = _promote(registry)
    assert [match.runbook_id for match in registry.find_applicable(signals, categories)] == [promoted.runbook_id]
    registry.connection.execute(
        "UPDATE promoted_runbooks SET proposal_json = ? WHERE runbook_id = ? AND version = ?",
        (_proposal().model_copy(update={"title": "Tampered promoted knowledge"}).model_dump_json(), promoted.runbook_id, promoted.version),
    )
    with pytest.raises(ValueError, match="digest is invalid"):
        registry.find_applicable(signals, categories)
    with pytest.raises(ValueError, match="digest is invalid"):
        registry.get_promoted(promoted.runbook_id, promoted.version)


def test_before_after_evaluators_measure_diagnosis_evidence_tools_and_citation():
    reference = {
        "expected_resource": "memory",
        "expected_trigger": "worker_concurrency_increase",
        "required_evidence": ["resources-1", "changes-1", "logs-1"],
        "distractor_evidence": ["health-1"],
        "required_diagnostics": ["check_site_health", "inspect_resources", "inspect_recent_changes", "inspect_recent_logs"],
    }
    baseline = {
        "primary_resource": "memory",
        "trigger": "worker_concurrency_increase",
        "evidence_refs": ["health-1", "resources-1", "changes-1", "logs-1"],
        "diagnostic_tool_calls": reference["required_diagnostics"],
        "runbook_tool_calls": ["search_approved_runbooks"],
        "runbook_citation": None,
        "runbook_citation_valid": True,
    }
    learned = {
        **baseline,
        "evidence_refs": reference["required_evidence"],
        "runbook_tool_calls": ["search_approved_runbooks", "open_approved_runbook"],
        "runbook_citation": {"runbook_id": "worker-concurrency-memory-pressure", "version": 1, "content_digest": "1" * 64},
    }
    assert diagnosis_correct({}, baseline, reference)
    assert required_evidence_recall({}, baseline, reference) == 1.0
    assert not distractor_avoidance({}, baseline, reference)
    assert required_diagnostic_coverage({}, baseline, reference) == 1.0
    assert not explicit_runbook_citation({}, baseline, reference)
    assert distractor_avoidance({}, learned, reference)
    assert explicit_runbook_citation({}, learned, reference)


def test_evaluator_signatures_match_langsmith_parameter_contract():
    for evaluator in EVALUATORS:
        assert list(inspect.signature(evaluator).parameters) == ["inputs", "outputs", "reference_outputs"]
