from __future__ import annotations

from typing import Any, Sequence

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from incident_response_agent.runbook_learning import (
    DeterministicRunbookEvaluator,
    PromotedRunbook,
    RunbookCandidate,
    RunbookCandidateState,
    RunbookRegistry,
    RunbookResearchProposal,
    RunbookReviewDecision,
    WorkerMemoryPressureLab,
    create_runbook_research_agent,
    research_runbook,
)
from incident_response_agent.site_investigation import InvestigationTrace, build_diagnostic_tools


class ScriptedResearchModel(BaseChatModel):
    responses: list[AIMessage]
    call_number: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted-runbook-research"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {}

    def bind_tools(self, _tools: Sequence[Any], **_kwargs: Any) -> "ScriptedResearchModel":
        return self

    def _generate(self, _messages: list[BaseMessage], stop: list[str] | None = None, run_manager: Any = None, **_kwargs: Any) -> ChatResult:
        del stop, run_manager
        message = self.responses[self.call_number]
        self.call_number += 1
        return ChatResult(generations=[ChatGeneration(message=message)])


def _tool(name: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": {}, "id": f"call-{name}"}])


def _proposal_args(**updates: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "problem_signature": "worker-concurrency-memory-pressure",
        "title": "Worker concurrency drives memory exhaustion",
        "summary": "Memory pressure and OOM kills begin after worker concurrency increases while other resources remain normal.",
        "applicability_signals": ["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom"],
        "required_evidence_categories": ["resources", "changes", "logs"],
        "diagnostic_steps": [
            "Confirm memory pressure while CPU and filesystem capacity remain normal.",
            "Compare current worker concurrency with the most recent known healthy value.",
            "Confirm OOM kills correlate with the elevated concurrency level.",
        ],
        "conclusion": "Escalate as worker-concurrency memory pressure only when the resource, change, and OOM correlation are all present.",
        "source_evidence_refs": ["resources-1", "changes-1", "logs-1"],
        "confidence": 0.93,
    }
    values.update(updates)
    return values


def _proposal_message(**updates: Any) -> AIMessage:
    return AIMessage(content="", tool_calls=[{
        "name": "RunbookResearchProposal",
        "args": _proposal_args(**updates),
        "id": "runbook-proposal",
    }])


def _research_proposal() -> RunbookResearchProposal:
    trace = InvestigationTrace()
    model = ScriptedResearchModel(responses=[
        _tool("check_site_health"),
        _tool("inspect_resources"),
        _tool("inspect_recent_changes"),
        _tool("inspect_recent_logs"),
        _proposal_message(),
    ])
    return research_runbook(create_runbook_research_agent(model, WorkerMemoryPressureLab(), trace), trace, "runbook-research-1")


def test_research_agent_sees_observations_but_not_hidden_expected_signature():
    target = WorkerMemoryPressureLab()
    rendered = " ".join(
        tool.invoke({}, config={"configurable": {"thread_id": "hidden-boundary"}})
        for tool in build_diagnostic_tools(target, InvestigationTrace())
    )
    assert target._expected_signature not in rendered
    proposal = _research_proposal()
    assert proposal.problem_signature == "worker-concurrency-memory-pressure"
    assert proposal.source_evidence_refs == ["resources-1", "changes-1", "logs-1"]


def test_research_rejects_unobserved_evidence_and_signals():
    trace = InvestigationTrace()
    model = ScriptedResearchModel(responses=[
        _tool("inspect_resources"),
        _tool("inspect_recent_changes"),
        _tool("inspect_recent_logs"),
        _proposal_message(source_evidence_refs=["resources-1", "invented-1"]),
    ])
    with pytest.raises(ValueError, match="not observed"):
        research_runbook(create_runbook_research_agent(model, WorkerMemoryPressureLab(), trace), trace, "invalid-research")


def test_simulated_human_approval_evaluates_promotes_persists_and_enables_reuse(tmp_path):
    database_path = str(tmp_path / "runbooks.sqlite3")
    registry = RunbookRegistry(database_path)
    candidate = registry.submit(_research_proposal())
    assert candidate.state == RunbookCandidateState.PENDING_REVIEW
    assert registry.find_applicable(
        {"memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom"},
        {"resources", "changes", "logs"},
    ) == []

    promoted = registry.review(
        candidate.candidate_id,
        RunbookReviewDecision.APPROVE,
        actor="simulated-sre-reviewer",
        evaluator=DeterministicRunbookEvaluator(),
        note="Synthetic reviewer accepts the narrow applicability contract.",
    )
    assert isinstance(promoted, PromotedRunbook)
    assert promoted.version == 1
    assert promoted.evaluation.passed
    assert promoted.evaluation.case_accuracy == 1.0

    reopened = RunbookRegistry(database_path)
    matches = reopened.find_applicable(
        {"http_503", "memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"},
        {"health", "resources", "changes", "logs"},
    )
    assert [(match.runbook_id, match.version) for match in matches] == [("worker-concurrency-memory-pressure", 1)]
    assert matches[0].proposal.diagnostic_steps[0].startswith("Confirm memory pressure")


def test_rejection_is_terminal_and_never_retrievable():
    registry = RunbookRegistry(":memory:")
    candidate = registry.submit(RunbookResearchProposal.model_validate(_proposal_args()))
    rejected = registry.review(
        candidate.candidate_id,
        RunbookReviewDecision.REJECT,
        actor="simulated-sre-reviewer",
        evaluator=DeterministicRunbookEvaluator(),
        note="Evidence is not sufficiently narrow.",
    )
    assert isinstance(rejected, RunbookCandidate)
    assert rejected.state == RunbookCandidateState.REJECTED
    assert registry.find_applicable(set(_proposal_args()["applicability_signals"]), {"resources", "changes", "logs"}) == []
    with pytest.raises(ValueError, match="only pending"):
        registry.review(candidate.candidate_id, RunbookReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicRunbookEvaluator())


def test_human_approval_cannot_bypass_hidden_evaluation_gate():
    broad = RunbookResearchProposal.model_validate(_proposal_args(
        applicability_signals=["memory_pressure", "oom_kill"],
        required_evidence_categories=["resources", "logs"],
    ))
    registry = RunbookRegistry(":memory:")
    candidate = registry.submit(broad)
    failed = registry.review(
        candidate.candidate_id,
        RunbookReviewDecision.APPROVE,
        actor="simulated-sre-reviewer",
        evaluator=DeterministicRunbookEvaluator(),
    )
    assert isinstance(failed, RunbookCandidate)
    assert failed.state == RunbookCandidateState.EVALUATION_FAILED
    assert registry.find_applicable({"memory_pressure", "oom_kill"}, {"resources", "logs"}) == []


def test_candidate_digest_detects_persistent_tampering():
    registry = RunbookRegistry(":memory:")
    candidate = registry.submit(RunbookResearchProposal.model_validate(_proposal_args()))
    registry.connection.execute(
        "UPDATE runbook_candidates SET proposal_json = ? WHERE candidate_id = ?",
        (RunbookResearchProposal.model_validate(_proposal_args(title="Tampered title")).model_dump_json(), candidate.candidate_id),
    )
    with pytest.raises(ValueError, match="digest is invalid"):
        registry.get_candidate(candidate.candidate_id)
