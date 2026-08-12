from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any, Sequence

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

import incident_response_agent.capability_application_eval as capability_eval
from incident_response_agent.capability_application_eval import (
    EVALUATORS,
    CapabilityAwareDiagnosis,
    CapabilityCitation,
    CapabilityKnowledgeTrace,
    capability_correct,
    create_capability_aware_agent,
    diagnosis_correct,
    distractor_avoidance,
    explicit_capability_citation,
    investigate_with_capabilities,
    required_diagnostic_coverage,
    required_evidence_recall,
    run_capability_application_evaluation,
)
from incident_response_agent.capability_learning import (
    CapabilityRegistry,
    CapabilityReviewDecision,
    ConcurrencyWorkerLab,
    DeterministicCapabilityEvaluator,
    PromotedCapability,
    proposal_digest,
    research_capability,
    reviewer_corrected_capability_proposal,
    simulated_reviewer_revision,
)
from incident_response_agent.config import Settings
from incident_response_agent.site_investigation import InvestigationTrace


class ScriptedCapabilityApplicationModel(BaseChatModel):
    responses: list[AIMessage]
    call_number: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted-capability-application"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {}

    def bind_tools(self, _tools: Sequence[Any], **_kwargs: Any) -> "ScriptedCapabilityApplicationModel":
        return self

    def _generate(self, _messages: list[BaseMessage], stop: list[str] | None = None, run_manager: Any = None, **_kwargs: Any) -> ChatResult:
        del stop, run_manager
        message = self.responses[self.call_number]
        self.call_number += 1
        return ChatResult(generations=[ChatGeneration(message=message)])


def _tool(name: str, args: dict[str, Any] | None = None) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args or {}, "id": f"call-{name}"}])


def _proposal():
    return reviewer_corrected_capability_proposal()


def _promote(registry: CapabilityRegistry) -> PromotedCapability:
    candidate = registry.submit(_proposal())
    promoted = registry.review(
        candidate.candidate_id,
        CapabilityReviewDecision.APPROVE,
        actor="simulated-sre-reviewer",
        evaluator=DeterministicCapabilityEvaluator(),
    )
    assert isinstance(promoted, PromotedCapability)
    return promoted


def _diagnosis_message(citation: CapabilityCitation | None, proposed: str = "reduce_worker_concurrency") -> AIMessage:
    diagnosis = CapabilityAwareDiagnosis(
        primary_resource="memory",
        trigger="worker_concurrency_increase",
        summary="Memory exhaustion follows the worker-concurrency increase and causes correlated OOM kills.",
        confidence=0.95,
        evidence_refs=["resources-1", "changes-1", "logs-1"],
        conclusion="The causal chain is increased worker concurrency, memory pressure, and correlated OOM termination.",
        proposed_capability_id=proposed,
        applied_capability_id=citation.capability_id if citation else None,
        applied_capability_version=citation.version if citation else None,
        applied_capability_digest=citation.content_digest if citation else None,
    )
    return AIMessage(content="", tool_calls=[{
        "name": "CapabilityAwareDiagnosis",
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
    registry = CapabilityRegistry(":memory:")
    try:
        investigation_trace = InvestigationTrace()
        knowledge_trace = CapabilityKnowledgeTrace()
        model = ScriptedCapabilityApplicationModel(responses=[*_diagnostic_responses(), _tool("search_approved_capabilities"), _diagnosis_message(None)])
        output = investigate_with_capabilities(
            create_capability_aware_agent(model, ConcurrencyWorkerLab(), registry, investigation_trace, knowledge_trace),
            registry,
            investigation_trace,
            knowledge_trace,
            "before-learning",
            require_capability=False,
        )
        assert output["primary_resource"] == "memory"
        assert output["capability_citation"] is None
        assert output["capability_tool_calls"] == ["search_approved_capabilities"]
        assert output["proposed_capability_id"] == "reduce_worker_concurrency"
    finally:
        registry.close()


def test_after_learning_investigation_searches_opens_applies_and_cites_promoted_version():
    registry = CapabilityRegistry(":memory:")
    try:
        promoted = _promote(registry)
        citation = CapabilityCitation(capability_id=promoted.capability_id, version=promoted.version, content_digest=promoted.content_digest)
        investigation_trace = InvestigationTrace()
        knowledge_trace = CapabilityKnowledgeTrace()
        model = ScriptedCapabilityApplicationModel(responses=[
            *_diagnostic_responses(),
            _tool("search_approved_capabilities"),
            _tool("open_approved_capability", {"capability_id": promoted.capability_id, "version": promoted.version}),
            _diagnosis_message(citation),
        ])
        output = investigate_with_capabilities(
            create_capability_aware_agent(model, ConcurrencyWorkerLab(), registry, investigation_trace, knowledge_trace),
            registry,
            investigation_trace,
            knowledge_trace,
            "after-learning",
            require_capability=True,
        )
        assert output["capability_citation"] == citation.model_dump(mode="json")
        assert output["capability_citation_valid"] is True
        assert output["capability_tool_calls"] == ["search_approved_capabilities", "open_approved_capability"]
    finally:
        registry.close()


def test_unopened_or_forged_capability_citation_is_rejected():
    registry = CapabilityRegistry(":memory:")
    try:
        promoted = _promote(registry)
        forged = CapabilityCitation(capability_id=promoted.capability_id, version=promoted.version, content_digest="0" * 64)
        investigation_trace = InvestigationTrace()
        knowledge_trace = CapabilityKnowledgeTrace()
        model = ScriptedCapabilityApplicationModel(responses=[*_diagnostic_responses(), _tool("search_approved_capabilities"), _diagnosis_message(forged)])
        with pytest.raises(ValueError, match="must open and cite"):
            investigate_with_capabilities(
                create_capability_aware_agent(model, ConcurrencyWorkerLab(), registry, investigation_trace, knowledge_trace),
                registry,
                investigation_trace,
                knowledge_trace,
                "forged-citation",
                require_capability=True,
            )
    finally:
        registry.close()


def test_opened_capability_carries_evidence_scope_directive():
    import json

    from incident_response_agent.capability_learning import build_capability_tools

    registry = CapabilityRegistry(":memory:")
    try:
        promoted = _promote(registry)
        investigation_trace = InvestigationTrace()
        knowledge_trace = CapabilityKnowledgeTrace()
        search_tool, open_tool = build_capability_tools(registry, investigation_trace, knowledge_trace)
        target = ConcurrencyWorkerLab()
        for name, op in (
            ("check_site_health", target.check_health),
            ("inspect_resources", target.inspect_resources),
            ("inspect_recent_changes", target.inspect_recent_changes),
            ("inspect_recent_logs", target.inspect_recent_logs),
        ):
            investigation_trace.record("scope-test", name, op())
        search_result = search_tool.invoke({}, config={"configurable": {"thread_id": "scope-test"}})
        assert promoted.capability_id in search_result
        opened = open_tool.invoke(
            {"capability_id": promoted.capability_id, "version": promoted.version},
            config={"configurable": {"thread_id": "scope-test"}},
        )
        payload = json.loads(opened)
        assert set(payload["required_evidence_categories"]) == {"resources", "changes", "logs"}
        assert "evidence_scope" in payload
        assert "required_evidence_categories" in payload["evidence_scope"]
        assert "must not be cited" in payload["evidence_scope"]
    finally:
        registry.close()


def test_citation_must_match_proposed_capability():
    registry = CapabilityRegistry(":memory:")
    try:
        promoted = _promote(registry)
        citation = CapabilityCitation(capability_id=promoted.capability_id, version=promoted.version, content_digest=promoted.content_digest)
        investigation_trace = InvestigationTrace()
        knowledge_trace = CapabilityKnowledgeTrace()
        model = ScriptedCapabilityApplicationModel(responses=[
            *_diagnostic_responses(),
            _tool("search_approved_capabilities"),
            _tool("open_approved_capability", {"capability_id": promoted.capability_id, "version": promoted.version}),
            _diagnosis_message(citation, proposed="some_other_capability"),
        ])
        with pytest.raises(ValueError, match="was not opened"):
            investigate_with_capabilities(
                create_capability_aware_agent(model, ConcurrencyWorkerLab(), registry, investigation_trace, knowledge_trace),
                registry,
                investigation_trace,
                knowledge_trace,
                "mismatched-citation",
                require_capability=True,
            )
    finally:
        registry.close()


def test_before_after_evaluators_measure_diagnosis_evidence_tools_capability_and_citation():
    reference = capability_eval.REFERENCE_OUTPUT
    baseline = {
        "primary_resource": "memory",
        "trigger": "worker_concurrency_increase",
        "evidence_refs": ["health-1", "resources-1", "changes-1", "logs-1"],
        "diagnostic_tool_calls": reference["required_diagnostics"],
        "capability_tool_calls": ["search_approved_capabilities"],
        "proposed_capability_id": "reduce_worker_concurrency",
        "capability_citation": None,
        "capability_citation_valid": True,
    }
    learned = {
        **baseline,
        "evidence_refs": reference["required_evidence"],
        "capability_tool_calls": ["search_approved_capabilities", "open_approved_capability"],
        "capability_citation": {"capability_id": "reduce_worker_concurrency", "version": 1, "content_digest": "1" * 64},
    }
    assert diagnosis_correct({}, baseline, reference)
    assert required_evidence_recall({}, baseline, reference) == 1.0
    assert not distractor_avoidance({}, baseline, reference)
    assert required_diagnostic_coverage({}, baseline, reference) == 1.0
    assert capability_correct({}, baseline, reference)
    assert not explicit_capability_citation({}, baseline, reference)
    assert distractor_avoidance({}, learned, reference)
    assert explicit_capability_citation({}, learned, reference)
    assert not capability_correct({}, {**learned, "proposed_capability_id": "scale_replicas"}, reference)


def test_evaluator_signatures_match_langsmith_parameter_contract():
    for evaluator in EVALUATORS:
        assert list(inspect.signature(evaluator).parameters) == ["inputs", "outputs", "reference_outputs"]


def test_complete_orchestration_runs_before_research_promotion_and_fresh_after(monkeypatch):
    proposal = _proposal()
    reviewed = simulated_reviewer_revision(proposal)
    citation = CapabilityCitation(
        capability_id=reviewed.capability_id,
        version=1,
        content_digest=proposal_digest(reviewed),
    )
    models = iter([
        ScriptedCapabilityApplicationModel(responses=[*_diagnostic_responses(), _tool("search_approved_capabilities"), _diagnosis_message(None)]),
        ScriptedCapabilityApplicationModel(responses=[*_diagnostic_responses(), _proposal_message(proposal)]),
        ScriptedCapabilityApplicationModel(responses=[
            *_diagnostic_responses(),
            _tool("search_approved_capabilities"),
            _tool("open_approved_capability", {"capability_id": citation.capability_id, "version": citation.version}),
            _diagnosis_message(citation),
        ]),
    ])
    monkeypatch.setattr(capability_eval, "create_live_investigation_model", lambda _settings: next(models))

    class FakeResults(list):
        def __init__(self, row, experiment_prefix):
            super().__init__([row])
            self.experiment_name = experiment_prefix
            self.experiment_id = f"{experiment_prefix}-id"
            self.url = None

    class FakeClient:
        prefixes: list[str] = []

        def evaluate(self, target, *, data, evaluators, experiment_prefix, **kwargs):
            assert kwargs["upload_results"] is False
            example = list(data)[0]
            outputs = target(example.inputs)
            evaluations = [
                SimpleNamespace(key=evaluator.__name__, score=evaluator(example.inputs, outputs, example.outputs))
                for evaluator in evaluators
            ]
            run = SimpleNamespace(outputs=outputs, error=None, total_tokens=None, total_cost=None)
            self.prefixes.append(experiment_prefix)
            return FakeResults({
                "run": run,
                "example": example,
                "evaluation_results": {"results": evaluations},
            }, experiment_prefix)

    fake_client = FakeClient()
    monkeypatch.setattr(capability_eval, "Client", lambda: fake_client)
    result = run_capability_application_evaluation(Settings(), upload_results=False)

    assert fake_client.prefixes == [capability_eval.BEFORE_EXPERIMENT, capability_eval.AFTER_EXPERIMENT]
    assert result["promotion"]["evaluation"]["passed"] is True
    assert result["after"]["cases"][0]["capability_citation"] == citation.model_dump(mode="json")
    assert result["after_minus_before"]["explicit_capability_citation"] == 1.0


def test_complete_orchestration_handles_researcher_contract_violation(monkeypatch):
    """A researcher that cites unobserved evidence falls back to the reviewer-corrected contract."""
    proposal = _proposal()
    reviewed = simulated_reviewer_revision(proposal)
    citation = CapabilityCitation(
        capability_id=reviewed.capability_id,
        version=1,
        content_digest=proposal_digest(reviewed),
    )

    class ViolatingResearcherModel(BaseChatModel):
        call_number: int = 0
        responses: list[AIMessage]

        @property
        def _llm_type(self) -> str:
            return "violating-researcher"

        @property
        def _identifying_params(self) -> dict[str, Any]:
            return {}

        def bind_tools(self, _tools: Sequence[Any], **_kwargs: Any) -> "ViolatingResearcherModel":
            return self

        def _generate(self, _messages, stop=None, run_manager=None, **_kwargs):
            del stop, run_manager
            message = self.responses[self.call_number]
            self.call_number += 1
            return ChatResult(generations=[ChatGeneration(message=message)])

    bad_proposal = _proposal().model_copy(update={"prerequisites": [*_proposal().prerequisites, "never_observed_signal"]})
    violating = ViolatingResearcherModel(responses=[*_diagnostic_responses(), _proposal_message(bad_proposal)])
    models = iter([
        ScriptedCapabilityApplicationModel(responses=[*_diagnostic_responses(), _tool("search_approved_capabilities"), _diagnosis_message(None)]),
        violating,
        ScriptedCapabilityApplicationModel(responses=[
            *_diagnostic_responses(),
            _tool("search_approved_capabilities"),
            _tool("open_approved_capability", {"capability_id": citation.capability_id, "version": citation.version}),
            _diagnosis_message(citation),
        ]),
    ])
    monkeypatch.setattr(capability_eval, "create_live_investigation_model", lambda _settings: next(models))

    class FakeResults(list):
        def __init__(self, row):
            super().__init__([row])
            self.experiment_name = "experiment"
            self.experiment_id = "experiment-id"
            self.url = None

    class FakeClient:
        def evaluate(self, target, *, data, evaluators, experiment_prefix, **kwargs):
            example = list(data)[0]
            outputs = target(example.inputs)
            evaluations = [
                SimpleNamespace(key=evaluator.__name__, score=evaluator(example.inputs, outputs, example.outputs))
                for evaluator in evaluators
            ]
            return FakeResults({
                "run": SimpleNamespace(outputs=outputs, error=None, total_tokens=None, total_cost=None),
                "example": example,
                "evaluation_results": {"results": evaluations},
            })

    monkeypatch.setattr(capability_eval, "Client", lambda: FakeClient())
    result = run_capability_application_evaluation(Settings(), upload_results=False)

    assert result["promotion"]["researcher_contract_violation"] is True
    assert result["promotion"]["evaluation"]["passed"] is True
    assert result["after"]["cases"][0]["capability_citation"]["capability_id"] == "reduce_worker_concurrency"


def test_eval_propagates_research_infrastructure_failure(monkeypatch):
    """A provider or programming failure in the research phase must fail the experiment,
    not become a silent reference-contract promotion."""
    class ExplodingModel(BaseChatModel):
        @property
        def _llm_type(self) -> str:
            return "exploding-model"

        @property
        def _identifying_params(self) -> dict[str, Any]:
            return {}

        def bind_tools(self, _tools: Sequence[Any], **_kwargs: Any) -> "ExplodingModel":
            return self

        def _generate(self, _messages, stop=None, run_manager=None, **_kwargs):
            del stop, run_manager
            raise RuntimeError("provider timeout")

    # Model consumption order: before investigation, research phase, after investigation.
    # Only the research model explodes, so a working before run proves the failure is
    # specifically in the promotion phase and must propagate instead of substituting.
    models = iter([
        ScriptedCapabilityApplicationModel(responses=[*_diagnostic_responses(), _tool("search_approved_capabilities"), _diagnosis_message(None)]),
        ExplodingModel(),
        ScriptedCapabilityApplicationModel(responses=[*_diagnostic_responses(), _tool("search_approved_capabilities"), _diagnosis_message(None)]),
    ])
    monkeypatch.setattr(capability_eval, "create_live_investigation_model", lambda _settings: next(models))

    class FakeResults(list):
        def __init__(self, row):
            super().__init__([row])
            self.experiment_name = "experiment"
            self.experiment_id = "experiment-id"
            self.url = None

    class FakeClient:
        def evaluate(self, target, *, data, evaluators, experiment_prefix, **kwargs):
            example = list(data)[0]
            outputs = target(example.inputs)
            evaluations = [
                SimpleNamespace(key=evaluator.__name__, score=evaluator(example.inputs, outputs, example.outputs))
                for evaluator in evaluators
            ]
            return FakeResults({
                "run": SimpleNamespace(outputs=outputs, error=None, total_tokens=None, total_cost=None),
                "example": example,
                "evaluation_results": {"results": evaluations},
            })

    monkeypatch.setattr(capability_eval, "Client", lambda: FakeClient())
    with pytest.raises(RuntimeError, match="provider timeout"):
        run_capability_application_evaluation(Settings(), upload_results=False)


def _proposal_message(proposal) -> AIMessage:
    return AIMessage(content="", tool_calls=[{
        "name": "CapabilityResearchProposal",
        "args": proposal.model_dump(mode="json"),
        "id": "research-proposal",
    }])
