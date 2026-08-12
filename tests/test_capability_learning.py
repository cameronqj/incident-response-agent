from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Sequence

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from incident_response_agent.capability_learning import (
    CAPABILITY_POLICY,
    CapabilityActivationRecord,
    CapabilityCandidateState,
    CapabilityRegistry,
    CapabilityResearchProposal,
    CapabilityReviewDecision,
    ConcurrencyWorkerLab,
    DeterministicCapabilityEvaluator,
    PromotedCapability,
    capability_policy_pass,
    create_capability_research_agent,
    research_capability,
    reviewer_corrected_capability_proposal,
    simulated_reviewer_revision,
)
from incident_response_agent.executor import ConcurrencyReductionExecutor, DisposableFilesystemExecutor
from incident_response_agent.model import FakeAnalyzer
from incident_response_agent.policy import OptionBinding, SafetyViolation, action_hash, build_option
from incident_response_agent.runbook_learning import RunbookRegistry
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.schemas import CapabilityBinding, Decision, DecisionRequest, ModelAssessment, RemediationOption, Scenario, ScenarioKind
from incident_response_agent.service import ConflictError, IncidentService
from incident_response_agent.site_investigation import InvestigationTrace
from incident_response_agent.storage import SQLiteStore
from incident_response_agent.telemetry import DeterministicENOSPCTelemetry, SyntheticWorkerConcurrencyTelemetry
from conftest import make_event


class ScriptedCapabilityModel(BaseChatModel):
    responses: list[AIMessage]
    call_number: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted-capability-model"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {}

    def bind_tools(self, _tools: Sequence[Any], **_kwargs: Any) -> "ScriptedCapabilityModel":
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        del messages, stop, run_manager, kwargs
        if self.call_number >= len(self.responses):
            raise AssertionError("scripted model exhausted its responses")
        message = self.responses[self.call_number]
        self.call_number += 1
        return ChatResult(generations=[ChatGeneration(message=message)])


def _tool(name: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": {}, "id": f"call-{name}"}])


def _proposal_args(**updates: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "capability_id": "reduce_worker_concurrency",
        "title": "Reduce worker concurrency under memory pressure",
        "summary": "Lowers the owned disposable worker concurrency when elevated concurrency correlates with OOM pressure.",
        "parameters": [{"name": "target_concurrency", "kind": "int", "minimum": 1, "maximum": 8, "required": True}],
        "allowed_targets": ["owned_disposable_worker"],
        "prerequisites": ["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"],
        "required_evidence_categories": ["resources", "changes", "logs"],
        "maximum_blast_radius": "Exactly one owned disposable worker; no scope beyond that single worker.",
        "approval_policy": "Requires application-owned human approval of the immutable proposal before activation.",
        "idempotency": "Activating at or below the approved target is a no-op success.",
        "timeout_seconds": 30,
        "verification_steps": ["Confirm the owned worker health check returns HTTP 200.", "Confirm OOM kills stop in bounded logs."],
        "rollback_steps": ["Restore the previous concurrency value.", "Re-verify the owned worker health check."],
        "source_evidence_refs": ["resources-1", "changes-1", "logs-1"],
        "confidence": 0.9,
    }
    values.update(updates)
    return values


def _proposal_message(**updates: Any) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": "CapabilityResearchProposal", "args": _proposal_args(**updates), "id": "capability-proposal"}])


def _research_proposal() -> CapabilityResearchProposal:
    trace = InvestigationTrace()
    model = ScriptedCapabilityModel(responses=[_tool("check_site_health"), _tool("inspect_resources"), _tool("inspect_recent_changes"), _tool("inspect_recent_logs"), _proposal_message()])
    return research_capability(
        create_capability_research_agent(model, ConcurrencyWorkerLab(), trace),
        trace,
        "capability-research-1",
    )


def test_research_agent_sees_observations_but_not_hidden_expected_capability():
    target = ConcurrencyWorkerLab()
    trace = InvestigationTrace()
    model = ScriptedCapabilityModel(responses=[_tool("check_site_health"), _tool("inspect_resources"), _tool("inspect_recent_changes"), _tool("inspect_recent_logs"), _proposal_message()])
    proposal = research_capability(create_capability_research_agent(model, target, trace), trace, "research-1")
    assert proposal.capability_id == "reduce_worker_concurrency"
    assert proposal.prerequisites == ["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"]
    assert proposal.required_evidence_categories == ["resources", "changes", "logs"]
    assert proposal.source_evidence_refs == ["resources-1", "changes-1", "logs-1"]


def test_research_rejects_unobserved_evidence_and_signals():
    trace = InvestigationTrace()
    model = ScriptedCapabilityModel(responses=[_tool("check_site_health"), _tool("inspect_resources"), _tool("inspect_recent_changes"), _tool("inspect_recent_logs"), _proposal_message(source_evidence_refs=["resources-1", "never-observed"])])
    with pytest.raises(ValueError):
        research_capability(create_capability_research_agent(model, ConcurrencyWorkerLab(), trace), trace, "invalid-research")


def test_simulated_human_approval_evaluates_promotes_persists_and_enables_reuse(tmp_path):
    database_path = str(tmp_path / "capabilities.sqlite3")
    registry = CapabilityRegistry(database_path)
    try:
        proposal = _research_proposal()
        candidate = registry.submit(proposal)
        promoted = registry.review(candidate.candidate_id, CapabilityReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicCapabilityEvaluator())
        assert isinstance(promoted, PromotedCapability)
        assert promoted.version == 1
        assert promoted.evaluation.passed
        matches = registry.find_approved({"memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"}, {"resources", "changes", "logs"})
        assert len(matches) == 1
        assert matches[0].capability_id == "reduce_worker_concurrency"
    finally:
        registry.close()


def test_rejection_is_terminal_and_never_retrievable():
    registry = CapabilityRegistry(":memory:")
    try:
        proposal = _research_proposal()
        candidate = registry.submit(proposal)
        rejected = registry.review(candidate.candidate_id, CapabilityReviewDecision.REJECT, "simulated-sre-reviewer", DeterministicCapabilityEvaluator())
        assert rejected.state == CapabilityCandidateState.REJECTED
        assert registry.find_approved({"memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"}, {"resources", "changes", "logs"}) == []
        with pytest.raises(ValueError):
            registry.review(candidate.candidate_id, CapabilityReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicCapabilityEvaluator())
    finally:
        registry.close()


def test_human_approval_cannot_bypass_hidden_evaluation_gate():
    registry = CapabilityRegistry(":memory:")
    try:
        broad = CapabilityResearchProposal.model_validate(_proposal_args(
            prerequisites=["memory_pressure", "oom_kill"],
            required_evidence_categories=["resources", "logs"],
            timeout_seconds=120,
        ))
        candidate = registry.submit(broad)
        reviewed = registry.review(candidate.candidate_id, CapabilityReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicCapabilityEvaluator())
        assert reviewed.state == CapabilityCandidateState.EVALUATION_FAILED
        assert registry.find_approved({"memory_pressure", "oom_kill"}, {"resources", "logs"}) == []
    finally:
        registry.close()


def test_simulated_reviewer_revision_preserves_original_and_passes_same_gate():
    registry = CapabilityRegistry(":memory:")
    try:
        overly_strict = CapabilityResearchProposal.model_validate(_proposal_args(
            prerequisites=["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill", "http_503", "worker_unavailable"],
            required_evidence_categories=["resources", "changes", "logs", "health"],
        ))
        original = registry.submit(overly_strict)
        revision = registry.revise(original.candidate_id, simulated_reviewer_revision(overly_strict), actor="simulated-sre-reviewer", note="keep causal prerequisites only")
        assert registry.get_candidate(original.candidate_id).state == CapabilityCandidateState.SUPERSEDED
        assert revision.supersedes_candidate_id == original.candidate_id
        promoted = registry.review(revision.candidate_id, CapabilityReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicCapabilityEvaluator())
        assert isinstance(promoted, PromotedCapability)
        assert promoted.proposal.prerequisites == ["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"]
        assert promoted.proposal.required_evidence_categories == ["resources", "changes", "logs"]
    finally:
        registry.close()


def test_candidate_digest_detects_persistent_tampering():
    registry = CapabilityRegistry(":memory:")
    try:
        candidate = registry.submit(_research_proposal())
        with registry.connection:
            registry.connection.execute("UPDATE capability_candidates SET proposal_json = ? WHERE candidate_id = ?", (json.dumps(_proposal_args(title="tampered title")), candidate.candidate_id))
        with pytest.raises(ValueError):
            registry.get_candidate(candidate.candidate_id)
    finally:
        registry.close()


def test_retrieval_returns_only_latest_promoted_version():
    registry = CapabilityRegistry(":memory:")
    try:
        first = registry.review(registry.submit(_research_proposal()).candidate_id, CapabilityReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicCapabilityEvaluator())
        assert isinstance(first, PromotedCapability)
        second_proposal = _research_proposal()
        second_proposal = second_proposal.model_copy(update={"title": "Refined capability version"})
        second = registry.review(registry.submit(second_proposal).candidate_id, CapabilityReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicCapabilityEvaluator())
        assert isinstance(second, PromotedCapability)
        matches = registry.find_approved({"memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"}, {"resources", "changes", "logs"})
        assert [(match.version, match.proposal.title) for match in matches] == [(2, "Refined capability version")]
    finally:
        registry.close()


def test_registries_are_separate_and_cross_promotion_is_impossible(tmp_path):
    capability_registry = CapabilityRegistry(":memory:")
    runbook_registry = RunbookRegistry(str(tmp_path / "runbooks.sqlite3"))
    try:
        promoted_capability = capability_registry.review(
            capability_registry.submit(_research_proposal()).candidate_id,
            CapabilityReviewDecision.APPROVE,
            "simulated-sre-reviewer",
            DeterministicCapabilityEvaluator(),
        )
        assert isinstance(promoted_capability, PromotedCapability)
        assert runbook_registry.find_applicable({"memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"}, {"resources", "changes", "logs"}) == []
        with pytest.raises(KeyError):
            runbook_registry.get_promoted("reduce_worker_concurrency", 1)
    finally:
        capability_registry.close()
        runbook_registry.close()


def test_promoted_capability_requires_review_decision_and_gate():
    registry = CapabilityRegistry(":memory:")
    try:
        candidate = registry.submit(_research_proposal())
        with pytest.raises(ValueError):
            registry.review(candidate.candidate_id, CapabilityReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicCapabilityEvaluator(), note="x" * 1001)
    finally:
        registry.close()


def test_capability_policy_rejects_unbounded_timeout_parameters_and_blast_radius():
    assert capability_policy_pass(_research_proposal()) == {
        "bounded_timeout": True,
        "bounded_parameters": True,
        "bounded_blast_radius": True,
        "has_verification": True,
        "has_rollback": True,
        "sufficient_confidence": True,
    }
    assert not capability_policy_pass(CapabilityResearchProposal.model_validate(_proposal_args(timeout_seconds=3600)))["bounded_timeout"]
    assert not capability_policy_pass(CapabilityResearchProposal.model_validate(_proposal_args(
        parameters=[{"name": "target_concurrency", "kind": "int", "minimum": 1, "maximum": 64, "required": True}],
    )))["bounded_parameters"]
    assert not capability_policy_pass(CapabilityResearchProposal.model_validate(_proposal_args(
        maximum_blast_radius="May touch any worker in the cluster when the owner is unavailable.",
    )))["bounded_blast_radius"]
    assert capability_policy_pass(_research_proposal())["has_verification"]
    assert capability_policy_pass(_research_proposal())["has_rollback"]


def test_contract_violation_revision_derives_from_model_proposal():
    """Salvage strips unobserved signals from the model's own proposal, not a hardcoded substitute."""
    from incident_response_agent.capability_learning import contract_violation_revision
    from incident_response_agent.site_investigation import DiagnosticObservation

    observations = {
        "resources-1": DiagnosticObservation(evidence_id="resources-1", category="resources", summary="memory pressure", signals=["memory_pressure"]),
        "changes-1": DiagnosticObservation(evidence_id="changes-1", category="changes", summary="concurrency increased", signals=["worker_concurrency_increased"]),
        "logs-1": DiagnosticObservation(evidence_id="logs-1", category="logs", summary="oom kills", signals=["oom_kill", "concurrency_correlated_oom"]),
        "health-1": DiagnosticObservation(evidence_id="health-1", category="health", summary="503", signals=["http_503"]),
    }
    proposal = CapabilityResearchProposal.model_validate(_proposal_args(
        prerequisites=["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill", "never_observed_signal"],
        source_evidence_refs=["resources-1", "changes-1", "logs-1", "phantom-9"],
    ))
    salvaged = contract_violation_revision(proposal, observations)
    assert salvaged is not None
    assert "never_observed_signal" not in salvaged.prerequisites
    assert "phantom-9" not in salvaged.source_evidence_refs
    assert salvaged.source_evidence_refs == ["resources-1", "changes-1", "logs-1"]
    assert salvaged.capability_id == proposal.capability_id


def test_contract_violation_revision_returns_none_when_unsalvageable():
    from incident_response_agent.capability_learning import contract_violation_revision
    from incident_response_agent.site_investigation import DiagnosticObservation

    observations = {
        "resources-1": DiagnosticObservation(evidence_id="resources-1", category="resources", summary="memory pressure", signals=["memory_pressure"]),
    }
    proposal = CapabilityResearchProposal.model_validate(_proposal_args(
        prerequisites=["invented_a", "invented_b"],
        source_evidence_refs=["phantom-1", "phantom-2"],
    ))
    assert contract_violation_revision(proposal, observations) is None


def test_capability_policy_constant_is_consistent():
    assert CAPABILITY_POLICY["max_timeout_seconds"] < 3600
    assert CAPABILITY_POLICY["max_parameter_maximum"] >= 4


def test_option_parameters_are_validated_and_bound_into_hash():
    registry = CapabilityRegistry(":memory:")
    try:
        promoted, binding = _promote_capability(registry)
        assert promoted.version == 1
        assessment = ModelAssessment(
            summary="worker memory pressure from elevated concurrency",
            severity="high",
            confidence=0.97,
            evidence_refs=["memory_pressure", "concurrency_correlated_oom"],
            action_id="reduce_worker_concurrency",
        )
        option = build_option(
            Scenario.WORKER_CONCURRENCY,
            ScenarioKind.SYNTHETIC_MARKER,
            assessment,
            binding=OptionBinding(parameters={"target_concurrency": 4}, target_id="lab-abc", capability=binding),
        )
        assert option.parameters == {"target_concurrency": 4}
        assert option.target_id == "lab-abc"
        assert option.capability == binding
        assert len(action_hash(1, Scenario.WORKER_CONCURRENCY, ScenarioKind.SYNTHETIC_MARKER, option)) == 64
        with pytest.raises(SafetyViolation):
            build_option(Scenario.WORKER_CONCURRENCY, ScenarioKind.SYNTHETIC_MARKER, assessment)
        with pytest.raises(SafetyViolation):
            build_option(Scenario.WORKER_CONCURRENCY, ScenarioKind.SYNTHETIC_MARKER, assessment, binding=OptionBinding(parameters={"target_concurrency": 9}, target_id="lab-abc", capability=binding))
        with pytest.raises(SafetyViolation):
            build_option(Scenario.WORKER_CONCURRENCY, ScenarioKind.SYNTHETIC_MARKER, assessment, binding=OptionBinding(parameters={"target_concurrency": 4}, target_id="../host", capability=binding))
        with pytest.raises(SafetyViolation):
            build_option(Scenario.WORKER_CONCURRENCY, ScenarioKind.SYNTHETIC_MARKER, assessment, binding=OptionBinding(parameters={"target_concurrency": 4, "extra": 1}, target_id="lab-abc", capability=binding))
        with pytest.raises(SafetyViolation):
            build_option(Scenario.WORKER_CONCURRENCY, ScenarioKind.SYNTHETIC_MARKER, assessment, binding=OptionBinding(parameters={"target_concurrency": 4}, target_id="lab-abc"))
    finally:
        registry.close()


def test_executor_accepts_only_owned_target_and_bounded_parameter():
    registry = CapabilityRegistry(":memory:")
    try:
        _, binding = _promote_capability(registry)
        lab = ConcurrencyWorkerLab()
        executor = ConcurrencyReductionExecutor(lab, registry)
        option = _option(parameters={"target_concurrency": 4}, target_id=lab.lab_id, capability=binding)
        result = executor.execute(option)
        assert result.success
        assert lab.current_concurrency == 4
        assert result.health_after == "healthy"
        other_lab = ConcurrencyWorkerLab()
        foreign = _option(parameters={"target_concurrency": 4}, target_id=other_lab.lab_id, capability=binding)
        assert executor.execute(foreign).failure_reason_code == "unauthorized_target"
        out_of_bounds = _option(parameters={"target_concurrency": 9}, target_id=lab.lab_id, capability=binding)
        assert executor.execute(out_of_bounds).failure_reason_code == "parameter_out_of_bounds"
    finally:
        registry.close()


def test_executor_is_idempotent_at_or_below_target():
    registry = CapabilityRegistry(":memory:")
    try:
        _, binding = _promote_capability(registry)
        lab = ConcurrencyWorkerLab()
        executor = ConcurrencyReductionExecutor(lab, registry)
        first = executor.execute(_option(parameters={"target_concurrency": 4}, target_id=lab.lab_id, capability=binding))
        assert first.success and lab.current_concurrency == 4
        second = executor.execute(_option(parameters={"target_concurrency": 4}, target_id=lab.lab_id, capability=binding))
        assert second.success and second.attempts == 0 and lab.current_concurrency == 4
        third = executor.execute(_option(parameters={"target_concurrency": 8}, target_id=lab.lab_id, capability=binding))
        assert third.success and third.attempts == 0 and lab.current_concurrency == 4
    finally:
        registry.close()


def test_executor_rolls_back_when_verification_fails():
    registry = CapabilityRegistry(":memory:")
    try:
        _, binding = _promote_capability(registry)
        lab = ConcurrencyWorkerLab(fail_verification=True)
        executor = ConcurrencyReductionExecutor(lab, registry)
        result = executor.execute(_option(parameters={"target_concurrency": 4}, target_id=lab.lab_id, capability=binding))
        assert not result.success
        assert result.failure_reason_code == "verification_failed"
        # rollback restores the original elevated concurrency; the incident remains unresolved
        assert lab.current_concurrency == 12
        assert not lab.healthy
    finally:
        registry.close()


def test_executor_rejects_wrong_action():
    registry = CapabilityRegistry(":memory:")
    try:
        _, binding = _promote_capability(registry)
        lab = ConcurrencyWorkerLab()
        executor = ConcurrencyReductionExecutor(lab, registry)
        option = _option(action_id="cleanup_rotated_logs", capability=binding)
        assert executor.execute(option).failure_reason_code == "unauthorized_action"
    finally:
        registry.close()


def test_executor_revalidates_registry_record_at_execution():
    """Execution must fail when the approved binding is stale, tampered, or unpromoted."""
    registry = CapabilityRegistry(":memory:")
    try:
        _, binding = _promote_capability(registry)
        lab = ConcurrencyWorkerLab()
        executor = ConcurrencyReductionExecutor(lab, registry)

        stale = CapabilityBinding(capability_id=binding.capability_id, version=2, content_digest=binding.content_digest)
        assert executor.execute(_option(parameters={"target_concurrency": 4}, target_id=lab.lab_id, capability=stale)).failure_reason_code == "capability_unpromoted"

        tampered = CapabilityBinding(capability_id=binding.capability_id, version=binding.version, content_digest="0" * 64)
        assert executor.execute(_option(parameters={"target_concurrency": 4}, target_id=lab.lab_id, capability=tampered)).failure_reason_code == "capability_digest_mismatch"

        unbound = _option(parameters={"target_concurrency": 4}, target_id=lab.lab_id)
        assert executor.execute(unbound).failure_reason_code == "capability_not_bound"

        # contract mismatch: executed parameter set differs from the promoted schema
        extra = _option(parameters={"target_concurrency": 4, "extra": 1}, target_id=lab.lab_id, capability=binding)
        assert executor.execute(extra).failure_reason_code == "parameter_contract_mismatch"
    finally:
        registry.close()


def _option(*, action_id: str = "reduce_worker_concurrency", parameters: dict | None = None, target_id: str | None = None, capability: CapabilityBinding | None = None) -> RemediationOption:
    return RemediationOption(
        action_id=action_id,
        title="reduce worker concurrency",
        evidence=["memory_pressure", "concurrency_correlated_oom"],
        confidence=0.97,
        impact="Lowers the owned disposable worker concurrency to the approved bound.",
        risk="Low: one owned disposable worker target; concrete values are chosen by application code.",
        action_preview="Set the owned worker concurrency to the approved target and verify recovery.",
        parameters=parameters,
        target_id=target_id,
        capability=capability,
    )


def _promote_capability(registry: CapabilityRegistry, lab: ConcurrencyWorkerLab | None = None) -> tuple[PromotedCapability, CapabilityBinding]:
    """Submit, review, and promote the reference contract; return the promoted record and its binding."""
    del lab
    candidate = registry.submit(reviewer_corrected_capability_proposal())
    promoted = registry.review(candidate.candidate_id, CapabilityReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicCapabilityEvaluator())
    assert isinstance(promoted, PromotedCapability)
    binding = CapabilityBinding(capability_id=promoted.capability_id, version=promoted.version, content_digest=promoted.content_digest)
    return promoted, binding


def test_worker_concurrency_end_to_end_control_plane(tmp_path):
    registry = CapabilityRegistry(":memory:")
    try:
        _, binding = _promote_capability(registry)
        lab = ConcurrencyWorkerLab()
        executor = ConcurrencyReductionExecutor(lab, registry)
        incident = IncidentService(
            SQLiteStore(":memory:"),
            SyntheticWorkerConcurrencyTelemetry(),
            FakeAnalyzer(),
            executor,
            proposal_ttl_seconds=60,
            execution_enabled=True,
            option_binding=lambda _scenario, _kind, _action_id: OptionBinding(
                parameters={"target_concurrency": lab.safe_concurrency},
                target_id=lab.lab_id,
                capability=binding,
            ),
        )
        try:
            run = incident.start_event(make_event("capability-e2e", "worker-concurrency"))
            assert run.proposal is not None
            proposal = run.proposal
            assert proposal.scenario_kind.value == "synthetic_marker"
            assert proposal.option.action_id == "reduce_worker_concurrency"
            assert proposal.option.parameters == {"target_concurrency": 4}
            assert proposal.option.target_id == lab.lab_id
            assert proposal.option.capability == binding
            approved = incident.decide(proposal.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=proposal.revision, action_hash=proposal.action_hash))
            assert approved.state.value == "approved"
            completed = incident.execute(proposal.proposal_id)
            assert completed.state.value == "succeeded"
            assert lab.current_concurrency == 4
            assert lab.healthy
        finally:
            incident.close()
    finally:
        registry.close()


def test_worker_concurrency_execution_fails_without_approval_or_with_tampered_hash():
    registry = CapabilityRegistry(":memory:")
    try:
        _, binding = _promote_capability(registry)
        lab = ConcurrencyWorkerLab()
        executor = ConcurrencyReductionExecutor(lab, registry)
        incident = IncidentService(
            SQLiteStore(":memory:"),
            SyntheticWorkerConcurrencyTelemetry(),
            FakeAnalyzer(),
            executor,
            proposal_ttl_seconds=60,
            execution_enabled=True,
            option_binding=lambda _scenario, _kind, _action_id: OptionBinding(
                parameters={"target_concurrency": lab.safe_concurrency},
                target_id=lab.lab_id,
                capability=binding,
            ),
        )
        try:
            run = incident.start_event(make_event("capability-no-approval", "worker-concurrency"))
            assert run.proposal is not None
            proposal = run.proposal
            with pytest.raises(ConflictError):
                incident.execute(proposal.proposal_id)
            tampered = DecisionRequest(decision=Decision.APPROVE, revision=proposal.revision, action_hash="0" * 64)
            with pytest.raises(ConflictError):
                incident.decide(proposal.proposal_id, tampered)
            assert lab.current_concurrency == 12
        finally:
            incident.close()
    finally:
        registry.close()


def test_full_scripted_orchestration_research_promotion_activation_and_rollback(tmp_path):
    """Research -> review revision -> promotion -> later incident -> activation -> rollback."""
    from incident_response_agent.capability_learning import (
        CapabilityActivationRecord,
        CapabilityCandidateState,
        CapabilityRegistry,
        CapabilityReviewDecision,
        ConcurrencyWorkerLab,
        DeterministicCapabilityEvaluator,
        PromotedCapability,
        create_capability_research_agent,
        research_capability,
        reviewer_corrected_capability_proposal,
        simulated_reviewer_revision,
    )
    from incident_response_agent.executor import ConcurrencyReductionExecutor
    from incident_response_agent.policy import OptionBinding
    from incident_response_agent.schemas import CapabilityBinding, Decision, DecisionRequest
    from incident_response_agent.service import IncidentService
    from incident_response_agent.site_investigation import FixedInvestigationTelemetry, InvestigationAnalyzer, InvestigationResult
    from incident_response_agent.storage import SQLiteStore

    database_path = str(tmp_path / "capability-orchestration.sqlite3")
    registry = CapabilityRegistry(database_path)
    lab = ConcurrencyWorkerLab(fail_verification=True)
    trace = InvestigationTrace()
    model = ScriptedCapabilityModel(responses=[
        _tool("check_site_health"),
        _tool("inspect_resources"),
        _tool("inspect_recent_changes"),
        _tool("inspect_recent_logs"),
        _proposal_message(),
    ])
    proposal = research_capability(create_capability_research_agent(model, lab, trace), trace, "orchestration-research")
    candidate = registry.submit(proposal)
    original = candidate
    revision = registry.revise(original.candidate_id, simulated_reviewer_revision(proposal), actor="simulated-sre-reviewer", note="keep causal prerequisites only")
    promoted = registry.review(revision.candidate_id, CapabilityReviewDecision.APPROVE, "simulated-sre-reviewer", DeterministicCapabilityEvaluator())
    assert isinstance(promoted, PromotedCapability)
    assert promoted.evaluation.passed
    assert registry.get_candidate(original.candidate_id).state == CapabilityCandidateState.SUPERSEDED

    result = InvestigationResult(
        diagnosed_scenario=Scenario.WORKER_CONCURRENCY,
        severity="high",
        confidence=0.97,
        evidence_refs=sorted(trace.observations_for("orchestration-research")),
        proposed_action_id="reduce_worker_concurrency",
        explanation="Worker memory pressure correlated with elevated concurrency; one bounded concurrency reduction is proposed.",
    )
    binding = CapabilityBinding(capability_id=promoted.capability_id, version=promoted.version, content_digest=promoted.content_digest)
    incident = IncidentService(
        SQLiteStore(":memory:"),
        FixedInvestigationTelemetry(lab.telemetry_for(result)),
        InvestigationAnalyzer(result),
        ConcurrencyReductionExecutor(lab, registry),
        proposal_ttl_seconds=60,
        execution_enabled=True,
        option_binding=lambda _scenario, _kind, _action_id: OptionBinding(
            parameters={"target_concurrency": lab.safe_concurrency},
            target_id=lab.lab_id,
            capability=binding,
        ),
    )
    try:
        run = incident.start_event(make_event("capability-orchestration", "worker-concurrency"))
        assert run.proposal is not None
        proposal_view = run.proposal
        assert proposal_view.option.action_id == "reduce_worker_concurrency"
        assert proposal_view.option.capability == binding
        approved = incident.decide(proposal_view.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=proposal_view.revision, action_hash=proposal_view.action_hash))
        assert approved.state.value == "approved"
        completed = incident.execute(proposal_view.proposal_id)
        assert completed.state.value == "failed"
        assert lab.current_concurrency == 12
        registry.record_activation(CapabilityActivationRecord(
            activation_id="act-orchestration",
            run_id=completed.run_id,
            proposal_id=proposal_view.proposal_id,
            capability_id=promoted.capability_id,
            version=promoted.version,
            target_id=lab.lab_id,
            outcome="rollback_applied",
            verification=False,
            rollback_applied=True,
            occurred_at=datetime.now(timezone.utc),
            actor="test",
        ))
        activations = registry.list_activations(promoted.capability_id)
        assert len(activations) == 1
        assert activations[0].outcome == "rollback_applied"
    finally:
        incident.close()
        registry.close()


def test_service_records_capability_activation_audit_and_otl(tmp_path):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox-audit")
    incident = IncidentService(
        SQLiteStore(":memory:"),
        DeterministicENOSPCTelemetry(),
        FakeAnalyzer(),
        DisposableFilesystemExecutor(sandbox),
        proposal_ttl_seconds=60,
        execution_enabled=True,
    )
    try:
        run = incident.start_event(make_event("capability-audit", "disk-exhaustion"))
        assert run.proposal is not None
        incident.record_capability_activation(run.run_id, run.proposal.proposal_id, "reduce_worker_concurrency", 1, "rollback_applied", True, "test")
        audit = incident.store.list_audit(run.run_id)
        assert any(
            item["event_type"] == "capability_activated"
            and item["metadata"]["capability_id"] == "reduce_worker_concurrency"
            and item["metadata"]["outcome"] == "rollback_applied"
            and item["metadata"]["rollback_applied"] is True
            for item in audit
        )
    finally:
        incident.close()


def test_service_rejects_unknown_capability_activation(tmp_path):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox-audit-2")
    incident = IncidentService(
        SQLiteStore(":memory:"),
        DeterministicENOSPCTelemetry(),
        FakeAnalyzer(),
        DisposableFilesystemExecutor(sandbox),
        proposal_ttl_seconds=60,
        execution_enabled=True,
    )
    try:
        run = incident.start_event(make_event("capability-audit-2", "disk-exhaustion"))
        assert run.proposal is not None
        with pytest.raises(ValueError):
            incident.record_capability_activation(run.run_id, run.proposal.proposal_id, "not-a-capability", 1, "succeeded", False, "test")
        with pytest.raises(ValueError):
            incident.record_capability_activation(run.run_id, run.proposal.proposal_id, "reduce_worker_concurrency", 1, "unsafe-outcome", False, "test")
    finally:
        incident.close()


def test_activation_record_is_auditable():
    registry = CapabilityRegistry(":memory:")
    try:
        registry.record_activation(_activation_record())
        rows = registry.list_activations("reduce_worker_concurrency")
        assert len(rows) == 1
        assert rows[0].outcome == "rollback_applied"
        assert rows[0].rollback_applied
        assert len(registry.list_activations("missing")) == 0
    finally:
        registry.close()


def _activation_record():
    from datetime import datetime, timezone

    return CapabilityActivationRecord(
        activation_id="act-1",
        run_id="run-1",
        proposal_id="proposal-1",
        capability_id="reduce_worker_concurrency",
        version=1,
        target_id="lab-abc",
        outcome="rollback_applied",
        verification=False,
        rollback_applied=True,
        occurred_at=datetime.now(timezone.utc),
        actor="test",
    )


def test_capability_model_fields_are_individually_bounded():
    with pytest.raises(ValueError):
        CapabilityResearchProposal.model_validate(_proposal_args(title="x" * 161))
    with pytest.raises(ValueError):
        CapabilityResearchProposal.model_validate(_proposal_args(summary="x" * 1001))
    with pytest.raises(ValueError):
        CapabilityResearchProposal.model_validate(_proposal_args(parameters=[{"name": "bad-name!", "kind": "int", "minimum": 1, "maximum": 8, "required": True}]))
    with pytest.raises(ValueError):
        CapabilityResearchProposal.model_validate(_proposal_args(parameters=[{"name": "target_concurrency", "kind": "int", "minimum": 9, "maximum": 8, "required": True}]))
    with pytest.raises(ValueError):
        CapabilityResearchProposal.model_validate(_proposal_args(verification_steps=["x" * 501]))
    with pytest.raises(ValueError):
        CapabilityResearchProposal.model_validate(_proposal_args(source_evidence_refs=["x" * 129]))
