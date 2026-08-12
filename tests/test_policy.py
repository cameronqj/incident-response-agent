from __future__ import annotations

import json

import pytest

from conftest import make_event
from incident_response_agent.policy import ALLOWED_ACTIONS, SCENARIO_KIND_ACTIONS, OptionBinding, SafetyViolation, action_hash, build_option
from incident_response_agent.schemas import CapabilityBinding, DecisionRequest, ModelAssessment, RemediationOption, Scenario, ScenarioKind
from incident_response_agent.service import ConflictError


def _assessment(action_id: str) -> ModelAssessment:
    return ModelAssessment(
        summary="synthetic assessment",
        severity="high",
        confidence=0.9,
        evidence_refs=["synthetic_signal"],
        action_id=action_id,
    )


@pytest.mark.parametrize(
    ("scenario_key", "action_id"),
    [(scenario_key, next(iter(actions))) for scenario_key, actions in SCENARIO_KIND_ACTIONS.items()],
)
def test_every_scenario_accepts_its_deterministic_action(scenario_key, action_id):
    scenario, scenario_kind = scenario_key
    binding = None
    if ALLOWED_ACTIONS[action_id].get("requires_parameters"):
        binding = OptionBinding(parameters={"target_concurrency": 4}, target_id="lab-abc")
    if ALLOWED_ACTIONS[action_id].get("requires_capability"):
        binding = OptionBinding(
            parameters={"target_concurrency": 4},
            target_id="lab-abc",
            capability=CapabilityBinding(capability_id="reduce_worker_concurrency", version=1, content_digest="1" * 64),
        )
    option = build_option(scenario, scenario_kind, _assessment(action_id), binding=binding)
    assert option.action_id == action_id


@pytest.mark.parametrize(
    ("scenario_key", "action_id"),
    [
        (scenario_key, action)
        for scenario_key in SCENARIO_KIND_ACTIONS
        for other_key, actions in SCENARIO_KIND_ACTIONS.items()
        if other_key != scenario_key
        for action in actions
        if action not in SCENARIO_KIND_ACTIONS[scenario_key]
    ],
)
def test_cross_scenario_actions_are_rejected(scenario_key, action_id):
    scenario, scenario_kind = scenario_key
    with pytest.raises(SafetyViolation):
        build_option(scenario, scenario_kind, _assessment(action_id))


def test_action_digest_binds_scenario_and_scenario_kind():
    option = build_option(Scenario.DISK_EXHAUSTION, ScenarioKind.SYNTHETIC_MARKER, _assessment("cleanup_rotated_logs"))
    marker_digest = action_hash(1, Scenario.DISK_EXHAUSTION, ScenarioKind.SYNTHETIC_MARKER, option)
    fault_digest = action_hash(1, Scenario.DISK_EXHAUSTION, ScenarioKind.CONTAINER_FAULT, option)
    other_scenario_digest = action_hash(1, Scenario.LOG_STORM, ScenarioKind.SYNTHETIC_MARKER, option)
    assert len({marker_digest, fault_digest, other_scenario_digest}) == 3


def test_real_and_marker_service_restart_actions_cannot_authorize_each_other():
    marker = build_option(
        Scenario.RESTARTING_SERVICE,
        ScenarioKind.SYNTHETIC_MARKER,
        _assessment("restart_disposable_service"),
    )
    real = build_option(
        Scenario.RESTARTING_SERVICE,
        ScenarioKind.CONTAINER_FAULT,
        _assessment("restart_unhealthy_container_service"),
    )
    assert marker.action_id != real.action_id
    with pytest.raises(SafetyViolation):
        build_option(Scenario.RESTARTING_SERVICE, ScenarioKind.CONTAINER_FAULT, _assessment(marker.action_id))
    with pytest.raises(SafetyViolation):
        build_option(Scenario.RESTARTING_SERVICE, ScenarioKind.SYNTHETIC_MARKER, _assessment(real.action_id))


def test_cross_scenario_proposal_cannot_be_approved_even_with_recomputed_digest(service):
    incident, _, _ = service
    run = incident.start_event(make_event("tampered-policy"))
    assert run.proposal is not None
    proposal = run.proposal
    wrong_option = RemediationOption(
        action_id="stop_runaway_process",
        title="tampered",
        evidence=["rotation_error"],
        confidence=1.0,
        impact="tampered",
        risk="tampered",
        action_preview="tampered",
    )
    wrong_digest = action_hash(1, Scenario.DISK_EXHAUSTION, ScenarioKind.SYNTHETIC_MARKER, wrong_option)
    incident.store.connection.execute(
        "UPDATE proposals SET option_json = ?, action_hash = ? WHERE proposal_id = ?",
        (json.dumps(wrong_option.model_dump(mode="json")), wrong_digest, proposal.proposal_id),
    )
    with pytest.raises(ConflictError):
        incident.decide(proposal.proposal_id, DecisionRequest(decision="approve", revision=1, action_hash=wrong_digest))
