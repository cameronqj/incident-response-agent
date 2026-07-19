from __future__ import annotations

import json

import pytest

from conftest import make_event
from incident_response_agent.policy import SCENARIO_ACTIONS, SafetyViolation, action_hash, build_option
from incident_response_agent.schemas import DecisionRequest, ModelAssessment, RemediationOption, Scenario, ScenarioKind
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
    ("scenario", "action_id"),
    [(scenario, next(iter(actions))) for scenario, actions in SCENARIO_ACTIONS.items()],
)
def test_every_scenario_accepts_its_deterministic_action(scenario, action_id):
    option = build_option(scenario, _assessment(action_id))
    assert option.action_id == action_id


@pytest.mark.parametrize(
    ("scenario", "action_id"),
    [
        (scenario, action)
        for scenario in Scenario
        for other_scenario, actions in SCENARIO_ACTIONS.items()
        if other_scenario != scenario
        for action in actions
    ],
)
def test_cross_scenario_actions_are_rejected(scenario, action_id):
    with pytest.raises(SafetyViolation):
        build_option(scenario, _assessment(action_id))


def test_action_digest_binds_scenario_and_scenario_kind():
    option = build_option(Scenario.DISK_EXHAUSTION, _assessment("cleanup_rotated_logs"))
    marker_digest = action_hash(1, Scenario.DISK_EXHAUSTION, ScenarioKind.SYNTHETIC_MARKER, option)
    fault_digest = action_hash(1, Scenario.DISK_EXHAUSTION, ScenarioKind.CONTAINER_FAULT, option)
    other_scenario_digest = action_hash(1, Scenario.LOG_STORM, ScenarioKind.SYNTHETIC_MARKER, option)
    assert len({marker_digest, fault_digest, other_scenario_digest}) == 3


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
