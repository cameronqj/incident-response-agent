from __future__ import annotations

import pytest

from incident_response_agent.schemas import Decision, DecisionRequest, EventRequest


@pytest.mark.parametrize(
    ("scenario", "marker_dir", "marker_name", "expected_action"),
    [
        ("runaway-cpu", "processes", "runaway_cpu.marker", "stop_runaway_process"),
        ("restarting-service", "services", "restart_loop.marker", "restart_disposable_service"),
        ("memory-oom", "memory", "memory_hog.marker", "stop_memory_hog"),
        ("log-storm", "logs/storm", "service.1.storm", "cleanup_log_storm_temp_files"),
    ],
)
def test_scenario_proposes_and_recovers_with_allowlisted_action(service, scenario, marker_dir, marker_name, expected_action):
    incident, _, sandbox = service
    marker_root = sandbox / marker_dir
    marker_root.mkdir(parents=True)
    marker = marker_root / marker_name
    marker.write_text("synthetic fault", encoding="utf-8")
    if scenario == "log-storm":
        temp_root = sandbox / "tmp"
        temp_root.mkdir()
        (temp_root / "cache.tmp").write_text("synthetic artifact", encoding="utf-8")

    run = incident.start_event(EventRequest(idempotency_key=f"scenario-{scenario}", payload={"scenario": scenario}))
    assert run.proposal is not None
    proposal = run.proposal
    assert proposal.assessment.action_id == expected_action
    assert proposal.option.action_id == expected_action

    approved = incident.decide(proposal.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=proposal.revision, action_hash=proposal.action_hash))
    completed = incident.execute(proposal.proposal_id)
    assert approved.state.value == "approved"
    assert completed.state.value == "succeeded"
    assert not marker.exists()
    if scenario == "restarting-service":
        assert (marker_root / "healthy.marker").exists()
