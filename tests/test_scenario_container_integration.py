from __future__ import annotations

import os
import shutil

import pytest

from incident_response_agent.executor import ContainerRemediationExecutor
from incident_response_agent.model import FakeAnalyzer
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.schemas import Decision, DecisionRequest
from incident_response_agent.service import IncidentService
from incident_response_agent.storage import SQLiteStore
from incident_response_agent.telemetry import ScenarioTelemetryCollector
from conftest import TEST_IMAGE, make_event


@pytest.mark.integration
@pytest.mark.parametrize(
    ("scenario", "marker_dir", "marker_name"),
    [
        ("runaway-cpu", "processes", "runaway_cpu.marker"),
        ("restarting-service", "services", "restart_loop.marker"),
        ("memory-oom", "memory", "memory_hog.marker"),
        ("log-storm", "logs/storm", "service.1.storm"),
    ],
)
def test_scenario_runs_through_agent_and_container(tmp_path, scenario, marker_dir, marker_name):
    if os.getenv("RUN_CONTAINER_TESTS") != "1":
        pytest.skip("set RUN_CONTAINER_TESTS=1 to run container integration")
    engine = shutil.which("podman") or shutil.which("docker")
    if not engine:
        pytest.fail("RUN_CONTAINER_TESTS=1 requires Docker or Podman")
    sandbox = DisposableSandbox.create_test_fixture(tmp_path)
    marker_root = sandbox.root / marker_dir
    marker_root.mkdir(parents=True)
    marker = marker_root / marker_name
    marker.write_text("synthetic fault", encoding="utf-8")
    if scenario == "log-storm":
        temp_root = sandbox.root / "tmp"
        temp_root.mkdir()
        (temp_root / "cache.tmp").write_text("synthetic artifact", encoding="utf-8")
    incident = IncidentService(
        SQLiteStore(":memory:"),
        ScenarioTelemetryCollector(),
        FakeAnalyzer(),
        ContainerRemediationExecutor(sandbox, TEST_IMAGE, engine=engine),
    )

    run = incident.start_event(make_event(f"container-{scenario}", scenario))
    assert run.proposal is not None
    proposal = run.proposal
    assert proposal.scenario_kind.value == "synthetic_marker"
    approved = incident.decide(proposal.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=proposal.revision, action_hash=proposal.action_hash))
    assert approved.state.value == "approved"
    completed = incident.execute(proposal.proposal_id)
    assert completed.state.value == "succeeded"
    assert not marker.exists()
    if scenario == "log-storm":
        assert not (sandbox.root / "tmp" / "cache.tmp").exists()
    if scenario == "restarting-service":
        assert (marker_root / "healthy.marker").exists()
