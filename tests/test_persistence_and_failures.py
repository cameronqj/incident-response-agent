from __future__ import annotations

import json
import sqlite3

import pytest

from conftest import FakeClock, make_event
from incident_response_agent.executor import DisposableFilesystemExecutor, ExecutionResult
from incident_response_agent.model import FakeAnalyzer
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.schemas import DecisionRequest
from incident_response_agent.service import ConflictError, ExpiredError, IncidentService
from incident_response_agent.storage import SQLiteStore
from incident_response_agent.telemetry import ScenarioTelemetryCollector


class FailingExecutor:
    def execute(self, option):
        return ExecutionResult(False, "synthetic executor failure", failure_reason_code="synthetic_failure")

    def close(self):
        pass


class FailingAnalyzer:
    def analyze(self, evidence, revision_note=None):
        raise RuntimeError("synthetic model failure")


def test_approved_proposal_expired_before_execution_has_no_side_effect(service):
    incident, clock, sandbox = service
    logs = sandbox / "logs"
    logs.mkdir()
    marker = logs / "service.1.rotated"
    marker.write_text("synthetic", encoding="utf-8")
    run = incident.start_event(make_event("approved-expiry"))
    assert run.proposal is not None
    proposal = run.proposal
    incident.decide(proposal.proposal_id, DecisionRequest(decision="approve", revision=proposal.revision, action_hash=proposal.action_hash))
    clock.advance(61)
    with pytest.raises(ExpiredError):
        incident.execute(proposal.proposal_id)
    assert marker.exists()
    assert incident.store.get_proposal(proposal.proposal_id)["status"] == "expired"
    assert incident.get_run(run.run_id).state.value == "expired"


def test_rejected_proposal_cannot_execute(service):
    incident, _, sandbox = service
    logs = sandbox / "logs"
    logs.mkdir()
    marker = logs / "service.1.rotated"
    marker.write_text("synthetic", encoding="utf-8")
    run = incident.start_event(make_event("rejected"))
    assert run.proposal is not None
    proposal = run.proposal
    rejected = incident.decide(proposal.proposal_id, DecisionRequest(decision="reject", revision=proposal.revision, action_hash=proposal.action_hash))
    assert rejected.state.value == "rejected"
    with pytest.raises(ConflictError):
        incident.execute(proposal.proposal_id)
    assert marker.exists()


def test_executor_failure_is_terminal_and_audited(tmp_path):
    service = IncidentService(SQLiteStore(":memory:"), ScenarioTelemetryCollector(), FakeAnalyzer(), FailingExecutor(), clock=FakeClock(), execution_enabled=True)
    run = service.start_event(make_event("executor-failure"))
    assert run.proposal is not None
    proposal = run.proposal
    service.decide(proposal.proposal_id, DecisionRequest(decision="approve", revision=proposal.revision, action_hash=proposal.action_hash))
    failed = service.execute(proposal.proposal_id)
    assert failed.state.value == "failed"
    assert any(item.event_type == "execution_result" and item.metadata["failure_reason_code"] == "synthetic_failure" for item in failed.audit)


def test_model_failure_persists_failed_run_and_reason():
    service = IncidentService(SQLiteStore(":memory:"), ScenarioTelemetryCollector(), FailingAnalyzer(), FailingExecutor(), clock=FakeClock(), execution_enabled=True)
    with pytest.raises(RuntimeError):
        service.start_event(make_event("model-failure"))
    run_id = service.store.connection.execute("SELECT run_id FROM runs").fetchone()[0]
    failed = service.get_run(run_id)
    assert failed.state.value == "failed"
    assert any(item.event_type == "run_failed" and item.metadata["failure_reason_code"] == "RuntimeError" for item in failed.audit)


def test_run_and_sanitized_event_survive_store_restart(tmp_path):
    database = str(tmp_path / "persistent.sqlite3")
    clock = FakeClock()
    first_sandbox = DisposableSandbox.create_test_fixture(tmp_path / "first-sandbox")
    first = IncidentService(SQLiteStore(database), ScenarioTelemetryCollector(), FakeAnalyzer(), DisposableFilesystemExecutor(first_sandbox), clock=clock, execution_enabled=True)
    run = first.start_event(make_event("persistent", summary="token=secret-value from /home/alice/private"))
    first.close()

    second_sandbox = DisposableSandbox.create_test_fixture(tmp_path / "second-sandbox")
    second = IncidentService(SQLiteStore(database), ScenarioTelemetryCollector(), FakeAnalyzer(), DisposableFilesystemExecutor(second_sandbox), clock=clock, execution_enabled=True)
    restored = second.get_run(run.run_id)
    stored_json = second.store.connection.execute("SELECT event_json FROM runs WHERE run_id = ?", (run.run_id,)).fetchone()[0]
    assert restored.run_id == run.run_id
    assert restored.state.value == "proposed"
    assert "secret-value" not in stored_json
    assert "/home/alice/private" not in stored_json


def test_legacy_database_migration_redacts_events_and_expires_active_proposals(tmp_path):
    database = str(tmp_path / "legacy.sqlite3")
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE runs (run_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, payload_hash TEXT NOT NULL, event_json TEXT NOT NULL, trace_id TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE proposals (proposal_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id), revision INTEGER NOT NULL, status TEXT NOT NULL, assessment_json TEXT NOT NULL, option_json TEXT NOT NULL, action_hash TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, approved_action_hash TEXT, UNIQUE(run_id, revision));
        CREATE TABLE audit (audit_id INTEGER PRIMARY KEY AUTOINCREMENT, trace_id TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES runs(run_id), proposal_id TEXT, event_type TEXT NOT NULL, metadata_json TEXT NOT NULL, occurred_at TEXT NOT NULL);
        """
    )
    connection.execute(
        "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("run-1", "legacy", "old-hash", json.dumps({"payload": {"scenario": "disk", "api_key": "legacy-secret"}}), "trace-1", "proposed", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
    )
    connection.execute(
        "INSERT INTO proposals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("proposal-1", "run-1", 1, "proposed", "{}", "{}", "old-digest", "2026-01-02T00:00:00+00:00", "2026-01-01T00:00:00+00:00", None),
    )
    connection.commit()
    connection.close()

    store = SQLiteStore(database)
    dump = "\n".join(store.connection.iterdump())
    assert "legacy-secret" not in dump
    assert store.get_run("run-1")["state"] == "expired"
    assert store.get_proposal("proposal-1")["status"] == "expired"
    assert any(item["metadata"].get("reason") == "security_schema_migration" for item in store.list_audit("run-1"))
