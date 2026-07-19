from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import FakeClock, make_event
from incident_response_agent.executor import ExecutionResult
from incident_response_agent.model import FakeAnalyzer
from incident_response_agent.schemas import DecisionRequest
from incident_response_agent.service import ConflictError, ExpiredError, IncidentService
from incident_response_agent.storage import SQLiteStore
from incident_response_agent.telemetry import ScenarioTelemetryCollector


class CountingAnalyzer:
    def __init__(self):
        self.delegate = FakeAnalyzer()
        self.calls = 0
        self.lock = threading.Lock()

    def analyze(self, evidence, revision_note=None):
        with self.lock:
            self.calls += 1
        return self.delegate.analyze(evidence, revision_note)


class CountingExecutor:
    def __init__(self, block: bool = False):
        self.calls = 0
        self.lock = threading.Lock()
        self.started = threading.Event()
        self.release = threading.Event()
        self.block = block

    def execute(self, option):
        with self.lock:
            self.calls += 1
        self.started.set()
        if self.block:
            assert self.release.wait(timeout=5)
        return ExecutionResult(True, "bounded fixture completed", deleted_count=1)

    def close(self):
        pass


def _services(tmp_path, *, executor=None, analyzer=None, ttl=60):
    database = str(tmp_path / "concurrency.sqlite3")
    clock = FakeClock()
    executor = executor or CountingExecutor()
    analyzer = analyzer or CountingAnalyzer()
    first = IncidentService(SQLiteStore(database), ScenarioTelemetryCollector(), analyzer, executor, proposal_ttl_seconds=ttl, clock=clock, execution_enabled=True)
    second = IncidentService(SQLiteStore(database), ScenarioTelemetryCollector(), analyzer, executor, proposal_ttl_seconds=ttl, clock=clock, execution_enabled=True)
    return first, second, clock, executor, analyzer


def _race(first, second):
    barrier = threading.Barrier(2)

    def invoke(operation):
        barrier.wait(timeout=5)
        try:
            return "ok", operation()
        except Exception as exc:
            return "error", exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        left = pool.submit(invoke, first)
        right = pool.submit(invoke, second)
        return left.result(), right.result()


def test_concurrent_duplicate_intake_creates_one_run_and_one_analysis(tmp_path):
    first, second, _, _, analyzer = _services(tmp_path)
    event = make_event("concurrent-duplicate")
    barrier = threading.Barrier(2)

    def start(service):
        barrier.wait(timeout=5)
        return service.start_event(event)

    with ThreadPoolExecutor(max_workers=2) as pool:
        left_future = pool.submit(start, first)
        right_future = pool.submit(start, second)
        left = left_future.result()
        right = right_future.result()
    assert left.run_id == right.run_id
    assert analyzer.calls == 1
    assert first.store.connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1


def test_approval_races_rejection_with_one_winner(tmp_path):
    first, second, _, _, _ = _services(tmp_path)
    run = first.start_event(make_event("approval-rejection"))
    assert run.proposal is not None
    proposal = run.proposal
    approve = DecisionRequest(decision="approve", revision=proposal.revision, action_hash=proposal.action_hash)
    reject = DecisionRequest(decision="reject", revision=proposal.revision, action_hash=proposal.action_hash)
    outcomes = _race(lambda: first.decide(proposal.proposal_id, approve), lambda: second.decide(proposal.proposal_id, reject))
    assert sum(status == "ok" for status, _ in outcomes) == 1
    assert sum(isinstance(value, ConflictError) for status, value in outcomes if status == "error") == 1
    assert first.store.get_proposal(proposal.proposal_id)["status"] in {"approved", "rejected"}


def test_approval_races_expiration_without_late_approval(tmp_path):
    first, second, clock, _, _ = _services(tmp_path, ttl=1)
    run = first.start_event(make_event("approval-expiration"))
    assert run.proposal is not None
    proposal = run.proposal
    clock.advance(2)
    approve = DecisionRequest(decision="approve", revision=proposal.revision, action_hash=proposal.action_hash)
    outcomes = _race(lambda: first.decide(proposal.proposal_id, approve), lambda: second.expire_due())
    assert first.store.get_proposal(proposal.proposal_id)["status"] == "expired"
    assert first.get_run(run.run_id).state.value == "expired"
    assert not any(status == "ok" and hasattr(value, "state") and value.state.value == "approved" for status, value in outcomes)


def test_two_workers_cannot_execute_same_proposal_twice(tmp_path):
    executor = CountingExecutor(block=True)
    first, second, _, _, _ = _services(tmp_path, executor=executor)
    run = first.start_event(make_event("double-execution"))
    assert run.proposal is not None
    proposal = run.proposal
    first.decide(proposal.proposal_id, DecisionRequest(decision="approve", revision=proposal.revision, action_hash=proposal.action_hash))

    with ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(first.execute, proposal.proposal_id)
        assert executor.started.wait(timeout=5)
        loser = pool.submit(second.execute, proposal.proposal_id)
        with pytest.raises(ConflictError):
            loser.result(timeout=5)
        executor.release.set()
        completed = winner.result(timeout=5)
    assert completed.state.value == "succeeded"
    assert executor.calls == 1


def test_execution_races_expiration_without_side_effect(tmp_path):
    executor = CountingExecutor()
    first, second, clock, _, _ = _services(tmp_path, executor=executor, ttl=1)
    run = first.start_event(make_event("execution-expiration"))
    assert run.proposal is not None
    proposal = run.proposal
    first.decide(proposal.proposal_id, DecisionRequest(decision="approve", revision=proposal.revision, action_hash=proposal.action_hash))
    clock.advance(2)
    _race(lambda: first.execute(proposal.proposal_id), lambda: second.expire_due())
    assert executor.calls == 0
    assert first.store.get_proposal(proposal.proposal_id)["status"] == "expired"


def test_superseded_proposal_never_executes(tmp_path):
    executor = CountingExecutor()
    first, _, _, _, _ = _services(tmp_path, executor=executor)
    run = first.start_event(make_event("superseded"))
    assert run.proposal is not None
    original = run.proposal
    revised = first.decide(original.proposal_id, DecisionRequest(decision="revise", revision=original.revision, action_hash=original.action_hash, note="bounded revision"))
    assert revised.proposal is not None
    with pytest.raises(ConflictError):
        first.execute(original.proposal_id)
    assert executor.calls == 0
