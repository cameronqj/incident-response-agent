from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from incident_response_agent.config import Settings
from incident_response_agent.executor import DisposableFilesystemExecutor
from incident_response_agent.model import FakeAnalyzer
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.schemas import EventRequest
from incident_response_agent.service import IncidentService
from incident_response_agent.storage import SQLiteStore
from incident_response_agent.telemetry import DeterministicENOSPCTelemetry


TEST_TOKEN = "test-bearer-token"
TEST_IMAGE = "docker.io/library/python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
OBSERVED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_event(
    idempotency_key: str,
    scenario: str = "disk-exhaustion",
    *,
    summary: str | None = None,
    log_lines: list[str] | None = None,
    context: list[dict[str, str]] | None = None,
) -> EventRequest:
    return EventRequest.model_validate(
        {
            "idempotency_key": idempotency_key,
            "source": "local_simulation",
            "observed_at": OBSERVED_AT,
            "payload": {
                "scenario": scenario,
                "summary": summary,
                "log_lines": log_lines or [],
                "context": context or [],
            },
        }
    )


class FakeClock:
    def __init__(self):
        self.current = OBSERVED_AT
        self.lock = threading.Lock()

    def now(self):
        with self.lock:
            return self.current

    def advance(self, seconds: int):
        with self.lock:
            self.current += timedelta(seconds=seconds)


@pytest.fixture
def api_settings():
    return Settings(bearer_token=TEST_TOKEN, execution_enabled=True, database_path=":memory:")


@pytest.fixture
def service(tmp_path: Path):
    clock = FakeClock()
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    incident = IncidentService(
        SQLiteStore(":memory:"),
        DeterministicENOSPCTelemetry(),
        FakeAnalyzer(),
        DisposableFilesystemExecutor(sandbox),
        proposal_ttl_seconds=60,
        clock=clock,
        execution_enabled=True,
    )
    yield incident, clock, sandbox.root
    incident.close()
