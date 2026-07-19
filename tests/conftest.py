from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from incident_response_agent.executor import DisposableFilesystemExecutor
from incident_response_agent.model import FakeAnalyzer
from incident_response_agent.service import IncidentService
from incident_response_agent.storage import SQLiteStore
from incident_response_agent.telemetry import DeterministicENOSPCTelemetry


class FakeClock:
    def __init__(self):
        self.current = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self):
        return self.current

    def advance(self, seconds: int):
        from datetime import timedelta

        self.current += timedelta(seconds=seconds)


@pytest.fixture
def service(tmp_path: Path):
    clock = FakeClock()
    sandbox = tmp_path / "sandbox"
    service = IncidentService(SQLiteStore(":memory:"), DeterministicENOSPCTelemetry(), FakeAnalyzer(), DisposableFilesystemExecutor(str(sandbox)), proposal_ttl_seconds=60, clock=clock)
    return service, clock, sandbox
