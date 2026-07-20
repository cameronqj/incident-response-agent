from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from conftest import make_event
from incident_response_agent.config import Settings
from incident_response_agent.executor import DisposableFilesystemExecutor
from incident_response_agent.model import FakeAnalyzer
from incident_response_agent.observability import build_observability
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.schemas import DecisionRequest
from incident_response_agent.service import IncidentService
from incident_response_agent.storage import SQLiteStore
from incident_response_agent.telemetry import DeterministicENOSPCTelemetry


OTEL_COLLECTOR_IMAGE = "docker.io/otel/opentelemetry-collector@sha256:6ed874ea083d67a3085acfc75343f2ad11d9abe6006d7ea4a16e2dba9af14e49"


def _engine() -> str:
    engine = shutil.which("podman") or shutil.which("docker")
    if not engine:
        pytest.fail("RUN_CONTAINER_TESTS=1 requires Docker or Podman")
    health = subprocess.run([engine, "info"], capture_output=True, text=True, timeout=20, check=False)
    if health.returncode != 0:
        pytest.fail(f"container engine is installed but unavailable: {health.stderr.strip()}")
    return engine


def _loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_port(port: int, timeout_seconds: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    pytest.fail("disposable OTLP collector did not become reachable")


@pytest.mark.integration
def test_otlp_export_reaches_hardened_disposable_collector(tmp_path):
    if os.getenv("RUN_CONTAINER_TESTS") != "1":
        pytest.skip("set RUN_CONTAINER_TESTS=1 to run container integration")
    engine = _engine()
    port = _loopback_port()
    name = f"incident-otel-{uuid.uuid4().hex[:12]}"
    config = Path(__file__).parent / "fixtures" / "otel-collector.yaml"
    run_command = [
        engine,
        "run",
        "--detach",
        "--name",
        name,
        "--pull=missing",
        "--read-only",
        "--cpus=0.5",
        "--memory=128m",
        "--memory-swap=128m",
        "--pids-limit=64",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        "10001:10001",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--publish",
        f"127.0.0.1:{port}:4318",
        "--mount",
        f"type=bind,src={config.resolve()},dst=/etc/otelcol/config.yaml,ro",
        OTEL_COLLECTOR_IMAGE,
        "--config=/etc/otelcol/config.yaml",
    ]
    started = subprocess.run(run_command, capture_output=True, text=True, timeout=60, check=False)
    assert started.returncode == 0, started.stderr
    sandbox = None
    service = None
    canary = "must-not-reach-otel-collector"
    try:
        _wait_for_port(port)
        sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
        logs = sandbox.resolve_child("logs")
        logs.mkdir()
        (logs / "service.1.rotated").write_text("synthetic", encoding="utf-8")
        settings = Settings(
            otel_enabled=True,
            otel_exporter_otlp_endpoint=f"http://127.0.0.1:{port}",
            database_path=":memory:",
        )
        settings.validate()
        observability = build_observability(settings)
        service = IncidentService(
            SQLiteStore(":memory:"),
            DeterministicENOSPCTelemetry(),
            FakeAnalyzer(),
            DisposableFilesystemExecutor(sandbox),
            execution_enabled=True,
            observability=observability,
        )
        run = service.start_event(make_event("otel-collector", summary=f"token={canary}"))
        assert run.proposal is not None
        proposal = run.proposal
        service.decide(
            proposal.proposal_id,
            DecisionRequest(decision="approve", revision=proposal.revision, action_hash=proposal.action_hash),
        )
        assert service.execute(proposal.proposal_id).state.value == "succeeded"
        assert observability.force_flush()
        service.close()
        service = None
        time.sleep(0.2)
        logs_result = subprocess.run([engine, "logs", name], capture_output=True, text=True, timeout=10, check=False)
        collector_output = logs_result.stdout + logs_result.stderr
        assert logs_result.returncode == 0
        assert "incident.start_event" in collector_output
        assert "incident.execution.count" in collector_output
        assert canary not in collector_output

        inspected = subprocess.run(
            [engine, "inspect", name, "--format", "{{json .HostConfig}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert inspected.returncode == 0
        host_config = inspected.stdout
        assert '"Privileged":false' in host_config
        assert '"ReadonlyRootfs":true' in host_config
    finally:
        if service is not None:
            service.close()
        elif sandbox is not None:
            sandbox.close()
        subprocess.run([engine, "rm", "-f", "--time", "0", name], capture_output=True, text=True, timeout=15, check=False)
