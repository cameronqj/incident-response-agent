from __future__ import annotations

import json
import subprocess

import pytest

from conftest import TEST_IMAGE, make_event
from incident_response_agent.container_lab import (
    LAB_LABEL,
    ContainerLabError,
    DisposableContainerService,
    RestartObservation,
)
from incident_response_agent.executor import DisposableServiceRestartExecutor
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.schemas import RemediationOption
from incident_response_agent.telemetry import ContainerServiceTelemetry


CID = "a" * 64


def _record(target: DisposableContainerService, health: str = "unhealthy", *, label: str | None = None) -> list[dict]:
    return [
        {
            "Config": {"Labels": {LAB_LABEL: label if label is not None else target.lab_id}},
            "HostConfig": {"Privileged": False},
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(target.sandbox.root),
                    "Destination": "/incident-sandbox",
                    "RW": True,
                }
            ],
            "State": {"Status": "running", "Health": {"Status": health}},
        }
    ]


def _option(action_id: str = "restart_unhealthy_container_service") -> RemediationOption:
    return RemediationOption(
        action_id=action_id,
        title="restart",
        evidence=["service_unhealthy"],
        confidence=1.0,
        impact="bounded",
        risk="low",
        action_preview="fixed target",
    )


def test_target_launch_is_hardened_owned_and_cleaned(tmp_path, monkeypatch):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    target = DisposableContainerService(sandbox, TEST_IMAGE, "podman", timeout_seconds=2)
    calls: list[list[str]] = []
    removed = False

    def fake_run(command, **kwargs):
        nonlocal removed
        calls.append(command)
        if command[1] == "run":
            (sandbox.root / "services" / "boot-count").write_text("1", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout=CID, stderr="")
        if command[1] == "rm":
            removed = True
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[1] == "inspect" and removed:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="missing")
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(_record(target)), stderr="")

    monkeypatch.setattr("incident_response_agent.container_lab.subprocess.run", fake_run)
    snapshot = target.start()
    assert snapshot.health_status == "unhealthy"
    command = calls[0]
    for flag in (
        "--restart=no",
        "--network=none",
        "--read-only",
        "--cpus=0.5",
        "--memory=128m",
        "--memory-swap=128m",
        "--pids-limit=64",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--health-cmd",
    ):
        assert flag in command
    assert "--privileged" not in command
    assert command[command.index("--label") + 1] == f"{LAB_LABEL}={target.lab_id}"
    assert command.count("--mount") == 1
    assert command[command.index("--mount") + 1] == f"type=bind,src={sandbox.root},dst=/incident-sandbox,rw"
    target.close()
    assert calls[-2][1:5] == ["rm", "-f", "--time", "0"]
    assert removed is True
    assert sandbox.root.stat().st_mode & 0o777 == 0o700
    assert (sandbox.root / "services").stat().st_mode & 0o777 == 0o700


def test_target_rejects_ownership_label_mismatch(tmp_path, monkeypatch):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    (sandbox.root / "services").mkdir()
    (sandbox.root / "services" / "boot-count").write_text("1", encoding="utf-8")
    target = DisposableContainerService(sandbox, TEST_IMAGE, "podman")
    target.container_id = CID

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(_record(target, label="wrong")), stderr="")

    monkeypatch.setattr("incident_response_agent.container_lab.subprocess.run", fake_run)
    with pytest.raises(ContainerLabError, match="ownership") as raised:
        target.snapshot()
    assert raised.value.reason_code == "target_ownership_mismatch"


def test_real_telemetry_requires_unhealthy_owned_target():
    class Target:
        def snapshot(self):
            return type("Snapshot", (), {"health_status": "healthy", "boot_count": 2})()

    telemetry = ContainerServiceTelemetry(Target())  # type: ignore[arg-type]
    with pytest.raises(ContainerLabError) as raised:
        telemetry.collect(make_event("healthy-target", "restarting-service"))
    assert raised.value.reason_code == "target_not_unhealthy"


def test_restart_executor_reports_real_health_observation():
    class Target:
        def restart_and_wait(self):
            return RestartObservation("unhealthy", "healthy", 2, 3, 1250)

        def close(self):
            pass

    result = DisposableServiceRestartExecutor(Target()).execute(_option())  # type: ignore[arg-type]
    assert result.success is True
    assert result.service_restarted is True
    assert result.health_before == "unhealthy"
    assert result.health_after == "healthy"
    assert result.attempts == 3
    assert result.latency_ms == 1250
    assert result.boot_count == 2


def test_restart_executor_rejects_marker_action_without_touching_target():
    class Target:
        def restart_and_wait(self):
            raise AssertionError("target must not be touched")

        def close(self):
            pass

    result = DisposableServiceRestartExecutor(Target()).execute(_option("restart_disposable_service"))  # type: ignore[arg-type]
    assert result.success is False
    assert result.failure_reason_code == "unauthorized_action"


def test_restart_uses_exact_owned_container_and_waits_for_health(tmp_path, monkeypatch):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    services = sandbox.root / "services"
    services.mkdir()
    boot_file = services / "boot-count"
    boot_file.write_text("1", encoding="utf-8")
    target = DisposableContainerService(sandbox, TEST_IMAGE, "podman", timeout_seconds=1)
    target.container_id = CID
    restarted = False
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        nonlocal restarted
        calls.append(command)
        if command[1] == "restart":
            assert command[-1] == CID
            restarted = True
            boot_file.write_text("2", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout=CID, stderr="")
        health = "healthy" if restarted else "unhealthy"
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(_record(target, health)), stderr="")

    monkeypatch.setattr("incident_response_agent.container_lab.subprocess.run", fake_run)
    observation = target.restart_and_wait()
    assert observation.health_before == "unhealthy"
    assert observation.health_after == "healthy"
    assert observation.boot_count == 2
    assert ["podman", "restart", "--time", "2", CID] in calls


def test_restart_failure_is_typed_and_does_not_claim_success(tmp_path, monkeypatch):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    services = sandbox.root / "services"
    services.mkdir()
    (services / "boot-count").write_text("1", encoding="utf-8")
    target = DisposableContainerService(sandbox, TEST_IMAGE, "podman", timeout_seconds=1)
    target.container_id = CID

    def fake_run(command, **kwargs):
        if command[1] == "restart":
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="failure")
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(_record(target)), stderr="")

    monkeypatch.setattr("incident_response_agent.container_lab.subprocess.run", fake_run)
    result = DisposableServiceRestartExecutor(target).execute(_option())
    assert result.success is False
    assert result.service_restarted is False
    assert result.failure_reason_code == "target_restart_failed"


def test_cleanup_failure_is_reported_and_sandbox_is_retained(tmp_path, monkeypatch):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    target = DisposableContainerService(sandbox, TEST_IMAGE, "podman")
    target.container_id = CID

    def fake_run(command, **kwargs):
        if command[1] == "rm":
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="failure")
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(_record(target)), stderr="")

    monkeypatch.setattr("incident_response_agent.container_lab.subprocess.run", fake_run)
    with pytest.raises(ContainerLabError) as raised:
        target.close()
    assert raised.value.reason_code == "container_cleanup_failed"
    assert sandbox.root.exists()
