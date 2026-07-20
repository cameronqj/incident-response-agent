from __future__ import annotations

import subprocess

import pytest

from conftest import TEST_IMAGE
from incident_response_agent.executor import ContainerRemediationExecutor
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.schemas import RemediationOption


def _option() -> RemediationOption:
    return RemediationOption(
        action_id="cleanup_rotated_logs",
        title="cleanup",
        evidence=["rotation_error"],
        confidence=1.0,
        impact="bounded",
        risk="low",
        action_preview="fixed",
    )


def test_container_command_enforces_limits_and_exact_mount(tmp_path, monkeypatch):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="cleanup_rotated_logs deleted=0", stderr="")

    monkeypatch.setattr("incident_response_agent.executor.subprocess.run", fake_run)
    result = ContainerRemediationExecutor(sandbox, TEST_IMAGE, engine="podman", timeout_seconds=7).execute(_option())
    assert result.success is True
    command = calls[0]
    for flag in (
        "--rm",
        "--pull=missing",
        "--network=none",
        "--read-only",
        "--cpus=0.5",
        "--memory=128m",
        "--memory-swap=128m",
        "--pids-limit=64",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ):
        assert flag in command
    assert "--privileged" not in command
    assert command[command.index("--user") + 1].split(":", 1)[0] != "0"
    assert command.count("--mount") == 1
    assert command[command.index("--mount") + 1] == f"type=bind,src={sandbox.root},dst=/incident-sandbox,rw"
    assert command[command.index("--tmpfs") + 1] == "/tmp:rw,noexec,nosuid,size=16m"
    assert TEST_IMAGE in command
    container_name = command[command.index("--name") + 1]
    assert calls[-1] == ["podman", "rm", "-f", container_name]


def test_docker_preserves_host_uid_mapping_for_owned_sandbox(tmp_path, monkeypatch):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="cleanup_rotated_logs deleted=0", stderr="")

    monkeypatch.setattr("incident_response_agent.executor.subprocess.run", fake_run)
    result = ContainerRemediationExecutor(sandbox, TEST_IMAGE, engine="/usr/bin/docker").execute(_option())
    assert result.success is True
    assert "--userns=host" in calls[0]


def test_timeout_forcibly_cleans_exact_container(tmp_path, monkeypatch):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[1] == "run":
            raise subprocess.TimeoutExpired(command, 1)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("incident_response_agent.executor.subprocess.run", fake_run)
    result = ContainerRemediationExecutor(sandbox, TEST_IMAGE, engine="podman", timeout_seconds=1).execute(_option())
    assert result.success is False
    assert result.failure_reason_code == "execution_timeout"
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["podman", "rm", "-f", name]


def test_mutable_container_image_is_rejected(tmp_path):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    with pytest.raises(ValueError):
        ContainerRemediationExecutor(sandbox, "python:3.12-alpine", engine="podman")
