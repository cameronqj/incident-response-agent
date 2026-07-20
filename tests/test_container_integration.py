from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from incident_response_agent.executor import ContainerRemediationExecutor
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.schemas import RemediationOption, ScenarioKind
from conftest import TEST_IMAGE


@pytest.mark.integration
def test_podman_failure_lab_is_non_root_and_isolated():
    if os.getenv("RUN_CONTAINER_TESTS") != "1":
        pytest.skip("set RUN_CONTAINER_TESTS=1 to run container integration")
    engine = shutil.which("podman") or shutil.which("docker")
    if not engine:
        pytest.fail("RUN_CONTAINER_TESTS=1 requires Docker or Podman")
    health = subprocess.run([engine, "info"], capture_output=True, text=True, timeout=20, check=False)
    if health.returncode != 0:
        pytest.fail(f"container engine is installed but unavailable: {health.stderr.strip()}")
    script = """
import errno
from pathlib import Path

target = Path('/lab/app.1.rotated')
written = 0
handle = target.open('wb')
try:
    while True:
        handle.write(b'x' * 65536)
        handle.flush()
        written += 65536
except OSError as error:
    assert error.errno == errno.ENOSPC, error
finally:
    handle.close()

assert target.exists()
target.unlink()
assert not target.exists()
print(f'recovered after {written} bytes')
"""
    result = subprocess.run(
        [
            engine,
            "run",
            "--rm",
            "--network=none",
            "--user",
            "65532:65532",
            "--mount",
            "type=tmpfs,destination=/lab,tmpfs-size=2097152,tmpfs-mode=1777",
            TEST_IMAGE,
            "python",
            "-c",
            "import os; assert os.geteuid() != 0\n" + script,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "recovered after" in result.stdout
    assert ScenarioKind.CONTAINER_FAULT.value == "container_fault"


@pytest.mark.integration
def test_memory_pressure_hits_hard_container_limit():
    if os.getenv("RUN_CONTAINER_TESTS") != "1":
        pytest.skip("set RUN_CONTAINER_TESTS=1 to run container integration")
    engine = shutil.which("podman") or shutil.which("docker")
    if not engine:
        pytest.fail("RUN_CONTAINER_TESTS=1 requires Docker or Podman")
    health = subprocess.run([engine, "info"], capture_output=True, text=True, timeout=20, check=False)
    if health.returncode != 0:
        pytest.fail(f"container engine is installed but unavailable: {health.stderr.strip()}")
    result = subprocess.run(
        [
            engine,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--memory=32m",
            "--memory-swap=32m",
            "--pids-limit=64",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            "65532:65532",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            TEST_IMAGE,
            "python",
            "-c",
            "chunks=[]; [chunks.append(bytearray(1024 * 1024)) for _ in range(128)]",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode in {137, -9}, result.stderr
    assert ScenarioKind.CONTAINER_FAULT.value == "container_fault"


@pytest.mark.integration
@pytest.mark.parametrize("action_id", ["cleanup_rotated_logs", "stop_runaway_process", "restart_disposable_service", "stop_memory_hog", "cleanup_log_storm_temp_files"])
def test_agent_remediation_executes_inside_container(tmp_path, action_id):
    if os.getenv("RUN_CONTAINER_TESTS") != "1":
        pytest.skip("set RUN_CONTAINER_TESTS=1 to run container integration")
    engine = shutil.which("podman") or shutil.which("docker")
    if not engine:
        pytest.fail("RUN_CONTAINER_TESTS=1 requires Docker or Podman")
    health = subprocess.run([engine, "info"], capture_output=True, text=True, timeout=20, check=False)
    if health.returncode != 0:
        pytest.fail(f"container engine is installed but unavailable: {health.stderr.strip()}")
    sandbox = DisposableSandbox.create_test_fixture(tmp_path)
    if action_id == "cleanup_rotated_logs":
        marker_root = sandbox.root / "logs"
        marker = marker_root / "service.1.rotated"
        marker_root.mkdir()
        marker.write_text("synthetic artifact", encoding="utf-8")
    elif action_id == "stop_runaway_process":
        marker_root = sandbox.root / "processes"
        marker = marker_root / "runaway_cpu.marker"
        marker_root.mkdir()
        marker.write_text("synthetic artifact", encoding="utf-8")
    elif action_id == "stop_memory_hog":
        marker_root = sandbox.root / "memory"
        marker = marker_root / "memory_hog.marker"
        marker_root.mkdir()
        marker.write_text("synthetic artifact", encoding="utf-8")
    elif action_id == "cleanup_log_storm_temp_files":
        marker_root = sandbox.root / "logs" / "storm"
        marker = marker_root / "service.1.storm"
        marker_root.mkdir(parents=True)
        marker.write_text("synthetic artifact", encoding="utf-8")
        temp_root = sandbox.root / "tmp"
        temp_root.mkdir()
        (temp_root / "cache.tmp").write_text("synthetic artifact", encoding="utf-8")
    else:
        marker_root = sandbox.root / "services"
        marker = marker_root / "restart_loop.marker"
        marker_root.mkdir()
        marker.write_text("synthetic artifact", encoding="utf-8")
    result = ContainerRemediationExecutor(sandbox, TEST_IMAGE, engine=engine).execute(
        RemediationOption(
            action_id=action_id,
            title=action_id,
            evidence=["low_free_space"],
            confidence=1.0,
            impact="bounded",
            risk="low",
            action_preview="fixed",
        )
    )
    assert result.success, f"{result.failure_reason_code}: {result.diagnostic}"
    assert not marker.exists()
    if action_id == "cleanup_log_storm_temp_files":
        assert not (sandbox.root / "tmp" / "cache.tmp").exists()
    if action_id == "restart_disposable_service":
        assert (sandbox.root / "services" / "healthy.marker").exists()
