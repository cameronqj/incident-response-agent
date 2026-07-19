from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from incident_response_agent.executor import ContainerRemediationExecutor
from incident_response_agent.schemas import RemediationOption


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
            "python:3.12-alpine",
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
    if action_id == "cleanup_rotated_logs":
        marker_root = tmp_path / "logs"
        marker = marker_root / "service.1.rotated"
        marker_root.mkdir()
        marker.write_text("synthetic artifact", encoding="utf-8")
    elif action_id == "stop_runaway_process":
        marker_root = tmp_path / "processes"
        marker = marker_root / "runaway_cpu.marker"
        marker_root.mkdir()
        marker.write_text("synthetic artifact", encoding="utf-8")
    elif action_id == "stop_memory_hog":
        marker_root = tmp_path / "memory"
        marker = marker_root / "memory_hog.marker"
        marker_root.mkdir()
        marker.write_text("synthetic artifact", encoding="utf-8")
    elif action_id == "cleanup_log_storm_temp_files":
        marker_root = tmp_path / "logs" / "storm"
        marker = marker_root / "service.1.storm"
        marker_root.mkdir(parents=True)
        marker.write_text("synthetic artifact", encoding="utf-8")
        temp_root = tmp_path / "tmp"
        temp_root.mkdir()
        (temp_root / "cache.tmp").write_text("synthetic artifact", encoding="utf-8")
    else:
        marker_root = tmp_path / "services"
        marker = marker_root / "restart_loop.marker"
        marker_root.mkdir()
        marker.write_text("synthetic artifact", encoding="utf-8")
    result = ContainerRemediationExecutor(str(tmp_path), engine=engine).execute(
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
    assert result.success, result.failure_reason_code
    assert not marker.exists()
    if action_id == "cleanup_log_storm_temp_files":
        assert not (tmp_path / "tmp" / "cache.tmp").exists()
    if action_id == "restart_disposable_service":
        assert (tmp_path / "services" / "healthy.marker").exists()
