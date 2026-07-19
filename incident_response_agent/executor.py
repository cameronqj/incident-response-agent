from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Protocol

from .schemas import RemediationOption


class ExecutionResult:
    def __init__(self, success: bool, message: str, deleted_count: int = 0, failure_reason_code: str | None = None):
        self.success = success
        self.message = message
        self.deleted_count = deleted_count
        self.failure_reason_code = failure_reason_code


class RemediationExecutor(Protocol):
    def execute(self, option: RemediationOption) -> ExecutionResult: ...


class DisposableFilesystemExecutor:
    """Resolves targets in code; it accepts no model-provided path or command."""

    def __init__(self, sandbox_root: str):
        self.sandbox_root = Path(sandbox_root).resolve()

    def execute(self, option: RemediationOption) -> ExecutionResult:
        if option.action_id not in {
            "cleanup_rotated_logs",
            "stop_runaway_process",
            "restart_disposable_service",
            "stop_memory_hog",
            "cleanup_log_storm_temp_files",
        }:
            return ExecutionResult(False, "action is not authorized", failure_reason_code="unauthorized_action")
        try:
            if option.action_id == "cleanup_rotated_logs":
                target = (self.sandbox_root / "logs").resolve()
                if self.sandbox_root not in target.parents:
                    return ExecutionResult(False, "sandbox target escaped root", failure_reason_code="sandbox_escape")
                target.mkdir(parents=True, exist_ok=True)
                deleted = 0
                for candidate in target.iterdir():
                    if candidate.is_file() and candidate.suffix in {".rotated", ".gz"}:
                        candidate.unlink()
                        deleted += 1
                return ExecutionResult(True, "rotated log cleanup completed", deleted_count=deleted)
            if option.action_id == "stop_runaway_process":
                marker = (self.sandbox_root / "processes" / "runaway_cpu.marker").resolve()
                if self.sandbox_root not in marker.parents:
                    return ExecutionResult(False, "sandbox target escaped root", failure_reason_code="sandbox_escape")
                deleted = int(marker.is_file())
                if deleted:
                    marker.unlink()
                return ExecutionResult(True, "runaway process fixture stopped", deleted_count=deleted)
            if option.action_id == "stop_memory_hog":
                marker = (self.sandbox_root / "memory" / "memory_hog.marker").resolve()
                if self.sandbox_root not in marker.parents:
                    return ExecutionResult(False, "sandbox target escaped root", failure_reason_code="sandbox_escape")
                deleted = int(marker.is_file())
                if deleted:
                    marker.unlink()
                return ExecutionResult(True, "memory-hog fixture stopped", deleted_count=deleted)
            if option.action_id == "cleanup_log_storm_temp_files":
                deleted = 0
                for relative_root, suffixes in (("logs/storm", {".storm"}), ("tmp", {".tmp"})):
                    target = (self.sandbox_root / relative_root).resolve()
                    if self.sandbox_root not in target.parents:
                        return ExecutionResult(False, "sandbox target escaped root", failure_reason_code="sandbox_escape")
                    if not target.is_dir():
                        continue
                    for candidate in target.iterdir():
                        if candidate.is_file() and candidate.suffix in suffixes:
                            candidate.unlink()
                            deleted += 1
                return ExecutionResult(True, "log-storm temporary-file cleanup completed", deleted_count=deleted)
            services = (self.sandbox_root / "services").resolve()
            if self.sandbox_root not in services.parents:
                return ExecutionResult(False, "sandbox target escaped root", failure_reason_code="sandbox_escape")
            services.mkdir(parents=True, exist_ok=True)
            loop_marker = services / "restart_loop.marker"
            if loop_marker.exists():
                loop_marker.unlink()
            (services / "healthy.marker").write_text("healthy", encoding="utf-8")
            return ExecutionResult(True, "disposable service restarted", deleted_count=1)
        except OSError:
            return ExecutionResult(False, "cleanup failed", failure_reason_code="filesystem_error")


CONTAINER_ACTION_SCRIPTS = {
    "cleanup_rotated_logs": """
from pathlib import Path

root = Path('/incident-sandbox/logs')
root.mkdir(parents=True, exist_ok=True)
deleted = 0
for candidate in root.iterdir():
    if candidate.is_file() and candidate.suffix in {'.rotated', '.gz'}:
        candidate.unlink()
        deleted += 1
print(f'cleanup_rotated_logs deleted={deleted}')
""",
    "stop_runaway_process": """
from pathlib import Path

marker = Path('/incident-sandbox/processes/runaway_cpu.marker')
deleted = int(marker.is_file())
if marker.is_file():
    marker.unlink()
print(f'stop_runaway_process deleted={deleted}')
""",
    "restart_disposable_service": """
from pathlib import Path

root = Path('/incident-sandbox/services')
root.mkdir(parents=True, exist_ok=True)
loop_marker = root / 'restart_loop.marker'
deleted = int(loop_marker.is_file())
if loop_marker.is_file():
    loop_marker.unlink()
(root / 'healthy.marker').write_text('healthy')
print(f'restart_disposable_service deleted={deleted}')
""",
    "stop_memory_hog": """
from pathlib import Path

marker = Path('/incident-sandbox/memory/memory_hog.marker')
deleted = int(marker.is_file())
if marker.is_file():
    marker.unlink()
print(f'stop_memory_hog deleted={deleted}')
""",
    "cleanup_log_storm_temp_files": """
from pathlib import Path

deleted = 0
for relative_root, suffixes in (
    ('logs/storm', {'.storm'}),
    ('tmp', {'.tmp'}),
):
    root = Path('/incident-sandbox') / relative_root
    if not root.is_dir():
        continue
    for candidate in root.iterdir():
        if candidate.is_file() and candidate.suffix in suffixes:
            candidate.unlink()
            deleted += 1
print(f'cleanup_log_storm_temp_files deleted={deleted}')
""",
}


class ContainerRemediationExecutor:
    """Execute only the fixed allowlisted cleanup inside an isolated container."""

    def __init__(self, sandbox_root: str, image: str = "python:3.12-alpine", engine: str | None = None, timeout_seconds: float = 30.0):
        self.sandbox_root = Path(sandbox_root).resolve()
        self.image = image
        self.engine = engine or shutil.which("podman") or shutil.which("docker")
        self.timeout_seconds = timeout_seconds

    def execute(self, option: RemediationOption) -> ExecutionResult:
        script = CONTAINER_ACTION_SCRIPTS.get(option.action_id)
        if script is None:
            return ExecutionResult(False, "action is not authorized", failure_reason_code="unauthorized_action")
        if self.sandbox_root == Path("/") or self.sandbox_root.parent == self.sandbox_root:
            return ExecutionResult(False, "sandbox root is not bounded", failure_reason_code="unsafe_sandbox_root")
        if not self.engine:
            return ExecutionResult(False, "container engine unavailable", failure_reason_code="container_engine_unavailable")
        logs_root = self.sandbox_root / "logs"
        try:
            logs_root.mkdir(parents=True, exist_ok=True)
            logs_root.chmod(0o777)
            command = [
                self.engine,
                "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user",
                "65532:65532",
                "--mount",
                f"type=bind,src={self.sandbox_root},dst=/incident-sandbox,rw",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                self.image,
                "python",
                "-c",
                script,
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout_seconds, check=False)
        except subprocess.TimeoutExpired:
            return ExecutionResult(False, "container cleanup timed out", failure_reason_code="execution_timeout")
        except OSError:
            return ExecutionResult(False, "container execution failed", failure_reason_code="container_runtime_error")
        if result.returncode != 0:
            return ExecutionResult(False, "container cleanup failed", failure_reason_code="container_exit_nonzero")
        match = re.search(r"deleted=(\d+)", result.stdout)
        deleted = int(match.group(1)) if match else 0
        return ExecutionResult(True, "container cleanup completed", deleted_count=deleted)
