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
        if option.action_id != "cleanup_rotated_logs":
            return ExecutionResult(False, "action is not authorized", failure_reason_code="unauthorized_action")
        logs_root = (self.sandbox_root / "logs").resolve()
        if self.sandbox_root not in logs_root.parents:
            return ExecutionResult(False, "sandbox target escaped root", failure_reason_code="sandbox_escape")
        try:
            logs_root.mkdir(parents=True, exist_ok=True)
            deleted = 0
            for candidate in logs_root.iterdir():
                if candidate.is_file() and candidate.suffix in {".rotated", ".gz"}:
                    candidate.unlink()
                    deleted += 1
            return ExecutionResult(True, "rotated log cleanup completed", deleted_count=deleted)
        except OSError:
            return ExecutionResult(False, "cleanup failed", failure_reason_code="filesystem_error")


CONTAINER_CLEANUP_SCRIPT = """
from pathlib import Path

root = Path('/incident-sandbox/logs')
root.mkdir(parents=True, exist_ok=True)
deleted = 0
for candidate in root.iterdir():
    if candidate.is_file() and candidate.suffix in {'.rotated', '.gz'}:
        candidate.unlink()
        deleted += 1
print(f'cleanup_rotated_logs deleted={deleted}')
"""


class ContainerRemediationExecutor:
    """Execute only the fixed allowlisted cleanup inside an isolated container."""

    def __init__(self, sandbox_root: str, image: str = "python:3.12-alpine", engine: str | None = None, timeout_seconds: float = 30.0):
        self.sandbox_root = Path(sandbox_root).resolve()
        self.image = image
        self.engine = engine or shutil.which("podman") or shutil.which("docker")
        self.timeout_seconds = timeout_seconds

    def execute(self, option: RemediationOption) -> ExecutionResult:
        if option.action_id != "cleanup_rotated_logs":
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
                CONTAINER_CLEANUP_SCRIPT,
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
