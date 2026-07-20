from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from typing import Protocol

from .container_lab import ContainerLabError, DisposableContainerService
from .sandbox import DisposableSandbox, SandboxViolation
from .schemas import RemediationOption


class ExecutionResult:
    def __init__(
        self,
        success: bool,
        message: str,
        deleted_count: int = 0,
        failure_reason_code: str | None = None,
        *,
        service_restarted: bool = False,
        health_before: str | None = None,
        health_after: str | None = None,
        attempts: int = 0,
        latency_ms: int = 0,
        boot_count: int = 0,
        diagnostic: str | None = None,
    ):
        self.success = success
        self.message = message
        self.deleted_count = deleted_count
        self.failure_reason_code = failure_reason_code
        self.service_restarted = service_restarted
        self.health_before = health_before
        self.health_after = health_after
        self.attempts = attempts
        self.latency_ms = latency_ms
        self.boot_count = boot_count
        # Runtime diagnostics are intentionally not written to audit records or API
        # responses. They exist only so direct adapter tests can explain failures.
        self.diagnostic = diagnostic


class RemediationExecutor(Protocol):
    def execute(self, option: RemediationOption) -> ExecutionResult: ...

    def close(self) -> None: ...


class DisabledExecutor:
    def execute(self, option: RemediationOption) -> ExecutionResult:
        return ExecutionResult(False, "remediation execution is disabled", failure_reason_code="execution_disabled")

    def close(self) -> None:
        pass


class DisposableServiceRestartExecutor:
    """Restart only the exact service represented by an owned lab capability."""

    def __init__(self, target: DisposableContainerService):
        self.target = target

    def execute(self, option: RemediationOption) -> ExecutionResult:
        if option.action_id != "restart_unhealthy_container_service":
            return ExecutionResult(False, "action is not authorized", failure_reason_code="unauthorized_action")
        try:
            observation = self.target.restart_and_wait()
        except ContainerLabError as exc:
            return ExecutionResult(False, "disposable service restart failed", failure_reason_code=exc.reason_code)
        return ExecutionResult(
            True,
            "disposable service restarted and verified healthy",
            service_restarted=True,
            health_before=observation.health_before,
            health_after=observation.health_after,
            attempts=observation.attempts,
            latency_ms=observation.latency_ms,
            boot_count=observation.boot_count,
        )

    def close(self) -> None:
        self.target.close()


class DisposableFilesystemExecutor:
    """Resolves targets in code; it accepts no model-provided path or command."""

    def __init__(self, sandbox: DisposableSandbox):
        self.sandbox = sandbox

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
            self.sandbox.validate()
            if option.action_id == "cleanup_rotated_logs":
                target = self.sandbox.resolve_child("logs")
                target.mkdir(parents=True, exist_ok=True)
                deleted = 0
                for candidate in target.iterdir():
                    if candidate.is_file() and candidate.suffix in {".rotated", ".gz"}:
                        candidate.unlink()
                        deleted += 1
                return ExecutionResult(True, "rotated log cleanup completed", deleted_count=deleted)
            if option.action_id == "stop_runaway_process":
                marker = self.sandbox.resolve_child("processes/runaway_cpu.marker")
                deleted = int(marker.is_file())
                if deleted:
                    marker.unlink()
                return ExecutionResult(True, "runaway-CPU marker fixture cleared", deleted_count=deleted)
            if option.action_id == "stop_memory_hog":
                marker = self.sandbox.resolve_child("memory/memory_hog.marker")
                deleted = int(marker.is_file())
                if deleted:
                    marker.unlink()
                return ExecutionResult(True, "memory-pressure marker fixture cleared", deleted_count=deleted)
            if option.action_id == "cleanup_log_storm_temp_files":
                deleted = 0
                for relative_root, suffixes in (("logs/storm", {".storm"}), ("tmp", {".tmp"})):
                    target = self.sandbox.resolve_child(relative_root)
                    if not target.is_dir():
                        continue
                    for candidate in target.iterdir():
                        if candidate.is_file() and candidate.suffix in suffixes:
                            candidate.unlink()
                            deleted += 1
                return ExecutionResult(True, "log-storm temporary-file cleanup completed", deleted_count=deleted)
            services = self.sandbox.resolve_child("services")
            services.mkdir(parents=True, exist_ok=True)
            loop_marker = services / "restart_loop.marker"
            if loop_marker.exists():
                loop_marker.unlink()
            (services / "healthy.marker").write_text("healthy", encoding="utf-8")
            return ExecutionResult(True, "restart-loop marker fixture reset", deleted_count=1)
        except SandboxViolation:
            return ExecutionResult(False, "sandbox validation failed", failure_reason_code="unsafe_sandbox_root")
        except OSError:
            return ExecutionResult(False, "cleanup failed", failure_reason_code="filesystem_error")

    def close(self) -> None:
        self.sandbox.close()


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

CONTAINER_ACTION_DIRECTORIES = {
    "cleanup_rotated_logs": ("logs",),
    "stop_runaway_process": ("processes",),
    "restart_disposable_service": ("services",),
    "stop_memory_hog": ("memory",),
    "cleanup_log_storm_temp_files": ("logs", "logs/storm", "tmp"),
}


class ContainerRemediationExecutor:
    """Execute only the fixed allowlisted cleanup inside an isolated container."""

    def __init__(self, sandbox: DisposableSandbox, image: str, engine: str | None = None, timeout_seconds: float = 30.0):
        if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image):
            raise ValueError("container image must be pinned by sha256 digest")
        self.sandbox = sandbox
        self.image = image
        self.engine = engine or shutil.which("podman") or shutil.which("docker")
        self.timeout_seconds = timeout_seconds

    def execute(self, option: RemediationOption) -> ExecutionResult:
        script = CONTAINER_ACTION_SCRIPTS.get(option.action_id)
        if script is None:
            return ExecutionResult(False, "action is not authorized", failure_reason_code="unauthorized_action")
        if not self.engine:
            return ExecutionResult(False, "container engine unavailable", failure_reason_code="container_engine_unavailable")
        container_name = f"incident-agent-{uuid.uuid4().hex}"
        process_uid = os.geteuid() if hasattr(os, "geteuid") else 65532
        process_gid = os.getegid() if hasattr(os, "getegid") else 65532
        uid = process_uid if process_uid != 0 else 65532
        gid = process_gid if process_uid != 0 else 65532
        writable_directories = CONTAINER_ACTION_DIRECTORIES[option.action_id]
        try:
            self.sandbox.validate()
            self.sandbox.prepare_container_access(writable_directories)
            command = [
                self.engine,
                "run",
                "--rm",
                "--pull=missing",
                "--name",
                container_name,
                "--network=none",
                "--read-only",
                "--cpus=0.5",
                "--memory=128m",
                "--memory-swap=128m",
                "--pids-limit=64",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
            ]
            command.extend([
                "--user",
                f"{uid}:{gid}",
                "--mount",
                f"type=bind,src={self.sandbox.root},dst=/incident-sandbox,rw",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                self.image,
                "python",
                "-c",
                script,
            ])
            result = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout_seconds, check=False)
        except subprocess.TimeoutExpired:
            return ExecutionResult(False, "container cleanup timed out", failure_reason_code="execution_timeout")
        except SandboxViolation:
            return ExecutionResult(False, "sandbox validation failed", failure_reason_code="unsafe_sandbox_root")
        except OSError:
            return ExecutionResult(False, "container execution failed", failure_reason_code="container_runtime_error")
        finally:
            try:
                subprocess.run(
                    [self.engine, "rm", "-f", container_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
            if self.sandbox.root.exists():
                try:
                    self.sandbox.restore_owner_access(writable_directories)
                except (OSError, SandboxViolation):
                    return ExecutionResult(
                        False,
                        "sandbox permissions could not be restored",
                        failure_reason_code="sandbox_permission_restore_failed",
                    )
        if result.returncode != 0:
            diagnostic = (result.stderr or result.stdout).replace(str(self.sandbox.root), "<sandbox>").strip()[:512]
            return ExecutionResult(
                False,
                "container cleanup failed",
                failure_reason_code="container_exit_nonzero",
                diagnostic=diagnostic or "container exited without diagnostic output",
            )
        match = re.search(r"deleted=(\d+)", result.stdout)
        deleted = int(match.group(1)) if match else 0
        return ExecutionResult(True, "container cleanup completed", deleted_count=deleted)

    def close(self) -> None:
        self.sandbox.close()
