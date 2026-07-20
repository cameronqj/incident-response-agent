from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .sandbox import DisposableSandbox


LAB_LABEL = "io.incident-response-agent.disposable-service"

SERVICE_SCRIPT = """
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

state = Path('/incident-sandbox/services/boot-count')
state.parent.mkdir(parents=True, exist_ok=True)
try:
    boot_count = int(state.read_text()) + 1
except (FileNotFoundError, ValueError):
    boot_count = 1
state.write_text(str(boot_count))
response_status = 503 if boot_count == 1 else 200

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(response_status if self.path == '/health' else 404)
        self.end_headers()
        self.wfile.write(b'unhealthy' if response_status != 200 else b'healthy')

    def log_message(self, *_args):
        pass

HTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
"""

HEALTH_COMMAND = (
    "python -c \"import urllib.request; "
    "urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=1)\""
)


class ContainerLabError(RuntimeError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class ContainerSnapshot:
    container_id: str
    runtime_status: str
    health_status: str
    boot_count: int


@dataclass(frozen=True)
class RestartObservation:
    health_before: str
    health_after: str
    boot_count: int
    attempts: int
    latency_ms: int


class DisposableContainerService:
    """Owned capability for one hardened disposable service container."""

    def __init__(
        self,
        sandbox: DisposableSandbox,
        image: str,
        engine: str,
        timeout_seconds: float = 30.0,
    ):
        if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image):
            raise ValueError("container image must be pinned by sha256 digest")
        if not engine:
            raise ContainerLabError("container_engine_unavailable", "container engine is unavailable")
        self.sandbox = sandbox
        self.image = image
        self.engine = engine
        self.timeout_seconds = timeout_seconds
        self.lab_id = uuid.uuid4().hex
        self.container_name = f"incident-service-{self.lab_id}"
        self.container_id: str | None = None

    @property
    def _is_podman(self) -> bool:
        return Path(self.engine).name == "podman"

    def _identity(self) -> str:
        return self.container_id or self.container_name

    def _run(self, command: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ContainerLabError("container_command_timeout", "container command timed out") from exc
        except OSError as exc:
            raise ContainerLabError("container_runtime_error", "container command failed") from exc

    def start(self) -> ContainerSnapshot:
        if self.container_id is not None:
            raise ContainerLabError("target_already_started", "disposable service is already started")
        self.sandbox.validate()
        services = self.sandbox.resolve_child("services")
        services.mkdir(mode=0o700, exist_ok=True)
        process_uid = os.geteuid() if hasattr(os, "geteuid") else 65532
        process_gid = os.getegid() if hasattr(os, "getegid") else 65532
        uid = process_uid if process_uid != 0 else 65532
        gid = process_gid if process_uid != 0 else 65532
        if process_uid == 0:
            services.chmod(0o700)
        self.sandbox.prepare_container_access(("services",))
        command = [
            self.engine,
            "run",
            "-d",
            "--pull=missing",
            "--name",
            self.container_name,
            "--label",
            f"{LAB_LABEL}={self.lab_id}",
            "--restart=no",
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
            "--health-cmd",
            HEALTH_COMMAND,
            "--health-interval=1s",
            "--health-timeout=1s",
            "--health-retries=2",
            self.image,
            "python",
            "-c",
            SERVICE_SCRIPT,
        ])
        result = self._run(command)
        if result.returncode != 0:
            self.close()
            raise ContainerLabError("container_start_failed", "disposable service failed to start")
        candidate = result.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", candidate):
            self.close()
            raise ContainerLabError("container_identity_invalid", "container runtime returned an invalid target identity")
        self.container_id = candidate
        try:
            snapshot, _ = self.wait_for_health("unhealthy", self.timeout_seconds)
            return snapshot
        except Exception:
            self.close()
            raise

    def _inspect_raw(self) -> dict:
        result = self._run([self.engine, "inspect", self._identity()], timeout=5)
        if result.returncode != 0:
            raise ContainerLabError("target_container_missing", "owned disposable service is missing")
        try:
            payload = json.loads(result.stdout)
            record = payload[0]
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
            raise ContainerLabError("container_inspect_invalid", "container inspection returned invalid data") from exc
        labels = (record.get("Config") or {}).get("Labels") or {}
        if labels.get(LAB_LABEL) != self.lab_id:
            raise ContainerLabError("target_ownership_mismatch", "container ownership label does not match")
        bind_mounts = [mount for mount in record.get("Mounts") or [] if mount.get("Type") == "bind"]
        if len(bind_mounts) != 1:
            raise ContainerLabError("target_mount_mismatch", "container has an unexpected bind-mount set")
        mount = bind_mounts[0]
        source = Path(str(mount.get("Source", ""))).resolve()
        if source != self.sandbox.root or mount.get("Destination") != "/incident-sandbox" or mount.get("RW") is not True:
            raise ContainerLabError("target_mount_mismatch", "container sandbox mount does not match")
        if (record.get("HostConfig") or {}).get("Privileged") is True:
            raise ContainerLabError("target_security_mismatch", "container unexpectedly has privileged mode")
        return record

    def snapshot(self) -> ContainerSnapshot:
        self.sandbox.validate()
        if self.container_id is None:
            raise ContainerLabError("target_container_missing", "disposable service has not been started")
        record = self._inspect_raw()
        state = record.get("State") or {}
        health = state.get("Health") or {}
        boot_file = self.sandbox.resolve_child("services/boot-count")
        try:
            boot_count = int(boot_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError, OSError):
            boot_count = 0
        return ContainerSnapshot(
            container_id=self.container_id,
            runtime_status=str(state.get("Status", "unknown")),
            health_status=str(health.get("Status", "unknown")),
            boot_count=boot_count,
        )

    def wait_for_health(self, expected: str, timeout_seconds: float) -> tuple[ContainerSnapshot, int]:
        deadline = time.monotonic() + timeout_seconds
        attempts = 0
        last: ContainerSnapshot | None = None
        while time.monotonic() < deadline:
            attempts += 1
            last = self.snapshot()
            if last.health_status == expected:
                return last, attempts
            time.sleep(0.25)
        actual = last.health_status if last else "unknown"
        detail = ""
        try:
            state = self._inspect_raw().get("State") or {}
            health = state.get("Health") or {}
            logs = health.get("Log") or []
            if logs:
                output = str(logs[-1].get("Output", "")).replace(str(self.sandbox.root), "<sandbox>").strip()[:512]
                if output:
                    detail = f": {output}"
        except ContainerLabError:
            pass
        raise ContainerLabError("target_health_timeout", f"target health remained {actual}, expected {expected}{detail}")

    def restart_and_wait(self) -> RestartObservation:
        before = self.snapshot()
        if before.health_status != "unhealthy":
            raise ContainerLabError("target_not_unhealthy", "only an unhealthy disposable service may be restarted")
        started = time.monotonic()
        result = self._run([self.engine, "restart", "--time", "2", before.container_id])
        if result.returncode != 0:
            raise ContainerLabError("target_restart_failed", "disposable service restart failed")
        after, attempts = self.wait_for_health("healthy", self.timeout_seconds)
        if after.container_id != before.container_id:
            raise ContainerLabError("target_identity_changed", "container identity changed during restart")
        return RestartObservation(
            health_before=before.health_status,
            health_after=after.health_status,
            boot_count=after.boot_count,
            attempts=attempts,
            latency_ms=int((time.monotonic() - started) * 1000),
        )

    def close(self) -> None:
        identity = self._identity()
        cleanup_error: ContainerLabError | None = None
        try:
            command = [self.engine, "rm", "-f"]
            if self._is_podman:
                command.extend(["--time", "0"])
            command.append(identity)
            try:
                self._run(command, timeout=10)
            except ContainerLabError as exc:
                cleanup_error = exc
            try:
                remaining = self._run([self.engine, "inspect", identity], timeout=5).returncode == 0
            except ContainerLabError:
                remaining = True
            if remaining:
                raise ContainerLabError("container_cleanup_failed", "disposable service container was not removed") from cleanup_error
            self.container_id = None
            self.sandbox.close()
        finally:
            if self.sandbox.root.exists():
                try:
                    self.sandbox.restore_owner_access(("services",))
                except (OSError, ValueError) as exc:
                    raise ContainerLabError(
                        "sandbox_permission_restore_failed",
                        "disposable service sandbox permissions could not be restored",
                    ) from exc
