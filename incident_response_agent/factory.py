from __future__ import annotations

import os
import shutil

from .config import Settings
from .container_lab import DisposableContainerService
from .executor import ContainerRemediationExecutor, DisabledExecutor, DisposableServiceRestartExecutor
from .model import FakeAnalyzer, LiveOpenAICompatibleAnalyzer
from .observability import build_observability
from .service import IncidentService
from .sandbox import DisposableSandbox
from .storage import SQLiteStore
from .telemetry import ContainerServiceTelemetry, DeterministicENOSPCTelemetry


def build_service(settings: Settings | None = None) -> IncidentService:
    settings = settings or Settings.from_env()
    settings.validate()
    store = SQLiteStore(settings.database_path)
    try:
        observability = build_observability(settings)
    except Exception:
        store.close()
        raise
    if settings.app_mode == "live":
        api_key = os.getenv(settings.api_key_env)
        if not api_key:
            raise ValueError(f"{settings.api_key_env} is required when APP_MODE=live")
        analyzer = LiveOpenAICompatibleAnalyzer(settings.base_url, settings.model, api_key, settings.model_timeout_seconds, settings.model_max_retries)
    else:
        analyzer = FakeAnalyzer()
    execution_engine = settings.execution_engine
    engine = execution_engine if execution_engine in {"podman", "docker"} else shutil.which("podman") or shutil.which("docker")
    if settings.lab_mode == "container-service":
        target = DisposableContainerService(
            DisposableSandbox.create_runtime(),
            settings.container_image,
            engine or "",
            settings.execution_timeout_seconds,
        )
        try:
            target.start()
        except Exception:
            observability.shutdown()
            store.close()
            raise
        telemetry = ContainerServiceTelemetry(target)
        executor = DisposableServiceRestartExecutor(target)
    elif not settings.execution_enabled:
        telemetry = DeterministicENOSPCTelemetry()
        executor = DisabledExecutor()
    elif execution_engine == "podman":
        telemetry = DeterministicENOSPCTelemetry()
        executor = ContainerRemediationExecutor(DisposableSandbox.create_runtime(), settings.container_image, "podman", settings.execution_timeout_seconds)
    elif execution_engine == "docker":
        telemetry = DeterministicENOSPCTelemetry()
        executor = ContainerRemediationExecutor(DisposableSandbox.create_runtime(), settings.container_image, "docker", settings.execution_timeout_seconds)
    elif execution_engine == "container":
        telemetry = DeterministicENOSPCTelemetry()
        executor = ContainerRemediationExecutor(DisposableSandbox.create_runtime(), settings.container_image, shutil.which("podman") or shutil.which("docker"), settings.execution_timeout_seconds)
    else:
        raise ValueError("EXECUTION_ENGINE must be podman, docker, or container")
    return IncidentService(
        store=store,
        telemetry=telemetry,
        analyzer=analyzer,
        executor=executor,
        proposal_ttl_seconds=settings.proposal_ttl_seconds,
        expiration_poll_seconds=settings.expiration_poll_seconds,
        execution_enabled=settings.execution_enabled,
        observability=observability,
    )
