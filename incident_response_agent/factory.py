from __future__ import annotations

import os
import shutil

from .config import Settings
from .executor import ContainerRemediationExecutor, DisabledExecutor
from .model import FakeAnalyzer, LiveOpenAICompatibleAnalyzer
from .service import IncidentService
from .sandbox import DisposableSandbox
from .storage import SQLiteStore
from .telemetry import DeterministicENOSPCTelemetry


def build_service(settings: Settings | None = None) -> IncidentService:
    settings = settings or Settings.from_env()
    settings.validate()
    store = SQLiteStore(settings.database_path)
    if settings.app_mode == "live":
        api_key = os.getenv(settings.api_key_env)
        if not api_key:
            raise ValueError(f"{settings.api_key_env} is required when APP_MODE=live")
        analyzer = LiveOpenAICompatibleAnalyzer(settings.base_url, settings.model, api_key, settings.model_timeout_seconds, settings.model_max_retries)
    else:
        analyzer = FakeAnalyzer()
    execution_engine = settings.execution_engine
    if not settings.execution_enabled:
        executor = DisabledExecutor()
    elif execution_engine == "podman":
        executor = ContainerRemediationExecutor(DisposableSandbox.create_runtime(), settings.container_image, "podman", settings.execution_timeout_seconds)
    elif execution_engine == "docker":
        executor = ContainerRemediationExecutor(DisposableSandbox.create_runtime(), settings.container_image, "docker", settings.execution_timeout_seconds)
    elif execution_engine == "container":
        executor = ContainerRemediationExecutor(DisposableSandbox.create_runtime(), settings.container_image, shutil.which("podman") or shutil.which("docker"), settings.execution_timeout_seconds)
    else:
        raise ValueError("EXECUTION_ENGINE must be podman, docker, or container")
    return IncidentService(
        store=store,
        telemetry=DeterministicENOSPCTelemetry(),
        analyzer=analyzer,
        executor=executor,
        proposal_ttl_seconds=settings.proposal_ttl_seconds,
        expiration_poll_seconds=settings.expiration_poll_seconds,
        execution_enabled=settings.execution_enabled,
    )
