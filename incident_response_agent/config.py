from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .security import is_loopback_host


class ConfigurationError(ValueError):
    pass


def _load_local_dotenv(path: Path) -> None:
    """Load non-exported values without ever logging their contents."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def _strict_bool(name: str, value: str) -> bool:
    if value not in {"0", "1"}:
        raise ConfigurationError(f"{name} must be exactly '0' or '1'")
    return value == "1"


@dataclass(frozen=True)
class Settings:
    app_mode: str = "demo"
    host: str = "127.0.0.1"
    bearer_token: str | None = field(default=None, repr=False)
    execution_enabled: bool = False
    lab_mode: str = "synthetic"
    base_url: str = "https://opencode.ai/zen/go/v1"
    model: str = "deepseek-v4-flash"
    api_key_env: str = "OPENCODE_KEY"
    model_timeout_seconds: float = 30.0
    model_max_retries: int = 2
    proposal_ttl_seconds: int = 900
    expiration_poll_seconds: float = 5.0
    database_path: str = ".data/incident-response.sqlite3"
    execution_engine: str = "container"
    container_image: str = "docker.io/library/python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
    execution_timeout_seconds: float = 30.0
    otel_enabled: bool = False
    otel_service_name: str = "incident-response-agent"
    otel_exporter_otlp_endpoint: str | None = None
    otel_export_timeout_seconds: float = 5.0

    @classmethod
    def from_env(cls, dotenv_path: str = ".env") -> "Settings":
        _load_local_dotenv(Path(dotenv_path))
        mode = os.getenv("APP_MODE", "demo").lower()
        if mode not in {"live", "demo"}:
            raise ConfigurationError("APP_MODE must be exactly 'live' or 'demo'")
        settings = cls(
            app_mode=mode,
            host=os.getenv("HOST", cls.host),
            bearer_token=os.getenv("INCIDENT_AGENT_BEARER_TOKEN") or None,
            execution_enabled=_strict_bool("EXECUTION_ENABLED", os.getenv("EXECUTION_ENABLED", "0")),
            lab_mode=os.getenv("LAB_MODE", cls.lab_mode),
            base_url=os.getenv("MODEL_BASE_URL", cls.base_url),
            model=os.getenv("MODEL_NAME", cls.model),
            api_key_env=os.getenv("MODEL_API_KEY_ENV", cls.api_key_env),
            model_timeout_seconds=float(os.getenv("MODEL_TIMEOUT_SECONDS", cls.model_timeout_seconds)),
            model_max_retries=int(os.getenv("MODEL_MAX_RETRIES", cls.model_max_retries)),
            proposal_ttl_seconds=int(os.getenv("PROPOSAL_TTL_SECONDS", cls.proposal_ttl_seconds)),
            expiration_poll_seconds=float(os.getenv("EXPIRATION_POLL_SECONDS", cls.expiration_poll_seconds)),
            database_path=os.getenv("DATABASE_PATH", cls.database_path),
            execution_engine=os.getenv("EXECUTION_ENGINE", cls.execution_engine),
            container_image=os.getenv("CONTAINER_IMAGE", cls.container_image),
            execution_timeout_seconds=float(os.getenv("EXECUTION_TIMEOUT_SECONDS", cls.execution_timeout_seconds)),
            otel_enabled=_strict_bool("OTEL_ENABLED", os.getenv("OTEL_ENABLED", "0")),
            otel_service_name=os.getenv("OTEL_SERVICE_NAME", cls.otel_service_name),
            otel_exporter_otlp_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or None,
            otel_export_timeout_seconds=float(os.getenv("OTEL_EXPORT_TIMEOUT_SECONDS", cls.otel_export_timeout_seconds)),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.app_mode == "live" and not os.getenv(self.api_key_env):
            raise ConfigurationError(
                f"{self.api_key_env} is required when APP_MODE=live; "
                "use APP_MODE=demo for offline execution"
            )
        if self.execution_enabled and not self.bearer_token:
            raise ConfigurationError("EXECUTION_ENABLED=1 requires INCIDENT_AGENT_BEARER_TOKEN")
        if not is_loopback_host(self.host) and not self.bearer_token:
            raise ConfigurationError("non-loopback HOST requires INCIDENT_AGENT_BEARER_TOKEN")
        if self.execution_enabled and self.execution_engine not in {"container", "podman", "docker"}:
            raise ConfigurationError("enabled execution requires EXECUTION_ENGINE=container, podman, or docker")
        if self.execution_enabled and not re.fullmatch(r".+@sha256:[0-9a-f]{64}", self.container_image):
            raise ConfigurationError("CONTAINER_IMAGE must be pinned by sha256 digest when execution is enabled")
        if self.model_max_retries < 0:
            raise ConfigurationError("MODEL_MAX_RETRIES must be non-negative")
        if self.proposal_ttl_seconds <= 0 or self.expiration_poll_seconds <= 0 or self.execution_timeout_seconds <= 0:
            raise ConfigurationError("timeouts and proposal TTL must be positive")
        if self.lab_mode not in {"synthetic", "container-service"}:
            raise ConfigurationError("LAB_MODE must be exactly 'synthetic' or 'container-service'")
        if self.lab_mode == "container-service" and not self.execution_enabled:
            raise ConfigurationError("LAB_MODE=container-service requires EXECUTION_ENABLED=1")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.otel_service_name):
            raise ConfigurationError("OTEL_SERVICE_NAME must be a bounded service identifier")
        if self.otel_export_timeout_seconds <= 0:
            raise ConfigurationError("OTEL_EXPORT_TIMEOUT_SECONDS must be positive")
        if self.otel_enabled and not self.otel_exporter_otlp_endpoint:
            raise ConfigurationError("OTEL_ENABLED=1 requires OTEL_EXPORTER_OTLP_ENDPOINT")
        if self.otel_exporter_otlp_endpoint:
            parsed = urlsplit(self.otel_exporter_otlp_endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ConfigurationError("OTEL_EXPORTER_OTLP_ENDPOINT must be an HTTP(S) origin")
            if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
                raise ConfigurationError("OTEL_EXPORTER_OTLP_ENDPOINT must not contain credentials, a path, query, or fragment")
            if parsed.scheme == "http" and not is_loopback_host(parsed.hostname):
                raise ConfigurationError("unencrypted OTLP export is allowed only to a loopback endpoint")
