from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

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
