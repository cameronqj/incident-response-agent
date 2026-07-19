from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


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


@dataclass(frozen=True)
class Settings:
    app_mode: str = "demo"
    base_url: str = "https://opencode.ai/zen/go/v1"
    model: str = "deepseek-v4-flash"
    api_key_env: str = "OPENCODE_KEY"
    model_timeout_seconds: float = 30.0
    model_max_retries: int = 2
    proposal_ttl_seconds: int = 900
    expiration_poll_seconds: float = 5.0
    database_path: str = ".data/incident-response.sqlite3"
    sandbox_root: str = ".incident-sandbox"
    execution_engine: str = ""
    container_image: str = "python:3.12-alpine"
    execution_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, dotenv_path: str = ".env") -> "Settings":
        _load_local_dotenv(Path(dotenv_path))
        mode = os.getenv("APP_MODE", "demo").lower()
        if mode not in {"live", "demo"}:
            raise ConfigurationError("APP_MODE must be exactly 'live' or 'demo'")
        settings = cls(
            app_mode=mode,
            base_url=os.getenv("MODEL_BASE_URL", cls.base_url),
            model=os.getenv("MODEL_NAME", cls.model),
            api_key_env=os.getenv("MODEL_API_KEY_ENV", cls.api_key_env),
            model_timeout_seconds=float(os.getenv("MODEL_TIMEOUT_SECONDS", cls.model_timeout_seconds)),
            model_max_retries=int(os.getenv("MODEL_MAX_RETRIES", cls.model_max_retries)),
            proposal_ttl_seconds=int(os.getenv("PROPOSAL_TTL_SECONDS", cls.proposal_ttl_seconds)),
            expiration_poll_seconds=float(os.getenv("EXPIRATION_POLL_SECONDS", cls.expiration_poll_seconds)),
            database_path=os.getenv("DATABASE_PATH", cls.database_path),
            sandbox_root=os.getenv("SANDBOX_ROOT", cls.sandbox_root),
            execution_engine=os.getenv("EXECUTION_ENGINE", cls.execution_engine),
            container_image=os.getenv("CONTAINER_IMAGE", cls.container_image),
            execution_timeout_seconds=float(os.getenv("EXECUTION_TIMEOUT_SECONDS", cls.execution_timeout_seconds)),
        )
        if settings.app_mode == "live" and not os.getenv(settings.api_key_env):
            raise ConfigurationError(
                f"{settings.api_key_env} is required when APP_MODE=live; "
                "use APP_MODE=demo for offline execution"
            )
        if settings.app_mode == "live" and settings.execution_engine == "filesystem":
            raise ConfigurationError("APP_MODE=live requires EXECUTION_ENGINE=container, podman, or docker")
        return settings
