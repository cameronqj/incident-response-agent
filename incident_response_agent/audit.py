from __future__ import annotations

from typing import Any, Dict


REDACT_KEYS = {"secret", "api_key", "authorization", "password", "raw_prompt", "command", "path", "body", "log"}


def sanitize(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if any(fragment in lowered for fragment in REDACT_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item, key) for item in value[:20]]
    if isinstance(value, str):
        return value[:500]
    return value


def safe_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    return sanitize(metadata)
