from __future__ import annotations

import hmac
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict

from .schemas import EventContextField, EventPayload, EventRequest


MAX_HTTP_BODY_BYTES = 16_384
MUTATING_ENDPOINTS = {
    ("POST", "/events"),
    ("POST", "/maintenance/expire"),
}
MUTATING_PREFIXES = (
    "/proposals/",
)
SENSITIVE_KEY_PARTS = (
    "api_key",
    "api-key",
    "apikey",
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
    "username",
    "user",
)
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|authorization|bearer|credential|password|secret|token|username|user)\s*[:=]\s*[^\s,;]+"
)
BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
UNIX_HOME_PATTERN = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[^/\s]+(?:/[^\s]*)?")
WINDOWS_HOME_PATTERN = re.compile(r"(?i)\b[A-Z]:\\Users\\[^\s\\]+(?:\\[^\s]*)?")
IPV4_PATTERN = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")


def is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _redact_ip(match: re.Match[str]) -> str:
    try:
        address = ipaddress.ip_address(match.group(0))
    except ValueError:
        return match.group(0)
    if address.is_private or address.is_loopback or address.is_link_local:
        return "[REDACTED_IP]"
    return match.group(0)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in {"token_count", "input_tokens", "output_tokens", "total_tokens"}:
        return False
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def sanitize_text(value: str) -> str:
    sanitized = BEARER_PATTERN.sub("Bearer [REDACTED]", value)
    sanitized = ASSIGNMENT_PATTERN.sub("[REDACTED_CREDENTIAL]", sanitized)
    sanitized = UNIX_HOME_PATTERN.sub("[REDACTED_PATH]", sanitized)
    sanitized = WINDOWS_HOME_PATTERN.sub("[REDACTED_PATH]", sanitized)
    sanitized = IPV4_PATTERN.sub(_redact_ip, sanitized)
    return sanitized[:500]


def sanitize(value: Any, key: str = "") -> Any:
    if is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): sanitize(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [sanitize(item, key) for item in value[:20]]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def sanitize_event(event: EventRequest) -> EventRequest:
    context = [
        EventContextField(
            key=item.key,
            value="[REDACTED]" if is_sensitive_key(item.key) else sanitize_text(item.value),
        )
        for item in event.payload.context
    ]
    payload = EventPayload(
        scenario=event.payload.scenario,
        summary=sanitize_text(event.payload.summary) if event.payload.summary else None,
        log_lines=[sanitize_text(line) for line in event.payload.log_lines],
        context=context,
    )
    return event.model_copy(update={"payload": payload})


def safe_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    return sanitize(metadata)


@dataclass(frozen=True)
class AccessPolicy:
    bearer_token: str | None
    loopback_only: bool
    actor: str = "bearer-token-user"


class HTTPAccessMiddleware:
    """Authenticate protected routes and bound request bodies before routing."""

    def __init__(self, app: Callable[..., Awaitable[None]], policy: AccessPolicy):
        self.app = app
        self.policy = policy

    @staticmethod
    def _response(status: int, body: bytes, headers: list[tuple[bytes, bytes]] | None = None):
        async def send_response(send):
            response_headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
            response_headers.extend(headers or [])
            await send({"type": "http.response.start", "status": status, "headers": response_headers})
            await send({"type": "http.response.body", "body": body})

        return send_response

    def _requires_authentication(self, method: str, path: str) -> bool:
        mutating = (method, path) in MUTATING_ENDPOINTS or (method == "POST" and path.startswith(MUTATING_PREFIXES))
        return mutating or not self.policy.loopback_only

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "GET").upper()
        path = scope.get("path", "")
        request_headers = {key.lower(): value for key, value in scope.get("headers", [])}
        if self._requires_authentication(method, path):
            if not self.policy.bearer_token:
                responder = self._response(503, b'{"detail":"mutating API is disabled until a bearer token is configured"}')
                await responder(send)
                return
            authorization = request_headers.get(b"authorization", b"").decode("latin-1")
            scheme, separator, candidate = authorization.partition(" ")
            valid = separator and scheme.lower() == "bearer" and hmac.compare_digest(candidate, self.policy.bearer_token)
            if not valid:
                responder = self._response(
                    401,
                    b'{"detail":"missing or invalid bearer token"}',
                    [(b"www-authenticate", b"Bearer")],
                )
                await responder(send)
                return
            scope.setdefault("state", {})["actor"] = self.policy.actor
        else:
            scope.setdefault("state", {})["actor"] = "loopback-read-only"

        if method == "POST" and path == "/events":
            content_length = request_headers.get(b"content-length", b"0")
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = MAX_HTTP_BODY_BYTES + 1
            if declared_size > MAX_HTTP_BODY_BYTES:
                responder = self._response(413, b'{"detail":"request body exceeds 16384 bytes"}')
                await responder(send)
                return
            consumed = 0

            async def limited_receive():
                nonlocal consumed
                message = await receive()
                if message["type"] == "http.request":
                    consumed += len(message.get("body", b""))
                    if consumed > MAX_HTTP_BODY_BYTES:
                        raise _BodyTooLarge
                return message

            try:
                await self.app(scope, limited_receive, send)
            except _BodyTooLarge:
                responder = self._response(413, b'{"detail":"request body exceeds 16384 bytes"}')
                await responder(send)
            return
        await self.app(scope, receive, send)


class _BodyTooLarge(Exception):
    pass
