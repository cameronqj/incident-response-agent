from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol

from .schemas import ModelAssessment, TelemetryEvidence


@dataclass(frozen=True)
class ModelResult:
    assessment: ModelAssessment
    latency_ms: int
    token_count: int
    retry_count: int


class Analyzer(Protocol):
    def analyze(self, evidence: TelemetryEvidence, revision_note: Optional[str] = None) -> ModelResult: ...


class FakeAnalyzer:
    def analyze(self, evidence: TelemetryEvidence, revision_note: Optional[str] = None) -> ModelResult:
        return ModelResult(
            assessment=ModelAssessment(
                summary="Failed log rotation is causing rapid log growth and critically low disposable-sandbox disk space.",
                severity="high",
                confidence=0.98,
                evidence_refs=["rotation_error", "low_free_space", "rapid_log_growth"],
                action_id="cleanup_rotated_logs",
            ),
            latency_ms=0,
            token_count=0,
            retry_count=0,
        )


class LiveOpenAICompatibleAnalyzer:
    def __init__(self, base_url: str, model: str, api_key: str, timeout_seconds: float, max_retries: int = 1):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def analyze(self, evidence: TelemetryEvidence, revision_note: Optional[str] = None) -> ModelResult:
        system = (
            "You are an incident assessment analyst. Return exactly one JSON object with exactly these keys: "
            "summary (string), severity (one of low, medium, high, critical), confidence (number from 0 to 1), "
            "evidence_refs (array of strings), and action_id (exactly cleanup_rotated_logs). "
            "Example: {\"summary\":\"disk pressure is caused by failed rotation\",\"severity\":\"high\","
            "\"confidence\":0.95,\"evidence_refs\":[\"rotation_error\",\"low_free_space\"],"
            "\"action_id\":\"cleanup_rotated_logs\"}. Never return shell commands, executable paths, "
            "file paths, or arbitrary parameters. The policy layer resolves targets."
        )
        user: Dict[str, Any] = {"evidence": evidence.model_dump(mode="json"), "revision_note": revision_note}
        last_error: Optional[Exception] = None
        started = time.monotonic()
        for retry in range(self.max_retries + 1):
            try:
                if retry:
                    user["repair_instruction"] = "The previous response failed schema validation. Return a corrected object matching every declared type exactly."
                payload = json.dumps(
                    {
                        "model": self.model,
                        "temperature": 0,
                        "max_tokens": 500,
                        "stream": False,
                        "response_format": {"type": "json_object"},
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": json.dumps(user, sort_keys=True)},
                        ],
                    }
                ).encode("utf-8")
                request = urllib.request.Request(
                    f"{self.base_url}/chat/completions",
                    data=payload,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "User-Agent": "incident-response-agent/0.1",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                    body = json.loads(response.read().decode("utf-8"))
                content = body["choices"][0]["message"]["content"]
                if isinstance(content, list):
                    content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
                content = str(content).strip()
                if content.startswith("```"):
                    content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()
                assessment = ModelAssessment.model_validate_json(content)
                usage = body.get("usage") or {}
                tokens = int(usage.get("total_tokens", 0) or 0)
                return ModelResult(assessment, int((time.monotonic() - started) * 1000), tokens, retry)
            except (urllib.error.URLError, TimeoutError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
        raise RuntimeError(f"live model analysis failed after bounded retries: {last_error}")
