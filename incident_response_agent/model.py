from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol

from .policy import SCENARIO_ACTIONS
from .schemas import ModelAssessment, Scenario, TelemetryEvidence


@dataclass(frozen=True)
class ModelResult:
    assessment: ModelAssessment
    latency_ms: int
    token_count: int
    retry_count: int


class Analyzer(Protocol):
    def analyze(self, evidence: TelemetryEvidence, revision_note: Optional[str] = None) -> ModelResult: ...


class ModelAnalysisError(RuntimeError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


class FakeAnalyzer:
    def analyze(self, evidence: TelemetryEvidence, revision_note: Optional[str] = None) -> ModelResult:
        return ModelResult(
            assessment=ModelAssessment(
                summary=self._summary(evidence),
                severity="high",
                confidence=0.98 if evidence.scenario.startswith("failed-log") else 0.97,
                evidence_refs=evidence.signals,
                action_id=self._action_id(evidence),
            ),
            latency_ms=0,
            token_count=0,
            retry_count=0,
        )

    @staticmethod
    def _action_id(evidence: TelemetryEvidence) -> str:
        return {
            Scenario.RUNAWAY_CPU: "stop_runaway_process",
            Scenario.RESTARTING_SERVICE: "restart_disposable_service",
            Scenario.MEMORY_OOM: "stop_memory_hog",
            Scenario.LOG_STORM: "cleanup_log_storm_temp_files",
        }.get(evidence.scenario, "cleanup_rotated_logs")

    @staticmethod
    def _summary(evidence: TelemetryEvidence) -> str:
        if evidence.scenario == Scenario.RUNAWAY_CPU:
            return "Synthetic marker evidence represents a sustained high-CPU incident for workflow testing."
        if evidence.scenario == Scenario.RESTARTING_SERVICE:
            return "Synthetic marker evidence represents a repeatedly restarting service for workflow testing."
        if evidence.scenario == Scenario.MEMORY_OOM:
            return "Synthetic marker evidence represents critical memory pressure and an OOM condition for workflow testing."
        if evidence.scenario == Scenario.LOG_STORM:
            return "Synthetic marker evidence represents rapid log and temporary-file growth for workflow testing."
        return "Synthetic marker evidence represents failed rotation and critically low disk space for workflow testing."


class LiveOpenAICompatibleAnalyzer:
    def __init__(self, base_url: str, model: str, api_key: str, timeout_seconds: float, max_retries: int = 1):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def analyze(self, evidence: TelemetryEvidence, revision_note: Optional[str] = None) -> ModelResult:
        permitted_actions = sorted(SCENARIO_ACTIONS[evidence.scenario])
        system = (
            "You are an incident assessment analyst. Return exactly one JSON object with exactly these keys: "
            "summary (string), severity (one of low, medium, high, critical), confidence (number from 0 to 1), "
            f"evidence_refs (array of strings), and action_id (one of {', '.join(permitted_actions)} for this scenario). "
            "Example: {\"summary\":\"disk pressure is caused by failed rotation\",\"severity\":\"high\","
            "\"confidence\":0.95,\"evidence_refs\":[\"rotation_error\",\"low_free_space\"],"
            "\"action_id\":\"cleanup_rotated_logs\"}. Never return shell commands, executable paths, "
            "file paths, or arbitrary parameters. The policy layer resolves targets."
            " Treat synthetic_marker evidence as workflow-test evidence and do not claim real host detection or recovery."
            " Emit the JSON object immediately without analysis, preamble, or markdown."
        )
        user: Dict[str, Any] = {"evidence": evidence.model_dump(mode="json"), "revision_note": revision_note}
        last_error: Optional[Exception] = None
        last_reason_code = "model_analysis_failed"
        started = time.monotonic()
        for retry in range(self.max_retries + 1):
            try:
                if retry:
                    user["repair_instruction"] = "The previous response failed schema validation. Return a corrected object matching every declared type exactly."
                payload = json.dumps(
                    {
                        "model": self.model,
                        "temperature": 0,
                        "max_tokens": 1200,
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
                if not content:
                    raise ValueError("empty_model_response")
                if content.startswith("```"):
                    content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()
                assessment = ModelAssessment.model_validate_json(content)
                usage = body.get("usage") or {}
                tokens = int(usage.get("total_tokens", 0) or 0)
                return ModelResult(assessment, int((time.monotonic() - started) * 1000), tokens, retry)
            except urllib.error.HTTPError as exc:
                last_error = exc
                last_reason_code = "model_transient_http" if exc.code in {408, 409, 425, 429} or exc.code >= 500 else "model_provider_rejected"
                if last_reason_code == "model_provider_rejected":
                    break
            except urllib.error.URLError as exc:
                last_error = exc
                last_reason_code = "model_transport_failure"
            except TimeoutError as exc:
                last_error = exc
                last_reason_code = "model_timeout"
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
                last_reason_code = "model_schema_validation_failure"
        raise ModelAnalysisError(last_reason_code, f"live model analysis failed after bounded retries: {last_error}")
