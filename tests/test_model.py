from __future__ import annotations

import urllib.error

import pytest
from pydantic import ValidationError

from incident_response_agent.model import MAX_MODEL_RESPONSE_BYTES, LiveOpenAICompatibleAnalyzer, ModelAnalysisError
from incident_response_agent.schemas import ModelAssessment, TelemetryEvidence


def _evidence() -> TelemetryEvidence:
    return TelemetryEvidence(
        scenario="disk-exhaustion",
        rotation_failed=True,
        free_bytes=4096,
        log_growth_bytes_per_minute=1024,
        affected_file_count=1,
    )


@pytest.mark.parametrize(
    ("status", "expected_reason", "expected_calls"),
    [(401, "model_provider_rejected", 1), (503, "model_transient_http", 3)],
)
def test_live_model_classifies_retryable_and_unsafe_failures(monkeypatch, status, expected_reason, expected_calls):
    calls = 0

    def fail(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise urllib.error.HTTPError("https://example.test", status, "failure", {}, None)

    monkeypatch.setattr("incident_response_agent.model.urllib.request.urlopen", fail)
    analyzer = LiveOpenAICompatibleAnalyzer("https://example.test/v1", "model", "key", 1, max_retries=2)
    with pytest.raises(ModelAnalysisError) as raised:
        analyzer.analyze(_evidence())
    assert raised.value.reason_code == expected_reason
    assert calls == expected_calls


def test_live_model_rejects_oversized_provider_response_before_parsing(monkeypatch):
    class OversizedResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, limit):
            assert limit == MAX_MODEL_RESPONSE_BYTES + 1
            return b"x" * limit

    monkeypatch.setattr("incident_response_agent.model.urllib.request.urlopen", lambda *_args, **_kwargs: OversizedResponse())
    analyzer = LiveOpenAICompatibleAnalyzer("https://example.test/v1", "model", "key", 1, max_retries=2)

    with pytest.raises(ModelAnalysisError) as raised:
        analyzer.analyze(_evidence())

    assert raised.value.reason_code == "model_response_too_large"


def test_model_evidence_reference_items_are_individually_bounded():
    valid = {
        "summary": "bounded",
        "severity": "high",
        "confidence": 1,
        "evidence_refs": ["x" * 500],
        "action_id": "cleanup_rotated_logs",
    }
    assert ModelAssessment.model_validate(valid).evidence_refs == ["x" * 500]

    with pytest.raises(ValidationError):
        ModelAssessment.model_validate({**valid, "evidence_refs": ["x" * 501]})
