from __future__ import annotations

import urllib.error

import pytest

from incident_response_agent.model import LiveOpenAICompatibleAnalyzer, ModelAnalysisError
from incident_response_agent.schemas import TelemetryEvidence


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
