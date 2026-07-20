from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from conftest import TEST_TOKEN, make_event
from incident_response_agent.app import create_app
from incident_response_agent.config import ConfigurationError, Settings
from incident_response_agent.schemas import DecisionRequest


def _request(app, method: str, path: str, **kwargs):
    async def execute():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(execute())


def test_mutating_endpoint_requires_valid_bearer_token(service, api_settings):
    incident, _, _ = service
    app = create_app(incident, api_settings)
    event = make_event("auth-valid").model_dump(mode="json")

    missing = _request(app, "POST", "/events", json=event)
    invalid = _request(app, "POST", "/events", json=event, headers={"Authorization": "Bearer wrong"})
    query_only = _request(app, "POST", f"/events?access_token={TEST_TOKEN}", json=event)
    valid = _request(app, "POST", "/events", json=event, headers={"Authorization": f"Bearer {TEST_TOKEN}"})

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert query_only.status_code == 401
    assert valid.status_code == 202


def test_no_token_disables_mutations_but_allows_loopback_reads(service):
    incident, _, _ = service
    run = incident.start_event(make_event("read-only"))
    settings = Settings(execution_enabled=False, bearer_token=None, database_path=":memory:")
    app = create_app(incident, settings)

    disabled = _request(app, "POST", "/events", json=make_event("disabled").model_dump(mode="json"))
    read = _request(app, "GET", f"/runs/{run.run_id}")

    assert disabled.status_code == 503
    assert read.status_code == 200


def test_non_loopback_requires_token_for_startup_and_reads(service):
    with pytest.raises(ConfigurationError):
        Settings(host="0.0.0.0").validate()

    incident, _, _ = service
    run = incident.start_event(make_event("remote-read"))
    settings = Settings(host="0.0.0.0", bearer_token=TEST_TOKEN)
    settings.validate()
    app = create_app(incident, settings)
    missing = _request(app, "GET", f"/runs/{run.run_id}")
    valid = _request(app, "GET", f"/runs/{run.run_id}", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert missing.status_code == 401
    assert valid.status_code == 200


def test_execution_enabled_without_token_fails_closed():
    with pytest.raises(ConfigurationError):
        Settings(execution_enabled=True).validate()


def test_token_is_hidden_from_settings_repr_and_image_must_be_immutable():
    settings = Settings(bearer_token=TEST_TOKEN)
    assert TEST_TOKEN not in repr(settings)
    with pytest.raises(ConfigurationError):
        Settings(bearer_token=TEST_TOKEN, execution_enabled=True, container_image="python:3.12-alpine").validate()


def test_container_service_lab_requires_execution_and_token():
    with pytest.raises(ConfigurationError):
        Settings(lab_mode="container-service", execution_enabled=False, bearer_token=TEST_TOKEN).validate()
    with pytest.raises(ConfigurationError):
        Settings(lab_mode="container-service", execution_enabled=True, bearer_token=None).validate()
    Settings(lab_mode="container-service", execution_enabled=True, bearer_token=TEST_TOKEN).validate()


def test_unknown_lab_mode_is_rejected():
    with pytest.raises(ConfigurationError):
        Settings(lab_mode="host-services").validate()


def test_execution_enabled_environment_flag_is_strict(monkeypatch, tmp_path):
    monkeypatch.setenv("EXECUTION_ENABLED", "true")
    monkeypatch.setenv("APP_MODE", "demo")
    with pytest.raises(ConfigurationError):
        Settings.from_env(str(tmp_path / "missing.env"))


def test_execution_disabled_rejects_authenticated_execution(service):
    incident, _, _ = service
    incident.execution_enabled = False
    run = incident.start_event(make_event("execution-disabled"))
    assert run.proposal is not None
    proposal = run.proposal
    incident.decide(
        proposal.proposal_id,
        DecisionRequest(decision="approve", revision=proposal.revision, action_hash=proposal.action_hash),
    )
    settings = Settings(bearer_token=TEST_TOKEN, execution_enabled=False)
    app = create_app(incident, settings)
    response = _request(
        app,
        "POST",
        f"/proposals/{proposal.proposal_id}/execute",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert response.status_code == 409


def test_token_and_sensitive_event_values_never_reach_sqlite_or_audit(service, api_settings, caplog):
    incident, _, _ = service
    app = create_app(incident, api_settings)
    event = make_event(
        "redacted-event",
        summary='Bearer payload-secret from /Users/alice/private at 192.168.1.4 token=payload-token {"token": "json-secret"}',  # pragma: allowlist secret
        log_lines=['api_key=raw-api-key password=raw-password {"credentials":{"api_key":"json-api-secret","password":"json-password"}}'],  # pragma: allowlist secret
        context=[{"key": "nested_secret", "value": "nested-secret-value"}],
    )
    response = _request(
        app,
        "POST",
        "/events",
        json=event.model_dump(mode="json"),
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert response.status_code == 202
    database_dump = "\n".join(incident.store.connection.iterdump())
    combined = database_dump + response.text + caplog.text
    for secret in (TEST_TOKEN, "payload-secret", "payload-token", "raw-api-key", "raw-password", "json-secret", "json-api-secret", "json-password", "nested-secret-value", "/Users/alice/private", "192.168.1.4"):
        assert secret not in combined
    assert "bearer-token-user" in database_dump
    persisted = json.loads(incident.store.connection.execute("SELECT event_json FROM runs WHERE idempotency_key = 'redacted-event'").fetchone()[0])
    assert persisted["payload"]["context"][0]["value"] == "[REDACTED]"
    assert "[REDACTED_PATH]" in persisted["payload"]["summary"]
    assert "[REDACTED_IP]" in persisted["payload"]["summary"]
    assert '"token": "[REDACTED]"' in persisted["payload"]["summary"]
    api_metadata = [item["metadata"] for item in response.json()["audit"]]
    database_metadata = [item["metadata"] for item in incident.store.list_audit(response.json()["run_id"])]
    assert api_metadata == database_metadata


def test_event_body_and_shape_are_bounded(service, api_settings):
    incident, _, _ = service
    app = create_app(incident, api_settings)
    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
    oversized = make_event("oversized").model_dump(mode="json")
    oversized["payload"]["summary"] = "x" * 20_000
    too_large = _request(app, "POST", "/events", json=oversized, headers=headers)
    arbitrary = make_event("arbitrary").model_dump(mode="json")
    arbitrary["payload"]["unsupported"] = {"nested": {"secret": "value"}}  # pragma: allowlist secret
    unsupported = _request(app, "POST", "/events", json=arbitrary, headers=headers)
    too_many_lines = make_event("too-many-lines").model_dump(mode="json")
    too_many_lines["payload"]["log_lines"] = ["line"] * 21
    line_limit = _request(app, "POST", "/events", json=too_many_lines, headers=headers)
    too_long = make_event("too-long").model_dump(mode="json")
    too_long["payload"]["log_lines"] = ["x" * 501]
    string_limit = _request(app, "POST", "/events", json=too_long, headers=headers)
    assert too_large.status_code == 413
    assert unsupported.status_code == 422
    assert line_limit.status_code == 422
    assert string_limit.status_code == 422
