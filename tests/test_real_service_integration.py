from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from dataclasses import replace

import httpx
import pytest

from conftest import TEST_IMAGE, TEST_TOKEN, make_event
from incident_response_agent.app import create_app
from incident_response_agent.config import ConfigurationError, Settings
from incident_response_agent.factory import build_service


def _container_engine() -> tuple[str, str]:
    path = shutil.which("podman") or shutil.which("docker")
    if not path:
        pytest.fail("container-service lab requires Docker or Podman")
    health = subprocess.run([path, "info"], capture_output=True, text=True, timeout=20, check=False)
    if health.returncode != 0:
        pytest.fail(f"container engine is installed but unavailable: {health.stderr.strip()}")
    return path, "podman" if path.endswith("podman") else "docker"


def _exercise_http_cycle(settings: Settings) -> tuple[dict, str, str]:
    engine_path, _ = _container_engine()
    service = build_service(settings)
    target = service.executor.target
    container_id = target.container_id
    assert container_id is not None
    app = create_app(service, settings)

    async def exercise() -> dict:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
            event = await client.post(
                "/events",
                json=make_event("real-container-service", "restarting-service").model_dump(mode="json"),
                headers=headers,
            )
            assert event.status_code == 202, event.text
            proposed = event.json()
            proposal = proposed["proposal"]
            assert proposal["scenario_kind"] == "container_fault"
            assert proposal["option"]["action_id"] == "restart_unhealthy_container_service"
            assert target.snapshot().health_status == "unhealthy"
            assert target.snapshot().boot_count == 1

            premature = await client.post(f"/proposals/{proposal['proposal_id']}/execute", headers=headers)
            assert premature.status_code == 409
            assert target.snapshot().health_status == "unhealthy"
            assert target.snapshot().boot_count == 1

            approval = await client.post(
                f"/proposals/{proposal['proposal_id']}/decision",
                json={"decision": "approve", "revision": proposal["revision"], "action_hash": proposal["action_hash"]},
                headers=headers,
            )
            assert approval.status_code == 200, approval.text
            assert target.snapshot().health_status == "unhealthy"

            execution = await client.post(f"/proposals/{proposal['proposal_id']}/execute", headers=headers)
            assert execution.status_code == 200, execution.text
            completed = execution.json()
            assert completed["state"] == "succeeded"
            assert target.container_id == container_id
            assert target.snapshot().health_status == "healthy"
            assert target.snapshot().boot_count == 2
            result = next(record for record in completed["audit"] if record["event_type"] == "execution_result")
            assert result["metadata"]["service_restarted"] is True
            assert result["metadata"]["health_before"] == "unhealthy"
            assert result["metadata"]["health_after"] == "healthy"
            assert result["metadata"]["boot_count"] == 2
            return completed

    try:
        completed = asyncio.run(exercise())
    finally:
        service.close()
    remaining = subprocess.run(
        [engine_path, "inspect", container_id],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert remaining.returncode != 0
    return completed, settings.model, settings.base_url


@pytest.mark.integration
def test_real_unhealthy_service_runs_through_authenticated_agent_flow(tmp_path):
    if os.getenv("RUN_CONTAINER_TESTS") != "1":
        pytest.skip("set RUN_CONTAINER_TESTS=1 to run container integration")
    _, engine_name = _container_engine()
    settings = Settings(
        app_mode="demo",
        bearer_token=TEST_TOKEN,
        execution_enabled=True,
        lab_mode="container-service",
        database_path=str(tmp_path / "real-service.sqlite3"),
        execution_engine=engine_name,
        container_image=TEST_IMAGE,
    )
    completed, _, _ = _exercise_http_cycle(settings)
    model_record = next(record for record in completed["audit"] if record["event_type"] == "model_completed")
    assert model_record["metadata"]["token_count"] == 0


@pytest.mark.integration
@pytest.mark.live
def test_live_inference_restarts_real_unhealthy_service(tmp_path):
    if os.getenv("RUN_CONTAINER_TESTS") != "1" or os.getenv("RUN_LIVE_TESTS") != "1":
        pytest.skip("set RUN_CONTAINER_TESTS=1 and RUN_LIVE_TESTS=1 for the combined live-container test")
    _, engine_name = _container_engine()
    try:
        settings = replace(
            Settings.from_env(".env"),
            app_mode="live",
            bearer_token=TEST_TOKEN,
            execution_enabled=True,
            lab_mode="container-service",
            database_path=str(tmp_path / "live-real-service.sqlite3"),
            execution_engine=engine_name,
            container_image=TEST_IMAGE,
        )
        settings.validate()
    except ConfigurationError as exc:
        pytest.fail(str(exc))
    completed, model, endpoint = _exercise_http_cycle(settings)
    model_record = next(record for record in completed["audit"] if record["event_type"] == "model_completed")
    print(
        json.dumps(
            {
                "endpoint_label": "configured-openai-compatible-chat-completions",
                "endpoint": endpoint,
                "model": model,
                "date": "2026-07-19",
                "real_model": True,
                "real_container_service": True,
                "retry_count": model_record["metadata"]["retry_count"],
                "latency_ms": model_record["metadata"]["latency_ms"],
                "token_count": model_record["metadata"]["token_count"],
            },
            sort_keys=True,
        )
    )
