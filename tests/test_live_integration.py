from __future__ import annotations

import asyncio
import json
import os
from dataclasses import replace

import httpx
import pytest

from incident_response_agent.app import create_app
from incident_response_agent.config import ConfigurationError, Settings
from incident_response_agent.factory import build_service
from conftest import TEST_IMAGE, TEST_TOKEN, make_event


@pytest.mark.live
def test_live_http_cycle(tmp_path):
    if os.getenv("RUN_LIVE_TESTS") != "1":
        pytest.skip("set RUN_LIVE_TESTS=1 to call the configured live model")
    try:
        settings = replace(
            Settings.from_env(".env"),
            app_mode="live",
            database_path=":memory:",
            bearer_token=TEST_TOKEN,
            execution_enabled=True,
            execution_engine="container",
            container_image=TEST_IMAGE,
        )
        settings.validate()
    except ConfigurationError as exc:
        pytest.fail(str(exc))
    service = build_service(settings)
    logs = service.executor.sandbox.root / "logs"
    logs.mkdir()
    (logs / "application.1.rotated").write_text("synthetic artifact", encoding="utf-8")
    app = create_app(service, settings)

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
            event = await client.post("/events", json=make_event("live-test").model_dump(mode="json"), headers=headers)
            assert event.status_code == 202, event.text
            proposal = event.json()["proposal"]
            approval = await client.post(f"/proposals/{proposal['proposal_id']}/decision", json={"decision": "approve", "revision": proposal["revision"], "action_hash": proposal["action_hash"]}, headers=headers)
            assert approval.status_code == 200, approval.text
            execution = await client.post(f"/proposals/{proposal['proposal_id']}/execute", headers=headers)
            assert execution.status_code == 200, execution.text
            result = execution.json()
            assert result["state"] == "succeeded"
            model_record = next(record for record in result["audit"] if record["event_type"] == "model_completed")
            assert model_record["metadata"]["retry_count"] <= settings.model_max_retries
            print(
                json.dumps(
                    {
                        "endpoint_label": "configured-openai-compatible-chat-completions",
                        "endpoint": settings.base_url,
                        "model": settings.model,
                        "date": "2026-07-19",
                        "real_model": True,
                        "retry_count": model_record["metadata"]["retry_count"],
                        "latency_ms": model_record["metadata"]["latency_ms"],
                        "token_count": model_record["metadata"]["token_count"],
                    },
                    sort_keys=True,
                )
            )

    asyncio.run(exercise())
