from __future__ import annotations

import asyncio
import os
from dataclasses import replace

import httpx
import pytest

from incident_response_agent.app import create_app
from incident_response_agent.config import ConfigurationError, Settings
from incident_response_agent.factory import build_service


@pytest.mark.live
def test_live_http_cycle(tmp_path):
    if os.getenv("RUN_LIVE_TESTS") != "1":
        pytest.skip("set RUN_LIVE_TESTS=1 to call the configured live model")
    try:
        settings = replace(Settings.from_env(".env"), app_mode="live", database_path=":memory:", sandbox_root=str(tmp_path))
    except ConfigurationError as exc:
        pytest.fail(str(exc))
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "application.1.rotated").write_text("synthetic artifact", encoding="utf-8")
    app = create_app(build_service(settings))

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            event = await client.post("/events", json={"idempotency_key": "live-test", "payload": {"scenario": "disk-exhaustion"}})
            assert event.status_code == 202, event.text
            proposal = event.json()["proposal"]
            approval = await client.post(f"/proposals/{proposal['proposal_id']}/decision", json={"decision": "approve", "revision": proposal["revision"], "action_hash": proposal["action_hash"]})
            assert approval.status_code == 200, approval.text
            execution = await client.post(f"/proposals/{proposal['proposal_id']}/execute")
            assert execution.status_code == 200, execution.text
            result = execution.json()
            assert result["state"] == "succeeded"
            assert any(record["event_type"] == "model_completed" for record in result["audit"])

    asyncio.run(exercise())
