from __future__ import annotations

import asyncio

import httpx

from incident_response_agent.app import create_app
from incident_response_agent.schemas import EventRequest


def test_http_event_and_conflicting_duplicate(service):
    incident, _, _ = service
    app = create_app(incident)

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/events", json={"idempotency_key": "api-1", "payload": {"scenario": "disk"}})
            assert response.status_code == 202
            body = response.json()
            proposal = body["proposal"]
            duplicate = await client.post("/events", json={"idempotency_key": "api-1", "payload": {"scenario": "disk"}})
            assert duplicate.status_code == 202
            assert duplicate.json()["duplicate"] is True
            conflict = await client.post("/events", json={"idempotency_key": "api-1", "payload": {"scenario": "other"}})
            assert conflict.status_code == 409
            decision = await client.post(f"/proposals/{proposal['proposal_id']}/decision", json={"decision": "approve", "revision": 1, "action_hash": proposal["action_hash"]})
            assert decision.status_code == 200

    asyncio.run(exercise())


def test_lifespan_expires_unanswered_proposal(service):
    incident, _, _ = service
    incident.proposal_ttl_seconds = 0
    incident.expiration_poll_seconds = 0.01
    app = create_app(incident)

    async def exercise():
        async with app.router.lifespan_context(app):
            run = incident.start_event(EventRequest(idempotency_key="auto-expire", payload={}))
            assert run.proposal is not None
            await asyncio.sleep(0.05)
            assert incident.store.get_proposal(run.proposal.proposal_id)["status"] == "expired"

    asyncio.run(exercise())
