from __future__ import annotations

import pytest

from incident_response_agent.schemas import Decision, DecisionRequest, EventRequest
from incident_response_agent.service import ConflictError, ExpiredError, InvalidTransitionError


def test_end_to_end_requires_bound_approval_and_executes(service):
    incident, _, sandbox = service
    (sandbox / "logs").mkdir(parents=True)
    (sandbox / "logs" / "service.1.rotated").write_text("synthetic", encoding="utf-8")

    run = incident.start_event(EventRequest(idempotency_key="event-1", payload={"scenario": "disk"}))
    assert run.state.value == "proposed"
    assert run.proposal is not None
    proposal = run.proposal

    with pytest.raises(InvalidTransitionError):
        incident.execute(proposal.proposal_id)

    approved = incident.decide(proposal.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=proposal.revision, action_hash=proposal.action_hash))
    assert approved.state.value == "approved"
    completed = incident.execute(proposal.proposal_id)
    assert completed.state.value == "succeeded"
    assert not (sandbox / "logs" / "service.1.rotated").exists()
    assert any(item.event_type == "tool_call" for item in completed.audit)


def test_duplicate_same_payload_returns_existing_run(service):
    incident, _, _ = service
    event = EventRequest(idempotency_key="same", payload={"scenario": "disk", "value": 1})
    first = incident.start_event(event)
    duplicate = incident.start_event(event)
    assert duplicate.run_id == first.run_id
    assert duplicate.duplicate is True


def test_duplicate_different_payload_conflicts(service):
    incident, _, _ = service
    incident.start_event(EventRequest(idempotency_key="same", payload={"value": 1}))
    with pytest.raises(ConflictError):
        incident.start_event(EventRequest(idempotency_key="same", payload={"value": 2}))


def test_approval_hash_cannot_be_reused_for_modified_revision(service):
    incident, _, _ = service
    run = incident.start_event(EventRequest(idempotency_key="hash", payload={}))
    assert run.proposal is not None
    proposal = run.proposal
    with pytest.raises(ConflictError):
        incident.decide(proposal.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=proposal.revision, action_hash="0" * 64))


def test_revision_creates_new_immutable_proposal(service):
    incident, _, _ = service
    run = incident.start_event(EventRequest(idempotency_key="revision", payload={}))
    assert run.proposal is not None
    original = run.proposal
    revised = incident.decide(original.proposal_id, DecisionRequest(decision=Decision.REVISE, revision=1, action_hash=original.action_hash, note="include rotation failure context"))
    assert revised.proposal is not None
    assert revised.proposal.revision == 2
    assert revised.proposal.proposal_id != original.proposal_id
    assert incident.store.get_proposal(original.proposal_id)["status"] == "superseded"


def test_expiration_prevents_approval(service):
    incident, clock, _ = service
    run = incident.start_event(EventRequest(idempotency_key="expire", payload={}))
    assert run.proposal is not None
    proposal = run.proposal
    clock.advance(61)
    with pytest.raises(ExpiredError):
        incident.decide(proposal.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=1, action_hash=proposal.action_hash))
    assert incident.store.get_proposal(proposal.proposal_id)["status"] == "expired"


def test_audit_redacts_sensitive_fields(service):
    incident, _, _ = service
    run = incident.start_event(EventRequest(idempotency_key="audit", payload={"secret": "not persisted in audit"}))
    audit = run.audit
    assert all("not persisted in audit" not in str(item.metadata) for item in audit)
    assert any(item.event_type == "model_completed" for item in audit)
