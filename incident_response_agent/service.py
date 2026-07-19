from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from .audit import safe_metadata
from .clock import Clock, SystemClock
from .executor import RemediationExecutor
from .model import Analyzer
from .policy import action_hash, build_option
from .schemas import Decision, DecisionRequest, EventRequest, ModelAssessment, ProposalState, RemediationOption, RunState, RunView
from .storage import SQLiteStore
from .telemetry import TelemetryCollector


ALLOWED_TRANSITIONS = {
    RunState.RECEIVED: {RunState.INVESTIGATING, RunState.FAILED},
    RunState.INVESTIGATING: {RunState.ASSESSED, RunState.FAILED},
    RunState.ASSESSED: {RunState.PROPOSED, RunState.FAILED},
    RunState.PROPOSED: {RunState.PROPOSED, RunState.APPROVED, RunState.REJECTED, RunState.EXPIRED, RunState.FAILED},
    RunState.APPROVED: {RunState.EXECUTING, RunState.FAILED},
    RunState.REJECTED: set(),
    RunState.EXPIRED: set(),
    RunState.EXECUTING: {RunState.SUCCEEDED, RunState.FAILED},
    RunState.SUCCEEDED: set(),
    RunState.FAILED: set(),
}


class ServiceError(Exception):
    status_code = 400


class ConflictError(ServiceError):
    status_code = 409


class NotFoundError(ServiceError):
    status_code = 404


class InvalidTransitionError(ServiceError):
    status_code = 409


class ExpiredError(ServiceError):
    status_code = 409


def _canonical_payload(event: EventRequest) -> str:
    return json.dumps(event.payload, sort_keys=True, separators=(",", ":"))


class IncidentService:
    def __init__(self, store: SQLiteStore, telemetry: TelemetryCollector, analyzer: Analyzer, executor: RemediationExecutor, proposal_ttl_seconds: int = 900, clock: Optional[Clock] = None, expiration_poll_seconds: float = 5.0):
        self.store = store
        self.telemetry = telemetry
        self.analyzer = analyzer
        self.executor = executor
        self.proposal_ttl_seconds = proposal_ttl_seconds
        self.clock = clock or SystemClock()
        self.expiration_poll_seconds = expiration_poll_seconds

    def _audit(self, run_id: str, trace_id: str, event_type: str, metadata: dict, proposal_id: Optional[str] = None) -> None:
        self.store.create_audit({"run_id": run_id, "trace_id": trace_id, "proposal_id": proposal_id, "event_type": event_type, "metadata": safe_metadata(metadata), "occurred_at": self.clock.now().isoformat()})

    def _state(self, run_id: str, trace_id: str, new_state: RunState, reason: str = "", proposal_id: Optional[str] = None) -> None:
        run = self.store.get_run(run_id)
        if not run:
            raise NotFoundError("run not found")
        previous_state = RunState(run["state"])
        if new_state not in ALLOWED_TRANSITIONS[previous_state]:
            raise InvalidTransitionError(f"run cannot transition from {previous_state.value} to {new_state.value}")
        self.store.update_run_state(run_id, new_state.value, self.clock.now().isoformat())
        self._audit(run_id, trace_id, "state_transition", {"from": previous_state.value, "to": new_state.value, "reason": reason}, proposal_id)

    def start_event(self, event: EventRequest) -> RunView:
        payload_hash = hashlib.sha256(_canonical_payload(event).encode("utf-8")).hexdigest()
        existing = self.store.find_by_idempotency(event.idempotency_key)
        if existing:
            if existing["payload_hash"] != payload_hash:
                raise ConflictError("idempotency key already belongs to a different payload")
            return self.get_run(existing["run_id"], duplicate=True)

        now = self.clock.now()
        run_id = str(uuid.uuid4())
        trace_id = event.trace_id or str(uuid.uuid4())
        self.store.create_run({"run_id": run_id, "idempotency_key": event.idempotency_key, "payload_hash": payload_hash, "event": event.model_dump(mode="json"), "trace_id": trace_id, "state": RunState.RECEIVED.value, "created_at": now.isoformat(), "updated_at": now.isoformat()})
        self._audit(run_id, trace_id, "event_received", {"event_type": event.event_type, "payload_hash": payload_hash})
        try:
            self._state(run_id, trace_id, RunState.INVESTIGATING, "event accepted")
            evidence = self.telemetry.collect(event)
            self._audit(run_id, trace_id, "telemetry_collected", {"scenario": evidence.scenario, "free_bytes": evidence.free_bytes, "affected_file_count": evidence.affected_file_count, "cpu_percent": evidence.cpu_percent, "memory_percent": evidence.memory_percent, "oom_kill_detected": evidence.oom_kill_detected, "log_storm_detected": evidence.log_storm_detected, "temp_file_count": evidence.temp_file_count, "runaway_process_detected": evidence.runaway_process_detected, "service_state": evidence.service_state, "restart_count": evidence.restart_count, "fault_injection": evidence.fault_injection})
            result = self.analyzer.analyze(evidence)
            self._audit(run_id, trace_id, "model_completed", {"latency_ms": result.latency_ms, "token_count": result.token_count, "retry_count": result.retry_count})
            self._state(run_id, trace_id, RunState.ASSESSED, "structured assessment validated")
            option = build_option(result.assessment)
            proposal_id = str(uuid.uuid4())
            expires = self.clock.now() + timedelta(seconds=self.proposal_ttl_seconds)
            self.store.create_proposal({"proposal_id": proposal_id, "run_id": run_id, "revision": 1, "status": ProposalState.PROPOSED.value, "assessment": result.assessment.model_dump(mode="json"), "option": option.model_dump(mode="json"), "action_hash": action_hash(1, option), "expires_at": expires.isoformat(), "created_at": self.clock.now().isoformat()})
            self._state(run_id, trace_id, RunState.PROPOSED, "remediation proposal created", proposal_id)
            event_to_proposal_ms = int((self.clock.now() - now).total_seconds() * 1000)
            self._audit(run_id, trace_id, "proposal_created", {"revision": 1, "action_id": option.action_id, "action_hash": action_hash(1, option), "expires_at": expires.isoformat(), "event_to_proposal_latency_ms": event_to_proposal_ms}, proposal_id)
        except Exception as exc:
            current = self.store.get_run(run_id)
            if current and current["state"] != RunState.FAILED.value:
                self._state(run_id, trace_id, RunState.FAILED, "workflow exception")
            self._audit(run_id, trace_id, "run_failed", {"failure_reason_code": type(exc).__name__})
            raise
        return self.get_run(run_id)

    def decide(self, proposal_id: str, request: DecisionRequest) -> RunView:
        proposal = self.store.get_proposal(proposal_id)
        if not proposal:
            raise NotFoundError("proposal not found")
        run = self.store.get_run(proposal["run_id"])
        assert run is not None
        if request.revision != proposal["revision"] or request.action_hash != proposal["action_hash"]:
            raise ConflictError("decision does not bind to the current immutable proposal revision and action hash")
        if proposal["status"] != ProposalState.PROPOSED.value:
            raise InvalidTransitionError(f"proposal is {proposal['status']}, not proposed")
        if self.clock.now().isoformat() >= proposal["expires_at"]:
            self.store.update_proposal(proposal_id, ProposalState.EXPIRED.value)
            self._state(run["run_id"], run["trace_id"], RunState.EXPIRED, "approval TTL elapsed", proposal_id)
            self._audit(run["run_id"], run["trace_id"], "proposal_expired", {"revision": proposal["revision"]}, proposal_id)
            raise ExpiredError("proposal has expired")

        if request.decision == Decision.REVISE:
            # Revision analysis uses the original evidence contract; this first slice keeps the
            # selected allowlisted action and changes only the immutable revision identity.
            assessment = ModelAssessment.model_validate(proposal["assessment"])
            if request.note:
                assessment = assessment.model_copy(update={"summary": f"{assessment.summary} Revision requested: {request.note}"})
            option = build_option(assessment)
            new_revision = proposal["revision"] + 1
            self.store.update_proposal(proposal_id, ProposalState.SUPERSEDED.value)
            new_id = str(uuid.uuid4())
            expires = self.clock.now() + timedelta(seconds=self.proposal_ttl_seconds)
            new_hash = action_hash(new_revision, option)
            self.store.create_proposal({"proposal_id": new_id, "run_id": run["run_id"], "revision": new_revision, "status": ProposalState.PROPOSED.value, "assessment": assessment.model_dump(mode="json"), "option": option.model_dump(mode="json"), "action_hash": new_hash, "expires_at": expires.isoformat(), "created_at": self.clock.now().isoformat()})
            self._state(run["run_id"], run["trace_id"], RunState.PROPOSED, "new proposal revision created", new_id)
            self._audit(run["run_id"], run["trace_id"], "proposal_revised", {"from_revision": proposal["revision"], "to_revision": new_revision, "action_hash": new_hash}, new_id)
            return self.get_run(run["run_id"])

        next_state = RunState.APPROVED if request.decision == Decision.APPROVE else RunState.REJECTED
        next_proposal_state = ProposalState.APPROVED if request.decision == Decision.APPROVE else ProposalState.REJECTED
        self.store.update_proposal(proposal_id, next_proposal_state.value, request.action_hash if request.decision == Decision.APPROVE else None)
        self._state(run["run_id"], run["trace_id"], next_state, f"human decision: {request.decision.value}", proposal_id)
        created_at = datetime.fromisoformat(proposal["created_at"])
        approval_wait_seconds = max(0.0, (self.clock.now() - created_at).total_seconds())
        self._audit(run["run_id"], run["trace_id"], "approval_decision", {"decision": request.decision.value, "revision": request.revision, "action_hash": request.action_hash, "approval_wait_seconds": approval_wait_seconds}, proposal_id)
        return self.get_run(run["run_id"])

    def execute(self, proposal_id: str) -> RunView:
        proposal = self.store.get_proposal(proposal_id)
        if not proposal:
            raise NotFoundError("proposal not found")
        run = self.store.get_run(proposal["run_id"])
        assert run is not None
        if proposal["status"] != ProposalState.APPROVED.value or proposal["approved_action_hash"] != proposal["action_hash"]:
            raise InvalidTransitionError("only an approved, hash-bound proposal can execute")
        self.store.update_proposal(proposal_id, ProposalState.EXECUTING.value)
        self._state(run["run_id"], run["trace_id"], RunState.EXECUTING, "explicit execution requested", proposal_id)
        try:
            result = self.executor.execute(RemediationOption.model_validate(proposal["option"]))
            final_proposal = ProposalState.SUCCEEDED if result.success else ProposalState.FAILED
            final_run = RunState.SUCCEEDED if result.success else RunState.FAILED
            self.store.update_proposal(proposal_id, final_proposal.value)
            self._state(run["run_id"], run["trace_id"], final_run, "remediation completed" if result.success else "remediation failed", proposal_id)
            self._audit(run["run_id"], run["trace_id"], "execution_result", {"success": result.success, "deleted_count": result.deleted_count, "failure_reason_code": result.failure_reason_code}, proposal_id)
        except Exception as exc:
            self.store.update_proposal(proposal_id, ProposalState.FAILED.value)
            self._state(run["run_id"], run["trace_id"], RunState.FAILED, "executor exception", proposal_id)
            self._audit(run["run_id"], run["trace_id"], "execution_result", {"success": False, "failure_reason_code": type(exc).__name__}, proposal_id)
        return self.get_run(run["run_id"])

    def expire_due(self) -> int:
        count = 0
        now = self.clock.now().isoformat()
        for proposal in self.store.active_proposals():
            if now >= proposal["expires_at"]:
                run = self.store.get_run(proposal["run_id"])
                self.store.update_proposal(proposal["proposal_id"], ProposalState.EXPIRED.value)
                if run:
                    self._state(run["run_id"], run["trace_id"], RunState.EXPIRED, "approval TTL elapsed", proposal["proposal_id"])
                    self._audit(run["run_id"], run["trace_id"], "proposal_expired", {"revision": proposal["revision"]}, proposal["proposal_id"])
                count += 1
        return count

    def get_run(self, run_id: str, duplicate: bool = False) -> RunView:
        run = self.store.get_run(run_id)
        if not run:
            raise NotFoundError("run not found")
        proposal = self.store.latest_proposal(run_id)
        return RunView(run_id=run["run_id"], trace_id=run["trace_id"], idempotency_key=run["idempotency_key"], state=run["state"], created_at=run["created_at"], updated_at=run["updated_at"], proposal=proposal, audit=self.store.list_audit(run_id), duplicate=duplicate)
