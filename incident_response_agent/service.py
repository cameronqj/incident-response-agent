from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional

from .audit import safe_metadata, sanitize_text
from .clock import Clock, SystemClock
from .executor import RemediationExecutor
from .model import Analyzer
from .policy import SafetyViolation, action_hash, build_option, validate_scenario_action
from .schemas import Decision, DecisionRequest, EventRequest, ModelAssessment, ProposalState, RemediationOption, RunState, RunView, Scenario, ScenarioKind
from .security import sanitize_event
from .storage import IdempotencyConflict, SQLiteStore, StoreConflict, StoreNotFound
from .telemetry import TelemetryCollector


class ServiceError(Exception):
    status_code = 400


class ConflictError(ServiceError):
    status_code = 409


class NotFoundError(ServiceError):
    status_code = 404


class InvalidTransitionError(ConflictError):
    pass


class ExpiredError(ConflictError):
    pass


class ExecutionDisabledError(ConflictError):
    pass


def _canonical_event(event: EventRequest) -> str:
    event_data = event.model_dump(mode="json")
    canonical = {key: event_data[key] for key in ("source", "observed_at", "event_type", "payload")}
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"))


class IncidentService:
    def __init__(
        self,
        store: SQLiteStore,
        telemetry: TelemetryCollector,
        analyzer: Analyzer,
        executor: RemediationExecutor,
        proposal_ttl_seconds: int = 900,
        clock: Optional[Clock] = None,
        expiration_poll_seconds: float = 5.0,
        execution_enabled: bool = True,
    ):
        self.store = store
        self.telemetry = telemetry
        self.analyzer = analyzer
        self.executor = executor
        self.proposal_ttl_seconds = proposal_ttl_seconds
        self.clock = clock or SystemClock()
        self.expiration_poll_seconds = expiration_poll_seconds
        self.execution_enabled = execution_enabled

    def _audit(self, run_id: str, trace_id: str, event_type: str, metadata: dict, actor: str, proposal_id: Optional[str] = None) -> None:
        details = dict(metadata)
        details["actor"] = actor
        self.store.create_audit({"run_id": run_id, "trace_id": trace_id, "proposal_id": proposal_id, "event_type": event_type, "metadata": safe_metadata(details), "occurred_at": self.clock.now().isoformat()})

    @staticmethod
    def _map_store_error(exc: Exception) -> ServiceError:
        if isinstance(exc, StoreNotFound):
            return NotFoundError(str(exc))
        return InvalidTransitionError(str(exc))

    def start_event(self, event: EventRequest, actor: str = "local-service") -> RunView:
        normalized = sanitize_event(event)
        payload_hash = hashlib.sha256(_canonical_event(normalized).encode("utf-8")).hexdigest()
        now = self.clock.now()
        run_id = str(uuid.uuid4())
        trace_id = normalized.trace_id or str(uuid.uuid4())
        row = {
            "run_id": run_id,
            "idempotency_key": normalized.idempotency_key,
            "payload_hash": payload_hash,
            "event": normalized.model_dump(mode="json"),
            "trace_id": trace_id,
            "state": RunState.RECEIVED.value,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
        audit = {
            "run_id": run_id,
            "trace_id": trace_id,
            "event_type": "event_received",
            "metadata": {"event_type": normalized.event_type, "source": normalized.source.value, "payload_hash": payload_hash, "actor": actor},
            "occurred_at": now.isoformat(),
        }
        try:
            stored, created = self.store.create_or_get_run(row, audit)
        except IdempotencyConflict as exc:
            raise ConflictError(str(exc)) from exc
        if not created:
            return self.get_run(stored["run_id"], duplicate=True)

        try:
            self.store.transition_run(run_id, RunState.RECEIVED.value, RunState.INVESTIGATING.value, self.clock.now().isoformat(), trace_id, "event accepted", actor)
            evidence = self.telemetry.collect(normalized)
            self._audit(
                run_id,
                trace_id,
                "telemetry_collected",
                {
                    "scenario": evidence.scenario.value,
                    "scenario_kind": evidence.scenario_kind.value,
                    "free_bytes": evidence.free_bytes,
                    "affected_file_count": evidence.affected_file_count,
                    "cpu_percent": evidence.cpu_percent,
                    "memory_percent": evidence.memory_percent,
                    "oom_kill_detected": evidence.oom_kill_detected,
                    "log_storm_detected": evidence.log_storm_detected,
                    "temp_file_count": evidence.temp_file_count,
                    "runaway_process_detected": evidence.runaway_process_detected,
                    "service_state": evidence.service_state,
                    "restart_count": evidence.restart_count,
                    "fault_injection": evidence.fault_injection,
                },
                actor,
            )
            result = self.analyzer.analyze(evidence)
            self._audit(run_id, trace_id, "model_completed", {"latency_ms": result.latency_ms, "token_count": result.token_count, "retry_count": result.retry_count}, actor)
            self.store.transition_run(run_id, RunState.INVESTIGATING.value, RunState.ASSESSED.value, self.clock.now().isoformat(), trace_id, "structured assessment validated", actor)
            option = build_option(evidence.scenario, result.assessment)
            proposal_id = str(uuid.uuid4())
            created_at = self.clock.now()
            expires = created_at + timedelta(seconds=self.proposal_ttl_seconds)
            digest = action_hash(1, evidence.scenario, evidence.scenario_kind, option)
            proposal = {
                "proposal_id": proposal_id,
                "run_id": run_id,
                "revision": 1,
                "status": ProposalState.PROPOSED.value,
                "scenario": evidence.scenario.value,
                "scenario_kind": evidence.scenario_kind.value,
                "assessment": result.assessment.model_dump(mode="json"),
                "option": option.model_dump(mode="json"),
                "action_hash": digest,
                "expires_at": expires.isoformat(),
                "created_at": created_at.isoformat(),
            }
            event_to_proposal_ms = int((created_at - now).total_seconds() * 1000)
            self.store.create_proposal_and_transition(proposal, created_at.isoformat(), trace_id, actor, event_to_proposal_ms)
        except Exception as exc:
            self.store.fail_run(run_id, self.clock.now().isoformat(), actor, getattr(exc, "reason_code", type(exc).__name__))
            if isinstance(exc, StoreConflict):
                raise ConflictError(str(exc)) from exc
            raise
        return self.get_run(run_id)

    def decide(self, proposal_id: str, request: DecisionRequest, actor: str = "local-service") -> RunView:
        proposal = self.store.get_proposal(proposal_id)
        if not proposal:
            raise NotFoundError("proposal not found")
        scenario = Scenario(proposal["scenario"])
        scenario_kind = ScenarioKind(proposal["scenario_kind"])
        stored_option = RemediationOption.model_validate(proposal["option"])
        try:
            validate_scenario_action(scenario, stored_option.action_id)
        except SafetyViolation as exc:
            raise ConflictError(str(exc)) from exc
        if action_hash(proposal["revision"], scenario, scenario_kind, stored_option) != proposal["action_hash"]:
            raise ConflictError("stored proposal action digest is invalid")
        new_proposal = None
        now = self.clock.now()
        if request.decision == Decision.REVISE:
            assessment = ModelAssessment.model_validate(proposal["assessment"])
            if request.note:
                assessment = assessment.model_copy(update={"summary": f"{assessment.summary} Revision requested: {sanitize_text(request.note)}"})
            option = build_option(scenario, assessment)
            new_revision = proposal["revision"] + 1
            expires = now + timedelta(seconds=self.proposal_ttl_seconds)
            new_proposal = {
                "proposal_id": str(uuid.uuid4()),
                "revision": new_revision,
                "scenario": scenario.value,
                "scenario_kind": scenario_kind.value,
                "assessment": assessment.model_dump(mode="json"),
                "option": option.model_dump(mode="json"),
                "action_hash": action_hash(new_revision, scenario, scenario_kind, option),
                "expires_at": expires.isoformat(),
                "created_at": now.isoformat(),
            }
        created_at = datetime.fromisoformat(proposal["created_at"])
        approval_wait_seconds = max(0.0, (now - created_at).total_seconds())
        try:
            run_id, outcome = self.store.decide_proposal(
                proposal_id,
                request.revision,
                request.action_hash,
                request.decision.value,
                now.isoformat(),
                actor,
                approval_wait_seconds,
                new_proposal,
            )
        except (StoreConflict, StoreNotFound) as exc:
            raise self._map_store_error(exc) from exc
        if outcome == "expired":
            raise ExpiredError("proposal has expired and was retained")
        return self.get_run(run_id)

    def execute(self, proposal_id: str, actor: str = "local-service") -> RunView:
        if not self.execution_enabled:
            raise ExecutionDisabledError("remediation execution is disabled by configuration")
        proposal = self.store.get_proposal(proposal_id)
        if not proposal:
            raise NotFoundError("proposal not found")
        scenario = Scenario(proposal["scenario"])
        scenario_kind = ScenarioKind(proposal["scenario_kind"])
        option = RemediationOption.model_validate(proposal["option"])
        try:
            validate_scenario_action(scenario, option.action_id)
        except SafetyViolation as exc:
            raise ConflictError(str(exc)) from exc
        digest = action_hash(proposal["revision"], scenario, scenario_kind, option)
        if digest != proposal["action_hash"]:
            raise ConflictError("stored proposal action digest is invalid")
        try:
            outcome, claimed = self.store.claim_execution(proposal_id, digest, self.clock.now().isoformat(), actor)
        except (StoreConflict, StoreNotFound) as exc:
            raise self._map_store_error(exc) from exc
        if outcome == "expired":
            raise ExpiredError("proposal expired before execution and was retained")
        assert claimed is not None
        run = self.store.get_run(claimed["run_id"])
        assert run is not None
        self._audit(run["run_id"], run["trace_id"], "tool_call", {"tool": "remediation_executor", "action_id": option.action_id, "scenario": scenario.value}, actor, proposal_id)
        try:
            result = self.executor.execute(option)
            self.store.finalize_execution(
                proposal_id,
                result.success,
                self.clock.now().isoformat(),
                actor,
                {"success": result.success, "deleted_count": result.deleted_count, "failure_reason_code": result.failure_reason_code},
            )
        except Exception as exc:
            self.store.finalize_execution(
                proposal_id,
                False,
                self.clock.now().isoformat(),
                actor,
                {"success": False, "failure_reason_code": getattr(exc, "reason_code", type(exc).__name__)},
            )
        return self.get_run(claimed["run_id"])

    def expire_due(self, actor: str = "expiration-worker") -> int:
        try:
            return self.store.expire_due(self.clock.now().isoformat(), actor)
        except StoreConflict as exc:
            raise ConflictError(str(exc)) from exc

    def get_run(self, run_id: str, duplicate: bool = False) -> RunView:
        run = self.store.get_run(run_id)
        if not run:
            raise NotFoundError("run not found")
        proposal = self.store.latest_proposal(run_id)
        return RunView(run_id=run["run_id"], trace_id=run["trace_id"], idempotency_key=run["idempotency_key"], state=run["state"], created_at=run["created_at"], updated_at=run["updated_at"], proposal=proposal, audit=self.store.list_audit(run_id), duplicate=duplicate)

    def close(self) -> None:
        self.executor.close()
        self.store.close()
