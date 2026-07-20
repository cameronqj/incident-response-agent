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
from .observability import NoopObservability, OpenTelemetryObservability
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
        observability: NoopObservability | OpenTelemetryObservability | None = None,
    ):
        self.store = store
        self.telemetry = telemetry
        self.analyzer = analyzer
        self.executor = executor
        self.proposal_ttl_seconds = proposal_ttl_seconds
        self.clock = clock or SystemClock()
        self.expiration_poll_seconds = expiration_poll_seconds
        self.execution_enabled = execution_enabled
        self.observability = observability or NoopObservability()

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
        with self.observability.span(
            "incident.start_event",
            {
                "incident.scenario": event.payload.scenario.value,
                "incident.event_source": event.source.value,
            },
        ) as lifecycle_span:
            return self._start_event(event, actor, lifecycle_span)

    def _start_event(self, event: EventRequest, actor: str, lifecycle_span) -> RunView:
        normalized = sanitize_event(event)
        payload_hash = hashlib.sha256(_canonical_event(normalized).encode("utf-8")).hexdigest()
        now = self.clock.now()
        run_id = str(uuid.uuid4())
        trace_id = normalized.trace_id or str(uuid.uuid4())
        lifecycle_span.set_attribute("incident.run_id", run_id)
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
            with self.observability.span("incident.telemetry.collect") as telemetry_span:
                evidence = self.telemetry.collect(normalized)
                telemetry_span.set_attribute("incident.scenario", evidence.scenario.value)
                telemetry_span.set_attribute("incident.scenario_kind", evidence.scenario_kind.value)
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
            with self.observability.span(
                "incident.model.analyze",
                {
                    "incident.scenario": evidence.scenario.value,
                    "incident.scenario_kind": evidence.scenario_kind.value,
                },
            ):
                result = self.analyzer.analyze(evidence)
            self.observability.record_model(
                result.latency_ms,
                result.token_count,
                result.retry_count,
                evidence.scenario.value,
            )
            self._audit(run_id, trace_id, "model_completed", {"latency_ms": result.latency_ms, "token_count": result.token_count, "retry_count": result.retry_count}, actor)
            self.store.transition_run(run_id, RunState.INVESTIGATING.value, RunState.ASSESSED.value, self.clock.now().isoformat(), trace_id, "structured assessment validated", actor)
            option = build_option(evidence.scenario, evidence.scenario_kind, result.assessment)
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
            lifecycle_span.set_attribute("incident.proposal_id", proposal_id)
            lifecycle_span.set_attribute("incident.action_id", option.action_id)
            lifecycle_span.set_attribute("incident.scenario_kind", evidence.scenario_kind.value)
            with self.observability.span(
                "incident.proposal.create",
                {
                    "incident.run_id": run_id,
                    "incident.proposal_id": proposal_id,
                    "incident.action_id": option.action_id,
                    "incident.scenario": evidence.scenario.value,
                    "incident.scenario_kind": evidence.scenario_kind.value,
                    "incident.proposal_revision": 1,
                },
            ):
                self.store.create_proposal_and_transition(proposal, created_at.isoformat(), trace_id, actor, event_to_proposal_ms)
            self.observability.record_event_to_proposal(
                event_to_proposal_ms,
                evidence.scenario.value,
                evidence.scenario_kind.value,
            )
        except Exception as exc:
            self.store.fail_run(run_id, self.clock.now().isoformat(), actor, getattr(exc, "reason_code", type(exc).__name__))
            if isinstance(exc, StoreConflict):
                raise ConflictError(str(exc)) from exc
            raise
        return self.get_run(run_id)

    def decide(self, proposal_id: str, request: DecisionRequest, actor: str = "local-service") -> RunView:
        with self.observability.span(
            "incident.proposal.decide",
            {
                "incident.proposal_id": proposal_id,
                "incident.proposal_revision": request.revision,
                "incident.decision": request.decision.value,
            },
        ) as lifecycle_span:
            return self._decide(proposal_id, request, actor, lifecycle_span)

    def _decide(self, proposal_id: str, request: DecisionRequest, actor: str, lifecycle_span) -> RunView:
        proposal = self.store.get_proposal(proposal_id)
        if not proposal:
            raise NotFoundError("proposal not found")
        scenario = Scenario(proposal["scenario"])
        scenario_kind = ScenarioKind(proposal["scenario_kind"])
        lifecycle_span.set_attribute("incident.run_id", proposal["run_id"])
        lifecycle_span.set_attribute("incident.scenario", scenario.value)
        lifecycle_span.set_attribute("incident.scenario_kind", scenario_kind.value)
        stored_option = RemediationOption.model_validate(proposal["option"])
        try:
            validate_scenario_action(scenario, scenario_kind, stored_option.action_id)
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
            option = build_option(scenario, scenario_kind, assessment)
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
        self.observability.record_decision(
            approval_wait_seconds,
            request.decision.value,
            scenario.value,
        )
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
        with self.observability.span(
            "incident.remediation.execute",
            {"incident.proposal_id": proposal_id},
        ) as lifecycle_span:
            return self._execute(proposal_id, actor, lifecycle_span)

    def _execute(self, proposal_id: str, actor: str, lifecycle_span) -> RunView:
        if not self.execution_enabled:
            raise ExecutionDisabledError("remediation execution is disabled by configuration")
        proposal = self.store.get_proposal(proposal_id)
        if not proposal:
            raise NotFoundError("proposal not found")
        scenario = Scenario(proposal["scenario"])
        scenario_kind = ScenarioKind(proposal["scenario_kind"])
        option = RemediationOption.model_validate(proposal["option"])
        lifecycle_span.set_attribute("incident.run_id", proposal["run_id"])
        lifecycle_span.set_attribute("incident.scenario", scenario.value)
        lifecycle_span.set_attribute("incident.scenario_kind", scenario_kind.value)
        lifecycle_span.set_attribute("incident.action_id", option.action_id)
        try:
            validate_scenario_action(scenario, scenario_kind, option.action_id)
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
        self._audit(
            run["run_id"],
            run["trace_id"],
            "tool_call",
            {
                "tool": "remediation_executor",
                "action_id": option.action_id,
                "scenario": scenario.value,
                "scenario_kind": scenario_kind.value,
            },
            actor,
            proposal_id,
        )
        try:
            with self.observability.span(
                "incident.remediation.tool",
                {
                    "incident.run_id": run["run_id"],
                    "incident.proposal_id": proposal_id,
                    "incident.action_id": option.action_id,
                    "incident.scenario": scenario.value,
                    "incident.scenario_kind": scenario_kind.value,
                },
            ):
                result = self.executor.execute(option)
            self.store.finalize_execution(
                proposal_id,
                result.success,
                self.clock.now().isoformat(),
                actor,
                {
                    "success": result.success,
                    "deleted_count": result.deleted_count,
                    "failure_reason_code": result.failure_reason_code,
                    "service_restarted": result.service_restarted,
                    "health_before": result.health_before,
                    "health_after": result.health_after,
                    "attempts": result.attempts,
                    "latency_ms": result.latency_ms,
                    "boot_count": result.boot_count,
                },
            )
            self.observability.record_execution(
                option.action_id,
                scenario.value,
                scenario_kind.value,
                result.success,
                result.failure_reason_code or "none",
            )
        except Exception as exc:
            reason_code = getattr(exc, "reason_code", type(exc).__name__)
            self.store.finalize_execution(
                proposal_id,
                False,
                self.clock.now().isoformat(),
                actor,
                {"success": False, "failure_reason_code": reason_code},
            )
            self.observability.record_execution(
                option.action_id,
                scenario.value,
                scenario_kind.value,
                False,
                reason_code,
            )
        return self.get_run(claimed["run_id"])

    def expire_due(self, actor: str = "expiration-worker") -> int:
        with self.observability.span("incident.proposal.expire_due") as lifecycle_span:
            try:
                count = self.store.expire_due(self.clock.now().isoformat(), actor)
            except StoreConflict as exc:
                raise ConflictError(str(exc)) from exc
            lifecycle_span.set_attribute("incident.expired_count", count)
            self.observability.record_expirations(count)
            return count

    def get_run(self, run_id: str, duplicate: bool = False) -> RunView:
        run = self.store.get_run(run_id)
        if not run:
            raise NotFoundError("run not found")
        proposal = self.store.latest_proposal(run_id)
        return RunView(run_id=run["run_id"], trace_id=run["trace_id"], idempotency_key=run["idempotency_key"], state=run["state"], created_at=run["created_at"], updated_at=run["updated_at"], proposal=proposal, audit=self.store.list_audit(run_id), duplicate=duplicate)

    def close(self) -> None:
        try:
            self.executor.close()
        finally:
            try:
                self.store.close()
            finally:
                self.observability.shutdown()
