"""Process-local Studio workflow for investigation, approval, and recovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import AnyMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import interrupt
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings
from .executor import DisposableFilesystemExecutor
from .sandbox import DisposableSandbox
from .schemas import Decision, DecisionRequest, EventRequest, RunState
from .service import IncidentService
from .site_investigation import (
    DisposableSiteLab,
    FixedInvestigationTelemetry,
    InvestigationAnalyzer,
    InvestigationResult,
    InvestigationTrace,
    SiteDiagnosticTarget,
    validate_investigation_result,
)
from .storage import SQLiteStore


class CausalWorkflowState(TypedDict, total=False):
    messages: Annotated[list[AnyMessage], add_messages]
    investigation: dict[str, Any]
    tool_calls: list[str]
    run_id: str
    proposal: dict[str, Any]
    decision: Literal["approve", "reject"]
    execution_state: str
    verification: dict[str, Any]


class ApprovalResume(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    proposal_id: str = Field(min_length=1)
    revision: int = Field(ge=1)
    action_hash: str = Field(min_length=64, max_length=64)


@dataclass
class ThreadRuntime:
    sandbox: DisposableSandbox
    lab: DisposableSiteLab

    @property
    def database_path(self) -> str:
        return str(self.sandbox.resolve_child("studio-workflow.sqlite3"))


@dataclass
class CausalRuntimeRegistry:
    """Own one isolated synthetic lab per Studio thread for this process lifetime."""

    _runtimes: dict[str, ThreadRuntime] = field(default_factory=dict, repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def for_thread(self, thread_id: str) -> ThreadRuntime:
        with self._lock:
            runtime = self._runtimes.get(thread_id)
            if runtime is None:
                sandbox = DisposableSandbox.create_runtime()
                runtime = ThreadRuntime(sandbox, DisposableSiteLab.causal_disk_exhaustion(sandbox))
                self._runtimes[thread_id] = runtime
            return runtime

    def close(self) -> None:
        with self._lock:
            runtimes = list(self._runtimes.values())
            self._runtimes.clear()
        for runtime in runtimes:
            runtime.sandbox.close()


@dataclass
class ThreadScopedCausalTarget(SiteDiagnosticTarget):
    registry: CausalRuntimeRegistry

    def _lab(self) -> DisposableSiteLab:
        return self.registry.for_thread(_thread_id()).lab

    def check_health(self):
        return self._lab().check_health()

    def inspect_resources(self):
        return self._lab().inspect_resources()

    def inspect_recent_logs(self):
        return self._lab().inspect_recent_logs()

    def inspect_recent_changes(self):
        return self._lab().inspect_recent_changes()


def _thread_id(config: RunnableConfig | None = None) -> str:
    if config is None:
        from langgraph.config import get_config

        config = get_config()
    value = config.get("configurable", {}).get("thread_id")
    if not value:
        raise ValueError("causal workflow requires a thread_id")
    return str(value)


def create_causal_recovery_graph(agent, registry: CausalRuntimeRegistry, trace: InvestigationTrace, settings: Settings, *, checkpointer=None):
    def service_for(thread_id: str, result: InvestigationResult) -> IncidentService:
        runtime = registry.for_thread(thread_id)
        return IncidentService(
            SQLiteStore(runtime.database_path),
            FixedInvestigationTelemetry(runtime.lab.telemetry_for(result)),
            InvestigationAnalyzer(result),
            DisposableFilesystemExecutor(runtime.sandbox, owns_sandbox=False),
            proposal_ttl_seconds=settings.proposal_ttl_seconds,
            execution_enabled=True,
        )

    def investigate(state: CausalWorkflowState, config: RunnableConfig) -> dict[str, Any]:
        thread_id = _thread_id(config)
        output = agent.invoke({"messages": state["messages"]}, config=config)
        result = validate_investigation_result(output["structured_response"], thread_id, trace)
        return {"investigation": result.model_dump(mode="json"), "tool_calls": trace.tool_calls_for(thread_id)}

    def build_proposal(state: CausalWorkflowState, config: RunnableConfig) -> dict[str, Any]:
        thread_id = _thread_id(config)
        result = InvestigationResult.model_validate(state["investigation"])
        service = service_for(thread_id, result)
        try:
            observed_at = datetime.now(timezone.utc)
            run = service.start_event(EventRequest.model_validate({
                "idempotency_key": f"studio:{thread_id}",
                "source": "local_simulation",
                "observed_at": observed_at,
                "payload": {"scenario": result.diagnosed_scenario.value, "summary": "multi-signal investigation completed"},
            }), actor="studio-causal-workflow")
            if not run.duplicate:
                service.record_diagnostic_tools(run.run_id, state["tool_calls"], "studio-causal-workflow")
            if run.proposal is None:
                raise ValueError("investigation did not produce a proposal")
            return {"run_id": run.run_id, "proposal": run.proposal.model_dump(mode="json")}
        finally:
            service.close()

    def approval(state: CausalWorkflowState, config: RunnableConfig) -> dict[str, Any]:
        proposal = state["proposal"]
        response = interrupt({
            "type": "approval_required",
            "proposal_id": proposal["proposal_id"],
            "revision": proposal["revision"],
            "action_hash": proposal["action_hash"],
            "action": proposal["option"],
            "allowed_decisions": ["approve", "reject"],
        })
        resume = ApprovalResume.model_validate(response)
        if resume.proposal_id != proposal["proposal_id"] or resume.revision != proposal["revision"] or resume.action_hash != proposal["action_hash"]:
            raise ValueError("approval does not match the immutable proposal")
        result = InvestigationResult.model_validate(state["investigation"])
        service = service_for(_thread_id(config), result)
        try:
            run = service.get_run(state["run_id"])
            expected_state = RunState.APPROVED if resume.decision == "approve" else RunState.REJECTED
            if run.state != expected_state:
                service.decide(
                    resume.proposal_id,
                    DecisionRequest(decision=Decision(resume.decision), revision=resume.revision, action_hash=resume.action_hash),
                    actor="studio-human-reviewer",
                )
            return {"decision": resume.decision}
        finally:
            service.close()

    def execute(state: CausalWorkflowState, config: RunnableConfig) -> dict[str, Any]:
        result = InvestigationResult.model_validate(state["investigation"])
        service = service_for(_thread_id(config), result)
        try:
            run = service.get_run(state["run_id"])
            if run.state == RunState.SUCCEEDED:
                return {"execution_state": run.state.value}
            if run.state != RunState.APPROVED:
                raise ValueError(f"proposal cannot execute from {run.state.value}")
            completed = service.execute(state["proposal"]["proposal_id"], actor="studio-causal-workflow")
            return {"execution_state": completed.state.value}
        finally:
            service.close()

    def verify(state: CausalWorkflowState, config: RunnableConfig) -> dict[str, Any]:
        thread_id = _thread_id(config)
        runtime = registry.for_thread(thread_id)
        observation = runtime.lab.check_health()
        healthy = observation.measurements["status_code"] == 200
        result = InvestigationResult.model_validate(state["investigation"])
        service = service_for(thread_id, result)
        try:
            run = service.get_run(state["run_id"])
            if not any(item.event_type == "recovery_verified" for item in run.audit):
                service.record_recovery_verification(run.run_id, state["proposal"]["proposal_id"], healthy, "studio-causal-workflow")
        finally:
            service.close()
        return {"verification": observation.model_dump(mode="json")}

    builder = StateGraph(CausalWorkflowState)
    builder.add_node("investigate", investigate)
    builder.add_node("build_immutable_proposal", build_proposal)
    builder.add_node("human_approval", approval)
    builder.add_node("execute_approved_action", execute)
    builder.add_node("verify_recovery", verify)
    builder.add_edge(START, "investigate")
    builder.add_edge("investigate", "build_immutable_proposal")
    builder.add_edge("build_immutable_proposal", "human_approval")
    builder.add_conditional_edges("human_approval", lambda state: state["decision"], {"approve": "execute_approved_action", "reject": END})
    builder.add_edge("execute_approved_action", "verify_recovery")
    builder.add_edge("verify_recovery", END)
    return builder.compile(checkpointer=checkpointer, name="causal-incident-recovery")
