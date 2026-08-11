from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Callable, Literal, Protocol

from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends import StateBackend
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.tools import StructuredTool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.config import get_config
from pydantic import BaseModel, ConfigDict, Field

from .audit import sanitize_text
from .model import ModelResult
from .observability import NoopObservability, OpenTelemetryObservability
from .policy import allowed_actions
from .sandbox import DisposableSandbox
from .schemas import ModelAssessment, Scenario, ScenarioKind, TelemetryEvidence
from .config import Settings


class SiteHealthAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    observed_at: datetime
    service: Literal["disposable-site"] = "disposable-site"
    symptom: Literal["health-check-failed"] = "health-check-failed"


class DiagnosticObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(pattern=r"^[a-z0-9_.-]+$")
    category: Literal["health", "resources", "services", "processes", "logs", "changes"]
    summary: str = Field(max_length=500)
    signals: list[str] = Field(max_length=20)
    measurements: dict[str, int | float | str | bool | None] = Field(default_factory=dict)


class InvestigationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    diagnosed_scenario: Scenario
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)
    proposed_action_id: str = Field(min_length=1, max_length=128)
    explanation: str = Field(min_length=1, max_length=2000)


class SiteDiagnosticTarget(Protocol):
    def check_health(self) -> DiagnosticObservation: ...
    def inspect_resources(self) -> DiagnosticObservation: ...
    def inspect_recent_logs(self) -> DiagnosticObservation: ...
    def inspect_recent_changes(self) -> DiagnosticObservation: ...


@dataclass
class DisposableSiteLab:
    """Owned synthetic site whose injected fault is never returned by diagnostics."""

    sandbox: DisposableSandbox
    _expected_scenario: Scenario = field(repr=False)
    _profile: Literal["baseline", "causal"] = field(default="baseline", repr=False)

    @classmethod
    def disk_exhaustion(cls, sandbox: DisposableSandbox) -> "DisposableSiteLab":
        logs = sandbox.resolve_child("logs")
        logs.mkdir(exist_ok=True)
        for index in range(3):
            (logs / f"application.{index}.rotated").write_text("bounded synthetic log\n", encoding="utf-8")
        (logs / "application.log").write_text("rotation failed: no space left on device\n", encoding="utf-8")
        return cls(sandbox=sandbox, _expected_scenario=Scenario.DISK_EXHAUSTION)

    @classmethod
    def causal_disk_exhaustion(cls, sandbox: DisposableSandbox) -> "DisposableSiteLab":
        lab = cls.disk_exhaustion(sandbox)
        lab._profile = "causal"
        return lab

    @property
    def expected_scenario(self) -> Scenario:
        """Harness-only ground truth. Never bind this property as an agent tool."""
        return self._expected_scenario

    def check_health(self) -> DiagnosticObservation:
        unhealthy = any(self.sandbox.resolve_child("logs").glob("*.rotated"))
        return DiagnosticObservation(evidence_id="health-1", category="health", summary="The local site health check returns HTTP 503." if unhealthy else "The local site health check returns HTTP 200.", signals=["http_503", "healthcheck_failed"] if unhealthy else ["healthcheck_passed"], measurements={"status_code": 503 if unhealthy else 200})

    def inspect_resources(self) -> DiagnosticObservation:
        unhealthy = any(self.sandbox.resolve_child("logs").glob("*.rotated"))
        cpu_percent = 78.0 if unhealthy and self._profile == "causal" else 12.0
        summary = "Filesystem capacity is critically low and CPU is elevated while memory remains normal." if unhealthy and self._profile == "causal" else "Filesystem capacity is critically low while CPU and memory remain normal." if unhealthy else "Filesystem capacity, CPU, and memory are normal."
        signals = ["low_free_space", "elevated_cpu"] if unhealthy and self._profile == "causal" else ["low_free_space"] if unhealthy else ["resources_normal"]
        return DiagnosticObservation(evidence_id="resources-1", category="resources", summary=summary, signals=signals, measurements={"free_bytes": 4096 if unhealthy else 1_048_576, "cpu_percent": cpu_percent, "memory_percent": 38.0})

    def inspect_recent_logs(self) -> DiagnosticObservation:
        return DiagnosticObservation(evidence_id="logs-1", category="logs", summary="Recent bounded logs report that normal rotation failed after the filesystem ran out of space.", signals=["rotation_error", "no_space_left"], measurements={"affected_file_count": 3, "log_growth_bytes_per_minute": 262_144})

    def inspect_recent_changes(self) -> DiagnosticObservation:
        if self._profile == "causal":
            return DiagnosticObservation(evidence_id="changes-1", category="changes", summary="A recent deployment completed successfully before the health check failed, with no rollback or configuration error reported.", signals=["deployment_completed", "no_deployment_error"], measurements={"minutes_before_failure": 18, "rollback_count": 0})
        return DiagnosticObservation(evidence_id="changes-1", category="changes", summary="No recent deployment or configuration change was recorded.", signals=["no_recent_change"], measurements={"change_count": 0})

    def telemetry_for(self, result: InvestigationResult) -> TelemetryEvidence:
        if result.diagnosed_scenario != self._expected_scenario:
            raise ValueError("diagnosis does not match observed lab state")
        return TelemetryEvidence(
            scenario=result.diagnosed_scenario,
            scenario_kind=ScenarioKind.SYNTHETIC_MARKER,
            rotation_failed=True,
            free_bytes=4096,
            log_growth_bytes_per_minute=262_144,
            affected_file_count=3,
            signals=result.evidence_refs,
            fault_injection="ENOSPC",
        )


@dataclass
class InvestigationTraceRun:
    observations: dict[str, DiagnosticObservation] = field(default_factory=dict)
    tool_calls: list[str] = field(default_factory=list)


@dataclass
class InvestigationTrace:
    """Thread-keyed diagnostic history shared safely by the compiled Studio graph."""

    _runs: dict[str, InvestigationTraceRun] = field(default_factory=dict, repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def record(self, thread_id: str, tool_name: str, observation: DiagnosticObservation) -> str:
        with self._lock:
            run = self._runs.setdefault(thread_id, InvestigationTraceRun())
            run.tool_calls.append(tool_name)
            run.observations[observation.evidence_id] = observation
        return observation.model_dump_json()

    def observations_for(self, thread_id: str) -> dict[str, DiagnosticObservation]:
        with self._lock:
            return dict(self._runs.get(thread_id, InvestigationTraceRun()).observations)

    def tool_calls_for(self, thread_id: str) -> list[str]:
        with self._lock:
            return list(self._runs.get(thread_id, InvestigationTraceRun()).tool_calls)


def build_diagnostic_tools(target: SiteDiagnosticTarget, trace: InvestigationTrace, observability: NoopObservability | OpenTelemetryObservability | None = None) -> list[StructuredTool]:
    observability = observability or NoopObservability()
    tools: list[StructuredTool] = []
    for name, description, operation in (
        ("check_site_health", "Check the owned disposable site's bounded HTTP health status.", target.check_health),
        ("inspect_resources", "Inspect bounded CPU, memory, and filesystem measurements for the owned site.", target.inspect_resources),
        ("inspect_recent_changes", "Inspect bounded recent deployment and configuration-change signals for the owned site.", target.inspect_recent_changes),
        ("inspect_recent_logs", "Inspect sanitized, bounded recent log signals for the owned site.", target.inspect_recent_logs),
    ):
        def make_invoke(op: Callable[[], DiagnosticObservation], tool_name: str) -> Callable[[], str]:
            def invoke() -> str:
                thread_id = str(get_config().get("configurable", {}).get("thread_id", "unscoped"))
                with observability.span("incident.agent.tool", {"incident.tool": tool_name}):
                    return trace.record(thread_id, tool_name, op())

            return invoke

        tools.append(StructuredTool.from_function(make_invoke(operation, name), name=name, description=description))
    return tools


SYSTEM_PROMPT = """You investigate one owned disposable site. Use the smallest useful set of read-only diagnostics to determine why its generic health check failed; stop gathering evidence once the cause is clear. Distinguish a supported causal chain from concurrent symptoms or merely recent events. Do not assume an incident category. Return a structured diagnosis immediately after reaching a supported conclusion. Never invent evidence, commands, paths, targets, or parameters. Cite only evidence_id values actually returned by tools. proposed_action_id must be exactly one of: cleanup_rotated_logs, stop_runaway_process, restart_disposable_service, stop_memory_hog, cleanup_log_storm_temp_files. Choose the action compatible with your diagnosed scenario. Deterministic policy and a human remain authoritative."""


RESOURCE_SUBAGENT = {
    "name": "resource-investigator",
    "description": "Analyze resource observations when the cause may be CPU, memory, or storage pressure.",
    "system_prompt": "Use only the available read-only diagnostic tools. Return a short evidence-based conclusion and cite evidence IDs.",
}

SERVICE_SUBAGENT = {
    "name": "service-log-investigator",
    "description": "Analyze site health and recent bounded logs.",
    "system_prompt": "Use only the available read-only diagnostic tools. Return a short evidence-based conclusion and cite evidence IDs.",
}


def create_incident_deep_agent(model: BaseChatModel, target: SiteDiagnosticTarget, trace: InvestigationTrace, observability: NoopObservability | OpenTelemetryObservability | None = None, *, platform_managed_checkpointing: bool = False):
    tools = build_diagnostic_tools(target, trace, observability)
    tools_by_name = {tool.name: tool for tool in tools}
    subagents = [
        {**RESOURCE_SUBAGENT, "tools": [tools_by_name["inspect_resources"]]},
        {**SERVICE_SUBAGENT, "tools": [tools_by_name["check_site_health"], tools_by_name["inspect_recent_changes"], tools_by_name["inspect_recent_logs"]]},
    ]
    return create_deep_agent(
        model=model,
        tools=tools,
        system_prompt=SYSTEM_PROMPT,
        subagents=subagents,
        response_format=InvestigationResult,
        backend=StateBackend(),
        permissions=[
            FilesystemPermission(operations=["read", "write"], paths=["/**"], mode="deny"),
        ],
        checkpointer=None if platform_managed_checkpointing else InMemorySaver(),
    )


def create_live_investigation_model(settings: Settings) -> ChatOpenAI:
    import os

    api_key = os.getenv(settings.api_key_env)
    if not api_key:
        raise ValueError(f"{settings.api_key_env} is required for the Deep Agents investigation demo")
    return ChatOpenAI(
        model=settings.deep_agent_model,
        base_url=settings.base_url,
        api_key=api_key,
        timeout=settings.model_timeout_seconds,
        max_retries=settings.model_max_retries,
        temperature=0,
        extra_body={"enable_thinking": False},
    )


def investigate_site(agent, alert: SiteHealthAlert, trace: InvestigationTrace, observability: NoopObservability | OpenTelemetryObservability | None = None) -> InvestigationResult:
    observability = observability or NoopObservability()
    started = time.monotonic()
    with observability.span("incident.site_investigation", {"incident.alert_kind": alert.symptom}) as span:
        output = agent.invoke(
            {
                "messages": [{"role": "user", "content": "The owned disposable site has failed its health check. Investigate the cause and propose one bounded remediation."}],
            },
            config={"configurable": {"thread_id": alert.idempotency_key}, "recursion_limit": 16},
        )
        result = InvestigationResult.model_validate(output["structured_response"])
        observations = trace.observations_for(alert.idempotency_key)
        tool_calls = trace.tool_calls_for(alert.idempotency_key)
        missing = sorted(set(result.evidence_refs) - set(observations))
        if missing:
            raise ValueError("diagnosis cited evidence that was not observed")
        if result.proposed_action_id not in allowed_actions(result.diagnosed_scenario, ScenarioKind.SYNTHETIC_MARKER):
            raise ValueError("diagnosis proposed an action outside deterministic policy")
        span.set_attribute("incident.diagnostic_tool_count", len(tool_calls))
        duration_ms = int((time.monotonic() - started) * 1000)
        span.set_attribute("incident.investigation_duration_ms", duration_ms)
        observability.record_investigation(duration_ms, len(tool_calls), "diagnosed")
        return result


class InvestigationAnalyzer:
    """Adapter that carries a validated investigation into the existing proposal workflow."""

    def __init__(self, result: InvestigationResult):
        self.result = result

    def analyze(self, evidence: TelemetryEvidence, revision_note: str | None = None) -> ModelResult:
        del revision_note
        if evidence.scenario != self.result.diagnosed_scenario:
            raise ValueError("investigation and telemetry scenario disagree")
        return ModelResult(
            assessment=ModelAssessment(
                summary=sanitize_text(self.result.explanation),
                severity=self.result.severity,
                confidence=self.result.confidence,
                evidence_refs=self.result.evidence_refs,
                action_id=self.result.proposed_action_id,
            ),
            latency_ms=0,
            token_count=0,
            retry_count=0,
        )


class FixedInvestigationTelemetry:
    def __init__(self, evidence: TelemetryEvidence):
        self.evidence = evidence

    def collect(self, _event) -> TelemetryEvidence:
        return self.evidence
