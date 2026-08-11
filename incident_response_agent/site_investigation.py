from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Literal, Protocol

from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends import StateBackend
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.tools import StructuredTool
from langchain_openai import ChatOpenAI
from langchain.agents.middleware import ModelRequest, ModelResponse, wrap_model_call
from langgraph.checkpoint.memory import InMemorySaver
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
    category: Literal["health", "resources", "services", "processes", "logs"]
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
    def inspect_services(self) -> DiagnosticObservation: ...
    def inspect_processes(self) -> DiagnosticObservation: ...
    def inspect_recent_logs(self) -> DiagnosticObservation: ...


@dataclass
class DisposableSiteLab:
    """Owned synthetic site whose injected fault is never returned by diagnostics."""

    sandbox: DisposableSandbox
    _expected_scenario: Scenario = field(repr=False)

    @classmethod
    def disk_exhaustion(cls, sandbox: DisposableSandbox) -> "DisposableSiteLab":
        logs = sandbox.resolve_child("logs")
        logs.mkdir(exist_ok=True)
        for index in range(3):
            (logs / f"application.{index}.rotated").write_text("bounded synthetic log\n", encoding="utf-8")
        (logs / "application.log").write_text("rotation failed: no space left on device\n", encoding="utf-8")
        return cls(sandbox=sandbox, _expected_scenario=Scenario.DISK_EXHAUSTION)

    @property
    def expected_scenario(self) -> Scenario:
        """Harness-only ground truth. Never bind this property as an agent tool."""
        return self._expected_scenario

    def check_health(self) -> DiagnosticObservation:
        unhealthy = any(self.sandbox.resolve_child("logs").glob("*.rotated"))
        return DiagnosticObservation(evidence_id="health-1", category="health", summary="The local site health check returns HTTP 503." if unhealthy else "The local site health check returns HTTP 200.", signals=["http_503", "healthcheck_failed"] if unhealthy else ["healthcheck_passed"], measurements={"status_code": 503 if unhealthy else 200})

    def inspect_resources(self) -> DiagnosticObservation:
        unhealthy = any(self.sandbox.resolve_child("logs").glob("*.rotated"))
        return DiagnosticObservation(evidence_id="resources-1", category="resources", summary="Filesystem capacity is critically low while CPU and memory remain normal." if unhealthy else "Filesystem capacity, CPU, and memory are normal.", signals=["low_free_space"] if unhealthy else ["resources_normal"], measurements={"free_bytes": 4096 if unhealthy else 1_048_576, "cpu_percent": 12.0, "memory_percent": 38.0})

    def inspect_services(self) -> DiagnosticObservation:
        return DiagnosticObservation(evidence_id="services-1", category="services", summary="The application service is running but unhealthy and has not restarted.", signals=["service_unhealthy"], measurements={"service_state": "running", "restart_count": 0})

    def inspect_processes(self) -> DiagnosticObservation:
        return DiagnosticObservation(evidence_id="processes-1", category="processes", summary="No runaway or memory-intensive process is present.", signals=["processes_normal"], measurements={"runaway_process_detected": False, "oom_kill_detected": False})

    def inspect_recent_logs(self) -> DiagnosticObservation:
        return DiagnosticObservation(evidence_id="logs-1", category="logs", summary="Recent bounded logs report failed rotation and no space remaining.", signals=["rotation_error", "rapid_log_growth"], measurements={"affected_file_count": 3, "log_growth_bytes_per_minute": 8_388_608})

    def telemetry_for(self, result: InvestigationResult) -> TelemetryEvidence:
        if result.diagnosed_scenario != self._expected_scenario:
            raise ValueError("diagnosis does not match observed lab state")
        return TelemetryEvidence(
            scenario=result.diagnosed_scenario,
            scenario_kind=ScenarioKind.SYNTHETIC_MARKER,
            rotation_failed=True,
            free_bytes=4096,
            log_growth_bytes_per_minute=8_388_608,
            affected_file_count=3,
            signals=result.evidence_refs,
            fault_injection="ENOSPC",
        )


@dataclass
class InvestigationTrace:
    observations: dict[str, DiagnosticObservation] = field(default_factory=dict)
    tool_calls: list[str] = field(default_factory=list)

    def record(self, tool_name: str, observation: DiagnosticObservation) -> str:
        self.tool_calls.append(tool_name)
        self.observations[observation.evidence_id] = observation
        return observation.model_dump_json()


def build_diagnostic_tools(target: SiteDiagnosticTarget, trace: InvestigationTrace, observability: NoopObservability | OpenTelemetryObservability | None = None) -> list[StructuredTool]:
    observability = observability or NoopObservability()
    tools: list[StructuredTool] = []
    for name, description, operation in (
        ("check_site_health", "Check the owned disposable site's bounded HTTP health status.", target.check_health),
        ("inspect_resources", "Inspect bounded CPU, memory, and filesystem measurements for the owned site.", target.inspect_resources),
        ("inspect_services", "Inspect bounded service state for the owned site.", target.inspect_services),
        ("inspect_processes", "Inspect bounded process anomaly signals for the owned site.", target.inspect_processes),
        ("inspect_recent_logs", "Inspect sanitized, bounded recent log signals for the owned site.", target.inspect_recent_logs),
    ):
        def make_invoke(op: Callable[[], DiagnosticObservation], tool_name: str) -> Callable[[], str]:
            def invoke() -> str:
                with observability.span("incident.agent.tool", {"incident.tool": tool_name}):
                    return trace.record(tool_name, op())

            return invoke

        tools.append(StructuredTool.from_function(make_invoke(operation, name), name=name, description=description))
    return tools


SYSTEM_PROMPT = """You investigate one owned disposable site. Plan a concise investigation and use only the supplied read-only diagnostic tools to determine why a generic health check failed. Do not assume an incident category. After diagnostics, immediately return a structured diagnosis. Never invent evidence, commands, paths, targets, or parameters. Cite only evidence_id values actually returned by tools. proposed_action_id must be exactly one of: cleanup_rotated_logs, stop_runaway_process, restart_disposable_service, stop_memory_hog, cleanup_log_storm_temp_files. Choose the action compatible with your diagnosed scenario. Deterministic policy and a human remain authoritative."""

AGENT_TOOL_ALLOWLIST = {
    "check_site_health",
    "inspect_resources",
    "inspect_services",
    "inspect_processes",
    "inspect_recent_logs",
    "InvestigationResult",
}


@wrap_model_call
def incident_tool_boundary(request: ModelRequest, handler: Callable[[ModelRequest], ModelResponse]) -> ModelResponse:
    """Hide generic filesystem tools from the incident model and retain the Deep Agent harness state internally."""
    tools = [tool for tool in request.tools if tool.name in AGENT_TOOL_ALLOWLIST]
    return handler(request.override(tools=tools))


RESOURCE_SUBAGENT = {
    "name": "resource-investigator",
    "description": "Analyze resource and process observations when the cause may be CPU, memory, or storage pressure.",
    "system_prompt": "Use only the available read-only diagnostic tools. Return a short evidence-based conclusion and cite evidence IDs.",
}

SERVICE_SUBAGENT = {
    "name": "service-log-investigator",
    "description": "Analyze site health, service state, and recent bounded logs.",
    "system_prompt": "Use only the available read-only diagnostic tools. Return a short evidence-based conclusion and cite evidence IDs.",
}


def create_incident_deep_agent(model: BaseChatModel, target: SiteDiagnosticTarget, trace: InvestigationTrace, observability: NoopObservability | OpenTelemetryObservability | None = None):
    tools = build_diagnostic_tools(target, trace, observability)
    subagents = [
        {**RESOURCE_SUBAGENT, "tools": tools[1:4]},
        {**SERVICE_SUBAGENT, "tools": [tools[0], tools[2], tools[4]]},
    ]
    return create_deep_agent(
        model=model,
        tools=tools,
        system_prompt=SYSTEM_PROMPT,
        subagents=subagents,
        middleware=[incident_tool_boundary],
        response_format=InvestigationResult,
        backend=StateBackend(),
        permissions=[
            FilesystemPermission(operations=["read", "write"], paths=["/**"], mode="deny"),
        ],
        checkpointer=InMemorySaver(),
    )


def create_live_investigation_model(settings: Settings) -> ChatOpenAI:
    import os

    api_key = os.getenv(settings.api_key_env)
    if not api_key:
        raise ValueError(f"{settings.api_key_env} is required for the Deep Agents investigation demo")
    return ChatOpenAI(
        model=settings.model,
        base_url=settings.base_url,
        api_key=api_key,
        timeout=settings.model_timeout_seconds,
        max_retries=settings.model_max_retries,
        temperature=0,
        extra_body={"thinking": {"type": "disabled"}},
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
        missing = sorted(set(result.evidence_refs) - set(trace.observations))
        if missing:
            raise ValueError("diagnosis cited evidence that was not observed")
        if result.proposed_action_id not in allowed_actions(result.diagnosed_scenario, ScenarioKind.SYNTHETIC_MARKER):
            raise ValueError("diagnosis proposed an action outside deterministic policy")
        span.set_attribute("incident.diagnostic_tool_count", len(trace.tool_calls))
        duration_ms = int((time.monotonic() - started) * 1000)
        span.set_attribute("incident.investigation_duration_ms", duration_ms)
        observability.record_investigation(duration_ms, len(trace.tool_calls), "diagnosed")
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
