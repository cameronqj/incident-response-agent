from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Annotated, ClassVar, Literal, Protocol
from uuid import uuid4

from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends import StateBackend
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.tools import StructuredTool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.config import get_config
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .runbook_application_eval import RunbookKnowledgeTrace, build_runbook_tools
from .runbook_learning import DiagnosticStep, EvidenceId, RunbookRegistry, SignalName
from .schemas import Scenario, ScenarioKind, TelemetryEvidence
from .site_investigation import DiagnosticObservation, InvestigationResult, InvestigationTrace, SiteDiagnosticTarget, build_diagnostic_tools


ParameterName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")]
CapabilityId = Annotated[str, Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]+$")]


class CapabilityCandidateState(str, Enum):
    PENDING_REVIEW = "pending_review"
    SUPERSEDED = "superseded"
    REJECTED = "rejected"
    EVALUATION_FAILED = "evaluation_failed"
    PROMOTED = "promoted"


class CapabilityReviewDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class CapabilityParameter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: ParameterName
    kind: Literal["int"] = "int"
    minimum: int = Field(ge=1)
    maximum: int = Field(ge=1)
    required: bool = True

    @model_validator(mode="after")
    def bounds_are_ordered(self) -> "CapabilityParameter":
        if self.minimum > self.maximum:
            raise ValueError("capability parameter minimum must not exceed maximum")
        return self


class CapabilityResearchProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: CapabilityId
    title: str = Field(min_length=3, max_length=160)
    summary: str = Field(min_length=10, max_length=1000)
    parameters: list[CapabilityParameter] = Field(min_length=1, max_length=3)
    allowed_targets: list[Literal["owned_disposable_worker"]] = Field(min_length=1, max_length=1)
    prerequisites: list[SignalName] = Field(min_length=2, max_length=12)
    required_evidence_categories: list[Literal["health", "resources", "services", "processes", "logs", "changes"]] = Field(min_length=2, max_length=6)
    maximum_blast_radius: str = Field(min_length=10, max_length=500)
    approval_policy: str = Field(min_length=10, max_length=500)
    idempotency: str = Field(min_length=10, max_length=500)
    timeout_seconds: int = Field(ge=1, le=3600)
    verification_steps: list[DiagnosticStep] = Field(min_length=1, max_length=4)
    rollback_steps: list[DiagnosticStep] = Field(min_length=1, max_length=4)
    source_evidence_refs: list[EvidenceId] = Field(min_length=2, max_length=12)
    confidence: float = Field(ge=0, le=1)


class CapabilityCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    state: CapabilityCandidateState
    proposal: CapabilityResearchProposal
    content_digest: str = Field(min_length=64, max_length=64)
    created_at: datetime
    reviewed_at: datetime | None = None
    reviewer: str | None = None
    review_note: str | None = None
    evaluation: CapabilityPromotionEvaluation | None = None
    supersedes_candidate_id: str | None = None


class CapabilityEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    signals: list[SignalName] = Field(max_length=20)
    evidence_categories: list[str] = Field(max_length=6)
    expected_match: bool


class CapabilityPromotionEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    case_count: int = Field(ge=1)
    case_accuracy: float = Field(ge=0, le=1)
    false_positive_count: int = Field(ge=0)
    bounded_timeout: bool
    bounded_parameters: bool
    bounded_blast_radius: bool
    has_verification: bool
    has_rollback: bool
    sufficient_confidence: bool
    results: dict[str, bool]


class PromotedCapability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: str
    version: int = Field(ge=1)
    proposal: CapabilityResearchProposal
    source_candidate_id: str
    content_digest: str
    promoted_at: datetime
    promoted_by: str
    evaluation: CapabilityPromotionEvaluation


class CapabilityActivationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activation_id: str
    run_id: str
    proposal_id: str
    capability_id: str
    version: int = Field(ge=1)
    target_id: str
    outcome: Literal["succeeded", "failed", "rollback_applied"]
    verification: bool
    rollback_applied: bool
    occurred_at: datetime
    actor: str


class CapabilityCitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: str = Field(min_length=3, max_length=128)
    version: int = Field(ge=1)
    content_digest: str = Field(min_length=64, max_length=64)


@dataclass
class CapabilityKnowledgeTrace:
    """Thread-keyed record of which promoted capabilities were searched and opened."""

    _search_results: dict[str, list[tuple[str, int]]] = field(default_factory=dict, repr=False)
    _opened: dict[str, list[CapabilityCitation]] = field(default_factory=dict, repr=False)
    _tool_calls: dict[str, list[str]] = field(default_factory=dict, repr=False)
    _lock: RLock = field(default_factory=RLock, repr=False)

    def record_search(self, thread_id: str, matches: list[PromotedCapability]) -> None:
        with self._lock:
            self._search_results[thread_id] = [(match.capability_id, match.version) for match in matches]
            self._tool_calls.setdefault(thread_id, []).append("search_approved_capabilities")

    def may_open(self, thread_id: str, capability_id: str, version: int) -> bool:
        with self._lock:
            return (capability_id, version) in self._search_results.get(thread_id, [])

    def record_open(self, thread_id: str, capability: PromotedCapability) -> CapabilityCitation:
        citation = CapabilityCitation(
            capability_id=capability.capability_id,
            version=capability.version,
            content_digest=capability.content_digest,
        )
        with self._lock:
            self._opened.setdefault(thread_id, []).append(citation)
            self._tool_calls.setdefault(thread_id, []).append("open_approved_capability")
        return citation

    def opened_for(self, thread_id: str) -> list[CapabilityCitation]:
        with self._lock:
            return list(self._opened.get(thread_id, []))

    def tool_calls_for(self, thread_id: str) -> list[str]:
        with self._lock:
            return list(self._tool_calls.get(thread_id, []))


def build_capability_tools(
    registry: CapabilityRegistry,
    investigation_trace: InvestigationTrace,
    knowledge_trace: CapabilityKnowledgeTrace,
) -> list[StructuredTool]:
    def search_approved_capabilities() -> str:
        """Search only promoted capabilities using signals already observed in this investigation."""
        thread_id = str(get_config().get("configurable", {}).get("thread_id", "unscoped"))
        observations = investigation_trace.observations_for(thread_id).values()
        signals = {signal for observation in observations for signal in observation.signals}
        categories = {observation.category for observation in investigation_trace.observations_for(thread_id).values()}
        matches = registry.find_approved(signals, categories)
        knowledge_trace.record_search(thread_id, matches)
        return json.dumps([
            {
                "capability_id": match.capability_id,
                "version": match.version,
                "title": match.proposal.title,
                "summary": match.proposal.summary,
            }
            for match in matches
        ], separators=(",", ":"), sort_keys=True)

    def open_approved_capability(capability_id: str, version: int) -> str:
        """Open one promoted capability version returned by the current thread's search."""
        thread_id = str(get_config().get("configurable", {}).get("thread_id", "unscoped"))
        if not knowledge_trace.may_open(thread_id, capability_id, version):
            raise ValueError("capability was not returned by the current investigation search")
        capability = registry.get_promoted(capability_id, version)
        citation = knowledge_trace.record_open(thread_id, capability)
        return json.dumps({
            "citation": citation.model_dump(mode="json"),
            "title": capability.proposal.title,
            "parameters": [parameter.model_dump(mode="json") for parameter in capability.proposal.parameters],
            "prerequisites": capability.proposal.prerequisites,
            "required_evidence_categories": capability.proposal.required_evidence_categories,
            "verification_steps": capability.proposal.verification_steps,
            "rollback_steps": capability.proposal.rollback_steps,
            "maximum_blast_radius": capability.proposal.maximum_blast_radius,
            "evidence_scope": (
                "EVIDENCE-SCOPE CONTRACT: this capability is supported only by observations in the "
                "required_evidence_categories list above. In your final diagnosis cite ONLY observations "
                "whose category is in that list; observations in any other category (such as a generic "
                "health status) are symptoms rather than causal evidence and must not be cited."
            ),
        }, separators=(",", ":"), sort_keys=True)

    return [
        StructuredTool.from_function(search_approved_capabilities),
        StructuredTool.from_function(open_approved_capability),
    ]


def reviewer_corrected_capability_proposal() -> CapabilityResearchProposal:
    """Reviewer-corrected contract used when a live researcher's proposal violates
    the observed-evidence contract; it cites only the lab's deterministic
    observations and never invents signals, so it is a sound basis for the gate."""
    return CapabilityResearchProposal.model_validate({
        "capability_id": "reduce_worker_concurrency",
        "title": "Reduce worker concurrency under memory pressure",
        "summary": "Lowers the owned disposable worker concurrency when elevated concurrency correlates with OOM pressure.",
        "parameters": [{"name": "target_concurrency", "kind": "int", "minimum": 1, "maximum": 8, "required": True}],
        "allowed_targets": ["owned_disposable_worker"],
        "prerequisites": ["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"],
        "required_evidence_categories": ["resources", "changes", "logs"],
        "maximum_blast_radius": "Exactly one owned disposable worker; no scope beyond that single worker.",
        "approval_policy": "Requires application-owned human approval of the immutable proposal before activation.",
        "idempotency": "Activating at or below the approved target is a no-op success.",
        "timeout_seconds": 30,
        "verification_steps": ["Confirm the owned worker health check returns HTTP 200.", "Confirm OOM kills stop in bounded logs."],
        "rollback_steps": ["Restore the previous concurrency value.", "Re-verify the owned worker health check."],
        "source_evidence_refs": ["resources-1", "changes-1", "logs-1"],
        "confidence": 0.9,
    })


CAPABILITY_POLICY = {
    "max_timeout_seconds": 60,
    "max_parameter_maximum": 8,
    "min_parameter_minimum": 1,
    "blast_radius_required": ("owned", "disposable", "one"),
    "blast_radius_forbidden": ("cluster", "namespace", "fleet", "all workers", "any worker", "each worker"),
}


@dataclass
class ConcurrencyWorkerLab(SiteDiagnosticTarget):
    """Owned disposable worker whose concurrency is the single controlled runtime parameter.

    The expected capability id is harness-only ground truth and is never exposed through
    diagnostic tools. Concrete runtime values are chosen by application code, not the model.
    """

    _expected_capability_id: ClassVar[str] = "reduce_worker_concurrency"

    current_concurrency: int = 12
    safe_concurrency: int = 4
    fail_verification: bool = False
    lab_id: str = field(default_factory=lambda: f"lab-{uuid4().hex[:12]}")
    _force_unhealthy: bool = field(default=False, repr=False)

    @property
    def healthy(self) -> bool:
        return not self._force_unhealthy and self.current_concurrency <= self.safe_concurrency

    def check_health(self) -> DiagnosticObservation:
        if self.healthy:
            return DiagnosticObservation(
                evidence_id="health-1",
                category="health",
                summary="The owned disposable worker API returns HTTP 200.",
                signals=["healthcheck_passed"],
                measurements={"status_code": 200},
            )
        return DiagnosticObservation(
            evidence_id="health-1",
            category="health",
            summary="The owned disposable worker API intermittently returns HTTP 503.",
            signals=["http_503", "worker_unavailable"],
            measurements={"status_code": 503},
        )

    def inspect_resources(self) -> DiagnosticObservation:
        if self.healthy:
            return DiagnosticObservation(
                evidence_id="resources-1",
                category="resources",
                summary="Worker memory, CPU, and filesystem capacity are normal.",
                signals=["memory_normal", "cpu_normal", "filesystem_normal"],
                measurements={"memory_percent": 44.0, "cpu_percent": 19.0, "free_bytes": 805_306_368},
            )
        return DiagnosticObservation(
            evidence_id="resources-1",
            category="resources",
            summary="Worker memory is at 96 percent while CPU and filesystem capacity remain normal.",
            signals=["memory_pressure", "cpu_normal", "filesystem_normal"],
            measurements={"memory_percent": 96.0, "cpu_percent": 19.0, "free_bytes": 805_306_368},
        )

    def inspect_recent_changes(self) -> DiagnosticObservation:
        return DiagnosticObservation(
            evidence_id="changes-1",
            category="changes",
            summary="Worker concurrency increased from 4 to 12 shortly before failures began; the application image did not change.",
            signals=["worker_concurrency_increased", "image_unchanged"],
            measurements={"previous_concurrency": 4, "current_concurrency": 12},
        )

    def inspect_recent_logs(self) -> DiagnosticObservation:
        if self.healthy:
            return DiagnosticObservation(
                evidence_id="logs-1",
                category="logs",
                summary="Bounded logs show no OOM kills or concurrency-correlated allocation failures.",
                signals=["no_oom_kill"],
                measurements={"oom_kill_count": 0, "observed_concurrency": self.current_concurrency},
            )
        return DiagnosticObservation(
            evidence_id="logs-1",
            category="logs",
            summary="Bounded logs show workers exceeding their memory limit and being OOM-killed when twelve jobs run concurrently.",
            signals=["oom_kill", "concurrency_correlated_oom"],
            measurements={"oom_kill_count": 4, "observed_concurrency": 12},
        )

    def apply(self, target_concurrency: int) -> int:
        previous = self.current_concurrency
        self.current_concurrency = target_concurrency
        if self.fail_verification:
            self._force_unhealthy = True
        return previous

    def restore(self, previous: int) -> None:
        self.current_concurrency = previous
        self._force_unhealthy = False

    def telemetry_for(self, result: InvestigationResult) -> TelemetryEvidence:
        if result.diagnosed_scenario != Scenario.WORKER_CONCURRENCY:
            raise ValueError("diagnosis does not match the owned worker lab state")
        return TelemetryEvidence(
            scenario=Scenario.WORKER_CONCURRENCY,
            scenario_kind=ScenarioKind.SYNTHETIC_MARKER,
            rotation_failed=False,
            free_bytes=1_048_576,
            log_growth_bytes_per_minute=0,
            affected_file_count=0,
            memory_percent=96.0 if not self.healthy else 44.0,
            oom_kill_detected=not self.healthy,
            worker_concurrency=self.current_concurrency,
            safe_worker_concurrency=self.safe_concurrency,
            signals=["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"],
            fault_injection="WORKER_CONCURRENCY_PRESSURE",
        )


CAPABILITY_RESEARCH_PROMPT = """You research one unfamiliar failure affecting one owned disposable worker service. Use the read-only diagnostics to establish a supported problem signature and propose a typed capability contract, not executable authority. Inspect health, resources, recent changes, and recent logs before concluding. After gathering evidence, call search_approved_runbooks; if a runbook matches, open the best version with open_approved_runbook and use its diagnostic guidance to shape the capability prerequisites. Return a structured capability proposal with a narrow lowercase capability_id, a parameter schema, allowed targets, prerequisites, required evidence categories, a maximum blast radius limited to exactly one owned disposable worker, an approval policy, an idempotency contract, a bounded timeout, verification steps, rollback steps, and only evidence IDs returned by tools. Do not propose commands, shell access, file paths, credentials, cluster-wide targets, or executable authority. A separate application-owned reviewer and deterministic evaluation gate decide whether the capability is promoted; concrete runtime values are chosen by application code and bound by human approval."""


def create_capability_research_agent(
    model: BaseChatModel,
    target: SiteDiagnosticTarget,
    trace: InvestigationTrace,
    runbook_registry: RunbookRegistry | None = None,
    knowledge_trace: RunbookKnowledgeTrace | None = None,
):
    tools = build_diagnostic_tools(target, trace)
    if runbook_registry is not None:
        knowledge_trace = knowledge_trace or RunbookKnowledgeTrace()
        tools.extend(build_runbook_tools(runbook_registry, trace, knowledge_trace))
    return create_deep_agent(
        model=model,
        tools=tools,
        system_prompt=CAPABILITY_RESEARCH_PROMPT,
        response_format=CapabilityResearchProposal,
        backend=StateBackend(),
        permissions=[FilesystemPermission(operations=["read", "write"], paths=["/**"], mode="deny")],
        checkpointer=InMemorySaver(),
    )


def _validate_research_proposal(proposal: CapabilityResearchProposal, observations: dict[str, DiagnosticObservation]) -> None:
    if set(proposal.source_evidence_refs) - set(observations):
        raise ValueError("capability proposal cited evidence that was not observed")
    observed_categories = {observation.category for observation in observations.values()}
    if set(proposal.required_evidence_categories) - observed_categories:
        raise ValueError("capability proposal requires an evidence category that was not observed")
    observed_signals = {signal for observation in observations.values() for signal in observation.signals}
    if set(proposal.prerequisites) - observed_signals:
        raise ValueError("capability proposal uses a prerequisite signal that was not observed")


def research_capability(agent, trace: InvestigationTrace, thread_id: str) -> CapabilityResearchProposal:
    output = agent.invoke(
        {"messages": [{"role": "user", "content": "The owned disposable worker has an unfamiliar recurring failure. Investigate it and propose a typed capability contract for one bounded remediation."}]},
        config={"configurable": {"thread_id": thread_id}, "recursion_limit": 14},
    )
    proposal = CapabilityResearchProposal.model_validate(output["structured_response"])
    _validate_research_proposal(proposal, trace.observations_for(thread_id))
    return proposal


def contract_violation_revision(proposal: CapabilityResearchProposal, observations: dict[str, DiagnosticObservation]) -> CapabilityResearchProposal | None:
    """Application-owned salvage of a proposal that violated the observed-evidence contract.

    Strips unobserved prerequisites, categories, and evidence refs from the model's own
    proposal so the reviewer revises model-derived content rather than a hardcoded
    substitute. Returns None when the model proposal cannot be salvaged (too few signals).
    """
    observed_signals = {signal for observation in observations.values() for signal in observation.signals}
    observed_categories = {observation.category for observation in observations.values()}
    observed_ids = set(observations)
    data = proposal.model_dump(mode="json")
    data["prerequisites"] = [signal for signal in data["prerequisites"] if signal in observed_signals]
    data["required_evidence_categories"] = [category for category in data["required_evidence_categories"] if category in observed_categories]
    data["source_evidence_refs"] = [ref for ref in data["source_evidence_refs"] if ref in observed_ids]
    if len(data["prerequisites"]) < 2 or len(data["required_evidence_categories"]) < 2 or len(data["source_evidence_refs"]) < 2:
        return None
    try:
        return CapabilityResearchProposal.model_validate(data)
    except ValidationError:
        return None


def research_capability_with_recovery(agent, trace: InvestigationTrace, thread_id: str) -> tuple[CapabilityResearchProposal, bool]:
    """Strict research with application-owned contract enforcement.

    Returns (proposal, recovered). When the model proposal violates the observed-evidence
    contract, the application strips the unobserved signals from the model's own proposal
    (contract_violation_revision); only if that cannot be salvaged does it substitute the
    application-owned reference contract.
    """
    output = agent.invoke(
        {"messages": [{"role": "user", "content": "The owned disposable worker has an unfamiliar recurring failure. Investigate it and propose a typed capability contract for one bounded remediation."}]},
        config={"configurable": {"thread_id": thread_id}, "recursion_limit": 14},
    )
    observations = trace.observations_for(thread_id)
    try:
        proposal = CapabilityResearchProposal.model_validate(output["structured_response"])
    except ValidationError:
        proposal = None
    if proposal is not None:
        try:
            _validate_research_proposal(proposal, observations)
            return proposal, False
        except ValueError:
            salvaged = contract_violation_revision(proposal, observations)
            if salvaged is not None:
                return salvaged, True
    return reviewer_corrected_capability_proposal(), True


def proposal_digest(proposal: CapabilityResearchProposal) -> str:
    encoded = json.dumps(proposal.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def capability_matches(proposal: CapabilityResearchProposal, signals: set[str], evidence_categories: set[str]) -> bool:
    return set(proposal.prerequisites).issubset(signals) and set(proposal.required_evidence_categories).issubset(evidence_categories)


def capability_policy_pass(proposal: CapabilityResearchProposal) -> dict[str, bool]:
    radius_text = proposal.maximum_blast_radius.lower()
    return {
        "bounded_timeout": proposal.timeout_seconds <= CAPABILITY_POLICY["max_timeout_seconds"],
        "bounded_parameters": all(
            parameter.minimum >= CAPABILITY_POLICY["min_parameter_minimum"] and parameter.maximum <= CAPABILITY_POLICY["max_parameter_maximum"]
            for parameter in proposal.parameters
        ),
        "bounded_blast_radius": all(token in radius_text for token in CAPABILITY_POLICY["blast_radius_required"])
        and not any(token in radius_text for token in CAPABILITY_POLICY["blast_radius_forbidden"]),
        "has_verification": len(proposal.verification_steps) >= 1,
        "has_rollback": len(proposal.rollback_steps) >= 1,
        "sufficient_confidence": proposal.confidence >= 0.8,
    }


DEFAULT_PROMOTION_CASES = (
    CapabilityEvaluationCase(
        case_id="same-worker-failure",
        signals=["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"],
        evidence_categories=["resources", "changes", "logs"],
        expected_match=True,
    ),
    CapabilityEvaluationCase(
        case_id="same-failure-with-noise",
        signals=["http_503", "memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill", "filesystem_normal"],
        evidence_categories=["health", "resources", "changes", "logs"],
        expected_match=True,
    ),
    CapabilityEvaluationCase(
        case_id="generic-memory-pressure",
        signals=["memory_pressure", "oom_kill"],
        evidence_categories=["resources", "logs"],
        expected_match=False,
    ),
    CapabilityEvaluationCase(
        case_id="concurrency-without-oom",
        signals=["worker_concurrency_increased", "latency_high"],
        evidence_categories=["health", "changes"],
        expected_match=False,
    ),
    CapabilityEvaluationCase(
        case_id="disk-exhaustion",
        signals=["http_503", "low_free_space", "rotation_error", "no_space_left"],
        evidence_categories=["health", "resources", "logs"],
        expected_match=False,
    ),
)


class CapabilityEvaluator(Protocol):
    def evaluate(self, proposal: CapabilityResearchProposal) -> CapabilityPromotionEvaluation: ...


class DeterministicCapabilityEvaluator:
    def __init__(self, cases: tuple[CapabilityEvaluationCase, ...] = DEFAULT_PROMOTION_CASES):
        if not cases:
            raise ValueError("capability promotion requires evaluation cases")
        self.cases = cases

    def evaluate(self, proposal: CapabilityResearchProposal) -> CapabilityPromotionEvaluation:
        results = {
            case.case_id: capability_matches(proposal, set(case.signals), set(case.evidence_categories)) == case.expected_match
            for case in self.cases
        }
        false_positive_count = sum(
            1
            for case in self.cases
            if not case.expected_match and capability_matches(proposal, set(case.signals), set(case.evidence_categories))
        )
        accuracy = sum(results.values()) / len(results)
        policy = capability_policy_pass(proposal)
        return CapabilityPromotionEvaluation(
            passed=accuracy == 1.0 and false_positive_count == 0 and all(policy.values()),
            case_count=len(results),
            case_accuracy=accuracy,
            false_positive_count=false_positive_count,
            results=results,
            **policy,
        )


class CapabilityRegistry:
    def __init__(self, database_path: str):
        self.database_path = database_path
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database_path, check_same_thread=False, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.lock = RLock()
        self._initialize()

    def _initialize(self) -> None:
        with self.lock:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS capability_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    proposal_json TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reviewed_at TEXT,
                    reviewer TEXT,
                    review_note TEXT,
                    evaluation_json TEXT,
                    supersedes_candidate_id TEXT REFERENCES capability_candidates(candidate_id)
                );
                CREATE TABLE IF NOT EXISTS promoted_capabilities (
                    capability_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    proposal_json TEXT NOT NULL,
                    source_candidate_id TEXT NOT NULL UNIQUE REFERENCES capability_candidates(candidate_id),
                    content_digest TEXT NOT NULL,
                    promoted_at TEXT NOT NULL,
                    promoted_by TEXT NOT NULL,
                    evaluation_json TEXT NOT NULL,
                    PRIMARY KEY(capability_id, version)
                );
                CREATE TABLE IF NOT EXISTS capability_activations (
                    activation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    target_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    verification INTEGER NOT NULL,
                    rollback_applied INTEGER NOT NULL,
                    occurred_at TEXT NOT NULL,
                    actor TEXT NOT NULL
                );
                """
            )
            columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(capability_candidates)").fetchall()}
            if "supersedes_candidate_id" not in columns:
                self.connection.execute("ALTER TABLE capability_candidates ADD COLUMN supersedes_candidate_id TEXT")

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def submit(self, proposal: CapabilityResearchProposal, now: datetime | None = None) -> CapabilityCandidate:
        created_at = now or datetime.now(timezone.utc)
        candidate = CapabilityCandidate(
            candidate_id=str(uuid4()),
            state=CapabilityCandidateState.PENDING_REVIEW,
            proposal=proposal,
            content_digest=proposal_digest(proposal),
            created_at=created_at,
        )
        with self.lock:
            self.connection.execute(
                "INSERT INTO capability_candidates(candidate_id, state, proposal_json, content_digest, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    candidate.candidate_id,
                    candidate.state.value,
                    candidate.proposal.model_dump_json(),
                    candidate.content_digest,
                    candidate.created_at.isoformat(),
                ),
            )
        return candidate

    def get_candidate(self, candidate_id: str) -> CapabilityCandidate:
        with self.lock:
            row = self.connection.execute("SELECT * FROM capability_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
        if row is None:
            raise KeyError("capability candidate not found")
        proposal = CapabilityResearchProposal.model_validate_json(row["proposal_json"])
        if proposal_digest(proposal) != row["content_digest"]:
            raise ValueError("stored capability candidate digest is invalid")
        return CapabilityCandidate(
            candidate_id=row["candidate_id"],
            state=CapabilityCandidateState(row["state"]),
            proposal=proposal,
            content_digest=row["content_digest"],
            created_at=datetime.fromisoformat(row["created_at"]),
            reviewed_at=datetime.fromisoformat(row["reviewed_at"]) if row["reviewed_at"] else None,
            reviewer=row["reviewer"],
            review_note=row["review_note"],
            evaluation=CapabilityPromotionEvaluation.model_validate_json(row["evaluation_json"]) if row["evaluation_json"] else None,
            supersedes_candidate_id=row["supersedes_candidate_id"],
        )

    def revise(
        self,
        candidate_id: str,
        revised_proposal: CapabilityResearchProposal,
        actor: str,
        note: str | None = None,
        now: datetime | None = None,
    ) -> CapabilityCandidate:
        if not actor or len(actor) > 128:
            raise ValueError("review actor must be a bounded non-empty identifier")
        if note is not None and len(note) > 1000:
            raise ValueError("review note exceeds 1000 characters")
        candidate = self.get_candidate(candidate_id)
        if candidate.state != CapabilityCandidateState.PENDING_REVIEW:
            raise ValueError("only pending capability candidates may be revised")
        revised_at = now or datetime.now(timezone.utc)
        revision = CapabilityCandidate(
            candidate_id=str(uuid4()),
            state=CapabilityCandidateState.PENDING_REVIEW,
            proposal=revised_proposal,
            content_digest=proposal_digest(revised_proposal),
            created_at=revised_at,
            supersedes_candidate_id=candidate_id,
        )
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                updated = self.connection.execute(
                    "UPDATE capability_candidates SET state = ?, reviewed_at = ?, reviewer = ?, review_note = ? WHERE candidate_id = ? AND state = ?",
                    (CapabilityCandidateState.SUPERSEDED.value, revised_at.isoformat(), actor, note, candidate_id, CapabilityCandidateState.PENDING_REVIEW.value),
                ).rowcount
                if updated != 1:
                    raise ValueError("capability candidate revision lost a concurrent decision")
                self.connection.execute(
                    "INSERT INTO capability_candidates(candidate_id, state, proposal_json, content_digest, created_at, supersedes_candidate_id) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        revision.candidate_id,
                        revision.state.value,
                        revision.proposal.model_dump_json(),
                        revision.content_digest,
                        revision.created_at.isoformat(),
                        candidate_id,
                    ),
                )
            except Exception:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()
        return revision

    def review(
        self,
        candidate_id: str,
        decision: CapabilityReviewDecision,
        actor: str,
        evaluator: CapabilityEvaluator,
        note: str | None = None,
        now: datetime | None = None,
    ) -> CapabilityCandidate | PromotedCapability:
        if not actor or len(actor) > 128:
            raise ValueError("review actor must be a bounded non-empty identifier")
        if note is not None and len(note) > 1000:
            raise ValueError("review note exceeds 1000 characters")
        candidate = self.get_candidate(candidate_id)
        if candidate.state != CapabilityCandidateState.PENDING_REVIEW:
            raise ValueError("only pending capability candidates may be reviewed")
        reviewed_at = now or datetime.now(timezone.utc)
        if decision == CapabilityReviewDecision.REJECT:
            with self.lock:
                updated = self.connection.execute(
                    "UPDATE capability_candidates SET state = ?, reviewed_at = ?, reviewer = ?, review_note = ? WHERE candidate_id = ? AND state = ?",
                    (CapabilityCandidateState.REJECTED.value, reviewed_at.isoformat(), actor, note, candidate_id, CapabilityCandidateState.PENDING_REVIEW.value),
                ).rowcount
            if updated != 1:
                raise ValueError("capability candidate review lost a concurrent decision")
            return self.get_candidate(candidate_id)

        evaluation = evaluator.evaluate(candidate.proposal)
        if not evaluation.passed:
            with self.lock:
                updated = self.connection.execute(
                    "UPDATE capability_candidates SET state = ?, reviewed_at = ?, reviewer = ?, review_note = ?, evaluation_json = ? WHERE candidate_id = ? AND state = ?",
                    (
                        CapabilityCandidateState.EVALUATION_FAILED.value,
                        reviewed_at.isoformat(),
                        actor,
                        note,
                        evaluation.model_dump_json(),
                        candidate_id,
                        CapabilityCandidateState.PENDING_REVIEW.value,
                    ),
                ).rowcount
            if updated != 1:
                raise ValueError("capability candidate review lost a concurrent decision")
            return self.get_candidate(candidate_id)

        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                version = int(self.connection.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM promoted_capabilities WHERE capability_id = ?", (candidate.proposal.capability_id,)).fetchone()[0])
                updated = self.connection.execute(
                    "UPDATE capability_candidates SET state = ?, reviewed_at = ?, reviewer = ?, review_note = ?, evaluation_json = ? WHERE candidate_id = ? AND state = ?",
                    (
                        CapabilityCandidateState.PROMOTED.value,
                        reviewed_at.isoformat(),
                        actor,
                        note,
                        evaluation.model_dump_json(),
                        candidate_id,
                        CapabilityCandidateState.PENDING_REVIEW.value,
                    ),
                ).rowcount
                if updated != 1:
                    raise ValueError("capability candidate review lost a concurrent decision")
                self.connection.execute(
                    "INSERT INTO promoted_capabilities(capability_id, version, proposal_json, source_candidate_id, content_digest, promoted_at, promoted_by, evaluation_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        candidate.proposal.capability_id,
                        version,
                        candidate.proposal.model_dump_json(),
                        candidate_id,
                        candidate.content_digest,
                        reviewed_at.isoformat(),
                        actor,
                        evaluation.model_dump_json(),
                    ),
                )
            except Exception:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()
        return PromotedCapability(
            capability_id=candidate.proposal.capability_id,
            version=version,
            proposal=candidate.proposal,
            source_candidate_id=candidate_id,
            content_digest=candidate.content_digest,
            promoted_at=reviewed_at,
            promoted_by=actor,
            evaluation=evaluation,
        )

    def find_approved(self, signals: set[str], evidence_categories: set[str]) -> list[PromotedCapability]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT promoted.* FROM promoted_capabilities promoted "
                "JOIN (SELECT capability_id, MAX(version) AS version FROM promoted_capabilities GROUP BY capability_id) latest "
                "ON promoted.capability_id = latest.capability_id AND promoted.version = latest.version "
                "ORDER BY promoted.promoted_at DESC"
            ).fetchall()
        matches: list[PromotedCapability] = []
        for row in rows:
            proposal = CapabilityResearchProposal.model_validate_json(row["proposal_json"])
            if proposal_digest(proposal) != row["content_digest"]:
                raise ValueError("stored promoted capability digest is invalid")
            if capability_matches(proposal, signals, evidence_categories):
                matches.append(PromotedCapability(
                    capability_id=row["capability_id"],
                    version=row["version"],
                    proposal=proposal,
                    source_candidate_id=row["source_candidate_id"],
                    content_digest=row["content_digest"],
                    promoted_at=datetime.fromisoformat(row["promoted_at"]),
                    promoted_by=row["promoted_by"],
                    evaluation=CapabilityPromotionEvaluation.model_validate_json(row["evaluation_json"]),
                ))
        return matches

    def get_promoted(self, capability_id: str, version: int) -> PromotedCapability:
        with self.lock:
            row = self.connection.execute(
                "SELECT * FROM promoted_capabilities WHERE capability_id = ? AND version = ?",
                (capability_id, version),
            ).fetchone()
        if row is None:
            raise KeyError("promoted capability not found")
        proposal = CapabilityResearchProposal.model_validate_json(row["proposal_json"])
        if proposal_digest(proposal) != row["content_digest"]:
            raise ValueError("stored promoted capability digest is invalid")
        return PromotedCapability(
            capability_id=row["capability_id"],
            version=row["version"],
            proposal=proposal,
            source_candidate_id=row["source_candidate_id"],
            content_digest=row["content_digest"],
            promoted_at=datetime.fromisoformat(row["promoted_at"]),
            promoted_by=row["promoted_by"],
            evaluation=CapabilityPromotionEvaluation.model_validate_json(row["evaluation_json"]),
        )

    def record_activation(self, record: CapabilityActivationRecord) -> None:
        # Activation history must reference a real promoted record. get_promoted
        # raises KeyError for an unknown capability or version and also
        # digest-verifies the stored contract, so a tampered or unpromoted
        # record cannot enter the activation history.
        self.get_promoted(record.capability_id, record.version)
        with self.lock:
            self.connection.execute(
                "INSERT INTO capability_activations(activation_id, run_id, proposal_id, capability_id, version, target_id, outcome, verification, rollback_applied, occurred_at, actor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.activation_id,
                    record.run_id,
                    record.proposal_id,
                    record.capability_id,
                    record.version,
                    record.target_id,
                    record.outcome,
                    int(record.verification),
                    int(record.rollback_applied),
                    record.occurred_at.isoformat(),
                    record.actor,
                ),
            )

    def list_activations(self, capability_id: str | None = None) -> list[CapabilityActivationRecord]:
        query = "SELECT * FROM capability_activations"
        parameters: tuple[str, ...] = ()
        if capability_id is not None:
            query += " WHERE capability_id = ?"
            parameters = (capability_id,)
        with self.lock:
            rows = self.connection.execute(query + " ORDER BY occurred_at ASC", parameters).fetchall()
        return [
            CapabilityActivationRecord(
                activation_id=row["activation_id"],
                run_id=row["run_id"],
                proposal_id=row["proposal_id"],
                capability_id=row["capability_id"],
                version=row["version"],
                target_id=row["target_id"],
                outcome=row["outcome"],
                verification=bool(row["verification"]),
                rollback_applied=bool(row["rollback_applied"]),
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                actor=row["actor"],
            )
            for row in rows
        ]


def simulated_reviewer_revision(proposal: CapabilityResearchProposal) -> CapabilityResearchProposal:
    """POC-only reviewer edit; production review remains an external human decision."""
    non_causal_context = {"http_503", "worker_unavailable", "cpu_normal", "filesystem_normal", "image_unchanged"}
    prerequisites = [signal for signal in proposal.prerequisites if signal not in non_causal_context]
    categories = [category for category in proposal.required_evidence_categories if category != "health"]
    blast_radius = proposal.maximum_blast_radius
    if not capability_policy_pass(proposal)["bounded_blast_radius"]:
        blast_radius = "Exactly one owned disposable worker; no scope beyond that single worker."
    return CapabilityResearchProposal.model_validate({
        **proposal.model_dump(mode="json"),
        "prerequisites": prerequisites,
        "required_evidence_categories": categories,
        "maximum_blast_radius": blast_radius,
    })
