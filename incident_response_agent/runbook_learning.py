from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Annotated, ClassVar, Literal, Protocol
from uuid import uuid4

from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends import StateBackend
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import BaseModel, ConfigDict, Field

from .site_investigation import DiagnosticObservation, InvestigationTrace, SiteDiagnosticTarget, build_diagnostic_tools


SignalName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")]
EvidenceId = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]*$")]
DiagnosticStep = Annotated[str, Field(min_length=5, max_length=500)]


class RunbookCandidateState(str, Enum):
    PENDING_REVIEW = "pending_review"
    SUPERSEDED = "superseded"
    REJECTED = "rejected"
    EVALUATION_FAILED = "evaluation_failed"
    PROMOTED = "promoted"


class RunbookReviewDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class RunbookResearchProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    problem_signature: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9.-]+$")
    title: str = Field(min_length=3, max_length=160)
    summary: str = Field(min_length=10, max_length=1000)
    applicability_signals: list[SignalName] = Field(min_length=2, max_length=12)
    required_evidence_categories: list[Literal["health", "resources", "services", "processes", "logs", "changes"]] = Field(min_length=2, max_length=6)
    diagnostic_steps: list[DiagnosticStep] = Field(min_length=2, max_length=8)
    conclusion: str = Field(min_length=10, max_length=1000)
    source_evidence_refs: list[EvidenceId] = Field(min_length=2, max_length=12)
    confidence: float = Field(ge=0, le=1)


class RunbookCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    state: RunbookCandidateState
    proposal: RunbookResearchProposal
    content_digest: str = Field(min_length=64, max_length=64)
    created_at: datetime
    reviewed_at: datetime | None = None
    reviewer: str | None = None
    review_note: str | None = None
    evaluation: RunbookPromotionEvaluation | None = None
    supersedes_candidate_id: str | None = None


class RunbookEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    signals: list[SignalName] = Field(max_length=20)
    evidence_categories: list[str] = Field(max_length=6)
    expected_match: bool


class RunbookPromotionEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    case_count: int = Field(ge=1)
    case_accuracy: float = Field(ge=0, le=1)
    false_positive_count: int = Field(ge=0)
    bounded_steps: bool
    sufficient_confidence: bool
    results: dict[str, bool]


class PromotedRunbook(BaseModel):
    model_config = ConfigDict(extra="forbid")

    runbook_id: str
    version: int = Field(ge=1)
    proposal: RunbookResearchProposal
    source_candidate_id: str
    content_digest: str
    promoted_at: datetime
    promoted_by: str
    evaluation: RunbookPromotionEvaluation


@dataclass(frozen=True)
class WorkerMemoryPressureLab(SiteDiagnosticTarget):
    """Unfamiliar disposable profile; the private expected label is never tool-visible."""

    _expected_signature: ClassVar[str] = "worker-concurrency-memory-pressure"

    def check_health(self) -> DiagnosticObservation:
        return DiagnosticObservation(
            evidence_id="health-1",
            category="health",
            summary="The owned disposable worker API intermittently returns HTTP 503.",
            signals=["http_503", "worker_unavailable"],
            measurements={"status_code": 503},
        )

    def inspect_resources(self) -> DiagnosticObservation:
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
        return DiagnosticObservation(
            evidence_id="logs-1",
            category="logs",
            summary="Bounded logs show workers exceeding their memory limit and being OOM-killed when twelve jobs run concurrently.",
            signals=["oom_kill", "concurrency_correlated_oom"],
            measurements={"oom_kill_count": 4, "observed_concurrency": 12},
        )


RUNBOOK_RESEARCH_PROMPT = """You research an unfamiliar failure affecting one owned disposable service. Use the read-only diagnostics to establish a supported problem signature and propose reusable diagnostic guidance, not an executable remediation. Inspect health, resources, recent changes, and recent logs before concluding. Return a structured runbook candidate with a narrow lowercase problem_signature, positive applicability signals, required evidence categories, bounded diagnostic steps, a conclusion or escalation condition, and only evidence IDs returned by tools. Do not propose commands, shell access, file paths, credentials, or executable authority. A separate application-owned reviewer and deterministic evaluation gate decide whether the candidate is promoted."""


def create_runbook_research_agent(model: BaseChatModel, target: SiteDiagnosticTarget, trace: InvestigationTrace):
    return create_deep_agent(
        model=model,
        tools=build_diagnostic_tools(target, trace),
        system_prompt=RUNBOOK_RESEARCH_PROMPT,
        response_format=RunbookResearchProposal,
        backend=StateBackend(),
        permissions=[FilesystemPermission(operations=["read", "write"], paths=["/**"], mode="deny")],
        checkpointer=InMemorySaver(),
    )


def research_runbook(agent, trace: InvestigationTrace, thread_id: str) -> RunbookResearchProposal:
    output = agent.invoke(
        {"messages": [{"role": "user", "content": "The owned disposable service has an unfamiliar recurring failure. Investigate it and propose reusable diagnostic guidance."}]},
        config={"configurable": {"thread_id": thread_id}, "recursion_limit": 14},
    )
    proposal = RunbookResearchProposal.model_validate(output["structured_response"])
    observations = trace.observations_for(thread_id)
    if set(proposal.source_evidence_refs) - set(observations):
        raise ValueError("runbook candidate cited evidence that was not observed")
    observed_categories = {observation.category for observation in observations.values()}
    if set(proposal.required_evidence_categories) - observed_categories:
        raise ValueError("runbook candidate requires an evidence category that was not observed")
    observed_signals = {signal for observation in observations.values() for signal in observation.signals}
    if set(proposal.applicability_signals) - observed_signals:
        raise ValueError("runbook candidate uses an applicability signal that was not observed")
    return proposal


def proposal_digest(proposal: RunbookResearchProposal) -> str:
    encoded = json.dumps(proposal.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def runbook_matches(proposal: RunbookResearchProposal, signals: set[str], evidence_categories: set[str]) -> bool:
    return set(proposal.applicability_signals).issubset(signals) and set(proposal.required_evidence_categories).issubset(evidence_categories)


DEFAULT_PROMOTION_CASES = (
    RunbookEvaluationCase(
        case_id="same-worker-failure",
        signals=["memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill"],
        evidence_categories=["health", "resources", "changes", "logs"],
        expected_match=True,
    ),
    RunbookEvaluationCase(
        case_id="same-failure-with-noise",
        signals=["http_503", "memory_pressure", "worker_concurrency_increased", "concurrency_correlated_oom", "oom_kill", "filesystem_normal"],
        evidence_categories=["health", "resources", "changes", "logs"],
        expected_match=True,
    ),
    RunbookEvaluationCase(
        case_id="generic-memory-pressure",
        signals=["memory_pressure", "oom_kill"],
        evidence_categories=["health", "resources", "logs"],
        expected_match=False,
    ),
    RunbookEvaluationCase(
        case_id="concurrency-without-oom",
        signals=["worker_concurrency_increased", "latency_high"],
        evidence_categories=["health", "changes"],
        expected_match=False,
    ),
    RunbookEvaluationCase(
        case_id="disk-exhaustion",
        signals=["http_503", "low_free_space", "rotation_error", "no_space_left"],
        evidence_categories=["health", "resources", "logs"],
        expected_match=False,
    ),
)


class RunbookEvaluator(Protocol):
    def evaluate(self, proposal: RunbookResearchProposal) -> RunbookPromotionEvaluation: ...


class DeterministicRunbookEvaluator:
    def __init__(self, cases: tuple[RunbookEvaluationCase, ...] = DEFAULT_PROMOTION_CASES):
        if not cases:
            raise ValueError("runbook promotion requires evaluation cases")
        self.cases = cases

    def evaluate(self, proposal: RunbookResearchProposal) -> RunbookPromotionEvaluation:
        results = {
            case.case_id: runbook_matches(proposal, set(case.signals), set(case.evidence_categories)) == case.expected_match
            for case in self.cases
        }
        false_positive_count = sum(
            1
            for case in self.cases
            if not case.expected_match and runbook_matches(proposal, set(case.signals), set(case.evidence_categories))
        )
        accuracy = sum(results.values()) / len(results)
        bounded_steps = 2 <= len(proposal.diagnostic_steps) <= 8
        sufficient_confidence = proposal.confidence >= 0.8
        return RunbookPromotionEvaluation(
            passed=accuracy == 1.0 and false_positive_count == 0 and bounded_steps and sufficient_confidence,
            case_count=len(results),
            case_accuracy=accuracy,
            false_positive_count=false_positive_count,
            bounded_steps=bounded_steps,
            sufficient_confidence=sufficient_confidence,
            results=results,
        )


class RunbookRegistry:
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
                CREATE TABLE IF NOT EXISTS runbook_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    proposal_json TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reviewed_at TEXT,
                    reviewer TEXT,
                    review_note TEXT,
                    evaluation_json TEXT,
                    supersedes_candidate_id TEXT REFERENCES runbook_candidates(candidate_id)
                );
                CREATE TABLE IF NOT EXISTS promoted_runbooks (
                    runbook_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    proposal_json TEXT NOT NULL,
                    source_candidate_id TEXT NOT NULL UNIQUE REFERENCES runbook_candidates(candidate_id),
                    content_digest TEXT NOT NULL,
                    promoted_at TEXT NOT NULL,
                    promoted_by TEXT NOT NULL,
                    evaluation_json TEXT NOT NULL,
                    PRIMARY KEY(runbook_id, version)
                );
                """
            )
            columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(runbook_candidates)").fetchall()}
            if "supersedes_candidate_id" not in columns:
                self.connection.execute("ALTER TABLE runbook_candidates ADD COLUMN supersedes_candidate_id TEXT")

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def submit(self, proposal: RunbookResearchProposal, now: datetime | None = None) -> RunbookCandidate:
        created_at = now or datetime.now(timezone.utc)
        candidate = RunbookCandidate(
            candidate_id=str(uuid4()),
            state=RunbookCandidateState.PENDING_REVIEW,
            proposal=proposal,
            content_digest=proposal_digest(proposal),
            created_at=created_at,
        )
        with self.lock:
            self.connection.execute(
                "INSERT INTO runbook_candidates(candidate_id, state, proposal_json, content_digest, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    candidate.candidate_id,
                    candidate.state.value,
                    candidate.proposal.model_dump_json(),
                    candidate.content_digest,
                    candidate.created_at.isoformat(),
                ),
            )
        return candidate

    def get_candidate(self, candidate_id: str) -> RunbookCandidate:
        with self.lock:
            row = self.connection.execute("SELECT * FROM runbook_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
        if row is None:
            raise KeyError("runbook candidate not found")
        proposal = RunbookResearchProposal.model_validate_json(row["proposal_json"])
        if proposal_digest(proposal) != row["content_digest"]:
            raise ValueError("stored runbook candidate digest is invalid")
        return RunbookCandidate(
            candidate_id=row["candidate_id"],
            state=RunbookCandidateState(row["state"]),
            proposal=proposal,
            content_digest=row["content_digest"],
            created_at=datetime.fromisoformat(row["created_at"]),
            reviewed_at=datetime.fromisoformat(row["reviewed_at"]) if row["reviewed_at"] else None,
            reviewer=row["reviewer"],
            review_note=row["review_note"],
            evaluation=RunbookPromotionEvaluation.model_validate_json(row["evaluation_json"]) if row["evaluation_json"] else None,
            supersedes_candidate_id=row["supersedes_candidate_id"],
        )

    def revise(
        self,
        candidate_id: str,
        revised_proposal: RunbookResearchProposal,
        actor: str,
        note: str | None = None,
        now: datetime | None = None,
    ) -> RunbookCandidate:
        if not actor or len(actor) > 128:
            raise ValueError("review actor must be a bounded non-empty identifier")
        if note is not None and len(note) > 1000:
            raise ValueError("review note exceeds 1000 characters")
        candidate = self.get_candidate(candidate_id)
        if candidate.state != RunbookCandidateState.PENDING_REVIEW:
            raise ValueError("only pending runbook candidates may be revised")
        revised_at = now or datetime.now(timezone.utc)
        revision = RunbookCandidate(
            candidate_id=str(uuid4()),
            state=RunbookCandidateState.PENDING_REVIEW,
            proposal=revised_proposal,
            content_digest=proposal_digest(revised_proposal),
            created_at=revised_at,
            supersedes_candidate_id=candidate_id,
        )
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                updated = self.connection.execute(
                    "UPDATE runbook_candidates SET state = ?, reviewed_at = ?, reviewer = ?, review_note = ? WHERE candidate_id = ? AND state = ?",
                    (RunbookCandidateState.SUPERSEDED.value, revised_at.isoformat(), actor, note, candidate_id, RunbookCandidateState.PENDING_REVIEW.value),
                ).rowcount
                if updated != 1:
                    raise ValueError("runbook candidate revision lost a concurrent decision")
                self.connection.execute(
                    "INSERT INTO runbook_candidates(candidate_id, state, proposal_json, content_digest, created_at, supersedes_candidate_id) VALUES (?, ?, ?, ?, ?, ?)",
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
        decision: RunbookReviewDecision,
        actor: str,
        evaluator: RunbookEvaluator,
        note: str | None = None,
        now: datetime | None = None,
    ) -> RunbookCandidate | PromotedRunbook:
        if not actor or len(actor) > 128:
            raise ValueError("review actor must be a bounded non-empty identifier")
        if note is not None and len(note) > 1000:
            raise ValueError("review note exceeds 1000 characters")
        candidate = self.get_candidate(candidate_id)
        if candidate.state != RunbookCandidateState.PENDING_REVIEW:
            raise ValueError("only pending runbook candidates may be reviewed")
        reviewed_at = now or datetime.now(timezone.utc)
        if decision == RunbookReviewDecision.REJECT:
            with self.lock:
                updated = self.connection.execute(
                    "UPDATE runbook_candidates SET state = ?, reviewed_at = ?, reviewer = ?, review_note = ? WHERE candidate_id = ? AND state = ?",
                    (RunbookCandidateState.REJECTED.value, reviewed_at.isoformat(), actor, note, candidate_id, RunbookCandidateState.PENDING_REVIEW.value),
                ).rowcount
            if updated != 1:
                raise ValueError("runbook candidate review lost a concurrent decision")
            return self.get_candidate(candidate_id)

        evaluation = evaluator.evaluate(candidate.proposal)
        if not evaluation.passed:
            with self.lock:
                updated = self.connection.execute(
                    "UPDATE runbook_candidates SET state = ?, reviewed_at = ?, reviewer = ?, review_note = ?, evaluation_json = ? WHERE candidate_id = ? AND state = ?",
                    (
                        RunbookCandidateState.EVALUATION_FAILED.value,
                        reviewed_at.isoformat(),
                        actor,
                        note,
                        evaluation.model_dump_json(),
                        candidate_id,
                        RunbookCandidateState.PENDING_REVIEW.value,
                    ),
                ).rowcount
            if updated != 1:
                raise ValueError("runbook candidate review lost a concurrent decision")
            return self.get_candidate(candidate_id)

        runbook_id = candidate.proposal.problem_signature
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                version = int(self.connection.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM promoted_runbooks WHERE runbook_id = ?", (runbook_id,)).fetchone()[0])
                updated = self.connection.execute(
                    "UPDATE runbook_candidates SET state = ?, reviewed_at = ?, reviewer = ?, review_note = ?, evaluation_json = ? WHERE candidate_id = ? AND state = ?",
                    (
                        RunbookCandidateState.PROMOTED.value,
                        reviewed_at.isoformat(),
                        actor,
                        note,
                        evaluation.model_dump_json(),
                        candidate_id,
                        RunbookCandidateState.PENDING_REVIEW.value,
                    ),
                ).rowcount
                if updated != 1:
                    raise ValueError("runbook candidate review lost a concurrent decision")
                self.connection.execute(
                    "INSERT INTO promoted_runbooks(runbook_id, version, proposal_json, source_candidate_id, content_digest, promoted_at, promoted_by, evaluation_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        runbook_id,
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
        return PromotedRunbook(
            runbook_id=runbook_id,
            version=version,
            proposal=candidate.proposal,
            source_candidate_id=candidate_id,
            content_digest=candidate.content_digest,
            promoted_at=reviewed_at,
            promoted_by=actor,
            evaluation=evaluation,
        )

    def find_applicable(self, signals: set[str], evidence_categories: set[str]) -> list[PromotedRunbook]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT promoted.* FROM promoted_runbooks promoted "
                "JOIN (SELECT runbook_id, MAX(version) AS version FROM promoted_runbooks GROUP BY runbook_id) latest "
                "ON promoted.runbook_id = latest.runbook_id AND promoted.version = latest.version "
                "ORDER BY promoted.promoted_at DESC"
            ).fetchall()
        matches: list[PromotedRunbook] = []
        for row in rows:
            proposal = RunbookResearchProposal.model_validate_json(row["proposal_json"])
            if proposal_digest(proposal) != row["content_digest"]:
                raise ValueError("stored promoted runbook digest is invalid")
            if runbook_matches(proposal, signals, evidence_categories):
                matches.append(PromotedRunbook(
                    runbook_id=row["runbook_id"],
                    version=row["version"],
                    proposal=proposal,
                    source_candidate_id=row["source_candidate_id"],
                    content_digest=row["content_digest"],
                    promoted_at=datetime.fromisoformat(row["promoted_at"]),
                    promoted_by=row["promoted_by"],
                    evaluation=RunbookPromotionEvaluation.model_validate_json(row["evaluation_json"]),
                ))
        return matches

    def get_promoted(self, runbook_id: str, version: int) -> PromotedRunbook:
        with self.lock:
            row = self.connection.execute(
                "SELECT * FROM promoted_runbooks WHERE runbook_id = ? AND version = ?",
                (runbook_id, version),
            ).fetchone()
        if row is None:
            raise KeyError("promoted runbook not found")
        proposal = RunbookResearchProposal.model_validate_json(row["proposal_json"])
        if proposal_digest(proposal) != row["content_digest"]:
            raise ValueError("stored promoted runbook digest is invalid")
        return PromotedRunbook(
            runbook_id=row["runbook_id"],
            version=row["version"],
            proposal=proposal,
            source_candidate_id=row["source_candidate_id"],
            content_digest=row["content_digest"],
            promoted_at=datetime.fromisoformat(row["promoted_at"]),
            promoted_by=row["promoted_by"],
            evaluation=RunbookPromotionEvaluation.model_validate_json(row["evaluation_json"]),
        )


def simulated_reviewer_revision(proposal: RunbookResearchProposal) -> RunbookResearchProposal:
    """POC-only reviewer edit; production review remains an external human decision."""
    non_causal_context = {"http_503", "worker_unavailable", "cpu_normal", "filesystem_normal", "image_unchanged"}
    applicability_signals = [signal for signal in proposal.applicability_signals if signal not in non_causal_context]
    required_categories = [category for category in proposal.required_evidence_categories if category != "health"]
    return RunbookResearchProposal.model_validate({
        **proposal.model_dump(mode="json"),
        "applicability_signals": applicability_signals,
        "required_evidence_categories": required_categories,
    })
