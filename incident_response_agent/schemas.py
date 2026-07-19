from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class RunState(str, Enum):
    RECEIVED = "received"
    INVESTIGATING = "investigating"
    ASSESSED = "assessed"
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ProposalState(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class Decision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    REVISE = "revise"


class EventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=256)
    event_type: str = Field(default="incident.detected", min_length=1, max_length=128)
    payload: Dict[str, Any] = Field(default_factory=dict)
    trace_id: Optional[str] = Field(default=None, max_length=128)


class TelemetryEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    rotation_failed: bool
    free_bytes: int = Field(ge=0)
    log_growth_bytes_per_minute: int = Field(ge=0)
    affected_file_count: int = Field(ge=0)
    cpu_percent: float = Field(default=0, ge=0, le=100)
    runaway_process_detected: bool = False
    service_state: Optional[str] = None
    restart_count: int = Field(default=0, ge=0)
    signals: List[str] = Field(default_factory=list)
    fault_injection: Optional[str] = None


class ModelAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2000)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    confidence: float = Field(ge=0, le=1)
    evidence_refs: List[str] = Field(default_factory=list, max_length=20)
    action_id: str = Field(min_length=1, max_length=128)


class RemediationOption(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    title: str
    evidence: List[str]
    confidence: float = Field(ge=0, le=1)
    impact: str
    risk: str
    action_preview: str


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    revision: int = Field(ge=1)
    action_hash: str = Field(min_length=64, max_length=64)
    note: Optional[str] = Field(default=None, max_length=1000)


class ProposalView(BaseModel):
    proposal_id: str
    run_id: str
    revision: int
    status: ProposalState
    assessment: ModelAssessment
    option: RemediationOption
    action_hash: str
    expires_at: datetime
    created_at: datetime
    approved_action_hash: Optional[str] = None


class AuditView(BaseModel):
    audit_id: int
    trace_id: str
    run_id: str
    proposal_id: Optional[str]
    event_type: str
    metadata: Dict[str, Any]
    occurred_at: datetime


class RunView(BaseModel):
    run_id: str
    trace_id: str
    idempotency_key: str
    state: RunState
    created_at: datetime
    updated_at: datetime
    proposal: Optional[ProposalView] = None
    audit: List[AuditView] = Field(default_factory=list)
    duplicate: bool = False
