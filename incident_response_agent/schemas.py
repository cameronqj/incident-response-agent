from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Scenario(str, Enum):
    DISK_EXHAUSTION = "disk-exhaustion"
    RUNAWAY_CPU = "runaway-cpu"
    MEMORY_OOM = "memory-oom"
    RESTARTING_SERVICE = "restarting-service"
    LOG_STORM = "log-storm"


class ScenarioKind(str, Enum):
    SYNTHETIC_MARKER = "synthetic_marker"
    CONTAINER_FAULT = "container_fault"


class EventSource(str, Enum):
    LOCAL_SIMULATION = "local_simulation"


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


ShortText = Annotated[str, Field(max_length=500)]


class EventContextField(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    value: ShortText


class EventPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: Scenario
    summary: Optional[ShortText] = None
    log_lines: List[ShortText] = Field(default_factory=list, max_length=20)
    context: List[EventContextField] = Field(default_factory=list, max_length=20)


class EventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    source: EventSource
    observed_at: datetime
    event_type: str = Field(default="incident.detected", pattern=r"^incident\.detected$")
    payload: EventPayload
    trace_id: Optional[str] = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value

    @model_validator(mode="after")
    def payload_must_be_bounded(self) -> "EventRequest":
        encoded = json.dumps(self.model_dump(mode="json"), separators=(",", ":")).encode("utf-8")
        if len(encoded) > 16_384:
            raise ValueError("event payload exceeds 16384 bytes")
        return self


class TelemetryEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: Scenario
    scenario_kind: ScenarioKind = ScenarioKind.SYNTHETIC_MARKER
    rotation_failed: bool
    free_bytes: int = Field(ge=0)
    log_growth_bytes_per_minute: int = Field(ge=0)
    affected_file_count: int = Field(ge=0)
    cpu_percent: float = Field(default=0, ge=0, le=100)
    memory_percent: float = Field(default=0, ge=0, le=100)
    oom_kill_detected: bool = False
    log_storm_detected: bool = False
    temp_file_count: int = Field(default=0, ge=0)
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
    evidence_refs: List[ShortText] = Field(default_factory=list, max_length=20)
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
    scenario: Scenario
    scenario_kind: ScenarioKind
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
