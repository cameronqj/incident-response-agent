from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Sequence

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from incident_response_agent.executor import DisposableFilesystemExecutor
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.schemas import Decision, DecisionRequest, EventRequest
from incident_response_agent.service import IncidentService
from incident_response_agent.site_investigation import (
    DisposableSiteLab,
    FixedInvestigationTelemetry,
    InvestigationAnalyzer,
    InvestigationResult,
    InvestigationTrace,
    SiteHealthAlert,
    build_diagnostic_tools,
    create_incident_deep_agent,
    investigate_site,
)
from incident_response_agent.storage import SQLiteStore


class ScriptedInvestigationModel(BaseChatModel):
    call_number: int = 0
    bound_tool_names: list[str] = []
    bad_evidence: bool = False

    @property
    def _llm_type(self) -> str:
        return "scripted-investigation"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {}

    def bind_tools(self, tools: Sequence[Any], **_kwargs: Any) -> "ScriptedInvestigationModel":
        self.bound_tool_names = [getattr(item, "name", "") for item in tools]
        return self

    def _generate(self, _messages: list[BaseMessage], stop: list[str] | None = None, run_manager: Any = None, **_kwargs: Any) -> ChatResult:
        del stop, run_manager
        self.call_number += 1
        if self.call_number == 1:
            message = AIMessage(content="", tool_calls=[{"name": "inspect_resources", "args": {}, "id": "resources"}])
        elif self.call_number == 2:
            message = AIMessage(content="", tool_calls=[{"name": "inspect_recent_logs", "args": {}, "id": "logs"}])
        else:
            refs = ["resources-1", "unobserved-secret"] if self.bad_evidence else ["resources-1", "logs-1"]
            message = AIMessage(
                content="",
                tool_calls=[{
                    "name": "InvestigationResult",
                    "id": "diagnosis",
                    "args": {
                        "diagnosed_scenario": "disk-exhaustion",
                        "severity": "high",
                        "confidence": 0.96,
                        "evidence_refs": refs,
                        "proposed_action_id": "cleanup_rotated_logs",
                        "explanation": "Failed log rotation exhausted the bounded filesystem.",
                    },
                }],
            )
        return ChatResult(generations=[ChatGeneration(message=message)])


def build_lab(tmp_path):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "site")
    return sandbox, DisposableSiteLab.disk_exhaustion(sandbox)


def test_diagnostics_expose_symptoms_not_hidden_ground_truth(tmp_path):
    sandbox, lab = build_lab(tmp_path)
    try:
        rendered = " ".join(tool.invoke({}) for tool in build_diagnostic_tools(lab, InvestigationTrace()))
        assert "disk-exhaustion" not in rendered
        assert "ENOSPC" not in rendered
        assert "low_free_space" in rendered
        assert lab.expected_scenario.value == "disk-exhaustion"
    finally:
        sandbox.close()


def test_deep_agent_uses_bounded_tools_and_returns_validated_diagnosis(tmp_path):
    sandbox, lab = build_lab(tmp_path)
    try:
        trace = InvestigationTrace()
        model = ScriptedInvestigationModel()
        agent = create_incident_deep_agent(model, lab, trace)
        result = investigate_site(agent, SiteHealthAlert(idempotency_key="site-1", observed_at=datetime.now(timezone.utc)), trace)
        assert result.diagnosed_scenario.value == "disk-exhaustion"
        assert trace.tool_calls == ["inspect_resources", "inspect_recent_logs"]
        assert "task" in model.bound_tool_names
        assert "execute" not in model.bound_tool_names
        assert "InvestigationResult" in model.bound_tool_names
    finally:
        sandbox.close()


def test_diagnosis_cannot_cite_unobserved_evidence(tmp_path):
    sandbox, lab = build_lab(tmp_path)
    try:
        trace = InvestigationTrace()
        agent = create_incident_deep_agent(ScriptedInvestigationModel(bad_evidence=True), lab, trace)
        with pytest.raises(ValueError, match="not observed"):
            investigate_site(agent, SiteHealthAlert(idempotency_key="site-2", observed_at=datetime.now(timezone.utc)), trace)
    finally:
        sandbox.close()


def test_investigation_hands_off_to_existing_approval_and_recovers(tmp_path):
    sandbox, lab = build_lab(tmp_path)
    service = None
    try:
        trace = InvestigationTrace()
        result = investigate_site(
            create_incident_deep_agent(ScriptedInvestigationModel(), lab, trace),
            SiteHealthAlert(idempotency_key="site-3", observed_at=datetime.now(timezone.utc)),
            trace,
        )
        service = IncidentService(
            SQLiteStore(":memory:"),
            FixedInvestigationTelemetry(lab.telemetry_for(result)),
            InvestigationAnalyzer(result),
            DisposableFilesystemExecutor(sandbox),
            execution_enabled=True,
        )
        run = service.start_event(EventRequest.model_validate({
            "idempotency_key": "site-3",
            "source": "local_simulation",
            "observed_at": datetime.now(timezone.utc),
            "payload": {"scenario": result.diagnosed_scenario.value},
        }))
        assert run.proposal is not None
        proposal = run.proposal
        service.decide(proposal.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=proposal.revision, action_hash=proposal.action_hash))
        completed = service.execute(proposal.proposal_id)
        assert completed.state.value == "succeeded"
        assert lab.check_health().measurements["status_code"] == 200
    finally:
        if service:
            service.close()
        sandbox.close()


@pytest.mark.live
def test_live_deep_agent_tool_call_compatibility(tmp_path):
    from incident_response_agent.config import Settings
    from incident_response_agent.site_investigation import create_live_investigation_model

    sandbox, lab = build_lab(tmp_path)
    try:
        settings = Settings.from_env()
        trace = InvestigationTrace()
        result = investigate_site(
            create_incident_deep_agent(create_live_investigation_model(settings), lab, trace),
            SiteHealthAlert(idempotency_key="live-site", observed_at=datetime.now(timezone.utc)),
            trace,
        )
        assert result.diagnosed_scenario.value == "disk-exhaustion"
        assert trace.tool_calls
    finally:
        sandbox.close()
