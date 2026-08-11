from __future__ import annotations

import json
from typing import Any, Sequence

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from incident_response_agent.reflection_eval import (
    EVALUATION_CASES,
    CritiqueResult,
    EvaluationTarget,
    action_correct,
    diagnosis_correct,
    distractor_rejection,
    evidence_precision,
    reference_output,
    run_direct_case,
    run_reflective_case,
    trajectory_coverage,
    within_tool_budget,
)
from incident_response_agent.site_investigation import InvestigationTrace, build_diagnostic_tools


class ScriptedEvalModel(BaseChatModel):
    responses: list[AIMessage]
    call_number: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted-reflection-eval"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {}

    def bind_tools(self, _tools: Sequence[Any], **_kwargs: Any) -> "ScriptedEvalModel":
        return self

    def _generate(self, _messages: list[BaseMessage], stop: list[str] | None = None, run_manager: Any = None, **_kwargs: Any) -> ChatResult:
        del stop, run_manager
        message = self.responses[self.call_number]
        self.call_number += 1
        return ChatResult(generations=[ChatGeneration(message=message)])


class FixedCritic:
    calls: int = 0

    def critique(self, _result, _observations):
        self.calls += 1
        return CritiqueResult(
            needs_revision=True,
            unsupported_evidence_refs=["changes-1"],
            missing_evidence_categories=[],
            explanation="The successful deployment excludes a hypothesis but does not support the disk-exhaustion cause.",
        )


class FixedReviser:
    calls: int = 0

    def revise(self, result, _critique, _observations):
        self.calls += 1
        return result.model_copy(update={"evidence_refs": ["resources-1", "logs-1"]})


def _tool(name: str, call_id: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": {}, "id": call_id}])


def _result(evidence_refs: list[str]) -> AIMessage:
    return AIMessage(content="", tool_calls=[{
        "name": "InvestigationResult",
        "id": f"result-{len(evidence_refs)}",
        "args": {
            "diagnosed_scenario": "disk-exhaustion",
            "severity": "high",
            "confidence": 0.94,
            "evidence_refs": evidence_refs,
            "proposed_action_id": "cleanup_rotated_logs",
            "explanation": "Low free space and failed rotation form the supported causal chain.",
        },
    }])


def test_eval_suite_has_five_hidden_ground_truth_cases():
    assert len(EVALUATION_CASES) == 5
    assert len(set(EVALUATION_CASES)) == 5
    for case in EVALUATION_CASES.values():
        trace = InvestigationTrace()
        rendered = " ".join(tool.invoke({}, config={"configurable": {"thread_id": case.case_id}}) for tool in build_diagnostic_tools(EvaluationTarget(case), trace))
        assert case.expected_scenario.value not in rendered
        assert case.expected_action not in rendered


def test_direct_eval_returns_json_serializable_trajectory():
    output = run_direct_case("disk-with-cpu-and-deploy-distractors", ScriptedEvalModel(responses=[
        _tool("inspect_resources", "resources"),
        _tool("inspect_recent_changes", "changes"),
        _tool("inspect_recent_logs", "logs"),
        _result(["resources-1", "changes-1", "logs-1"]),
    ]))
    assert output["diagnosed_scenario"] == "disk-exhaustion"
    assert output["critique_used"] is False
    assert output["tool_calls"] == ["inspect_resources", "inspect_recent_changes", "inspect_recent_logs"]
    json.dumps(output)


def test_reflection_runs_exactly_one_critique_and_removes_distractor():
    critic = FixedCritic()
    reviser = FixedReviser()
    output = run_reflective_case("disk-with-cpu-and-deploy-distractors", ScriptedEvalModel(responses=[
        _tool("inspect_resources", "resources"),
        _tool("inspect_recent_changes", "changes"),
        _tool("inspect_recent_logs", "logs"),
        _result(["resources-1", "changes-1", "logs-1"]),
    ]), critic, reviser)
    assert critic.calls == 1
    assert reviser.calls == 1
    assert output["critique_used"] is True
    assert output["evidence_refs"] == ["resources-1", "logs-1"]
    assert output["tool_calls"] == ["inspect_resources", "inspect_recent_changes", "inspect_recent_logs"]


def test_deterministic_evaluators_score_correctness_evidence_and_trajectory():
    reference = reference_output(EVALUATION_CASES["disk-with-cpu-and-deploy-distractors"])
    good = {
        "diagnosed_scenario": "disk-exhaustion",
        "proposed_action_id": "cleanup_rotated_logs",
        "evidence_refs": ["resources-1", "logs-1"],
        "tool_calls": ["inspect_resources", "inspect_recent_logs"],
    }
    noisy = {**good, "evidence_refs": ["resources-1", "logs-1", "changes-1"]}
    wrong = {**good, "diagnosed_scenario": "runaway-cpu", "proposed_action_id": "stop_runaway_process"}

    assert diagnosis_correct({}, good, reference)
    assert action_correct({}, good, reference)
    assert evidence_precision({}, good, reference) == 1.0
    assert distractor_rejection({}, good, reference)
    assert not distractor_rejection({}, noisy, reference)
    assert evidence_precision({}, noisy, reference) == 2 / 3
    assert trajectory_coverage({}, good, reference) == 1.0
    assert within_tool_budget({}, good, reference)
    assert not diagnosis_correct({}, wrong, reference)
    assert not action_correct({}, wrong, reference)
