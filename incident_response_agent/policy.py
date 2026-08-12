from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Optional

from .schemas import CapabilityBinding, ModelAssessment, RemediationOption, Scenario, ScenarioKind


ALLOWED_ACTIONS: Dict[str, Dict[str, str]] = {
    "cleanup_rotated_logs": {
        "title": "Clean up rotated logs",
        "impact": "Reclaims disposable-sandbox disk space by deleting known rotated-log artifacts.",
        "risk": "Low: fixed-scope deletion inside the disposable incident sandbox only.",
        "preview": "Delete matching rotated-log artifacts from the configured disposable sandbox.",
    },
    "stop_runaway_process": {
        "title": "Clear the runaway-CPU marker fixture",
        "impact": "Clears the fixed synthetic marker used to exercise the CPU incident workflow.",
        "risk": "Low: fixed-scope marker removal inside the disposable incident sandbox only.",
        "preview": "Remove the fixed runaway-CPU marker; no real process is stopped.",
    },
    "restart_disposable_service": {
        "title": "Reset the restart-loop marker fixture",
        "impact": "Clears the fixed restart-loop marker and writes a synthetic healthy marker.",
        "risk": "Low: fixed-scope marker changes inside the disposable incident sandbox only.",
        "preview": "Reset synthetic service markers; no real service is restarted.",
    },
    "restart_unhealthy_container_service": {
        "title": "Restart the unhealthy disposable service",
        "impact": "Restarts the exact owned disposable service container and verifies its bounded health check.",
        "risk": "Low: one internally created container target; no host or caller-selected service is reachable.",
        "preview": "Restart the owned disposable service once and wait for its health status to become healthy.",
    },
    "stop_memory_hog": {
        "title": "Clear the memory-pressure marker fixture",
        "impact": "Clears the fixed marker used to exercise the memory-pressure workflow.",
        "risk": "Low: fixed-scope marker removal inside the disposable incident sandbox only.",
        "preview": "Remove the memory-pressure marker; no real process memory is reclaimed.",
    },
    "cleanup_log_storm_temp_files": {
        "title": "Clean up log-storm temporary files",
        "impact": "Reclaims disposable-sandbox space from fixed log-storm and temporary-file artifacts.",
        "risk": "Low: fixed-scope storm artifacts inside the disposable incident sandbox only.",
        "preview": "Delete fixed log-storm and temporary-file artifacts from the disposable sandbox.",
    },
    "reduce_worker_concurrency": {
        "title": "Reduce worker concurrency",
        "impact": "Lowers the owned disposable worker's concurrency to the approved bound and verifies recovery.",
        "risk": "Low: one owned disposable worker target; concrete values are chosen by application code and bound by approval.",
        "preview": "Set the owned worker's concurrency to the approved target and verify its health check recovers.",
        "requires_parameters": True,
        "requires_capability": True,
        "parameter_minimum": 1,
        "parameter_maximum": 8,
        "parameter_target_key": "target_concurrency",
        "parameter_target_id_key": "target_id",
    },
}

SCENARIO_KIND_ACTIONS: Dict[tuple[Scenario, ScenarioKind], FrozenSet[str]] = {
    (Scenario.DISK_EXHAUSTION, ScenarioKind.SYNTHETIC_MARKER): frozenset({"cleanup_rotated_logs"}),
    (Scenario.RUNAWAY_CPU, ScenarioKind.SYNTHETIC_MARKER): frozenset({"stop_runaway_process"}),
    (Scenario.MEMORY_OOM, ScenarioKind.SYNTHETIC_MARKER): frozenset({"stop_memory_hog"}),
    (Scenario.RESTARTING_SERVICE, ScenarioKind.SYNTHETIC_MARKER): frozenset({"restart_disposable_service"}),
    (Scenario.RESTARTING_SERVICE, ScenarioKind.CONTAINER_FAULT): frozenset({"restart_unhealthy_container_service"}),
    (Scenario.LOG_STORM, ScenarioKind.SYNTHETIC_MARKER): frozenset({"cleanup_log_storm_temp_files"}),
    (Scenario.WORKER_CONCURRENCY, ScenarioKind.SYNTHETIC_MARKER): frozenset({"reduce_worker_concurrency"}),
}


class SafetyViolation(ValueError):
    pass


def allowed_actions(scenario: Scenario, scenario_kind: ScenarioKind) -> FrozenSet[str]:
    actions = SCENARIO_KIND_ACTIONS.get((scenario, scenario_kind))
    if actions is None:
        raise SafetyViolation(f"scenario {scenario.value} does not support evidence kind {scenario_kind.value}")
    return actions


def validate_scenario_action(scenario: Scenario, scenario_kind: ScenarioKind, action_id: str) -> None:
    if action_id not in allowed_actions(scenario, scenario_kind):
        raise SafetyViolation(
            f"action {action_id} is not authorized for scenario {scenario.value} and evidence kind {scenario_kind.value}"
        )


@dataclass(frozen=True)
class OptionBinding:
    """Application-chosen concrete binding for an option, never model-supplied."""

    parameters: Optional[Dict[str, Any]] = None
    target_id: Optional[str] = None
    capability: Optional[CapabilityBinding] = None


def build_option(
    scenario: Scenario,
    scenario_kind: ScenarioKind,
    assessment: ModelAssessment,
    binding: Optional[OptionBinding] = None,
) -> RemediationOption:
    definition = ALLOWED_ACTIONS.get(assessment.action_id)
    if definition is None:
        raise SafetyViolation(f"model selected an action outside the allowlist: {assessment.action_id}")
    validate_scenario_action(scenario, scenario_kind, assessment.action_id)
    parameters = None
    target_id = None
    capability = None
    if binding is not None:
        parameters = binding.parameters
        target_id = binding.target_id
        capability = binding.capability
    if definition.get("requires_parameters"):
        _validate_action_parameters(assessment.action_id, definition, parameters)
    if definition.get("requires_capability"):
        if capability is None:
            raise SafetyViolation(f"action {assessment.action_id} requires a promoted capability binding")
        if capability.capability_id != "reduce_worker_concurrency":
            raise SafetyViolation(f"action {assessment.action_id} is not authorized by capability {capability.capability_id}")
    if target_id is not None and (not isinstance(target_id, str) or not re.fullmatch(r"^[a-z0-9_-]+$", target_id) or not (1 <= len(target_id) <= 128)):
        raise SafetyViolation("action target identifier is not bounded")
    return RemediationOption(
        action_id=assessment.action_id,
        title=definition["title"],
        evidence=assessment.evidence_refs,
        confidence=assessment.confidence,
        impact=definition["impact"],
        risk=definition["risk"],
        action_preview=definition["preview"],
        parameters=parameters,
        target_id=target_id,
        capability=capability,
    )


def _validate_action_parameters(action_id: str, definition: Dict[str, Any], parameters: Optional[Dict[str, Any]]) -> None:
    if parameters is None:
        raise SafetyViolation(f"action {action_id} requires concrete application-chosen parameters")
    target_key = definition["parameter_target_key"]
    minimum = int(definition["parameter_minimum"])
    maximum = int(definition["parameter_maximum"])
    if set(parameters) != {target_key}:
        raise SafetyViolation(f"action {action_id} requires exactly the approved parameter key")
    target_value = parameters[target_key]
    if isinstance(target_value, bool) or not isinstance(target_value, int):
        raise SafetyViolation(f"action {action_id} target parameter must be an integer")
    if not (minimum <= target_value <= maximum):
        raise SafetyViolation(f"action {action_id} target parameter is outside approved bounds")


def action_hash(revision: int, scenario: Scenario, scenario_kind: ScenarioKind, option: RemediationOption) -> str:
    canonical = json.dumps(
        {
            "revision": revision,
            "scenario": scenario.value,
            "scenario_kind": scenario_kind.value,
            "option": option.model_dump(mode="json"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
