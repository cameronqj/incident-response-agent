from __future__ import annotations

import hashlib
import json
from typing import Dict, FrozenSet

from .schemas import ModelAssessment, RemediationOption, Scenario, ScenarioKind


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
}

SCENARIO_ACTIONS: Dict[Scenario, FrozenSet[str]] = {
    Scenario.DISK_EXHAUSTION: frozenset({"cleanup_rotated_logs"}),
    Scenario.RUNAWAY_CPU: frozenset({"stop_runaway_process"}),
    Scenario.MEMORY_OOM: frozenset({"stop_memory_hog"}),
    Scenario.RESTARTING_SERVICE: frozenset({"restart_disposable_service"}),
    Scenario.LOG_STORM: frozenset({"cleanup_log_storm_temp_files"}),
}


class SafetyViolation(ValueError):
    pass


def validate_scenario_action(scenario: Scenario, action_id: str) -> None:
    if action_id not in SCENARIO_ACTIONS[scenario]:
        raise SafetyViolation(f"action {action_id} is not authorized for scenario {scenario.value}")


def build_option(scenario: Scenario, assessment: ModelAssessment) -> RemediationOption:
    definition = ALLOWED_ACTIONS.get(assessment.action_id)
    if definition is None:
        raise SafetyViolation(f"model selected an action outside the allowlist: {assessment.action_id}")
    validate_scenario_action(scenario, assessment.action_id)
    return RemediationOption(
        action_id=assessment.action_id,
        title=definition["title"],
        evidence=assessment.evidence_refs,
        confidence=assessment.confidence,
        impact=definition["impact"],
        risk=definition["risk"],
        action_preview=definition["preview"],
    )


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
