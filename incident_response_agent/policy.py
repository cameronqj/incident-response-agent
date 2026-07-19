from __future__ import annotations

import hashlib
import json
from typing import Dict

from .schemas import ModelAssessment, RemediationOption


ALLOWED_ACTIONS: Dict[str, Dict[str, str]] = {
    "cleanup_rotated_logs": {
        "title": "Clean up rotated logs",
        "impact": "Reclaims disposable-sandbox disk space by deleting known rotated-log artifacts.",
        "risk": "Low: fixed-scope deletion inside the disposable incident sandbox only.",
        "preview": "Delete matching rotated-log artifacts from the configured disposable sandbox.",
    },
    "stop_runaway_process": {
        "title": "Stop the runaway process",
        "impact": "Stops the known synthetic runaway-process fixture and returns CPU pressure to normal.",
        "risk": "Low: fixed-scope process fixture inside the disposable incident sandbox only.",
        "preview": "Stop the fixed runaway-process fixture in the disposable sandbox.",
    },
    "restart_disposable_service": {
        "title": "Restart the disposable service",
        "impact": "Restarts the fixed synthetic service fixture and clears its restart-loop marker.",
        "risk": "Low: fixed-scope service fixture inside the disposable incident sandbox only.",
        "preview": "Restart the fixed service fixture in the disposable sandbox.",
    },
    "stop_memory_hog": {
        "title": "Stop the memory-hog fixture",
        "impact": "Stops the fixed synthetic memory-hog fixture and releases disposable-container memory pressure.",
        "risk": "Low: fixed-scope memory fixture inside the disposable incident sandbox only.",
        "preview": "Stop the fixed memory-hog fixture in the disposable sandbox.",
    },
    "cleanup_log_storm_temp_files": {
        "title": "Clean up log-storm temporary files",
        "impact": "Reclaims disposable-sandbox space from fixed log-storm and temporary-file artifacts.",
        "risk": "Low: fixed-scope storm artifacts inside the disposable incident sandbox only.",
        "preview": "Delete fixed log-storm and temporary-file artifacts from the disposable sandbox.",
    },
}


class SafetyViolation(ValueError):
    pass


def build_option(assessment: ModelAssessment) -> RemediationOption:
    definition = ALLOWED_ACTIONS.get(assessment.action_id)
    if definition is None:
        raise SafetyViolation(f"model selected an action outside the allowlist: {assessment.action_id}")
    return RemediationOption(
        action_id=assessment.action_id,
        title=definition["title"],
        evidence=assessment.evidence_refs,
        confidence=assessment.confidence,
        impact=definition["impact"],
        risk=definition["risk"],
        action_preview=definition["preview"],
    )


def action_hash(revision: int, option: RemediationOption) -> str:
    canonical = json.dumps(
        {"revision": revision, "option": option.model_dump(mode="json")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
