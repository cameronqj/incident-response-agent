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
    }
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
