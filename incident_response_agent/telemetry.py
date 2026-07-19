from __future__ import annotations

from typing import Protocol

from .schemas import EventRequest, TelemetryEvidence


class TelemetryCollector(Protocol):
    def collect(self, event: EventRequest) -> TelemetryEvidence: ...


class SyntheticDiskExhaustionTelemetry:
    """Safe synthetic evidence; it never inspects the host."""

    def collect(self, event: EventRequest) -> TelemetryEvidence:
        return TelemetryEvidence(
            scenario="failed-log-rotation-disk-exhaustion",
            rotation_failed=True,
            free_bytes=4096,
            log_growth_bytes_per_minute=8_388_608,
            affected_file_count=12,
            signals=["rotation_error", "low_free_space", "rapid_log_growth"],
            fault_injection="ENOSPC",
        )


class DeterministicENOSPCTelemetry(SyntheticDiskExhaustionTelemetry):
    """Portable CI fixture representing ENOSPC without filling a real disk."""

    pass
