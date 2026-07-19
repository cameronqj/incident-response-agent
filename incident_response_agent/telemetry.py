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


class SyntheticRunawayCPUTelemetry:
    """Synthetic process and utilization evidence; it never inspects the host."""

    def collect(self, event: EventRequest) -> TelemetryEvidence:
        return TelemetryEvidence(
            scenario="runaway-cpu",
            rotation_failed=False,
            free_bytes=1_048_576,
            log_growth_bytes_per_minute=0,
            affected_file_count=0,
            cpu_percent=99.7,
            runaway_process_detected=True,
            signals=["sustained_high_cpu", "runaway_process"],
            fault_injection="CPU_PRESSURE",
        )


class SyntheticRestartingServiceTelemetry:
    """Synthetic service-supervisor evidence; it never inspects the host."""

    def collect(self, event: EventRequest) -> TelemetryEvidence:
        return TelemetryEvidence(
            scenario="restarting-service",
            rotation_failed=False,
            free_bytes=1_048_576,
            log_growth_bytes_per_minute=0,
            affected_file_count=0,
            service_state="restarting",
            restart_count=9,
            signals=["service_unhealthy", "restart_loop", "crash_backoff"],
            fault_injection="RESTART_LOOP",
        )


class ScenarioTelemetryCollector:
    """Route synthetic events to explicit, bounded scenario adapters."""

    def __init__(self):
        self.adapters = {
            "failed-log-rotation-disk-exhaustion": SyntheticDiskExhaustionTelemetry(),
            "disk-exhaustion": SyntheticDiskExhaustionTelemetry(),
            "disk": SyntheticDiskExhaustionTelemetry(),
            "runaway-cpu": SyntheticRunawayCPUTelemetry(),
            "restarting-service": SyntheticRestartingServiceTelemetry(),
        }

    def collect(self, event: EventRequest) -> TelemetryEvidence:
        scenario = str(event.payload.get("scenario", "failed-log-rotation-disk-exhaustion"))
        adapter = self.adapters.get(scenario)
        if adapter is None:
            raise ValueError(f"unsupported synthetic scenario: {scenario}")
        return adapter.collect(event)


class DeterministicENOSPCTelemetry(ScenarioTelemetryCollector):
    """Portable CI fixture representing ENOSPC without filling a real disk."""

    pass
