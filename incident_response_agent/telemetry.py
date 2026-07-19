from __future__ import annotations

from typing import Protocol

from .schemas import EventRequest, Scenario, ScenarioKind, TelemetryEvidence


class TelemetryCollector(Protocol):
    def collect(self, event: EventRequest) -> TelemetryEvidence: ...


class SyntheticDiskExhaustionTelemetry:
    """Safe synthetic evidence; it never inspects the host."""

    def collect(self, event: EventRequest) -> TelemetryEvidence:
        return TelemetryEvidence(
            scenario=Scenario.DISK_EXHAUSTION,
            scenario_kind=ScenarioKind.SYNTHETIC_MARKER,
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
            scenario=Scenario.RUNAWAY_CPU,
            scenario_kind=ScenarioKind.SYNTHETIC_MARKER,
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
            scenario=Scenario.RESTARTING_SERVICE,
            scenario_kind=ScenarioKind.SYNTHETIC_MARKER,
            rotation_failed=False,
            free_bytes=1_048_576,
            log_growth_bytes_per_minute=0,
            affected_file_count=0,
            service_state="restarting",
            restart_count=9,
            signals=["service_unhealthy", "restart_loop", "crash_backoff"],
            fault_injection="RESTART_LOOP",
        )


class SyntheticMemoryOOMTelemetry:
    """Synthetic memory-pressure evidence; it never inspects the host."""

    def collect(self, event: EventRequest) -> TelemetryEvidence:
        return TelemetryEvidence(
            scenario=Scenario.MEMORY_OOM,
            scenario_kind=ScenarioKind.SYNTHETIC_MARKER,
            rotation_failed=False,
            free_bytes=1_048_576,
            log_growth_bytes_per_minute=0,
            affected_file_count=0,
            memory_percent=99.2,
            oom_kill_detected=True,
            signals=["memory_pressure", "oom_kill", "allocation_failures"],
            fault_injection="OOM_PRESSURE",
        )


class SyntheticLogStormTelemetry:
    """Synthetic log-storm and temporary-file evidence; it never inspects the host."""

    def collect(self, event: EventRequest) -> TelemetryEvidence:
        return TelemetryEvidence(
            scenario=Scenario.LOG_STORM,
            scenario_kind=ScenarioKind.SYNTHETIC_MARKER,
            rotation_failed=False,
            free_bytes=65_536,
            log_growth_bytes_per_minute=67_108_864,
            affected_file_count=128,
            log_storm_detected=True,
            temp_file_count=24,
            signals=["rapid_log_growth", "temp_file_growth", "rotation_backlog"],
            fault_injection="LOG_STORM",
        )


class ScenarioTelemetryCollector:
    """Route synthetic events to explicit, bounded scenario adapters."""

    def __init__(self):
        self.adapters = {
            Scenario.DISK_EXHAUSTION: SyntheticDiskExhaustionTelemetry(),
            Scenario.RUNAWAY_CPU: SyntheticRunawayCPUTelemetry(),
            Scenario.RESTARTING_SERVICE: SyntheticRestartingServiceTelemetry(),
            Scenario.MEMORY_OOM: SyntheticMemoryOOMTelemetry(),
            Scenario.LOG_STORM: SyntheticLogStormTelemetry(),
        }

    def collect(self, event: EventRequest) -> TelemetryEvidence:
        scenario = event.payload.scenario
        adapter = self.adapters.get(scenario)
        if adapter is None:
            raise ValueError(f"unsupported synthetic scenario: {scenario}")
        return adapter.collect(event)


class DeterministicENOSPCTelemetry(ScenarioTelemetryCollector):
    """Portable CI fixture representing ENOSPC without filling a real disk."""

    pass
