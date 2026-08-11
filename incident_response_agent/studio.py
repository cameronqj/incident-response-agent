"""Local LangSmith Studio entry point for the synthetic site investigator."""

from __future__ import annotations

import atexit

from incident_response_agent.config import Settings
from incident_response_agent.sandbox import DisposableSandbox
from incident_response_agent.site_investigation import DisposableSiteLab, InvestigationTrace, create_incident_deep_agent, create_live_investigation_model


settings = Settings.from_env()
sandbox = DisposableSandbox.create_runtime()
atexit.register(sandbox.close)

lab = DisposableSiteLab.disk_exhaustion(sandbox)
trace = InvestigationTrace()
graph = create_incident_deep_agent(
    create_live_investigation_model(settings),
    lab,
    trace,
    platform_managed_checkpointing=True,
)
