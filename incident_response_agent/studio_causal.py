"""Local LangSmith Studio entry point for the causal site investigation experiment."""

from __future__ import annotations

import atexit

from incident_response_agent.causal_workflow import CausalRuntimeRegistry, ThreadScopedCausalTarget, create_causal_recovery_graph
from incident_response_agent.config import Settings
from incident_response_agent.site_investigation import InvestigationTrace, create_incident_deep_agent, create_live_investigation_model


settings = Settings.from_env()
registry = CausalRuntimeRegistry()
atexit.register(registry.close)
trace = InvestigationTrace()
investigator = create_incident_deep_agent(
    create_live_investigation_model(settings),
    ThreadScopedCausalTarget(registry),
    trace,
    platform_managed_checkpointing=True,
)
graph = create_causal_recovery_graph(investigator, registry, trace, settings)
