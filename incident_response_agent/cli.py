from __future__ import annotations

import argparse
import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .config import Settings
from .executor import DisposableFilesystemExecutor
from .factory import build_service
from .model import FakeAnalyzer
from .sandbox import DisposableSandbox
from .schemas import Decision, DecisionRequest, EventRequest
from .service import IncidentService
from .storage import SQLiteStore
from .telemetry import DeterministicENOSPCTelemetry


def demo() -> None:
    sandbox = DisposableSandbox.create_runtime()
    try:
        logs = sandbox.resolve_child("logs")
        logs.mkdir()
        (logs / "application.1.rotated").write_text("synthetic log artifact", encoding="utf-8")
        service = IncidentService(SQLiteStore(":memory:"), DeterministicENOSPCTelemetry(), FakeAnalyzer(), DisposableFilesystemExecutor(sandbox), proposal_ttl_seconds=900, execution_enabled=True)
        run = service.start_event(EventRequest.model_validate({"idempotency_key": "demo-disk-001", "source": "local_simulation", "observed_at": datetime.now(timezone.utc), "payload": {"scenario": "disk-exhaustion"}}))
        print(json.dumps({"phase": "proposal", "run": run.model_dump(mode="json")}, indent=2))
        assert run.proposal is not None
        approved = service.decide(run.proposal.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=run.proposal.revision, action_hash=run.proposal.action_hash))
        executed = service.execute(approved.proposal.proposal_id if approved.proposal else run.proposal.proposal_id)
        print(json.dumps({"phase": "executed", "run": executed.model_dump(mode="json")}, indent=2))
    finally:
        sandbox.close()


def container_service_demo() -> None:
    settings = replace(Settings.from_env(), lab_mode="container-service", execution_enabled=True)
    settings.validate()
    service = build_service(settings)
    try:
        run = service.start_event(
            EventRequest.model_validate(
                {
                    "idempotency_key": f"container-service-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
                    "source": "local_simulation",
                    "observed_at": datetime.now(timezone.utc),
                    "payload": {"scenario": "restarting-service", "summary": "owned disposable service is unhealthy"},
                }
            ),
            actor="container-service-demo",
        )
        assert run.proposal is not None
        proposal = run.proposal
        print(
            json.dumps(
                {
                    "phase": "proposal",
                    "run_id": run.run_id,
                    "proposal_id": proposal.proposal_id,
                    "revision": proposal.revision,
                    "action_hash": proposal.action_hash,
                    "scenario_kind": proposal.scenario_kind.value,
                    "option": proposal.option.model_dump(mode="json"),
                },
                indent=2,
            )
        )
        response = input("Type approve to restart this exact disposable service proposal: ").strip().lower()
        decision = Decision.APPROVE if response == "approve" else Decision.REJECT
        decided = service.decide(
            proposal.proposal_id,
            DecisionRequest(decision=decision, revision=proposal.revision, action_hash=proposal.action_hash),
            actor="container-service-demo",
        )
        if decision == Decision.REJECT:
            print(json.dumps({"phase": "rejected", "state": decided.state.value}, indent=2))
            return
        completed = service.execute(proposal.proposal_id, actor="container-service-demo")
        result_record = next(record for record in completed.audit if record.event_type == "execution_result")
        print(
            json.dumps(
                {"phase": "executed", "state": completed.state.value, "execution": result_record.metadata},
                indent=2,
            )
        )
    finally:
        service.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="incident-response")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="run the offline disk-exhaustion demo")
    subparsers.add_parser("container-service-demo", help="detect and restart one owned disposable service")
    serve_parser = subparsers.add_parser("serve", help="run the FastAPI service")
    serve_parser.add_argument("--host", default=None)
    serve_parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if args.command == "demo":
        demo()
        return
    if args.command == "container-service-demo":
        container_service_demo()
        return
    import uvicorn

    settings = Settings.from_env()
    if args.host:
        settings = replace(settings, host=args.host)
        settings.validate()
        os.environ["HOST"] = args.host
    from .app import app

    uvicorn.run(app, host=settings.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
