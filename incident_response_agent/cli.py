from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .config import Settings
from .executor import DisposableFilesystemExecutor
from .factory import build_service
from .model import FakeAnalyzer
from .schemas import Decision, DecisionRequest, EventRequest
from .service import IncidentService
from .storage import SQLiteStore
from .telemetry import DeterministicENOSPCTelemetry


def demo() -> None:
    with tempfile.TemporaryDirectory(prefix="incident-response-") as sandbox:
        logs = Path(sandbox) / "logs"
        logs.mkdir()
        (logs / "application.1.rotated").write_text("synthetic log artifact", encoding="utf-8")
        service = IncidentService(SQLiteStore(":memory:"), DeterministicENOSPCTelemetry(), FakeAnalyzer(), DisposableFilesystemExecutor(sandbox), proposal_ttl_seconds=900)
        run = service.start_event(EventRequest(idempotency_key="demo-disk-001", payload={"scenario": "disk-exhaustion"}))
        print(json.dumps({"phase": "proposal", "run": run.model_dump(mode="json")}, indent=2))
        assert run.proposal is not None
        approved = service.decide(run.proposal.proposal_id, DecisionRequest(decision=Decision.APPROVE, revision=run.proposal.revision, action_hash=run.proposal.action_hash))
        executed = service.execute(approved.proposal.proposal_id if approved.proposal else run.proposal.proposal_id)
        print(json.dumps({"phase": "executed", "run": executed.model_dump(mode="json")}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="incident-response")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="run the offline disk-exhaustion demo")
    serve_parser = subparsers.add_parser("serve", help="run the FastAPI service")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if args.command == "demo":
        demo()
        return
    import uvicorn

    settings = Settings.from_env()
    uvicorn.run("incident_response_agent.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
