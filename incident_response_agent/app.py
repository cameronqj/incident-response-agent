from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .factory import build_service
from .config import Settings
from .security import AccessPolicy, HTTPAccessMiddleware, is_loopback_host
from .schemas import DecisionRequest, EventRequest, RunView
from .service import IncidentService, ServiceError


def create_app(service: IncidentService | None = None, settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    service = service or build_service(settings)

    async def expire_loop():
        while True:
            await asyncio.sleep(service.expiration_poll_seconds)
            service.expire_due()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = asyncio.create_task(expire_loop())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            service.close()

    app = FastAPI(title="incident-response-agent", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        HTTPAccessMiddleware,
        policy=AccessPolicy(settings.bearer_token, is_loopback_host(settings.host)),
    )

    @app.exception_handler(ServiceError)
    async def service_error_handler(_: Request, exc: ServiceError):
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})

    @app.post("/events", response_model=RunView, status_code=202)
    def receive_event(event: EventRequest, request: Request) -> RunView:
        try:
            return service.start_event(event, actor=request.state.actor)
        except ServiceError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    @app.get("/runs/{run_id}", response_model=RunView)
    def get_run(run_id: str) -> RunView:
        try:
            return service.get_run(run_id)
        except ServiceError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    @app.post("/proposals/{proposal_id}/decision", response_model=RunView)
    def decide(proposal_id: str, decision: DecisionRequest, request: Request) -> RunView:
        try:
            return service.decide(proposal_id, decision, actor=request.state.actor)
        except ServiceError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    @app.post("/proposals/{proposal_id}/execute", response_model=RunView)
    def execute(proposal_id: str, request: Request) -> RunView:
        try:
            return service.execute(proposal_id, actor=request.state.actor)
        except ServiceError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    @app.post("/maintenance/expire", response_model=dict)
    def expire(request: Request) -> dict:
        return {"expired_count": service.expire_due(actor=request.state.actor)}

    return app


app = create_app()
