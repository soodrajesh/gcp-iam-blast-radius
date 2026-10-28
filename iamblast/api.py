"""HTTP API and viewer. Authentication is Cloud Run IAM. Analyses are kept in memory only (they
describe who can do what in a project, so nothing is persisted by default)."""

from __future__ import annotations

import json
import logging
import re
import threading
from collections import OrderedDict
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import __version__, catalog
from .collector import CollectError, collect
from .config import Settings
from .llm import Budget, LLMError, make_llm
from .models import Analysis
from .orchestrator import analyze
from .snapshot import SnapshotError

SAMPLES = resources.files("iamblast") / "samples"


class AnalyzeRequest(BaseModel):
    snapshot: dict | None = None
    live_project: str | None = None
    llm: str | None = None


class _Memory:
    def __init__(self, cap: int = 50):
        self._d: OrderedDict[str, Analysis] = OrderedDict()
        self._cap, self._lock = cap, threading.Lock()
        self._spend: dict[str, float] = {}

    def save(self, a: Analysis) -> None:
        with self._lock:
            self._d[a.id] = a
            while len(self._d) > self._cap:
                self._d.popitem(last=False)

    def get(self, i: str) -> Analysis | None:
        return self._d.get(i)

    def recent(self, n: int) -> list[Analysis]:
        return list(reversed(self._d.values()))[:n]

    def spend(self) -> float:
        return self._spend.get(datetime.now(UTC).strftime("%Y%m%d"), 0.0)

    def add_spend(self, usd: float) -> None:
        k = datetime.now(UTC).strftime("%Y%m%d")
        with self._lock:
            self._spend[k] = self._spend.get(k, 0.0) + usd


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings()
    mem = _Memory()
    app = FastAPI(title="iamblast", version=__version__)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (resources.files("iamblast") / "ui.html").read_text()

    @app.get("/api/config")
    def config():
        return {
            "version": __version__,
            "provider": cfg.provider,
            "model": cfg.model,
            "allowed_providers": cfg.allowed_providers,
            "live_projects": cfg.live_projects,
            "daily_budget_usd": cfg.daily_budget_usd,
            "spend_today_usd": round(mem.spend(), 6),
            "roles_in_catalog": len(catalog.ROLE_CAPS),
        }

    @app.get("/api/samples")
    def samples():
        return sorted(p.name.removesuffix(".json") for p in Path(str(SAMPLES)).glob("*.json"))

    @app.get("/api/samples/{name}")
    def sample(name: str):
        f = SAMPLES / f"{name}.json"
        if not re.fullmatch(r"[a-z0-9_]+", name) or not f.is_file():
            raise HTTPException(404, "no such sample")
        return json.loads(f.read_text())

    @app.post("/api/analyses", response_model=Analysis)
    async def create(req: Request):
        raw = await req.body()
        if len(raw) > cfg.max_body_bytes:
            raise HTTPException(413, "snapshot too large")
        try:
            body = AnalyzeRequest.model_validate_json(raw)
        except ValueError as e:
            raise HTTPException(422, f"invalid request: {str(e)[:300]}") from e
        if bool(body.snapshot) == bool(body.live_project):
            raise HTTPException(422, "send exactly one of 'snapshot' or 'live_project'")
        provider = body.llm or cfg.provider
        if provider not in cfg.allowed_providers:
            raise HTTPException(
                403, f"provider '{provider}' not allowed here ({', '.join(cfg.allowed_providers)})"
            )
        notes: list[str] = []
        if provider not in ("none", "mock") and mem.spend() >= cfg.daily_budget_usd:
            provider = "none"
            notes.append(f"daily model budget ${cfg.daily_budget_usd:.2f} reached; rules only")
        doc = body.snapshot
        if body.live_project:
            if body.live_project not in cfg.live_projects:
                raise HTTPException(403, f"live analysis of '{body.live_project}' is not enabled")
            try:
                doc = collect(body.live_project, list(cfg.internal_domains)).model_dump(mode="json")
            except CollectError as e:
                raise HTTPException(502, str(e)) from e
        try:
            llm = make_llm(provider, cfg.model if provider == cfg.provider else None)
        except LLMError as e:
            raise HTTPException(503, str(e)) from e
        try:
            a = await analyze(doc, llm, budget=Budget(cfg.max_llm_calls, cfg.review_budget_usd))
        except SnapshotError as e:
            raise HTTPException(422, str(e)) from e
        a.degraded = notes + a.degraded
        mem.add_spend(a.cost_usd)
        mem.save(a)
        return a

    @app.get("/api/analyses", response_model=list[Analysis])
    def list_analyses(limit: int = 20):
        return mem.recent(max(1, min(limit, 50)))

    @app.get("/api/analyses/{aid}", response_model=Analysis)
    def get(aid: str):
        a = mem.get(aid)
        if a is None:
            raise HTTPException(404, "no such analysis")
        return a

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception):
        logging.getLogger("iamblast").exception("unhandled error", exc_info=exc)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    return app


def app_factory() -> FastAPI:  # uvicorn --factory iamblast.api:app_factory
    return create_app()
