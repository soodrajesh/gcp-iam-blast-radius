"""Pipeline:

snapshot -> [engine] reach + graph          deterministic
         -> [rules]  findings               deterministic, owns severity
         -> parallel: [analyst x N]  explain top escalation findings (model, validated)
                      [planner x M]  propose narrower roles (model, verified by simulation)
         -> [verifier] rule-based patches   deterministic simulation, for every fixable finding
         -> [judge]  posture + summary      posture from rules only"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC

from . import rules
from .agents import explain, propose
from .graph import Engine
from .llm import LLM, Budget
from .models import SEV_RANK as RANK
from .models import Analysis, Finding, TraceStep, Verified
from .remediate import default_patch, verify
from .snapshot import load, sha256

TOP_ANALYSTS, TOP_PLANNERS = 4, 4


def _now() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat(timespec="seconds")


async def analyze(
    doc, llm: LLM, *, budget: Budget | None = None, timeout: float = 45.0
) -> Analysis:
    t0 = time.perf_counter()
    budget = budget or Budget()
    snap = load(doc)
    ms = lambda: int((time.perf_counter() - t0) * 1000)  # noqa: E731
    trace: list[TraceStep] = []

    e0 = time.perf_counter()
    eng = Engine(snap)
    reaches = eng.all_reach()
    findings = rules.evaluate(snap, eng)
    trace.append(
        TraceStep(
            agent="engine",
            action="reach+rules",
            start_ms=0,
            duration_ms=int((time.perf_counter() - e0) * 1000),
            note=f"{len(snap.bindings)} bindings, {len(eng.principals)} principals, "
            f"{len(findings)} findings",
        )
    )

    dropped: list[dict[str, str]] = []
    degraded: list[str] = []
    escalations = [f for f in findings if f.rule == "IAM001"][:TOP_ANALYSTS]
    fixable = [f for f in findings if f.severity in ("critical", "high") and f.rule != "IAM005"]

    async def run_analyst(f: Finding):
        return f, await explain(f, eng, snap, llm, budget, t0, timeout)

    async def run_planner(f: Finding):
        return f, await propose(f, snap, llm, budget, t0, timeout)

    use_llm = llm.name != "none"
    analyst_res, planner_res = [], []
    if use_llm:
        analyst_res, planner_res = await asyncio.gather(
            asyncio.gather(*(run_analyst(f) for f in escalations)),
            asyncio.gather(*(run_planner(f) for f in fixable[:TOP_PLANNERS])),
        )
    else:
        trace.append(
            TraceStep(
                agent="analyst",
                action="explain",
                status="skipped",
                start_ms=ms(),
                note="no model configured",
            )
        )

    for f, (note, step, why) in analyst_res:
        trace.append(step)
        if note:
            f.note = note
        elif why:
            dropped.append({"agent": "analyst", "item": f"note for {f.id}", "reason": why})
        elif step.status == "error":
            degraded.append(f"analyst {f.id}: {step.note}")
    fixes: list[Verified] = []
    v0 = time.perf_counter()
    for f in fixable:  # deterministic fixes for every fixable finding
        p = default_patch(snap, eng, f)
        if p:
            fixes.append(verify(snap, p, f.id, "rule", f.principal))
    for f, (res, step) in planner_res:
        trace.append(step)
        if step.status == "error":
            degraded.append(f"planner {f.id}: {step.note}")
        if res:
            patch, why = res
            v = verify(snap, patch, f.id, "llm", f.principal, why)
            if v.accepted:
                fixes.append(v)
            else:
                dropped.append(
                    {
                        "agent": "planner",
                        "item": f"{patch.op} {patch.role} for {f.id}",
                        "reason": v.reason,
                    }
                )
    trace.append(
        TraceStep(
            agent="verifier",
            action="simulate",
            start_ms=int((v0 - t0) * 1000),
            duration_ms=int((time.perf_counter() - v0) * 1000),
            note=f"{sum(v.accepted for v in fixes)} accepted of {len(fixes)} verified",
        )
    )

    fixes = [v for v in fixes if v.accepted]
    post = rules.posture(findings)
    from .judge import summarize

    j0 = time.perf_counter()
    step = TraceStep(agent="judge", action="summarize", start_ms=int((j0 - t0) * 1000))
    summary = await summarize(post, findings, reaches, llm, budget, step)
    step.duration_ms = int((time.perf_counter() - j0) * 1000)
    trace.append(step)

    findings.sort(key=lambda f: (-RANK[f.severity], f.rule, f.principal))
    return Analysis(
        id=uuid.uuid4().hex[:12],
        created_at=_now(),
        project=snap.project,
        provider=llm.name,
        model=llm.model,
        posture=post,
        summary=summary,
        unclassified_roles=sorted(eng.unclassified),
        reaches=reaches,
        findings=findings,
        fixes=fixes,
        dropped=dropped,
        degraded=degraded,
        trace=trace,
        snapshot_sha256=sha256(snap),
        cost_usd=round(sum(s.cost_usd for s in trace), 6),
        duration_ms=ms(),
        graph=eng.graph(),
    )
