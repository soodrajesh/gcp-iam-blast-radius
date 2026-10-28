"""Opt-in tests against real services. Each makes a few capped calls and writes nothing."""

import os

import pytest

from iamblast.collector import collect
from iamblast.llm import Budget, make_llm
from iamblast.orchestrator import analyze

from .helpers import sample


async def _check(provider):
    a = await analyze(sample("acme_prod"), make_llm(provider), budget=Budget())
    assert a.posture == "critical" and a.fixes and a.cost_usd < 0.05


@pytest.mark.live_vertex
@pytest.mark.skipif(not os.environ.get("IAMBLAST_LIVE_VERTEX"), reason="set IAMBLAST_LIVE_VERTEX=1")
async def test_vertex():
    await _check("vertex")


@pytest.mark.live_openai
@pytest.mark.skipif(not os.environ.get("IAMBLAST_LIVE_OPENAI"), reason="set IAMBLAST_LIVE_OPENAI=1")
async def test_openai():
    await _check("openai")


@pytest.mark.live_gcp
@pytest.mark.skipif(
    not os.environ.get("IAMBLAST_LIVE_PROJECT"), reason="set IAMBLAST_LIVE_PROJECT=<project>"
)
async def test_collect_real_project_is_read_only_and_analyzable():
    snap = collect(os.environ["IAMBLAST_LIVE_PROJECT"])
    assert snap.bindings and snap.service_accounts is not None
    a = await analyze(snap.model_dump(mode="json"), make_llm("none"))
    assert a.reaches
