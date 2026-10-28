from __future__ import annotations

import os
from dataclasses import dataclass, field


def _list(name: str, default: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.environ.get(name, default).split(",") if x.strip())


@dataclass
class Settings:
    provider: str = field(default_factory=lambda: os.environ.get("IAMBLAST_LLM", "mock"))
    model: str | None = field(default_factory=lambda: os.environ.get("IAMBLAST_MODEL") or None)
    allowed_providers: tuple[str, ...] = field(
        default_factory=lambda: _list("IAMBLAST_ALLOWED_PROVIDERS", "mock,none")
    )
    live_projects: tuple[str, ...] = field(
        default_factory=lambda: _list("IAMBLAST_LIVE_PROJECTS", "")
    )
    internal_domains: tuple[str, ...] = field(
        default_factory=lambda: _list("IAMBLAST_INTERNAL_DOMAINS", "")
    )
    daily_budget_usd: float = field(
        default_factory=lambda: float(os.environ.get("IAMBLAST_DAILY_BUDGET_USD", 0.5))
    )
    review_budget_usd: float = field(
        default_factory=lambda: float(os.environ.get("IAMBLAST_REVIEW_BUDGET_USD", 0.05))
    )
    max_llm_calls: int = field(
        default_factory=lambda: int(os.environ.get("IAMBLAST_MAX_LLM_CALLS", 12))
    )
    max_body_bytes: int = 5_000_000
