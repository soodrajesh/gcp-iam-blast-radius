"""Data model: a snapshot of a project's IAM, and the analysis computed from it."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Binding(BaseModel):
    scope: str  # "project" or "sa:<email>"
    role: str
    member: str  # user:x, serviceAccount:x, group:x, domain:x, allUsers, allAuthenticatedUsers
    conditional: bool = False


class SAKey(BaseModel):
    type: Literal["USER_MANAGED", "SYSTEM_MANAGED"] = "USER_MANAGED"
    age_days: int = 0


class ServiceAccount(BaseModel):
    email: str
    disabled: bool = False
    keys: list[SAKey] = Field(default_factory=list)

    @property
    def member(self) -> str:
        return f"serviceAccount:{self.email}"

    @property
    def is_default(self) -> bool:
        return self.email.endswith("-compute@developer.gserviceaccount.com") or self.email.endswith(
            "@appspot.gserviceaccount.com"
        )


class Snapshot(BaseModel):
    project: str
    collected_at: str = ""
    internal_domains: list[str] = Field(
        default_factory=list
    )  # domains whose users count as internal
    bindings: list[Binding] = Field(default_factory=list)
    service_accounts: list[ServiceAccount] = Field(default_factory=list)


class Hop(BaseModel):
    """One step of lateral movement: `source` becomes `target` because of `binding`."""

    source: str
    target: str  # a serviceAccount: member
    how: str  # human-readable mechanism
    binding: Binding


class Reach(BaseModel):
    principal: str
    direct_caps: list[str]
    effective_caps: list[str]
    gained_caps: list[str]
    direct_score: int
    score: int
    level: Literal["low", "medium", "high", "severe"]
    reachable: list[str]  # service accounts it can become, nearest first
    paths: dict[str, list[Hop]] = Field(default_factory=dict)  # target SA -> hops


class Finding(BaseModel):
    id: str = ""
    rule: str
    severity: Severity
    principal: str
    title: str
    detail: str = ""
    evidence: list[str] = Field(default_factory=list)
    source: Literal["rule", "llm"] = "rule"
    note: str = ""  # model-written explanation (validated), never affects severity


class Patch(BaseModel):
    """A proposed change to the policy, always verified by re-running the engine."""

    op: Literal["remove", "replace"]
    scope: str
    member: str
    role: str  # role removed, or replaced
    new_role: str | None = None


class Verified(BaseModel):
    finding_id: str
    patch: Patch
    origin: Literal["rule", "llm"]
    accepted: bool
    reason: str
    score_before: int = 0
    score_after: int = 0
    total_before: int = 0
    total_after: int = 0
    commands: list[str] = Field(default_factory=list)
    rationale: str = ""


class TraceStep(BaseModel):
    agent: str
    action: str
    status: Literal["ok", "skipped", "error"] = "ok"
    start_ms: int = 0
    duration_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    note: str = ""


class Analysis(BaseModel):
    id: str
    created_at: str
    project: str
    provider: str
    model: str
    posture: Literal["healthy", "needs_attention", "critical"]
    summary: str
    unclassified_roles: list[str] = Field(default_factory=list)
    reaches: list[Reach] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    fixes: list[Verified] = Field(default_factory=list)
    dropped: list[dict[str, str]] = Field(default_factory=list)
    degraded: list[str] = Field(default_factory=list)
    trace: list[TraceStep] = Field(default_factory=list)
    snapshot_sha256: str = ""
    cost_usd: float = 0.0
    duration_ms: int = 0
    graph: dict[str, Any] = Field(default_factory=dict)
