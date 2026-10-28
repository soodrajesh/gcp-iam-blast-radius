"""Fix proposals and their verification. A patch is never trusted: it is applied to a copy of the
snapshot and the engine is re-run. It is accepted only if it removes real access without
creating any."""

from __future__ import annotations

from . import catalog
from .graph import Engine
from .models import Binding, Finding, Patch, Snapshot, Verified


def apply_patch(snap: Snapshot, patch: Patch) -> Snapshot:
    new = snap.model_copy(deep=True)
    for i, b in enumerate(new.bindings):
        if (b.scope, b.member, b.role) == (patch.scope, patch.member, patch.role):
            if patch.op == "remove":
                del new.bindings[i]
            else:
                new.bindings[i] = Binding(
                    scope=b.scope,
                    member=b.member,
                    role=patch.new_role or b.role,
                    conditional=b.conditional,
                )
            return new
    raise ValueError("binding not found")


def verify(
    snap: Snapshot, patch: Patch, finding_id: str, origin: str, principal: str, rationale: str = ""
) -> Verified:
    base = Verified(
        finding_id=finding_id,
        patch=patch,
        origin=origin,
        accepted=False,
        reason="",
        rationale=rationale[:300],
    )
    exists = any(
        (b.scope, b.member, b.role) == (patch.scope, patch.member, patch.role)
        for b in snap.bindings
    )
    if not exists:
        base.reason = "rejected: the binding to change does not exist in the snapshot"
        return base
    if patch.op == "replace":
        old, new = catalog.caps_of(patch.role), catalog.caps_of(patch.new_role or "")
        if new is None:
            base.reason = (
                "rejected: replacement role is not in the catalog, so its effect cannot be verified"
            )
            return base
        if old is None or not new <= old:
            base.reason = "rejected: replacement role grants capabilities the original did not"
            return base
        if patch.new_role == patch.role:
            base.reason = "rejected: replacement is the same role"
            return base
    patched = apply_patch(snap, patch)
    if _has_iam_admin(snap) and not _has_iam_admin(patched):
        base.reason = "rejected: would leave the project with no identity able to change IAM policy"
        return base
    before, after = Engine(snap), Engine(patched)
    rb, ra = (
        {r.principal: r.score for r in before.all_reach()},
        {r.principal: r.score for r in after.all_reach()},
    )
    base.total_before, base.total_after = sum(rb.values()), sum(ra.values())
    base.score_before, base.score_after = rb.get(principal, 0), ra.get(principal, 0)
    worse = [p for p in ra if ra[p] > rb.get(p, 0)]
    if worse:
        base.reason = f"rejected: raises the blast radius of {worse[0]}"
    elif base.total_after >= base.total_before:
        base.reason = "rejected: does not reduce any blast radius"
    else:
        base.accepted = True
        base.reason = f"accepted: total blast radius {base.total_before} -> {base.total_after}"
        base.commands = commands(snap.project, patch)
    return base


def _has_iam_admin(snap: Snapshot) -> bool:
    return any(
        b.scope == "project" and "iam_admin" in (catalog.caps_of(b.role) or ())
        for b in snap.bindings
    )


def commands(project: str, patch: Patch) -> list[str]:
    if patch.scope == "project":
        rm = (
            f"gcloud projects remove-iam-policy-binding {project} "
            f"--member='{patch.member}' --role='{patch.role}'"
        )
        add = (
            f"gcloud projects add-iam-policy-binding {project} "
            f"--member='{patch.member}' --role='{patch.new_role}'"
        )
    else:
        sa = patch.scope[3:]
        rm = (
            f"gcloud iam service-accounts remove-iam-policy-binding {sa} --project {project} "
            f"--member='{patch.member}' --role='{patch.role}'"
        )
        add = (
            f"gcloud iam service-accounts add-iam-policy-binding {sa} --project {project} "
            f"--member='{patch.member}' --role='{patch.new_role}'"
        )
    return (
        [add, rm] if patch.op == "replace" else [rm]
    )  # add the narrower role first: no access gap


def default_patch(snap: Snapshot, eng: Engine, f: Finding) -> Patch | None:
    """Rule-based fix: remove the binding that grants the first hop (IAM001) or the offending one."""
    if f.rule == "IAM001":
        r = eng.reach(f.principal)
        for t in r.reachable:
            if set(eng._direct[t]) & set(r.gained_caps):
                h = r.paths[t][0]
                return Patch(
                    op="remove", scope=h.binding.scope, member=h.binding.member, role=h.binding.role
                )
    if f.rule in ("IAM002", "IAM003", "IAM004", "IAM007"):
        for b in snap.bindings:
            if b.member == f.principal and any(
                f.evidence and e.endswith(f"{b.member} {b.role}") for e in f.evidence
            ):
                return Patch(op="remove", scope=b.scope, member=b.member, role=b.role)
    return None
