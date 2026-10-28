"""Deterministic findings. Severity comes from here and nowhere else."""

from __future__ import annotations

from . import catalog
from .graph import Engine
from .models import Finding, Snapshot

PUBLIC = {"allUsers", "allAuthenticatedUsers"}
OLD_KEY_DAYS = 90


def _is_human(p: str) -> bool:
    return p.startswith(("user:", "group:"))


def _domain(p: str) -> str:
    return p.split("@", 1)[1].lower() if "@" in p else ""


def evaluate(snap: Snapshot, eng: Engine) -> list[Finding]:
    out: list[Finding] = []

    def add(rule, sev, principal, title, detail="", evidence=()):
        out.append(
            Finding(
                rule=rule,
                severity=sev,
                principal=principal,
                title=title,
                detail=detail,
                evidence=list(evidence),
            )
        )

    reaches = {r.principal: r for r in eng.all_reach()}

    # IAM001: privilege escalation through service-account hops
    for p, r in reaches.items():
        if not r.reachable or not r.gained_caps:
            continue
        gained_iam = "iam_admin" in r.gained_caps
        material = set(r.gained_caps) & {
            "iam_admin",
            "code_exec",
            "secrets_read",
            "data_write",
            "key_create_any",
            "impersonate_any",
        }
        if not material:
            continue
        critical = gained_iam or (r.score >= 70 and r.direct_score < 70)
        target = next(
            (t for t in r.reachable if set(eng._direct[t]) & set(r.gained_caps)), r.reachable[0]
        )
        chain = " -> ".join([p] + [h.target for h in r.paths[target]])
        add(
            "IAM001",
            "critical" if critical else "high",
            p,
            f"{p} can escalate from score {r.direct_score} to {r.score}",
            f"Through service-account hops it gains: {', '.join(r.gained_caps)}.",
            [chain] + [f"{h.source} {h.how} [{h.binding.role}]" for h in r.paths[target]],
        )

    # IAM002: public principals
    for b in snap.bindings:
        if b.member in PUBLIC:
            add(
                "IAM002",
                "critical",
                b.member,
                f"{b.role} granted to {b.member} on {b.scope}",
                "Anyone on the internet holds this role.",
                [f"{b.scope}: {b.member} {b.role}"],
            )

    # IAM003: primitive roles
    for b in snap.bindings:
        if (
            b.role in ("roles/owner", "roles/editor")
            and b.member not in PUBLIC
            and b.scope == "project"
        ):
            sa = eng.sas.get(b.member)
            default = bool(sa and sa.is_default)
            sev = (
                "high"
                if (b.role == "roles/owner" or b.member.startswith("serviceAccount:"))
                else "medium"
            )
            what = "the default service account" if default else "an identity"
            add(
                "IAM003",
                sev,
                b.member,
                f"{b.role} on {b.member}",
                f"Primitive role held by {what}; it carries thousands of permissions.",
                [f"project: {b.member} {b.role}"],
            )

    # IAM004: external human identities
    internal = {d.lower() for d in snap.internal_domains}
    if internal:
        for b in snap.bindings:
            if b.member.startswith("user:") and _domain(b.member) not in internal:
                r = reaches.get(b.member)
                add(
                    "IAM004",
                    "high" if r and r.score >= 40 else "medium",
                    b.member,
                    f"External identity {b.member} holds {b.role}",
                    f"Domain {_domain(b.member)} is outside {', '.join(sorted(internal))}.",
                    [f"{b.scope}: {b.member} {b.role}"],
                )

    # IAM005: long-lived SA keys
    for sa in snap.service_accounts:
        for k in sa.keys:
            if k.type == "USER_MANAGED":
                old = k.age_days > OLD_KEY_DAYS
                add(
                    "IAM005",
                    "high" if old else "medium",
                    sa.member,
                    f"User-managed key on {sa.email} ({k.age_days} days old)",
                    "Exportable keys leak through repos, laptops and logs.",
                    [f"key age {k.age_days}d"],
                )

    # IAM006: long impersonation chains (lateral movement)
    for p, r in reaches.items():
        longest = max((len(v) for v in r.paths.values()), default=0)
        if longest >= 2:
            t = max(r.paths, key=lambda x: len(r.paths[x]))
            add(
                "IAM006",
                "medium",
                p,
                f"{p} can reach {t.split(':', 1)[1]} in {longest} hops",
                "Multi-hop chains are hard to audit and are how small grants become large ones.",
                [" -> ".join([p] + [h.target for h in r.paths[t]])],
            )

    # IAM007: project-wide actAs / token creation for non-admins
    for b in snap.bindings:
        if b.scope == "project" and b.role in (
            "roles/iam.serviceAccountUser",
            "roles/iam.serviceAccountTokenCreator",
        ):
            add(
                "IAM007",
                "high",
                b.member,
                f"{b.role} granted project-wide to {b.member}",
                "Project-level grants apply to every service account, including future ones.",
                [f"project: {b.member} {b.role}"],
            )

    # IAM008: disabled SAs that still hold roles
    for sa in snap.service_accounts:
        if sa.disabled and sa.member in eng.project_bindings:
            add(
                "IAM008",
                "low",
                sa.member,
                f"Disabled service account {sa.email} still has roles",
                "Dead identities keep their grants and can be re-enabled by anyone with SA admin.",
            )

    # IAM010: holders of IAM admin have full control by construction
    for p in reaches:
        held = [
            b
            for b in eng.project_bindings.get(p, [])
            if "iam_admin" in (catalog.caps_of(b.role) or ()) and b.role != "roles/owner"
        ]
        for b in held:
            add(
                "IAM010",
                "low",
                p,
                f"{p} can change IAM policy ({b.role})",
                "Full control of the project by design; keep the holder list short and reviewed.",
                [f"project: {b.member} {b.role}"],
            )

    # IAM009: coverage gap
    if eng.unclassified:
        add(
            "IAM009",
            "info",
            "-",
            f"{len(eng.unclassified)} role(s) not in the catalog",
            "Their capabilities are not scored, so blast radii may be understated.",
            sorted(eng.unclassified),
        )

    out.sort(
        key=lambda f: (
            -["info", "low", "medium", "high", "critical"].index(f.severity),
            f.rule,
            f.principal,
        )
    )
    counts: dict[str, int] = {}
    for f in out:
        counts[f.rule] = counts.get(f.rule, 0) + 1
        f.id = f"{f.rule}-{counts[f.rule]}"
    return out


def posture(findings: list[Finding]) -> str:
    sev = {f.severity for f in findings if f.source == "rule"}
    if "critical" in sev:
        return "critical"
    if "high" in sev or sum(f.severity == "medium" for f in findings) >= 3:
        return "needs_attention"
    return "healthy"
