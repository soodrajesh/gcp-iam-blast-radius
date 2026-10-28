import pytest

from iamblast import rules
from iamblast.graph import Engine
from iamblast.models import Patch
from iamblast.remediate import apply_patch, commands, verify
from iamblast.snapshot import SnapshotError, load

from .helpers import sample, snap

A = "a@p.iam.gserviceaccount.com"
SA = f"serviceAccount:{A}"


def findings(d):
    s = load(d)
    return s, Engine(s), rules.evaluate(s, Engine(s))


def ids(fs, rule):
    return [f for f in fs if f.rule == rule]


def test_samples_postures():
    assert rules.posture(findings(sample("acme_prod"))[2]) == "critical"
    assert rules.posture(findings(sample("editor_sprawl"))[2]) == "critical"
    assert rules.posture(findings(sample("tidy_project"))[2]) == "healthy"


def test_public_principal_is_critical():
    f = findings(snap([("allUsers", "roles/storage.objectViewer")]))[2]
    assert ids(f, "IAM002")[0].severity == "critical"


def test_external_domain_flagged_only_when_domains_configured():
    d = snap([("user:x@gmail.com", "roles/viewer")])
    assert ids(findings(d)[2], "IAM004")
    d["internal_domains"] = []
    assert not ids(findings(d)[2], "IAM004")


def test_old_keys_high_new_keys_medium():
    d = snap([], [A])
    d["service_accounts"][0]["keys"] = [
        {"type": "USER_MANAGED", "age_days": 200},
        {"type": "USER_MANAGED", "age_days": 5},
    ]
    assert sorted(f.severity for f in ids(findings(d)[2], "IAM005")) == ["high", "medium"]


def test_chain_rule_and_disabled_sa_rule():
    d = snap(
        [
            ("user:u@acme.com", "roles/iam.serviceAccountTokenCreator", f"sa:{A}"),
            (SA, "roles/iam.serviceAccountTokenCreator", "sa:b@p.iam.gserviceaccount.com"),
            (SA, "roles/viewer"),
        ],
        [A, "b@p.iam.gserviceaccount.com"],
    )
    assert ids(findings(d)[2], "IAM006")
    d2 = snap([(SA, "roles/viewer")], [(A, True)])
    assert ids(findings(d2)[2], "IAM008")


def test_iam_admin_holder_is_low_not_escalation():
    f = findings(snap([("group:admins@acme.com", "roles/resourcemanager.projectIamAdmin")], [A]))[2]
    assert not ids(f, "IAM001") and ids(f, "IAM010")[0].severity == "low"


def test_coverage_gap_reported():
    assert ids(findings(snap([("user:u@acme.com", "roles/custom.x")]))[2], "IAM009")


def test_bad_snapshot_raises():
    for bad in ({}, {"project": 1}, {"project": "p", "bindings": "x"}):
        with pytest.raises(SnapshotError):
            load(bad)


# --- remediation ---------------------------------------------------------------------------


def test_removing_the_enabling_binding_is_accepted_and_reduces_total():
    s, e, f = findings(sample("acme_prod"))
    esc = ids(f, "IAM001")[-1]  # carol: token creator on ci-deployer
    from iamblast.remediate import default_patch

    v = verify(s, default_patch(s, e, esc), esc.id, "rule", esc.principal)
    assert v.accepted and v.total_after < v.total_before and v.commands


def test_nonexistent_binding_rejected():
    s = load(snap([("user:u@acme.com", "roles/viewer")]))
    v = verify(
        s,
        Patch(op="remove", scope="project", member="user:u@acme.com", role="roles/owner"),
        "X",
        "llm",
        "user:u@acme.com",
    )
    assert not v.accepted and "does not exist" in v.reason


def test_replacement_that_adds_capabilities_is_rejected():
    s = load(snap([("user:u@acme.com", "roles/viewer")]))
    p = Patch(
        op="replace",
        scope="project",
        member="user:u@acme.com",
        role="roles/viewer",
        new_role="roles/owner",
    )
    assert (
        "grants capabilities the original did not"
        in verify(s, p, "X", "llm", "user:u@acme.com").reason
    )


def test_replacement_with_unclassified_role_is_rejected():
    s = load(snap([("user:u@acme.com", "roles/editor")]))
    p = Patch(
        op="replace",
        scope="project",
        member="user:u@acme.com",
        role="roles/editor",
        new_role="roles/made.up",
    )
    assert "not in the catalog" in verify(s, p, "X", "llm", "user:u@acme.com").reason


def test_narrowing_replacement_accepted_with_add_before_remove():
    s = load(snap([("user:u@acme.com", "roles/editor")]))
    p = Patch(
        op="replace",
        scope="project",
        member="user:u@acme.com",
        role="roles/editor",
        new_role="roles/run.developer",
    )
    v = verify(s, p, "X", "llm", "user:u@acme.com")
    assert (
        v.accepted
        and "add-iam-policy-binding" in v.commands[0]
        and "remove-iam-policy-binding" in v.commands[1]
    )


def test_noop_change_that_reduces_nothing_is_rejected():
    s = load(snap([("user:u@acme.com", "roles/logging.logWriter")]))
    p = Patch(
        op="remove", scope="project", member="user:u@acme.com", role="roles/logging.logWriter"
    )
    assert "does not reduce" in verify(s, p, "X", "rule", "user:u@acme.com").reason


def test_never_removes_the_last_iam_admin():
    s = load(snap([("user:o@acme.com", "roles/owner")]))
    p = Patch(op="remove", scope="project", member="user:o@acme.com", role="roles/owner")
    assert "no identity able to change IAM" in verify(s, p, "X", "rule", "user:o@acme.com").reason


def test_apply_patch_does_not_mutate_original():
    s = load(snap([("user:u@acme.com", "roles/editor")]))
    apply_patch(
        s, Patch(op="remove", scope="project", member="user:u@acme.com", role="roles/editor")
    )
    assert len(s.bindings) == 1


def test_sa_scope_commands():
    c = commands(
        "p",
        Patch(
            op="remove",
            scope=f"sa:{A}",
            member="user:u@acme.com",
            role="roles/iam.serviceAccountTokenCreator",
        ),
    )
    assert c[0].startswith("gcloud iam service-accounts remove-iam-policy-binding")
