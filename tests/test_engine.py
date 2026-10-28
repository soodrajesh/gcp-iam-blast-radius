from iamblast import catalog
from iamblast.graph import Engine
from iamblast.snapshot import load

from .helpers import snap

A = "a@p.iam.gserviceaccount.com"
B = "b@p.iam.gserviceaccount.com"
C = "c@p.iam.gserviceaccount.com"
SA = lambda e: f"serviceAccount:{e}"  # noqa: E731


def eng(bindings, sas=()):
    return Engine(load(snap(bindings, sas)))


def test_owner_has_every_capability_and_scores_100():
    r = eng([("user:o@acme.com", "roles/owner")]).reach("user:o@acme.com")
    assert set(r.direct_caps) == set(catalog.ALL_CAPS) and r.score == 100


def test_iam_admin_means_everything_but_is_not_escalation():
    r = eng([("user:i@acme.com", "roles/resourcemanager.projectIamAdmin")], [A]).reach(
        "user:i@acme.com"
    )
    assert r.score == 100 and r.direct_score == 100 and r.gained_caps == []


def test_sa_scoped_token_creator_is_one_hop():
    e = eng(
        [
            ("user:u@acme.com", "roles/iam.serviceAccountTokenCreator", f"sa:{A}"),
            (SA(A), "roles/storage.admin"),
        ],
        [A],
    )
    r = e.reach("user:u@acme.com")
    assert r.reachable == [SA(A)] and {"data_read", "data_write"} <= set(r.gained_caps)
    assert [h.target for h in r.paths[SA(A)]] == [SA(A)]


def test_actas_alone_is_not_enough_but_actas_plus_code_exec_is():
    only_actas = eng(
        [("user:u@acme.com", "roles/iam.serviceAccountUser"), (SA(A), "roles/storage.admin")], [A]
    )
    assert only_actas.reach("user:u@acme.com").reachable == []
    both = eng(
        [
            ("user:u@acme.com", "roles/iam.serviceAccountUser"),
            ("user:u@acme.com", "roles/run.developer"),
            (SA(A), "roles/storage.admin"),
        ],
        [A],
    )
    assert both.reach("user:u@acme.com").reachable == [SA(A)]


def test_multi_hop_chain_and_shortest_path():
    e = eng(
        [
            ("user:u@acme.com", "roles/iam.serviceAccountTokenCreator", f"sa:{A}"),
            (SA(A), "roles/iam.serviceAccountTokenCreator", f"sa:{B}"),
            (SA(B), "roles/owner"),
        ],
        [A, B],
    )
    r = e.reach("user:u@acme.com")
    assert r.reachable == [SA(A), SA(B)] and len(r.paths[SA(B)]) == 2 and r.score == 100


def test_cycles_terminate():
    e = eng(
        [
            (SA(A), "roles/iam.serviceAccountTokenCreator", f"sa:{B}"),
            (SA(B), "roles/iam.serviceAccountTokenCreator", f"sa:{A}"),
        ],
        [A, B],
    )
    assert e.reach(SA(A)).reachable == [SA(B)]


def test_disabled_service_accounts_cannot_be_reached():
    e = eng(
        [("user:u@acme.com", "roles/iam.serviceAccountTokenCreator"), (SA(A), "roles/owner")],
        [(A, True)],
    )
    assert e.reach("user:u@acme.com").reachable == []


def test_project_wide_token_creator_reaches_all():
    e = eng(
        [("user:u@acme.com", "roles/iam.serviceAccountTokenCreator"), (SA(A), "roles/owner")],
        [A, B],
    )
    assert set(e.reach("user:u@acme.com").reachable) == {SA(A), SA(B)}


def test_editor_can_pivot_to_owner_service_account():
    e = eng([("user:u@acme.com", "roles/editor"), (SA(A), "roles/owner")], [A])
    r = e.reach("user:u@acme.com")
    assert "iam_admin" in r.gained_caps


def test_unknown_roles_are_reported_not_ignored_and_service_agents_are_excluded():
    e = eng(
        [
            ("user:u@acme.com", "roles/custom.thing"),
            ("serviceAccount:service-1@gcp-sa-x.iam.gserviceaccount.com", "roles/x.serviceAgent"),
        ]
    )
    assert e.unclassified == {"roles/custom.thing"}


def test_score_levels_and_caps():
    assert catalog.score(set(catalog.ALL_CAPS)) == 100
    assert (
        catalog.level(70) == "severe"
        and catalog.level(39) == "medium"
        and catalog.level(5) == "low"
    )


def test_deterministic():
    d = snap([("user:u@acme.com", "roles/editor"), (SA(A), "roles/owner")], [A, B])
    assert Engine(load(d)).all_reach() == Engine(load(d)).all_reach()
