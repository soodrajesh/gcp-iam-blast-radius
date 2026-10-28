"""Regenerate iamblast/samples/*.json.   .venv/bin/python scripts/build_samples.py"""

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "iamblast" / "samples"


def b(member, role, scope="project"):
    return {"scope": scope, "role": role, "member": member}


def sa(email, keys=(), disabled=False):
    return {
        "email": email,
        "disabled": disabled,
        "keys": [{"type": "USER_MANAGED", "age_days": d} for d in keys],
    }


P = "acme-prod"
DEPLOY = f"ci-deployer@{P}.iam.gserviceaccount.com"
TF = f"terraform@{P}.iam.gserviceaccount.com"
APP = f"orders-app@{P}.iam.gserviceaccount.com"
DATA = f"etl@{P}.iam.gserviceaccount.com"
COMPUTE = "123456789-compute@developer.gserviceaccount.com"
OLD = f"legacy-batch@{P}.iam.gserviceaccount.com"

SAMPLES = {
    "acme_prod": {
        "project": P,
        "collected_at": "2026-10-28T00:00:00Z",
        "internal_domains": ["acme.com"],
        "service_accounts": [
            sa(DEPLOY, keys=[210]),
            sa(TF),
            sa(APP),
            sa(DATA),
            sa(COMPUTE),
            sa(OLD, disabled=True),
        ],
        "bindings": [
            b("user:alice@acme.com", "roles/owner"),
            b("user:bob@acme.com", "roles/run.developer"),
            b("user:bob@acme.com", "roles/iam.serviceAccountUser"),
            b("user:carol@acme.com", "roles/viewer"),
            b("user:carol@acme.com", "roles/iam.serviceAccountTokenCreator", f"sa:{DEPLOY}"),
            b("user:eve@gmail.com", "roles/storage.admin"),
            b("group:platform@acme.com", "roles/editor"),
            b(f"serviceAccount:{DEPLOY}", "roles/cloudbuild.builds.editor"),
            b(f"serviceAccount:{DEPLOY}", "roles/run.admin"),
            b(f"serviceAccount:{DEPLOY}", "roles/iam.serviceAccountTokenCreator", f"sa:{TF}"),
            b(f"serviceAccount:{TF}", "roles/owner"),
            b(f"serviceAccount:{APP}", "roles/secretmanager.secretAccessor"),
            b(f"serviceAccount:{APP}", "roles/datastore.user"),
            b(f"serviceAccount:{DATA}", "roles/bigquery.dataEditor"),
            b(f"serviceAccount:{COMPUTE}", "roles/editor"),
            b(f"serviceAccount:{OLD}", "roles/storage.objectAdmin"),
            b("allUsers", "roles/storage.objectViewer"),
            b("user:dave@acme.com", "roles/custom.dbOperator"),
        ],
    },
    "tidy_project": {
        "project": "tidy-co",
        "collected_at": "2026-10-28T00:00:00Z",
        "internal_domains": ["tidy.io"],
        "service_accounts": [
            sa("api@tidy-co.iam.gserviceaccount.com"),
            sa("jobs@tidy-co.iam.gserviceaccount.com"),
        ],
        "bindings": [
            b("group:admins@tidy.io", "roles/resourcemanager.projectIamAdmin"),
            b("user:ann@tidy.io", "roles/viewer"),
            b("serviceAccount:api@tidy-co.iam.gserviceaccount.com", "roles/datastore.user"),
            b("serviceAccount:api@tidy-co.iam.gserviceaccount.com", "roles/logging.logWriter"),
            b("serviceAccount:jobs@tidy-co.iam.gserviceaccount.com", "roles/bigquery.dataViewer"),
            b(
                "user:ann@tidy.io",
                "roles/iam.serviceAccountUser",
                "sa:api@tidy-co.iam.gserviceaccount.com",
            ),
        ],
    },
    "editor_sprawl": {
        "project": "startup-1",
        "collected_at": "2026-10-28T00:00:00Z",
        "internal_domains": ["startup.dev"],
        "service_accounts": [
            sa("111-compute@developer.gserviceaccount.com", keys=[400]),
            sa("admin-sa@startup-1.iam.gserviceaccount.com"),
        ],
        "bindings": [
            b("user:cto@startup.dev", "roles/owner"),
            b("user:dev1@startup.dev", "roles/editor"),
            b("user:dev2@startup.dev", "roles/editor"),
            b("user:dev3@startup.dev", "roles/editor"),
            b("serviceAccount:111-compute@developer.gserviceaccount.com", "roles/editor"),
            b("serviceAccount:admin-sa@startup-1.iam.gserviceaccount.com", "roles/owner"),
        ],
    },
}

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, doc in SAMPLES.items():
        (OUT / f"{name}.json").write_text(json.dumps(doc, indent=1) + "\n")
    print(f"wrote {len(SAMPLES)} samples")
