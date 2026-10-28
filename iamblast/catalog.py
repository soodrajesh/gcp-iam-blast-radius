"""Role -> capability catalog. This is a curated approximation of what each role lets an identity
do, not a copy of IAM's permission lists. Roles missing from it are reported as `unclassified`
(a coverage gap), never silently treated as harmless.

Capabilities:
  iam_admin        change IAM policy, so it can grant itself anything
  impersonate_any  mint tokens for any service account (or edit SA policies to do so)
  key_create_any   create keys for any service account
  actas_any        attach any service account to a resource ("actAs")
  code_exec        run code on GCP infrastructure (Cloud Run, VMs, Functions, Build)
  secrets_read     read secret values
  data_write / data_read   modify / read stored data
  kms_use          encrypt/decrypt with project keys
  network_admin    change firewalls, routes, load balancers"""

from __future__ import annotations

import re

WEIGHTS: dict[str, int] = {
    "iam_admin": 40,
    "impersonate_any": 15,
    "key_create_any": 15,
    "code_exec": 15,
    "secrets_read": 15,
    "data_write": 12,
    "data_read": 8,
    "kms_use": 8,
    "network_admin": 8,
    "actas_any": 5,
}
ALL_CAPS = tuple(WEIGHTS)

OWNER = set(ALL_CAPS)
EDITOR = {
    "actas_any",
    "code_exec",
    "key_create_any",
    "secrets_read",
    "data_write",
    "data_read",
    "kms_use",
    "network_admin",
}

ROLE_CAPS: dict[str, set[str]] = {
    "roles/owner": OWNER,
    "roles/editor": EDITOR,
    "roles/viewer": {"data_read"},
    "roles/browser": set(),
    "roles/resourcemanager.projectIamAdmin": {"iam_admin"},
    "roles/iam.securityAdmin": {"iam_admin"},
    "roles/iam.serviceAccountTokenCreator": {"impersonate_any"},
    "roles/iam.serviceAccountUser": {"actas_any"},
    "roles/iam.serviceAccountKeyAdmin": {"key_create_any"},
    "roles/iam.serviceAccountAdmin": {"key_create_any", "actas_any", "impersonate_any"},
    "roles/iam.workloadIdentityUser": {"impersonate_any"},
    "roles/iam.securityReviewer": set(),
    "roles/run.admin": {"code_exec"},
    "roles/run.developer": {"code_exec"},
    "roles/run.invoker": set(),
    "roles/cloudfunctions.admin": {"code_exec"},
    "roles/cloudfunctions.developer": {"code_exec"},
    "roles/compute.instanceAdmin.v1": {"code_exec"},
    "roles/compute.admin": {"code_exec", "network_admin"},
    "roles/compute.networkAdmin": {"network_admin"},
    "roles/cloudbuild.builds.editor": {"code_exec"},
    "roles/storage.admin": {"data_read", "data_write"},
    "roles/storage.objectAdmin": {"data_read", "data_write"},
    "roles/storage.objectViewer": {"data_read"},
    "roles/storage.objectCreator": {"data_write"},
    "roles/bigquery.admin": {"data_read", "data_write"},
    "roles/bigquery.dataEditor": {"data_read", "data_write"},
    "roles/bigquery.dataViewer": {"data_read"},
    "roles/bigquery.jobUser": set(),
    "roles/datastore.owner": {"data_read", "data_write"},
    "roles/datastore.user": {"data_read", "data_write"},
    "roles/datastore.viewer": {"data_read"},
    "roles/secretmanager.admin": {"secrets_read"},
    "roles/secretmanager.secretAccessor": {"secrets_read"},
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": {"kms_use"},
    "roles/artifactregistry.writer": {"data_write", "data_read"},
    "roles/artifactregistry.reader": {"data_read"},
    "roles/logging.logWriter": set(),
    "roles/logging.viewer": {"data_read"},
    "roles/monitoring.viewer": set(),
    "roles/aiplatform.user": set(),
    "roles/cloudbuild.builds.builder": {"code_exec", "data_write", "data_read"},
    "roles/cloudbuild.builds.viewer": {"data_read"},
    "roles/cloudsql.client": {"data_read", "data_write"},
    "roles/cloudsql.admin": {"data_read", "data_write"},
    "roles/cloudsql.viewer": {"data_read"},
    "roles/container.admin": {
        "code_exec",
        "secrets_read",
        "network_admin",
        "data_read",
        "data_write",
    },
    "roles/container.developer": {"code_exec", "data_read", "data_write"},
    "roles/container.viewer": {"data_read"},
    "roles/pubsub.admin": {"data_read", "data_write"},
    "roles/pubsub.editor": {"data_read", "data_write"},
    "roles/pubsub.viewer": {"data_read"},
    "roles/logging.admin": {"data_read"},
    "roles/logging.privateLogViewer": {"data_read"},
    "roles/monitoring.admin": set(),
    "roles/monitoring.editor": set(),
    "roles/monitoring.metricWriter": set(),
    "roles/dns.admin": {"network_admin"},
    "roles/storage.objectUser": {"data_read", "data_write"},
    "roles/storage.legacyBucketReader": {"data_read"},
    "roles/bigquery.user": set(),
    "roles/bigquery.dataOwner": {"data_read", "data_write"},
    "roles/dataproc.worker": {"data_read", "data_write"},
    "roles/dataflow.admin": {"code_exec"},
    "roles/dataflow.worker": {"data_read", "data_write"},
    "roles/dataproc.editor": {"code_exec"},
    "roles/notebooks.admin": {"code_exec"},
    "roles/workflows.invoker": set(),
    "roles/cloudtasks.enqueuer": set(),
    "roles/secretmanager.viewer": set(),
    "roles/serviceusage.serviceUsageConsumer": set(),
    "roles/serviceusage.serviceUsageAdmin": set(),
    "roles/billing.user": set(),
    "roles/pubsub.publisher": {"data_write"},
    "roles/pubsub.subscriber": {"data_read"},
}

PRIMITIVE = {"roles/owner", "roles/editor", "roles/viewer"}


def caps_of(role: str) -> set[str] | None:
    """None means the role is not in the catalog (unclassified)."""
    return ROLE_CAPS.get(role)


def score(caps: set[str]) -> int:
    return min(100, sum(WEIGHTS[c] for c in caps))


def level(s: int) -> str:
    return "severe" if s >= 70 else "high" if s >= 40 else "medium" if s >= 20 else "low"


def is_google_managed(member: str) -> bool:
    """Service agents Google creates and manages (roles/*.serviceAgent). Not impersonable by users
    and not part of the customer's policy decisions, so they are excluded from coverage warnings."""
    return (
        "@gcp-sa-" in member
        or member.endswith("@cloudservices.gserviceaccount.com")
        or re.match(r"serviceAccount:service-\d+@", member) is not None
        or "@container-engine-robot" in member
    )
