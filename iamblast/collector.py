"""Read-only collection of a project's IAM over the REST APIs using Application Default
Credentials. Needs roles/iam.securityReviewer (or equivalent get/list IAM permissions) and writes
nothing. Used by the CLI (`iamblast collect`) and the service's live mode."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .models import Binding, SAKey, ServiceAccount, Snapshot

CRM = "https://cloudresourcemanager.googleapis.com/v1"
IAM = "https://iam.googleapis.com/v1"
V3 = {
    "options": {"requestedPolicyVersion": 3}
}  # v3 returns conditions instead of *_withcond_ roles


class CollectError(RuntimeError):
    pass


def _session():
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    return AuthorizedSession(creds)


def _bindings(scope: str, policy: dict[str, Any]) -> list[Binding]:
    out = []
    for b in policy.get("bindings", []):
        for m in b.get("members", []):
            out.append(
                Binding(scope=scope, role=b["role"], member=m, conditional=bool(b.get("condition")))
            )
    return out


def _age_days(ts: str) -> int:
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return max(0, (datetime.now(UTC) - t).days)
    except ValueError:
        return 0


def collect(project: str, internal_domains: list[str] | None = None, session=None) -> Snapshot:
    s = session or _session()

    def call(method: str, url: str, **kw) -> dict[str, Any]:
        r = s.request(method, url, timeout=30, **kw)
        if r.status_code != 200:
            raise CollectError(
                f"{method} {url.split('/v')[-1][:80]} -> {r.status_code}: {r.text[:160]}"
            )
        return r.json()

    bindings = _bindings("project", call("POST", f"{CRM}/projects/{project}:getIamPolicy", json=V3))
    accounts: list[ServiceAccount] = []
    token = ""
    while True:
        page = call(
            "GET",
            f"{IAM}/projects/{project}/serviceAccounts",
            params={"pageSize": 100, "pageToken": token},
        )
        for a in page.get("accounts", []):
            email = a["email"]
            keys = call(
                "GET",
                f"{IAM}/projects/{project}/serviceAccounts/{email}/keys",
                params={"keyTypes": "USER_MANAGED"},
            ).get("keys", [])
            accounts.append(
                ServiceAccount(
                    email=email,
                    disabled=bool(a.get("disabled")),
                    keys=[
                        SAKey(type="USER_MANAGED", age_days=_age_days(k.get("validAfterTime", "")))
                        for k in keys
                    ],
                )
            )
            bindings += _bindings(
                f"sa:{email}",
                call(
                    "POST",
                    f"{IAM}/projects/{project}/serviceAccounts/{email}:getIamPolicy",
                    json=V3,
                ),
            )
        token = page.get("nextPageToken", "")
        if not token:
            break
    return Snapshot(
        project=project,
        collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
        internal_domains=internal_domains or [],
        bindings=bindings,
        service_accounts=accounts,
    )
