import json

import pytest
from fastapi.testclient import TestClient

import iamblast.api as api
from iamblast.api import create_app
from iamblast.cli import main
from iamblast.collector import CollectError
from iamblast.config import Settings

from .helpers import sample, snap


@pytest.fixture
def client():
    s = Settings(provider="mock", allowed_providers=("mock", "none"), live_projects=("proj-a",))
    return TestClient(create_app(s))


def test_basic_endpoints(client):
    assert client.get("/healthz").json()["ok"]
    assert client.get("/api/config").json()["roles_in_catalog"] > 30
    assert "acme_prod" in client.get("/api/samples").json()
    assert client.get("/api/samples/..%2Fx").status_code == 404
    assert "IAM Blast Radius" in client.get("/").text


def test_analyze_get_list(client):
    r = client.post("/api/analyses", json={"snapshot": sample("acme_prod")})
    assert r.status_code == 200 and r.json()["posture"] == "critical"
    aid = r.json()["id"]
    assert client.get(f"/api/analyses/{aid}").json()["id"] == aid
    assert [a["id"] for a in client.get("/api/analyses").json()] == [aid]
    assert client.get("/api/analyses/nope").status_code == 404


def test_request_validation(client):
    assert client.post("/api/analyses", json={}).status_code == 422
    assert (
        client.post(
            "/api/analyses", json={"snapshot": sample("acme_prod"), "live_project": "proj-a"}
        ).status_code
        == 422
    )
    assert client.post("/api/analyses", json={"snapshot": {"nope": 1}}).status_code == 422
    assert client.post("/api/analyses", content=b"x").status_code == 422
    assert (
        client.post(
            "/api/analyses", json={"snapshot": sample("acme_prod"), "llm": "openai"}
        ).status_code
        == 403
    )


def test_live_mode_is_allow_listed_and_uses_collector(client, monkeypatch):
    assert client.post("/api/analyses", json={"live_project": "other"}).status_code == 403
    from iamblast.snapshot import load

    monkeypatch.setattr(
        api, "collect", lambda p, d: load(snap([("user:u@acme.com", "roles/viewer")]))
    )
    assert (
        client.post("/api/analyses", json={"live_project": "proj-a"}).json()["posture"] == "healthy"
    )

    def boom(p, d):
        raise CollectError("403 denied")

    monkeypatch.setattr(api, "collect", boom)
    assert client.post("/api/analyses", json={"live_project": "proj-a"}).status_code == 502


def test_body_limit():
    s = Settings(provider="none", allowed_providers=("none",))
    s.max_body_bytes = 50
    assert (
        TestClient(create_app(s))
        .post("/api/analyses", json={"snapshot": sample("acme_prod")})
        .status_code
        == 413
    )


def test_nothing_is_persisted_outside_memory(client):
    a = client.post("/api/analyses", json={"snapshot": sample("tidy_project")}).json()
    assert "bindings" not in a  # the raw snapshot is never echoed or stored; only its hash
    assert len(a["snapshot_sha256"]) == 64


def test_cli_exit_codes_and_output(tmp_path, capsys):
    for name, code in [("tidy_project", 0), ("acme_prod", 2)]:
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(sample(name)))
        assert main(["analyze", str(p), "--llm", "none"]) == code
    out = capsys.readouterr().out
    assert "POSTURE: CRITICAL" in out and "gcloud projects remove-iam-policy-binding" in out
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert main(["analyze", str(bad)]) == 3
    assert main(["analyze", str(tmp_path / "missing.json")]) == 3


def test_cli_json(tmp_path, capsys):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(sample("tidy_project")))
    assert main(["analyze", str(p), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["posture"] == "healthy"
