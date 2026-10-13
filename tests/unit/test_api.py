"""API surface tests via FastAPI's TestClient (in-process, no server)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


def alert_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "id": "api-1",
        "source": "edr",
        "sensor_id": "edr-1",
        "severity": "low",
        "title": "Vendor update",
        "event_time": NOW.isoformat(),
        "ingest_time": NOW.isoformat(),
        "payload": "update installed from update.microsoft.com and verified",
        "host": "WS-1001",
    }
    body.update(overrides)
    return body


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_intake_benign_alert_gets_deterministic_verdict(client: TestClient) -> None:
    response = client.post("/v1/alerts", json=alert_body())
    assert response.status_code == 200
    data = response.json()
    assert data["disposition"] == "benign"
    assert data["decided_by"] == "deterministic"


def test_intake_malicious_alert(client: TestClient) -> None:
    response = client.post(
        "/v1/alerts",
        json=alert_body(
            id="api-2",
            severity="medium",
            title="Beaconing",
            payload="beacon to 185.220.101.7 every 60s",
            dst_ip="185.220.101.7",
        ),
    )
    assert response.json()["disposition"] == "malicious"


def test_get_alert_and_verdict_lineage(client: TestClient) -> None:
    # Distinct title/host/time so dedup does not (correctly) collapse this
    # into the api-1 alert — same shape inside the window IS a duplicate.
    later = datetime(2026, 1, 15, 15, 0, tzinfo=UTC)
    client.post(
        "/v1/alerts",
        json=alert_body(
            id="api-3",
            title="Vendor update follow-up",
            host="WS-1002",
            event_time=later.isoformat(),
            ingest_time=later.isoformat(),
        ),
    )
    alert = client.get("/v1/alerts/api-3")
    assert alert.status_code == 200
    assert alert.json()["alert"]["id"] == "api-3"
    verdicts = client.get("/v1/verdicts/api-3").json()["verdicts"]
    assert len(verdicts) == 1
    assert client.get("/v1/alerts/nope").status_code == 404


def test_approval_flow_records_decision_only(client: TestClient) -> None:
    created = client.post(
        "/v1/approvals",
        json={
            "action": "isolate_host",
            "target": "WS-1001",
            "justification": "confirmed beaconing",
            "requested_by": "analyst.kim",
        },
    )
    assert created.status_code == 200
    approval = created.json()
    assert approval["status"] == "pending"
    decided = client.post(
        f"/v1/approvals/{approval['id']}/decision",
        json={"decision": "approved", "decided_by": "ir.lead"},
    )
    assert decided.json()["status"] == "approved"
    assert decided.json()["decided_by"] == "ir.lead"
    # The API can record the decision; nothing anywhere executes it.
    assert client.get("/v1/approvals").json()["approvals"]
    assert (
        client.post(
            "/v1/approvals/nope/decision", json={"decision": "approved", "decided_by": "x"}
        ).status_code
        == 404
    )
