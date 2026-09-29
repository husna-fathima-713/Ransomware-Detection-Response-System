from fastapi.testclient import TestClient

from app.main import app
from app.api import routes


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "RDRS",
    }


def test_events_endpoint(monkeypatch):
    expected = [
        {
            "id": 1,
            "event_type": "modify",
            "path": "data/sandbox/test.txt",
            "extension": ".txt",
            "old_extension": "",
            "timestamp": "2026-09-29T10:00:00",
        }
    ]

    monkeypatch.setattr(
        routes,
        "get_recent_events",
        lambda limit: expected,
    )

    response = client.get("/events?limit=10")

    assert response.status_code == 200
    assert response.json() == expected


def test_alerts_endpoint(monkeypatch):
    expected = [
        {
            "id": 1,
            "score": 70,
            "level": "warning",
            "rule": "mass_rename",
            "timestamp": "2026-09-29T10:00:00",
        }
    ]

    monkeypatch.setattr(
        routes,
        "get_recent_alerts",
        lambda limit: expected,
    )

    response = client.get("/alerts?limit=10")

    assert response.status_code == 200
    assert response.json() == expected


def test_processes_endpoint(monkeypatch):
    expected = [
        {
            "id": 1,
            "pid": 1234,
            "name": "test_process",
            "username": "test_user",
            "cpu_percent": 12.5,
            "memory_percent": 2.5,
            "timestamp": "2026-09-29T10:00:00",
        }
    ]

    monkeypatch.setattr(
        routes,
        "get_recent_processes",
        lambda limit: expected,
    )

    response = client.get("/processes?limit=10")

    assert response.status_code == 200
    assert response.json() == expected


def test_incidents_endpoint(monkeypatch):
    expected = [
        {
            "id": 1,
            "score": 100,
            "level": "critical",
            "status": "open",
            "affected_files": [
                "data/sandbox/test.locked"
            ],
            "timestamp": "2026-09-29T10:00:00",
        }
    ]

    monkeypatch.setattr(
        routes,
        "get_recent_incidents",
        lambda limit: expected,
    )

    response = client.get("/incidents?limit=10")

    assert response.status_code == 200
    assert response.json() == expected


def test_json_report_endpoint(monkeypatch):
    monkeypatch.setattr(
        routes.report_generator,
        "generate_json",
        lambda: "reports/test_report.json",
    )

    response = client.post("/reports/json")

    assert response.status_code == 200
    assert response.json() == {
        "status": "generated",
        "format": "json",
        "path": "reports/test_report.json",
    }


def test_csv_report_endpoint(monkeypatch):
    monkeypatch.setattr(
        routes.report_generator,
        "generate_csv",
        lambda: "reports/test_report.csv",
    )

    response = client.post("/reports/csv")

    assert response.status_code == 200
    assert response.json() == {
        "status": "generated",
        "format": "csv",
        "path": "reports/test_report.csv",
    }