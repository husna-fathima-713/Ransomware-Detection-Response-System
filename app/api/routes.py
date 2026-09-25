from fastapi import APIRouter

from app.database.database import get_session
from app.database.models import Alert, FileEventRecord, Incident
from app.database.repository import (
    get_recent_alerts,
    get_recent_events,
    get_recent_incidents,
    get_recent_processes,
)
from app.reports.report_generator import ReportGenerator

router = APIRouter()

report_generator = ReportGenerator()


@router.get("/health")
def health() -> dict:
    """Return API health status."""
    return {
        "status": "healthy",
        "service": "RDRS",
    }


@router.get("/status")
def status() -> dict:
    """Return basic RDRS monitoring status."""
    session = get_session()

    try:
        event_count = session.query(FileEventRecord).count()
        alert_count = session.query(Alert).count()
        incident_count = session.query(Incident).count()

        return {
            "status": "monitoring",
            "events": event_count,
            "alerts": alert_count,
            "incidents": incident_count,
        }
    finally:
        session.close()


@router.get("/events")
def events(limit: int = 50) -> list[dict]:
    """Return recent filesystem events."""
    return get_recent_events(limit)


@router.get("/alerts")
def alerts(limit: int = 50) -> list[dict]:
    """Return recent threat alerts."""
    return get_recent_alerts(limit)


@router.get("/processes")
def processes(limit: int = 50) -> list[dict]:
    """Return recent process snapshots."""
    return get_recent_processes(limit)


@router.get("/incidents")
def incidents(limit: int = 50) -> list[dict]:
    """Return recent security incidents."""
    return get_recent_incidents(limit)


@router.post("/reports/json")
def generate_json_report() -> dict:
    """Generate a JSON security report."""
    report_path = report_generator.generate_json()

    return {
        "status": "generated",
        "format": "json",
        "path": report_path,
    }


@router.post("/reports/csv")
def generate_csv_report() -> dict:
    """Generate a CSV security report."""
    report_path = report_generator.generate_csv()

    return {
        "status": "generated",
        "format": "csv",
        "path": report_path,
    }