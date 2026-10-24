
from fastapi import APIRouter, HTTPException, Query
from loguru import logger

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

MAX_RECORD_LIMIT = 500


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
def events(
    limit: int = Query(default=50, ge=1, le=MAX_RECORD_LIMIT),
) -> list[dict]:
    """Return a bounded number of recent filesystem events."""
    return get_recent_events(limit)


@router.get("/alerts")
def alerts(
    limit: int = Query(default=50, ge=1, le=MAX_RECORD_LIMIT),
) -> list[dict]:
    """Return a bounded number of recent threat alerts."""
    return get_recent_alerts(limit)


@router.get("/processes")
def processes(
    limit: int = Query(default=50, ge=1, le=MAX_RECORD_LIMIT),
) -> list[dict]:
    """Return a bounded number of recent process snapshots."""
    return get_recent_processes(limit)


@router.get("/incidents")
def incidents(
    limit: int = Query(default=50, ge=1, le=MAX_RECORD_LIMIT),
) -> list[dict]:
    """Return a bounded number of recent security incidents."""
    return get_recent_incidents(limit)


def _generate_report(generator_method, report_format: str) -> dict:
    """Generate a report and return a controlled API error on failure."""
    try:
        report_path = generator_method()
    except Exception:
        logger.exception(
            "Failed to generate {} report",
            report_format,
        )
        raise HTTPException(
            status_code=500,
            detail="Report generation failed.",
        ) from None

    return {
        "status": "generated",
        "format": report_format,
        "path": report_path,
    }


@router.post("/reports/json")
def generate_json_report() -> dict:
    """Generate a JSON security report."""
    return _generate_report(
        report_generator.generate_json,
        "json",
    )


@router.post("/reports/csv")
def generate_csv_report() -> dict:
    """Generate a CSV security report."""
    return _generate_report(
        report_generator.generate_csv,
        "csv",
    )
