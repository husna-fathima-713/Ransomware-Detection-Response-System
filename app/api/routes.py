from fastapi import APIRouter

from app.database.database import get_session
from app.database.models import Alert, FileEventRecord
from app.database.repository import (
    get_recent_alerts,
    get_recent_events,
)

router = APIRouter()


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

        return {
            "status": "monitoring",
            "events": event_count,
            "alerts": alert_count,
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