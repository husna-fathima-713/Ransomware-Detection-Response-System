
import logging
from datetime import datetime

from app.database.database import get_session
from app.database.models import (
    Alert,
    FileEventRecord,
    Incident,
    ProcessRecord,
)


logger = logging.getLogger(__name__)


def _save_record(record) -> None:
    """Save one database record with safe transaction handling."""
    session = get_session()

    try:
        session.add(record)
        session.commit()
    except Exception:
        session.rollback()
        logger.exception(
            "Database write failed for %s.",
            type(record).__name__,
        )
        raise
    finally:
        session.close()


def save_file_event(
    event_type: str,
    path: str,
    extension: str = "",
    old_extension: str = "",
    timestamp: datetime | None = None,
) -> None:
    """Save a filesystem event to SQLite."""
    record = FileEventRecord(
        event_type=event_type,
        path=path,
        extension=extension,
        old_extension=old_extension,
        timestamp=timestamp or datetime.now(),
    )

    _save_record(record)


def save_process_snapshot(
    process: dict,
    timestamp: datetime | None = None,
) -> None:
    """Save a process snapshot to SQLite."""
    record = ProcessRecord(
        pid=process["pid"],
        name=process["name"] or "",
        username=process["username"],
        cpu_percent=process["cpu_percent"] or 0.0,
        memory_percent=process["memory_percent"] or 0.0,
        timestamp=timestamp or datetime.now(),
    )

    _save_record(record)


def save_alert(
    score: int,
    level: str,
    rule: str,
    timestamp: datetime | None = None,
) -> None:
    """Save a threat alert to SQLite."""
    record = Alert(
        score=score,
        level=level,
        rule=rule,
        timestamp=timestamp or datetime.now(),
    )

    _save_record(record)


def save_incident(
    score: int,
    level: str,
    affected_files: list[str],
    timestamp: datetime | None = None,
) -> None:
    """Save a security incident to SQLite."""
    record = Incident(
        score=score,
        level=level,
        status="open",
        affected_files="\n".join(affected_files),
        timestamp=timestamp or datetime.now(),
    )

    _save_record(record)


def get_recent_events(limit: int = 50) -> list[dict]:
    """Return the most recent filesystem events."""
    session = get_session()

    try:
        records = (
            session.query(FileEventRecord)
            .order_by(FileEventRecord.timestamp.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "id": record.id,
                "event_type": record.event_type,
                "path": record.path,
                "extension": record.extension,
                "old_extension": record.old_extension,
                "timestamp": record.timestamp.isoformat(),
            }
            for record in records
        ]
    finally:
        session.close()


def get_recent_alerts(limit: int = 50) -> list[dict]:
    """Return the most recent threat alerts."""
    session = get_session()

    try:
        records = (
            session.query(Alert)
            .order_by(Alert.timestamp.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "id": record.id,
                "score": record.score,
                "level": record.level,
                "rule": record.rule,
                "timestamp": record.timestamp.isoformat(),
            }
            for record in records
        ]
    finally:
        session.close()


def get_recent_processes(limit: int = 50) -> list[dict]:
    """Return the most recent process snapshots."""
    session = get_session()

    try:
        records = (
            session.query(ProcessRecord)
            .order_by(ProcessRecord.timestamp.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "id": record.id,
                "pid": record.pid,
                "name": record.name,
                "username": record.username,
                "cpu_percent": record.cpu_percent,
                "memory_percent": record.memory_percent,
                "timestamp": record.timestamp.isoformat(),
            }
            for record in records
        ]
    finally:
        session.close()


def get_recent_incidents(limit: int = 50) -> list[dict]:
    """Return the most recent security incidents."""
    session = get_session()

    try:
        records = (
            session.query(Incident)
            .order_by(Incident.timestamp.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "id": record.id,
                "score": record.score,
                "level": record.level,
                "status": record.status,
                "affected_files": (
                    record.affected_files.splitlines()
                    if record.affected_files
                    else []
                ),
                "timestamp": record.timestamp.isoformat(),
            }
            for record in records
        ]
    finally:
        session.close()
