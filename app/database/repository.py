from datetime import datetime

from app.database.database import get_session
from app.database.models import FileEventRecord


def save_file_event(
    event_type: str,
    path: str,
    extension: str = "",
    old_extension: str = "",
    timestamp: datetime | None = None,
) -> None:
    """Save a filesystem event to SQLite."""
    session = get_session()

    try:
        record = FileEventRecord(
            event_type=event_type,
            path=path,
            extension=extension,
            old_extension=old_extension,
            timestamp=timestamp or datetime.now(),
        )

        session.add(record)
        session.commit()
    finally:
        session.close()


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