
import logging
import math
from datetime import datetime
from numbers import Real

from app.database.database import get_session
from app.database.models import (
    Alert,
    FileEventRecord,
    Incident,
    ProcessRecord,
)


logger = logging.getLogger(__name__)

VALID_LEVELS = {"normal", "warning", "critical"}


def _validate_text(value, field_name, allow_empty=False):
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string.")

    if not allow_empty and not value.strip():
        raise ValueError(f"{field_name} cannot be empty.")


def _validate_timestamp(timestamp):
    if timestamp is not None and not isinstance(timestamp, datetime):
        raise TypeError("timestamp must be a datetime object.")


def _validate_score(score):
    if (
        isinstance(score, bool)
        or not isinstance(score, int)
        or not 0 <= score <= 100
    ):
        raise ValueError("score must be an integer between 0 and 100.")


def _validate_level(level):
    if not isinstance(level, str) or level not in VALID_LEVELS:
        raise ValueError(
            "level must be normal, warning, or critical."
        )


def _validate_limit(limit):
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit <= 0
    ):
        raise ValueError("limit must be a positive integer.")


def _validate_process_number(value, field_name, maximum=None):
    if (
        isinstance(value, bool)
        or not isinstance(value, Real)
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(
            f"{field_name} must be a finite non-negative number."
        )

    if maximum is not None and value > maximum:
        raise ValueError(
            f"{field_name} must not exceed {maximum}."
        )


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
    _validate_text(event_type, "event_type")
    _validate_text(path, "path")
    _validate_text(extension, "extension", allow_empty=True)
    _validate_text(old_extension, "old_extension", allow_empty=True)
    _validate_timestamp(timestamp)

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
    if not isinstance(process, dict):
        raise TypeError("process must be a dictionary.")

    _validate_timestamp(timestamp)

    required_fields = {
        "pid",
        "name",
        "username",
        "cpu_percent",
        "memory_percent",
    }

    missing_fields = required_fields.difference(process)

    if missing_fields:
        raise ValueError(
            "Missing process fields: "
            + ", ".join(sorted(missing_fields))
        )

    pid = process["pid"]

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("pid must be a positive integer.")

    name = process["name"]
    username = process["username"]

    if name is not None and not isinstance(name, str):
        raise TypeError("process name must be a string or None.")

    if username is not None and not isinstance(username, str):
        raise TypeError("username must be a string or None.")

    cpu_percent = process["cpu_percent"]
    memory_percent = process["memory_percent"]

    # Preserve the existing behaviour for unavailable psutil metrics.
    if cpu_percent is None:
        cpu_percent = 0.0

    if memory_percent is None:
        memory_percent = 0.0

    _validate_process_number(cpu_percent, "cpu_percent")
    _validate_process_number(
        memory_percent,
        "memory_percent",
        maximum=100,
    )

    record = ProcessRecord(
        pid=pid,
        name=name or "",
        username=username,
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        timestamp=timestamp or datetime.now(),
    )

    _save_record(record)


def save_alert(
    score: int,
    level: str,
    rule: str,
    timestamp: datetime | None = None,
) -> None:
    _validate_score(score)
    _validate_level(level)
    _validate_text(rule, "rule")
    _validate_timestamp(timestamp)

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
    _validate_score(score)
    _validate_level(level)
    _validate_timestamp(timestamp)

    if not isinstance(affected_files, list):
        raise TypeError("affected_files must be a list.")

    for path in affected_files:
        _validate_text(path, "affected file path")

    record = Incident(
        score=score,
        level=level,
        status="open",
        affected_files="\n".join(affected_files),
        timestamp=timestamp or datetime.now(),
    )

    _save_record(record)


def get_recent_events(limit: int = 50) -> list[dict]:
    _validate_limit(limit)

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
    _validate_limit(limit)

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
    _validate_limit(limit)

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
    _validate_limit(limit)

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
