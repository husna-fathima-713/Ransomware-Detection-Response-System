from pathlib import Path

from loguru import logger


def setup_logging(log_directory: str = "logs") -> None:
    """Configure RDRS application logging."""
    log_path = Path(log_directory)
    log_path.mkdir(parents=True, exist_ok=True)

    logger.remove()

    logger.add(
        log_path / "system.log",
        rotation="10 MB",
        retention="7 days",
        level="INFO",
    )

    logger.add(
        log_path / "events.log",
        rotation="10 MB",
        retention="7 days",
        level="INFO",
        filter=lambda record: record["extra"].get("log_type") == "event",
    )

    logger.add(
        log_path / "alerts.log",
        rotation="10 MB",
        retention="7 days",
        level="WARNING",
        filter=lambda record: record["extra"].get("log_type") == "alert",
    )

    logger.add(
        log_path / "errors.log",
        rotation="10 MB",
        retention="7 days",
        level="ERROR",
    )

    logger.add(
        log_path / "audit.log",
        rotation="10 MB",
        retention="7 days",
        level="INFO",
        filter=lambda record: record["extra"].get("log_type") == "audit",
    )