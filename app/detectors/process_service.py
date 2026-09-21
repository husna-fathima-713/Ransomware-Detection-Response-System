import asyncio
from datetime import datetime

from loguru import logger

from app.database.repository import save_process_snapshot
from app.detectors.process_monitor import get_process_snapshot


async def process_monitor_loop(
    interval_seconds: int = 5,
) -> None:
    """Continuously collect and persist process snapshots."""
    logger.info(
        "Process monitoring started with {} second interval",
        interval_seconds,
    )

    try:
        while True:
            timestamp = datetime.now()
            processes = get_process_snapshot()

            for process in processes:
                save_process_snapshot(
                    process,
                    timestamp=timestamp,
                )

            logger.info(
                "Saved process snapshot: {} processes",
                len(processes),
            )

            await asyncio.sleep(interval_seconds)

    except asyncio.CancelledError:
        logger.info("Process monitoring stopped")
        raise