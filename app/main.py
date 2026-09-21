import asyncio
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from loguru import logger

from app.api.routes import router
from app.core.config import load_config
from app.core.logging_config import setup_logging
from app.database.database import create_database
from app.detectors.file_monitor import start_monitor
from app.detectors.process_service import process_monitor_loop


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and shut down the RDRS application."""
    config = load_config()

    setup_logging(config["logging"]["directory"])
    create_database()

    logger.info("RDRS application started")

    watch_path = config["monitoring"]["watch_paths"][0]
    window_seconds = config["monitoring"]["sliding_window_seconds"]
    thresholds = config["detection"]["thresholds"]
    scan_interval = config["monitoring"]["scan_interval_seconds"]

    observer = start_monitor(
        watch_path,
        window_seconds,
        thresholds,
    )

    logger.info("Filesystem monitoring started")

    process_task = asyncio.create_task(
        process_monitor_loop(scan_interval)
    )

    try:
        yield
    finally:
        process_task.cancel()

        try:
            await process_task
        except asyncio.CancelledError:
            pass

        observer.stop()
        observer.join()

        logger.info("RDRS application stopped")


app = FastAPI(
    title="Ransomware Detection and Response System",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router)


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )