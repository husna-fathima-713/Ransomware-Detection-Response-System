import time

import uvicorn
from fastapi import FastAPI
from loguru import logger

from app.api.routes import router
from app.core.config import load_config
from app.core.logging_config import setup_logging
from app.database.database import create_database
from app.detectors.file_monitor import start_monitor
from app.detectors.process_stats import get_process_stats


app = FastAPI(
    title="Ransomware Detection and Response System",
    version="1.0.0",
)

app.include_router(router)


@app.on_event("startup")
def startup() -> None:
    """Initialize the RDRS application."""
    config = load_config()

    setup_logging(config["logging"]["directory"])
    create_database()

    logger.info("RDRS application started")

    watch_path = config["monitoring"]["watch_paths"][0]
    window_seconds = config["monitoring"]["sliding_window_seconds"]
    thresholds = config["detection"]["thresholds"]

    start_monitor(
        watch_path,
        window_seconds,
        thresholds,
    )

    logger.info("Filesystem monitoring started")


@app.on_event("shutdown")
def shutdown() -> None:
    """Log application shutdown."""
    logger.info("RDRS application stopped")


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )