from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from loguru import logger

from app.api.routes import router
from app.core.config import load_config
from app.core.logging_config import setup_logging
from app.database.database import create_database
from app.detectors.file_monitor import start_monitor


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

    observer = start_monitor(
        watch_path,
        window_seconds,
        thresholds,
    )

    logger.info("Filesystem monitoring started")

    yield

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