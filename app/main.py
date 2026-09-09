from loguru import logger

from app.core.config import load_config
from app.core.logging_config import setup_logging
from app.detectors.file_monitor import start_monitor


def main() -> None:
    config = load_config()

    setup_logging(config["logging"]["directory"])

    logger.info("RDRS application started")

    print("RDRS - Ransomware Detection and Response System")
    print("Status: monitoring")

    watch_path = config["monitoring"]["watch_paths"][0]

    print(f"Watching: {watch_path}")

    observer = start_monitor(watch_path)

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping RDRS monitor...")
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()