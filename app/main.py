import time

from loguru import logger

from app.core.config import load_config
from app.core.logging_config import setup_logging
from app.detectors.file_monitor import start_monitor
from app.detectors.process_stats import get_process_stats


def main() -> None:
    config = load_config()

    setup_logging(config["logging"]["directory"])

    logger.info("RDRS application started")

    print("RDRS - Ransomware Detection and Response System")
    print("Status: monitoring")

    watch_path = config["monitoring"]["watch_paths"][0]
    window_seconds = config["monitoring"]["sliding_window_seconds"]
    thresholds = config["detection"]["thresholds"]

    print(f"Watching: {watch_path}")
    print(f"Sliding window: {window_seconds} seconds")

    observer = start_monitor(
        watch_path,
        window_seconds,
        thresholds,
    )

    try:
        while True:
            process_stats = get_process_stats()

            print(
                f"[PROCESS] total={process_stats['total_processes']} | "
                f"high_cpu={process_stats['high_cpu_count']} | "
                f"highest_cpu="
                f"{process_stats['highest_cpu_percent']:.1f}%"
            )

            time.sleep(5)

    except KeyboardInterrupt:
        print("\nStopping RDRS monitor...")
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()