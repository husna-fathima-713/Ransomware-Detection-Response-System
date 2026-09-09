from loguru import logger

from app.core.config import load_config
from app.core.logging_config import setup_logging


def main() -> None:
    config = load_config()

    setup_logging(config["logging"]["directory"])

    logger.info("RDRS application started")

    print("RDRS - Ransomware Detection and Response System")
    print("Status: initialized")
    print(f"Monitoring: {config['monitoring']['watch_paths']}")


if __name__ == "__main__":
    main()