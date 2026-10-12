
import logging
from pathlib import Path
import shutil


logger = logging.getLogger(__name__)


class QuarantineManager:
    """Safely copy suspicious files into the quarantine directory."""

    def __init__(
        self,
        quarantine_path: str = "data/quarantine",
        simulation_mode: bool = True,
    ) -> None:
        self.quarantine_path = Path(quarantine_path)
        self.simulation_mode = simulation_mode

    def quarantine_file(self, file_path: str) -> str | None:
        """Copy a suspicious file to quarantine without modifying its source."""
        source = Path(file_path)
        destination = None

        try:
            if not source.exists() or not source.is_file():
                logger.warning(
                    "Quarantine skipped: source file is missing or invalid: %s",
                    source,
                )
                return None

            self.quarantine_path.mkdir(
                parents=True,
                exist_ok=True,
            )

            destination = self.quarantine_path / source.name
            counter = 1

            while destination.exists():
                destination = (
                    self.quarantine_path
                    / f"{source.stem}_{counter}{source.suffix}"
                )
                counter += 1

            shutil.copy2(source, destination)

            logger.info(
                "File copied to quarantine: %s",
                destination,
            )

            return str(destination)

        except OSError:
            logger.exception(
                "Quarantine copy failed for: %s",
                source,
            )

            if destination is not None:
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    logger.exception(
                        "Failed to remove incomplete quarantine file: %s",
                        destination,
                    )

            return None

    def quarantine_files(
        self,
        file_paths: list[str],
    ) -> list[str]:
        """Quarantine multiple files while continuing after individual failures."""
        quarantined = []

        for file_path in file_paths:
            result = self.quarantine_file(file_path)

            if result:
                quarantined.append(result)

        return quarantined
