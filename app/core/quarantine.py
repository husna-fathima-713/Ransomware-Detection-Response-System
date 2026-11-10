
import logging
import os
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
        if not isinstance(quarantine_path, (str, os.PathLike)):
            raise TypeError("quarantine_path must be a string or path.")

        if not str(quarantine_path).strip():
            raise ValueError("quarantine_path cannot be empty.")

        if not isinstance(simulation_mode, bool):
            raise TypeError("simulation_mode must be a boolean.")

        self.quarantine_path = Path(quarantine_path)
        self.simulation_mode = simulation_mode

    def _reserve_destination(self, source: Path) -> Path:
        """Atomically reserve a unique destination filename."""
        counter = 0

        while True:
            if counter == 0:
                filename = source.name
            else:
                filename = f"{source.stem}_{counter}{source.suffix}"

            destination = self.quarantine_path / filename

            try:
                descriptor = os.open(
                    destination,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                os.close(descriptor)
                return destination

            except FileExistsError:
                counter += 1

    def quarantine_file(self, file_path: str) -> str | None:
        """Copy a suspicious file without modifying its source."""
        if not isinstance(file_path, (str, os.PathLike)):
            raise TypeError("file_path must be a string or path.")

        source = Path(file_path)
        destination = None

        try:
            if source.is_symlink():
                logger.warning("Quarantine skipped: symbolic link: %s", source)
                return None

            if not source.exists() or not source.is_file():
                logger.warning(
                    "Quarantine skipped: source file is missing or invalid: %s",
                    source,
                )
                return None

            source_resolved = source.resolve(strict=True)

            if self.quarantine_path.is_symlink():
                logger.warning(
                    "Quarantine skipped: destination directory is a symbolic link."
                )
                return None

            self.quarantine_path.mkdir(parents=True, exist_ok=True)

            quarantine_resolved = self.quarantine_path.resolve(strict=True)

            if not quarantine_resolved.is_dir():
                logger.warning("Quarantine destination is not a directory.")
                return None

            if source_resolved == quarantine_resolved:
                logger.warning("Quarantine skipped: source is the destination directory.")
                return None

            if source_resolved.parent == quarantine_resolved:
                logger.warning("Quarantine skipped: source is already in quarantine.")
                return None

            destination = self._reserve_destination(source)

            shutil.copy2(source_resolved, destination)

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

    def quarantine_files(self, file_paths: list[str]) -> list[str]:
        """Quarantine multiple files while continuing after individual failures."""
        if not isinstance(file_paths, list):
            raise TypeError("file_paths must be a list.")

        quarantined = []

        for file_path in file_paths:
            result = self.quarantine_file(file_path)

            if result:
                quarantined.append(result)

        return quarantined
