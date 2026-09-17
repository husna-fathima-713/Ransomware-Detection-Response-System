from pathlib import Path
import shutil


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
        """Copy a suspicious file to quarantine."""
        source = Path(file_path)

        if not source.exists() or not source.is_file():
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

        return str(destination)

    def quarantine_files(
        self,
        file_paths: list[str],
    ) -> list[str]:
        """Quarantine multiple suspicious files."""
        quarantined = []

        for file_path in file_paths:
            result = self.quarantine_file(file_path)

            if result:
                quarantined.append(result)

        return quarantined