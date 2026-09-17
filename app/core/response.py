from datetime import datetime

from app.core.quarantine import QuarantineManager
from app.database.repository import save_alert, save_incident


class ResponseEngine:
    """Create alerts, incidents, and quarantine evidence."""

    def __init__(
        self,
        simulation_mode: bool = True,
        quarantine_path: str = "data/quarantine",
    ) -> None:
        self.simulation_mode = simulation_mode

        self.quarantine = QuarantineManager(
            quarantine_path=quarantine_path,
            simulation_mode=simulation_mode,
        )

    def handle_detection(
        self,
        score: int,
        level: str,
        triggered_rules: list[str],
        affected_files: list[str],
    ) -> list[str]:
        """Handle a detected threat and preserve evidence."""
        timestamp = datetime.now()

        for rule in triggered_rules:
            save_alert(
                score=score,
                level=level,
                rule=rule,
                timestamp=timestamp,
            )

        quarantined_files = []

        if level == "critical":
            quarantined_files = self.quarantine.quarantine_files(
                affected_files
            )

            save_incident(
                score=score,
                level=level,
                affected_files=quarantined_files,
                timestamp=timestamp,
            )

        return quarantined_files