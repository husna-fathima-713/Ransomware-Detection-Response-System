from datetime import datetime

from app.database.repository import save_alert, save_incident


class ResponseEngine:
    """Create alerts and incidents from threat detection results."""

    def __init__(self, simulation_mode: bool = True) -> None:
        self.simulation_mode = simulation_mode

    def handle_detection(
        self,
        score: int,
        level: str,
        triggered_rules: list[str],
        affected_files: list[str],
    ) -> None:
        """Handle a detected threat."""
        timestamp = datetime.now()

        for rule in triggered_rules:
            save_alert(
                score=score,
                level=level,
                rule=rule,
                timestamp=timestamp,
            )

        if level == "critical":
            save_incident(
                score=score,
                level=level,
                affected_files=affected_files,
                timestamp=timestamp,
            )