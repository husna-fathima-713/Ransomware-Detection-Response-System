from app.detectors.event_stats import EventStats


class ThreatDetector:
    """Detect suspicious filesystem activity using configured thresholds."""

    def __init__(
        self,
        event_stats: EventStats,
        thresholds: dict,
    ) -> None:
        self.event_stats = event_stats
        self.thresholds = thresholds

    def detect(self) -> dict:
        """Evaluate recent filesystem activity against thresholds."""
        statistics = self.event_stats.calculate()

        triggered_rules = []

        if (
            statistics["modified"]
            >= self.thresholds["files_modified_per_minute"]
        ):
            triggered_rules.append("rapid_file_modification")

        if statistics["renamed"] >= self.thresholds["rename_count"]:
            triggered_rules.append("mass_rename")

        if (
            statistics["extension_changes"]
            >= self.thresholds["extension_change_count"]
        ):
            triggered_rules.append("extension_changes")

        return {
            "detected": bool(triggered_rules),
            "triggered_rules": triggered_rules,
            "statistics": statistics,
        }