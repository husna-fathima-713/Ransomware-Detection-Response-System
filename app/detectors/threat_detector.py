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

        rapid_encryption = (
            statistics["modified"]
            >= self.thresholds["files_modified_per_minute"]
        )

        mass_rename = (
            statistics["renamed"]
            >= self.thresholds["rename_count"]
        )

        extension_changes = (
            statistics["extension_changes"]
            >= self.thresholds["extension_change_count"]
        )

        if rapid_encryption:
            triggered_rules.append("rapid_file_modification")

        if mass_rename:
            triggered_rules.append("mass_rename")

        if extension_changes:
            triggered_rules.append("extension_changes")

        signals = {
            "rapid_encryption": rapid_encryption,
            "mass_rename": mass_rename,
            "high_entropy": False,
            "cpu_spike": False,
            "unknown_program": False,
        }

        return {
            "detected": bool(triggered_rules),
            "triggered_rules": triggered_rules,
            "signals": signals,
            "statistics": statistics,
        }