from pathlib import Path

from app.core.entropy import calculate_file_entropy
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

    def detect(
        self,
        affected_files: list[str] | None = None,
    ) -> dict:
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

        high_entropy = False
        average_entropy = 0.0
        entropy_values = []

        for file_path in affected_files or []:
            path = Path(file_path)

            if not path.exists() or not path.is_file():
                continue

            try:
                entropy = calculate_file_entropy(path)
                entropy_values.append(entropy)
            except (OSError, ValueError):
                continue

        if entropy_values:
            average_entropy = (
                sum(entropy_values) / len(entropy_values)
            )

            high_entropy = (
                average_entropy
                >= self.thresholds["average_entropy"]
            )

        if rapid_encryption:
            triggered_rules.append("rapid_file_modification")

        if mass_rename:
            triggered_rules.append("mass_rename")

        if extension_changes:
            triggered_rules.append("extension_changes")

        if high_entropy:
            triggered_rules.append("high_entropy")

        signals = {
            "rapid_encryption": rapid_encryption,
            "mass_rename": mass_rename,
            "high_entropy": high_entropy,
            "cpu_spike": False,
            "unknown_program": False,
        }

        return {
            "detected": bool(triggered_rules),
            "triggered_rules": triggered_rules,
            "signals": signals,
            "statistics": statistics,
            "average_entropy": average_entropy,
        }