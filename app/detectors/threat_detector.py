from pathlib import Path

from app.core.entropy import calculate_file_entropy
from app.detectors.event_stats import EventStats
from app.detectors.process_stats import get_process_stats


class ThreatDetector:
    """Detect suspicious filesystem and process activity."""

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
        """Evaluate recent filesystem and process activity."""
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

        process_statistics = get_process_stats()

        highest_cpu = process_statistics[
            "highest_cpu_percent"
        ]

        cpu_spike = (
            highest_cpu
            >= self.thresholds["cpu_spike_percent"]
        )

        if rapid_encryption:
            triggered_rules.append(
                "rapid_file_modification"
            )

        if mass_rename:
            triggered_rules.append(
                "mass_rename"
            )

        if extension_changes:
            triggered_rules.append(
                "extension_changes"
            )

        if high_entropy:
            triggered_rules.append(
                "high_entropy"
            )

        if cpu_spike:
            triggered_rules.append(
                "cpu_spike"
            )

        signals = {
            "rapid_encryption": rapid_encryption,
            "mass_rename": mass_rename,
            "high_entropy": high_entropy,
            "cpu_spike": cpu_spike,
            "unknown_program": False,
        }

        return {
            "detected": bool(triggered_rules),
            "triggered_rules": triggered_rules,
            "signals": signals,
            "statistics": statistics,
            "average_entropy": average_entropy,
            "process_statistics": process_statistics,
        }