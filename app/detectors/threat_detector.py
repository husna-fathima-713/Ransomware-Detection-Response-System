
import math
from numbers import Real
from pathlib import Path

from app.core.entropy import calculate_file_entropy
from app.detectors.event_stats import EventStats
from app.detectors.process_stats import get_process_stats


REQUIRED_THRESHOLDS = {
    "files_modified_per_minute",
    "rename_count",
    "extension_change_count",
    "average_entropy",
    "cpu_spike_percent",
}


class ThreatDetector:
    def __init__(
        self,
        event_stats: EventStats,
        thresholds: dict,
    ) -> None:
        if not isinstance(event_stats, EventStats):
            raise TypeError("event_stats must be an EventStats instance.")

        if not isinstance(thresholds, dict):
            raise TypeError("thresholds must be a dictionary.")

        missing = REQUIRED_THRESHOLDS - thresholds.keys()
        if missing:
            raise ValueError(
                f"Missing detection thresholds: {', '.join(sorted(missing))}"
            )

        validated_thresholds = {}

        for name in REQUIRED_THRESHOLDS:
            value = thresholds[name]

            if (
                isinstance(value, bool)
                or not isinstance(value, Real)
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError(
                    f"Threshold '{name}' must be a finite, non-negative number."
                )

            if name != "cpu_spike_percent" and value == 0:
                raise ValueError(
                    f"Threshold '{name}' must be greater than zero."
                )

            if name == "average_entropy" and value > 8:
                raise ValueError(
                    "Threshold 'average_entropy' cannot exceed 8."
                )

            validated_thresholds[name] = value

        self.event_stats = event_stats
        self.thresholds = validated_thresholds

    def detect(self, affected_files: list[str] | None = None) -> dict:
        if affected_files is not None:
            if not isinstance(affected_files, list):
                raise TypeError("affected_files must be a list of file paths.")

            if any(not isinstance(path, str) for path in affected_files):
                raise ValueError("Every affected file path must be a string.")

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

        entropy_values = []

        for file_path in affected_files or []:
            path = Path(file_path)

            try:
                if not path.is_file():
                    continue

                entropy = calculate_file_entropy(path)

                if (
                    isinstance(entropy, bool)
                    or not isinstance(entropy, Real)
                    or not math.isfinite(entropy)
                    or not 0 <= entropy <= 8
                ):
                    continue

                entropy_values.append(float(entropy))

            except (OSError, ValueError):
                continue

        average_entropy = (
            sum(entropy_values) / len(entropy_values)
            if entropy_values
            else 0.0
        )

        high_entropy = (
            bool(entropy_values)
            and average_entropy >= self.thresholds["average_entropy"]
        )

        process_statistics = get_process_stats()
        highest_cpu = process_statistics.get("highest_cpu_percent", 0.0)

        if (
            isinstance(highest_cpu, bool)
            or not isinstance(highest_cpu, Real)
            or not math.isfinite(highest_cpu)
            or highest_cpu < 0
        ):
            highest_cpu = 0.0

        cpu_spike = (
            highest_cpu >= self.thresholds["cpu_spike_percent"]
        )

        if rapid_encryption:
            triggered_rules.append("rapid_file_modification")

        if mass_rename:
            triggered_rules.append("mass_rename")

        if extension_changes:
            triggered_rules.append("extension_changes")

        if high_entropy:
            triggered_rules.append("high_entropy")

        if cpu_spike:
            triggered_rules.append("cpu_spike")

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
