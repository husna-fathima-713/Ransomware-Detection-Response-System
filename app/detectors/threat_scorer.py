
import math
from numbers import Real


DEFAULT_LEVELS = {
    "normal": 40,
    "warning": 70,
    "critical": 90,
}


class ThreatScorer:
    """Calculate a 0-100 threat score from detection signals."""

    def __init__(
        self,
        weights: dict,
        levels: dict | None = None,
    ) -> None:
        if not isinstance(weights, dict):
            raise ValueError("Threat weights must be a dictionary.")

        self.weights = {}

        for signal, weight in weights.items():
            if not isinstance(signal, str) or not signal.strip():
                raise ValueError("Signal names must be non-empty strings.")

            self._validate_number(
                weight,
                f"Weight for '{signal}'",
                minimum=0,
            )
            self.weights[signal] = weight

        configured_levels = (
            DEFAULT_LEVELS.copy() if levels is None else levels
        )

        if not isinstance(configured_levels, dict):
            raise ValueError("Threat levels must be a dictionary.")

        required_levels = ("normal", "warning", "critical")

        for level in required_levels:
            if level not in configured_levels:
                raise ValueError(f"Missing severity threshold: '{level}'.")

            self._validate_number(
                configured_levels[level],
                f"Threshold for '{level}'",
                minimum=0,
                maximum=100,
            )

        if not (
            configured_levels["normal"]
            < configured_levels["warning"]
            < configured_levels["critical"]
        ):
            raise ValueError(
                "Severity thresholds must be strictly increasing: "
                "normal < warning < critical."
            )

        self.levels = {
            level: configured_levels[level]
            for level in required_levels
        }

    @staticmethod
    def _validate_number(
        value,
        name: str,
        minimum=None,
        maximum=None,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, Real)
            or not math.isfinite(value)
        ):
            raise ValueError(f"{name} must be a finite number.")

        if minimum is not None and value < minimum:
            raise ValueError(f"{name} must be at least {minimum}.")

        if maximum is not None and value > maximum:
            raise ValueError(f"{name} must not exceed {maximum}.")

    def calculate_score(self, signals: dict) -> int | float:
        """Calculate a weighted threat score, capped at 100."""
        if not isinstance(signals, dict):
            raise ValueError("Detection signals must be a dictionary.")

        score = 0

        for signal, active in signals.items():
            if not isinstance(active, bool):
                raise ValueError(
                    f"Detection signal '{signal}' must be a boolean."
                )

            if active:
                score += self.weights.get(signal, 0)

        return min(score, 100)

    def get_level(self, score: int | float) -> str:
        """Convert a validated score into a severity level."""
        self._validate_number(
            score,
            "Threat score",
            minimum=0,
            maximum=100,
        )

        if score >= self.levels["critical"]:
            return "critical"

        if score >= self.levels["warning"]:
            return "warning"

        return "normal"

    def score_detection(self, detection: dict) -> dict:
        """Calculate score and severity from a detection result."""
        if not isinstance(detection, dict):
            raise ValueError("Detection result must be a dictionary.")

        signals = detection.get("signals", {})

        score = self.calculate_score(signals)
        level = self.get_level(score)

        return {
            **detection,
            "score": score,
            "level": level,
        }
