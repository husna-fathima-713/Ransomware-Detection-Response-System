class ThreatScorer:
    """Calculate a 0-100 threat score from detection signals."""

    def __init__(
        self,
        weights: dict,
        levels: dict | None = None,
    ) -> None:
        self.weights = weights
        self.levels = levels or {
            "normal": 40,
            "warning": 70,
            "critical": 100,
        }

    def calculate_score(self, signals: dict) -> int:
        """Calculate a weighted threat score."""
        score = 0

        for signal, active in signals.items():
            if active:
                score += self.weights.get(signal, 0)

        return min(score, 100)

    def get_level(self, score: int) -> str:
        """Convert a score into a severity level."""
        if score >= self.levels["critical"]:
            return "critical"

        if score >= self.levels["warning"]:
            return "warning"

        return "normal"

    def score_detection(self, detection: dict) -> dict:
        """Calculate score and severity from a detection result."""
        signals = detection.get("signals", {})

        score = self.calculate_score(signals)
        level = self.get_level(score)

        return {
            **detection,
            "score": score,
            "level": level,
        }