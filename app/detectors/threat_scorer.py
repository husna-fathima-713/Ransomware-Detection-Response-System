class ThreatScorer:
    """Calculate a 0-100 threat score from triggered detection rules."""

    def __init__(self, weights: dict) -> None:
        self.weights = weights

    def calculate_score(self, triggered_rules: list[str]) -> int:
        """Calculate the weighted threat score."""
        score = 0

        rule_mapping = {
            "rapid_file_modification": "rapid_encryption",
            "mass_rename": "mass_rename",
            "extension_changes": "rapid_encryption",
        }

        for rule in triggered_rules:
            weight_name = rule_mapping.get(rule)

            if weight_name:
                score += self.weights.get(weight_name, 0)

        return min(score, 100)

    def get_level(self, score: int) -> str:
        """Convert a threat score into a severity level."""
        if score >= self.weights.get("critical", 100):
            return "critical"

        if score >= self.weights.get("warning", 70):
            return "warning"

        return "normal"