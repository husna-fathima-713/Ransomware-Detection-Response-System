
import logging
import math
from datetime import datetime
from numbers import Real

from app.core.quarantine import QuarantineManager
from app.database.repository import save_alert, save_incident


logger = logging.getLogger(__name__)

VALID_LEVELS = {"normal", "warning", "critical"}


class ResponseEngine:
    """Create alerts, incidents, and quarantine evidence."""

    def __init__(
        self,
        simulation_mode: bool = True,
        quarantine_path: str = "data/quarantine",
    ) -> None:
        if not isinstance(simulation_mode, bool):
            raise TypeError("simulation_mode must be a boolean.")

        if not isinstance(quarantine_path, (str,)):
            raise TypeError("quarantine_path must be a string.")

        if not quarantine_path.strip():
            raise ValueError("quarantine_path cannot be empty.")

        self.simulation_mode = simulation_mode

        self.quarantine = QuarantineManager(
            quarantine_path=quarantine_path,
            simulation_mode=simulation_mode,
        )

    @staticmethod
    def _validate_score(score: int) -> None:
        if (
            isinstance(score, bool)
            or not isinstance(score, Real)
            or not math.isfinite(score)
            or not 0 <= score <= 100
        ):
            raise ValueError("score must be a finite number between 0 and 100.")

    @staticmethod
    def _validate_level(level: str) -> None:
        if not isinstance(level, str) or level not in VALID_LEVELS:
            raise ValueError(
                "level must be normal, warning, or critical."
            )

    @staticmethod
    def _validate_file_list(
        values: list[str],
        field_name: str,
    ) -> None:
        if not isinstance(values, list):
            raise TypeError(f"{field_name} must be a list.")

        if any(
            not isinstance(value, str) or not value.strip()
            for value in values
        ):
            raise ValueError(
                f"Every entry in {field_name} must be a non-empty string."
            )

    @staticmethod
    def _validate_rules(triggered_rules: list[str]) -> None:
        if not isinstance(triggered_rules, list):
            raise TypeError("triggered_rules must be a list.")

        if any(
            not isinstance(rule, str) or not rule.strip()
            for rule in triggered_rules
        ):
            raise ValueError(
                "Every triggered rule must be a non-empty string."
            )

    def handle_detection(
        self,
        score: int,
        level: str,
        triggered_rules: list[str],
        affected_files: list[str],
    ) -> list[str]:
        """Record a detection and preserve available quarantine evidence."""
        self._validate_score(score)
        self._validate_level(level)
        self._validate_rules(triggered_rules)
        self._validate_file_list(affected_files, "affected_files")

        timestamp = datetime.now()

        # Attempt every alert independently so one failed write does not
        # prevent the remaining alerts or a critical incident from being saved.
        for rule in triggered_rules:
            try:
                save_alert(
                    score=score,
                    level=level,
                    rule=rule,
                    timestamp=timestamp,
                )
            except Exception:
                logger.exception(
                    "Failed to save alert for rule: %s",
                    rule,
                )

        quarantined_files = []

        if level == "critical":
            try:
                quarantined_files = self.quarantine.quarantine_files(
                    affected_files
                )

                if not isinstance(quarantined_files, list):
                    raise TypeError(
                        "Quarantine manager returned an invalid result."
                    )

                if any(
                    not isinstance(path, str) or not path.strip()
                    for path in quarantined_files
                ):
                    raise ValueError(
                        "Quarantine manager returned an invalid file path."
                    )

            except Exception:
                logger.exception(
                    "Quarantine operation failed during critical response."
                )
                quarantined_files = []

            failed_count = len(affected_files) - len(quarantined_files)

            if failed_count > 0:
                logger.warning(
                    "Critical response completed with %d file(s) not quarantined.",
                    failed_count,
                )

            # Store the original affected paths. Quarantine destinations are
            # returned separately and must not replace the incident evidence.
            try:
                save_incident(
                    score=score,
                    level=level,
                    affected_files=affected_files,
                    timestamp=timestamp,
                )
            except Exception:
                logger.exception(
                    "Failed to save incident record for critical detection."
                )
                raise

        return quarantined_files
