import csv
import json
from datetime import datetime
from pathlib import Path

from app.database.repository import (
    get_recent_alerts,
    get_recent_events,
    get_recent_incidents,
    get_recent_processes,
)


class ReportGenerator:
    """Generate JSON and CSV reports from RDRS data."""

    def __init__(
        self,
        output_directory: str = "reports",
    ) -> None:
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def collect_data(self) -> dict:
        """Collect recent RDRS data."""
        return {
            "generated_at": datetime.now().isoformat(),
            "events": get_recent_events(1000),
            "alerts": get_recent_alerts(1000),
            "incidents": get_recent_incidents(1000),
            "processes": get_recent_processes(1000),
        }

    def generate_json(self) -> str:
        """Generate a JSON report."""
        data = self.collect_data()

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        output_path = (
            self.output_directory
            / f"rdrs_report_{timestamp}.json"
        )

        with output_path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                data,
                file,
                indent=4,
            )

        return str(output_path)

    def generate_csv(self) -> str:
        """Generate a CSV report containing security events."""
        events = get_recent_events(1000)
        alerts = get_recent_alerts(1000)
        incidents = get_recent_incidents(1000)

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        output_path = (
            self.output_directory
            / f"rdrs_report_{timestamp}.csv"
        )

        rows = []

        for event in events:
            rows.append(
                {
                    "record_type": "event",
                    "id": event["id"],
                    "event_type": event["event_type"],
                    "path": event["path"],
                    "score": "",
                    "level": "",
                    "status": "",
                    "rule": "",
                    "timestamp": event["timestamp"],
                }
            )

        for alert in alerts:
            rows.append(
                {
                    "record_type": "alert",
                    "id": alert["id"],
                    "event_type": "",
                    "path": "",
                    "score": alert["score"],
                    "level": alert["level"],
                    "status": "",
                    "rule": alert["rule"],
                    "timestamp": alert["timestamp"],
                }
            )

        for incident in incidents:
            rows.append(
                {
                    "record_type": "incident",
                    "id": incident["id"],
                    "event_type": "",
                    "path": "\n".join(
                        incident["affected_files"]
                    ),
                    "score": incident["score"],
                    "level": incident["level"],
                    "status": incident["status"],
                    "rule": "",
                    "timestamp": incident["timestamp"],
                }
            )

        fieldnames = [
            "record_type",
            "id",
            "event_type",
            "path",
            "score",
            "level",
            "status",
            "rule",
            "timestamp",
        ]

        with output_path.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames,
            )

            writer.writeheader()
            writer.writerows(rows)

        return str(output_path)