from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.core.response import ResponseEngine
from app.database.database import create_database
from app.database.repository import save_file_event
from app.detectors.event import FileEvent
from app.detectors.event_history import EventHistory
from app.detectors.event_stats import EventStats
from app.detectors.threat_detector import ThreatDetector
from app.detectors.threat_scorer import ThreatScorer


class RDRSEventHandler(FileSystemEventHandler):
    """Handle file-system events and respond to suspicious activity."""

    def __init__(
        self,
        window_seconds: int = 60,
        thresholds: dict | None = None,
        scoring_weights: dict | None = None,
        scoring_levels: dict | None = None,
        response_config: dict | None = None,
    ) -> None:
        super().__init__()

        self.event_count = 0
        self.history = EventHistory(window_seconds)
        self.stats = EventStats(self.history)

        self.thresholds = thresholds or {
            "files_modified_per_minute": 20,
            "rename_count": 10,
            "extension_change_count": 5,
            "average_entropy": 7.2,
            "cpu_spike_percent": 80.0,
        }

        self.detector = ThreatDetector(
            self.stats,
            self.thresholds,
        )

        self.scorer = ThreatScorer(
            weights=scoring_weights or {},
            levels=scoring_levels,
        )

        response_config = response_config or {}

        self.response_engine = ResponseEngine(
            simulation_mode=response_config.get(
                "simulation_mode",
                True,
            ),
            quarantine_path=response_config.get(
                "quarantine_path",
                "data/quarantine",
            ),
        )

    def _handle_event(
        self,
        event_type: str,
        path: str,
        old_extension: str = "",
    ) -> None:
        event = FileEvent.create(
            event_type,
            path,
            old_extension,
        )

        self.event_count += 1
        self.history.add(event)

        save_file_event(
            event_type=event.event_type,
            path=event.path,
            extension=event.extension,
            old_extension=event.old_extension,
            timestamp=event.timestamp,
        )

        statistics = self.stats.calculate()

        affected_files = [
            recent_event.path
            for recent_event in self.history.get_events()
            if recent_event.event_type in {
                "create",
                "modify",
                "rename",
            }
        ]

        detection = self.detector.detect(
            affected_files=affected_files,
        )

        scored_detection = self.scorer.score_detection(
            detection
        )

        print(
            f"[EVENT] {event.event_type.upper()} | "
            f"{event.timestamp.isoformat()} | "
            f"{event.path} | "
            f"{event.extension or '[no extension]'}"
        )

        print(
            f"[STATS] total={statistics['total_events']} | "
            f"created={statistics['created']} | "
            f"modified={statistics['modified']} | "
            f"deleted={statistics['deleted']} | "
            f"renamed={statistics['renamed']} | "
            f"extension_changes="
            f"{statistics['extension_changes']}"
        )

        process_statistics = detection[
            "process_statistics"
        ]

        print(
            f"[PROCESS] highest_cpu="
            f"{process_statistics['highest_cpu_percent']:.2f}% | "
            f"high_cpu_count="
            f"{process_statistics['high_cpu_count']}"
        )

        if scored_detection["detected"]:
            score = scored_detection["score"]
            level = scored_detection["level"]
            triggered_rules = scored_detection[
                "triggered_rules"
            ]

            quarantined_files = (
                self.response_engine.handle_detection(
                    score=score,
                    level=level,
                    triggered_rules=triggered_rules,
                    affected_files=affected_files,
                )
            )

            print(
                f"[THREAT] DETECTED | "
                f"score={score} | "
                f"level={level} | "
                f"rules={triggered_rules}"
            )

            if quarantined_files:
                print(
                    f"[RESPONSE] Quarantined: "
                    f"{quarantined_files}"
                )

    def on_created(self, event) -> None:
        if not event.is_directory:
            self._handle_event(
                "create",
                event.src_path,
            )

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._handle_event(
                "modify",
                event.src_path,
            )

    def on_deleted(self, event) -> None:
        if not event.is_directory:
            self._handle_event(
                "delete",
                event.src_path,
            )

    def on_moved(self, event) -> None:
        if not event.is_directory:
            old_extension = ""

            if "." in event.src_path.split("/")[-1]:
                old_extension = (
                    "."
                    + event.src_path.rsplit(".", 1)[-1]
                )

            self._handle_event(
                "rename",
                event.dest_path,
                old_extension,
            )


def start_monitor(
    watch_path: str,
    window_seconds: int = 60,
    thresholds: dict | None = None,
    scoring_weights: dict | None = None,
    scoring_levels: dict | None = None,
    response_config: dict | None = None,
) -> Observer:
    """Start monitoring a directory."""
    create_database()

    observer = Observer()

    handler = RDRSEventHandler(
        window_seconds=window_seconds,
        thresholds=thresholds,
        scoring_weights=scoring_weights,
        scoring_levels=scoring_levels,
        response_config=response_config,
    )

    observer.schedule(
        handler,
        path=watch_path,
        recursive=True,
    )

    observer.start()

    return observer