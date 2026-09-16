from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.database.database import create_database
from app.database.repository import save_file_event
from app.detectors.event import FileEvent
from app.detectors.event_history import EventHistory
from app.detectors.event_stats import EventStats
from app.detectors.threat_detector import ThreatDetector


class RDRSEventHandler(FileSystemEventHandler):
    """Handle file-system events and detect suspicious activity."""

    def __init__(
        self,
        window_seconds: int = 60,
        thresholds: dict | None = None,
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
        }

        self.detector = ThreatDetector(
            self.stats,
            self.thresholds,
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
        detection = self.detector.detect()

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

        if detection["detected"]:
            print(
                f"[THREAT] DETECTED | "
                f"rules={detection['triggered_rules']}"
            )

    def on_created(self, event) -> None:
        if not event.is_directory:
            self._handle_event("create", event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._handle_event("modify", event.src_path)

    def on_deleted(self, event) -> None:
        if not event.is_directory:
            self._handle_event("delete", event.src_path)

    def on_moved(self, event) -> None:
        if not event.is_directory:
            old_extension = ""

            if "." in event.src_path.split("/")[-1]:
                old_extension = "." + event.src_path.rsplit(".", 1)[-1]

            self._handle_event(
                "rename",
                event.dest_path,
                old_extension,
            )


def start_monitor(
    watch_path: str,
    window_seconds: int = 60,
    thresholds: dict | None = None,
) -> Observer:
    """Start monitoring a directory."""
    create_database()

    observer = Observer()

    handler = RDRSEventHandler(
        window_seconds,
        thresholds,
    )

    observer.schedule(
        handler,
        path=watch_path,
        recursive=True,
    )

    observer.start()

    return observer