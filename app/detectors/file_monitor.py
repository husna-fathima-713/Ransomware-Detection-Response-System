from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.detectors.event import FileEvent


class RDRSEventHandler(FileSystemEventHandler):
    """Handle file-system events for RDRS."""

    def __init__(self) -> None:
        super().__init__()
        self.event_count = 0

    def _handle_event(self, event_type: str, path: str) -> None:
        event = FileEvent.create(event_type, path)
        self.event_count += 1

        print(
            f"[EVENT] {event.event_type.upper()} | "
            f"{event.timestamp.isoformat()} | "
            f"{event.path} | "
            f"{event.extension or '[no extension]'} | "
            f"COUNT={self.event_count}"
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
            self._handle_event("rename", event.dest_path)


def start_monitor(watch_path: str) -> Observer:
    """Start monitoring a directory."""
    observer = Observer()
    handler = RDRSEventHandler()

    observer.schedule(
        handler,
        path=watch_path,
        recursive=True,
    )

    observer.start()

    return observer