from pathlib import Path
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class RDRSEventHandler(FileSystemEventHandler):
    """Handle file-system events for RDRS."""

    def _log_event(self, event_type: str, path: str) -> None:
        file_path = Path(path)

        print(
            f"[EVENT] {event_type.upper()} | "
            f"{datetime.now().isoformat()} | "
            f"{file_path}"
        )

    def on_created(self, event) -> None:
        if not event.is_directory:
            self._log_event("create", event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._log_event("modify", event.src_path)

    def on_deleted(self, event) -> None:
        if not event.is_directory:
            self._log_event("delete", event.src_path)

    def on_moved(self, event) -> None:
        if not event.is_directory:
            self._log_event(
                "rename",
                f"{event.src_path} -> {event.dest_path}",
            )


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