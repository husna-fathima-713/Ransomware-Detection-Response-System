from collections import deque
from datetime import datetime, timedelta

from app.detectors.event import FileEvent


class EventHistory:
    """Maintain filesystem events within a sliding time window."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.events: deque[FileEvent] = deque()

    def add(self, event: FileEvent) -> None:
        self.events.append(event)
        self._remove_expired()

    def _remove_expired(self) -> None:
        cutoff = datetime.now() - self.window

        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def get_events(self) -> list[FileEvent]:
        self._remove_expired()
        return list(self.events)

    def count(self) -> int:
        self._remove_expired()
        return len(self.events)